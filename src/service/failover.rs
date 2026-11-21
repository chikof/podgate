//! The `failover` service: use a fallback service while the main one has no healthy server.
//! Reference: `docs/ref/svc-weighted-failover.md`.
//!
//! ```json
//! { "name": "safe", "type": "failover", "service": "web", "fallback": "web-standby",
//!   "fallback_hold_secs": 10 }
//! ```
//!
//! `service` and `fallback` are a `loadbalancer`, `weighted` or `failover` service of the same
//! app, `name` or `name@revision` (see [`super::graph`]).
//!
//! The primary takes the request while it has at least one server that may (healthy, not
//! ejected, not already tried by this request). Otherwise the fallback does. Flapping is damped:
//! each request that finds the primary down keeps the fallback in use for `fallback_hold_secs`
//! (default 10, at most 3600) from then on, so the fallback keeps serving for that long after
//! the primary recovers. The hold is runtime state in [`super::state::ServiceState`], outside the
//! table, so a push that leaves the service alone keeps it. A request that only skips the
//! primary's servers because it already tried them (a retry) never starts a hold.
//!
//! A primary with no server at all is *asleep* (`scale_to_zero`): the fallback does not take over
//! and the app is woken instead, because a service nobody has started is not a broken one.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::graph::{self, ChildRef, Graph, Node, Path, Readiness};
use super::state::{self, ServiceState};
use super::{Lease, PickCx};
use crate::compile::Invalid;
use podgate_model::Declared;

/// The default `fallback_hold_secs`.
const DEFAULT_HOLD_SECS: u64 = 10;
/// The largest `fallback_hold_secs`.
const MAX_HOLD_SECS: u64 = 3600;

/// The configuration of a `failover` service.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The service that takes requests while it has a healthy server: `name` or
    /// `name@revision`.
    service: String,
    /// The service that takes them otherwise: `name` or `name@revision`.
    fallback: String,
    /// How long the fallback keeps serving after the primary was last seen without a healthy
    /// server, default 10, at most 3600.
    #[serde(default)]
    fallback_hold_secs: Option<u64>,
}

/// A compiled `failover` service. Its two children are names; each revision resolves them into
/// links (see `graph::resolve`): index `0` is the primary, `1` the fallback.
#[derive(Debug)]
pub struct Failover {
    children: [ChildRef; 2],
    hold_ms: u64,
    shared: Arc<ServiceState>,
    fingerprint: u64,
}

/// What the service does with a request now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Primary,
    /// The fallback; `primary_down` when it is because the primary has no server that may take
    /// the request, not because a hold is running.
    Fallback {
        primary_down: bool,
    },
    Unavailable(Readiness),
}

fn invalid(why: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_service", format!("failover: {why}"))
}

impl Failover {
    pub(super) fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let hold = config.fallback_hold_secs.unwrap_or(DEFAULT_HOLD_SECS);
        if hold > MAX_HOLD_SECS {
            return Err(invalid(format!(
                "fallback_hold_secs is at most {MAX_HOLD_SECS}"
            )));
        }
        if config.service == config.fallback {
            return Err(invalid("service and fallback are the same service"));
        }
        Ok(Self {
            children: [
                ChildRef::parse("failover", &config.service, 1)?,
                ChildRef::parse("failover", &config.fallback, 1)?,
            ],
            hold_ms: hold * 1000,
            shared: Arc::default(),
            fingerprint: state::fingerprint(declared),
        })
    }

    /// The primary and the fallback.
    #[must_use]
    pub fn children(&self) -> &[ChildRef] {
        &self.children
    }

    /// The service's fingerprint and shared state, for the registry to carry over.
    pub(super) fn state_mut(&mut self) -> (u64, &mut Arc<ServiceState>) {
        (self.fingerprint, &mut self.shared)
    }

    fn decide(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Decision {
        let links = graph.links(node);
        let (Some(primary), Some(fallback)) = (links.first(), links.get(1)) else {
            return Decision::Unavailable(Readiness::Asleep);
        };
        let ready = |link: &graph::Link| {
            graph::readiness(graph, link.node, cx, now, depth + 1) == Readiness::Ready
        };
        match graph::readiness(graph, primary.node, cx, now, depth + 1) {
            Readiness::Ready if now < self.shared.held_until() && ready(fallback) => {
                Decision::Fallback {
                    primary_down: false,
                }
            }
            Readiness::Ready => Decision::Primary,
            Readiness::Asleep => Decision::Unavailable(Readiness::Asleep),
            Readiness::Down if ready(fallback) => Decision::Fallback { primary_down: true },
            Readiness::Down => Decision::Unavailable(Readiness::Down),
        }
    }

    pub(super) fn readiness(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Readiness {
        match self.decide(graph, node, cx, now, depth) {
            Decision::Primary | Decision::Fallback { .. } => Readiness::Ready,
            Decision::Unavailable(readiness) => readiness,
        }
    }

    /// The child a request would go to now: `0` the primary, `1` the fallback.
    pub(super) fn likely(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Option<usize> {
        match self.decide(graph, node, cx, now, depth) {
            Decision::Primary => Some(0),
            Decision::Fallback { .. } => Some(1),
            Decision::Unavailable(_) => None,
        }
    }

    /// The server a new request goes to. Allocates nothing.
    pub(super) fn pick(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        path: &mut Path,
        depth: usize,
    ) -> Option<(SocketAddr, Lease)> {
        let links = graph.links(node);
        match self.decide(graph, node, cx, now, depth) {
            Decision::Primary => graph::enter(graph, links, 0, cx, now, path, depth)
                .or_else(|| graph::enter(graph, links, 1, cx, now, path, depth)),
            Decision::Fallback { primary_down } => {
                if primary_down && let Some(primary) = links.first() {
                    let bare = PickCx {
                        excluded: &[],
                        ..cx
                    };
                    if graph::readiness(graph, primary.node, bare, now, depth + 1)
                        == Readiness::Down
                    {
                        self.shared.hold_until(now.saturating_add(self.hold_ms));
                    }
                }
                graph::enter(graph, links, 1, cx, now, path, depth)
            }
            Decision::Unavailable(_) => None,
        }
    }
}
