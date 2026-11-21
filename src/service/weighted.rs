//! The `weighted` service: a weighted choice among other services, optionally sticky. Reference:
//! `docs/ref/svc-weighted-failover.md`.
//!
//! ```json
//! { "name": "split", "type": "weighted",
//!   "services": [ { "service": "web-v1", "weight": 90 }, { "service": "web-v2@r2", "weight": 10 } ],
//!   "sticky": { "cookie": { "name": "__podgate_svc" } } }
//! ```
//!
//! A child is a `loadbalancer`, `weighted` or `failover` service of the same app, `name` or
//! `name@revision` (see [`super::graph`]). At most [`MAX_CHILDREN`] children, each with a weight
//! of `0` to `65535`, at least one above `0`; a child of weight `0` is never chosen.
//!
//! Weights are relative among the children that are *eligible*: some server below them may take
//! the request. A child with none is skipped, so its share goes to the others in proportion to
//! their weights and a weighted service never sends to a dead child while another lives. A pick
//! takes the next ticket of a turn of `sum of eligible weights` tickets, spread by a stride that
//! is coprime to the turn, so every turn gives each child exactly its weight and the children
//! alternate instead of taking runs.
//!
//! `sticky` pins a client to one child with a cookie of the parent (default name
//! `__podgate_svc`, so it does not collide with the `__podgate_srv` of a child's own `sticky`):
//! while that child is eligible the client goes to it, and the child's own `sticky` then pins a
//! server inside it. Otherwise the weighted choice decides and the response carries a cookie for
//! the child chosen. The cookie value is keyed like a server's (see [`super::sticky`]) with the
//! child's name as declared in place of the server URL.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::graph::{self, ChildRef, Graph, Link, Node, Path, Readiness};
use super::state::{self, ServiceState};
use super::{Lease, PickCx, Sticky};
use crate::compile::Invalid;
use podgate_model::{Declared, SkewSecret};

/// Most children one `weighted` service declares.
pub(super) const MAX_CHILDREN: usize = 32;

/// Spreads tickets over a turn; a prime above any turn (the weights add up to under 2^22).
const TICKET_STRIDE: u64 = 2_654_435_761;

/// The configuration of a `weighted` service.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// The children and their relative weights.
    services: Vec<ChildConfig>,
    /// Pins a client to one child by cookie.
    #[serde(default)]
    #[schemars(with = "Option<super::sticky::Config>")]
    sticky: Option<Value>,
}

/// One child as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ChildConfig {
    /// A `loadbalancer`, `weighted` or `failover` service of the app: `name`, or
    /// `name@revision`.
    service: String,
    /// Relative weight, `0` to `65535`; `0` never receives a request.
    weight: u16,
}

/// A compiled `weighted` service. Its children are names; each revision resolves them into
/// [`Link`]s (`graph::resolve`).
#[derive(Debug)]
pub struct Weighted {
    children: Box<[ChildRef]>,
    sticky: Option<Sticky>,
    shared: Arc<ServiceState>,
    fingerprint: u64,
}

fn invalid(why: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_service", format!("weighted: {why}"))
}

impl Weighted {
    pub(super) fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        if config.services.is_empty() || config.services.len() > MAX_CHILDREN {
            return Err(invalid(format!(
                "services lists 1 to {MAX_CHILDREN} children"
            )));
        }
        if config.services.iter().all(|child| child.weight == 0) {
            return Err(invalid("at least one child needs a weight above 0"));
        }
        let children = config
            .services
            .iter()
            .map(|child| ChildRef::parse("weighted", &child.service, child.weight))
            .collect::<Result<Box<[_]>, _>>()?;
        let sticky = config
            .sticky
            .as_ref()
            .map(|value| Sticky::compile_as(value, super::sticky::DEFAULT_PARENT_NAME))
            .transpose()?;
        Ok(Self {
            children,
            sticky,
            shared: Arc::default(),
            fingerprint: state::fingerprint(declared),
        })
    }

    /// The children as declared, in order.
    #[must_use]
    pub fn children(&self) -> &[ChildRef] {
        &self.children
    }

    /// The sticky cookie setting, when the service pins clients to a child.
    #[must_use]
    pub fn sticky(&self) -> Option<&Sticky> {
        self.sticky.as_ref()
    }

    /// The label of child `index` as declared, which the sticky cookie is keyed on.
    #[must_use]
    pub fn child_label(&self, index: usize) -> Option<&str> {
        self.children.get(index).map(|child| &*child.label)
    }

    /// Keys the sticky cookie, if any; see `Sticky::bind`.
    pub(super) fn bind_sticky(
        &mut self,
        secret: Option<&SkewSecret>,
        app: &str,
        service: &str,
    ) -> Result<(), Invalid> {
        match &mut self.sticky {
            Some(sticky) => sticky.bind(secret, app, service),
            None => Ok(()),
        }
    }

    /// The service's fingerprint and shared state, for the registry to carry over.
    pub(super) fn state_mut(&mut self) -> (u64, &mut Arc<ServiceState>) {
        (self.fingerprint, &mut self.shared)
    }

    /// Whether `link` may take the request: it has a weight and is ready.
    fn eligible(graph: &dyn Graph, link: &Link, cx: PickCx<'_>, now: u64, depth: usize) -> bool {
        link.weight > 0
            && graph::readiness(graph, link.node, cx, now, depth + 1) == Readiness::Ready
    }

    /// `Ready` when some child is eligible, `Down` when none is but a child with weight has
    /// servers, `Asleep` when every child with weight has none.
    pub(super) fn readiness(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Readiness {
        let mut down = false;
        for link in graph.links(node).iter().filter(|link| link.weight > 0) {
            match graph::readiness(graph, link.node, cx, now, depth + 1) {
                Readiness::Ready => return Readiness::Ready,
                Readiness::Down => down = true,
                Readiness::Asleep => {}
            }
        }
        if down {
            Readiness::Down
        } else {
            Readiness::Asleep
        }
    }

    /// The child a request would most likely go to: the eligible one with the largest weight.
    pub(super) fn likely(
        &self,
        graph: &dyn Graph,
        node: Node,
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Option<usize> {
        let links = graph.links(node);
        let mut best: Option<(usize, u16)> = None;
        for (index, link) in links.iter().enumerate() {
            if Self::eligible(graph, link, cx, now, depth)
                && best.is_none_or(|(_, w)| link.weight > w)
            {
                best = Some((index, link.weight));
            }
        }
        best.map(|(index, _)| index)
    }

    fn pinned(
        &self,
        graph: &dyn Graph,
        links: &[Link],
        cx: PickCx<'_>,
        now: u64,
        depth: usize,
    ) -> Option<usize> {
        self.sticky.as_ref()?.pinned_by(
            cx.request,
            self.children.len(),
            |key, index| {
                Some(super::sticky::keyed_by_label(
                    key,
                    &self.children.get(index)?.label,
                ))
            },
            |index| {
                links
                    .get(index)
                    .is_some_and(|link| Self::eligible(graph, link, cx, now, depth))
            },
        )
    }

    /// The server a new request goes to: through the pinned child while it is eligible, else
    /// through the child the next ticket of the turn names. Allocates nothing.
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
        if let Some(index) = self.pinned(graph, links, cx, now, depth)
            && let Some(found) = graph::enter(graph, links, index, cx, now, path, depth)
        {
            return Some(found);
        }
        let total: u64 = links
            .iter()
            .filter(|link| Self::eligible(graph, link, cx, now, depth))
            .map(|link| u64::from(link.weight))
            .sum();
        if total == 0 {
            return None;
        }
        let mut ticket = self.shared.turn() % total * (TICKET_STRIDE % total) % total;
        let mut chosen = None;
        for (index, link) in links.iter().enumerate() {
            if !Self::eligible(graph, link, cx, now, depth) {
                continue;
            }
            let weight = u64::from(link.weight);
            if ticket < weight {
                chosen = Some(index);
                break;
            }
            ticket -= weight;
        }
        let chosen = chosen?;
        if let Some(found) = graph::enter(graph, links, chosen, cx, now, path, depth) {
            return Some(found);
        }
        // The chosen child lost its last server between the check and the pick: any other.
        links.iter().enumerate().find_map(|(index, link)| {
            if index == chosen || !Self::eligible(graph, link, cx, now, depth) {
                return None;
            }
            graph::enter(graph, links, index, cx, now, path, depth)
        })
    }
}
