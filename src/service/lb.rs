//! Load balancing algorithms, one file each in `lb/`.
//!
//! [`Balancer`] picks the index of one server per request. Built: `round_robin`. Planned and
//! refused with `service_not_built`: `weighted_round_robin`, `least_conn`, `p2c_ewma` (power of
//! two choices on the EWMA of response latency), `random`, `ip_hash`, `uri_hash` and
//! `header_hash`; any other name is `invalid_service`.
//!
//! Adding an algorithm: a file in `lb/` with a type that has `compile` and `pick`, one variant
//! in [`Balancer`] and one arm in each of its `match` statements, and its name removed from
//! `UNBUILT`. Every algorithm skips servers that are not [`Server::available`] and returns
//! `None` when none is.

mod round_robin;

use pingora::http::RequestHeader;

use super::Server;
use crate::compile::Invalid;
use round_robin::RoundRobin;

/// Algorithms that are planned and not built yet.
const UNBUILT: [&str; 7] = [
    "weighted_round_robin",
    "least_conn",
    "p2c_ewma",
    "random",
    "ip_hash",
    "uri_hash",
    "header_hash",
];

/// What a balancer may look at to pick a server.
#[derive(Debug, Clone, Copy)]
pub struct PickCx<'a> {
    /// The request head, for the hashing algorithms.
    pub request: &'a RequestHeader,
}

/// A compiled algorithm.
#[derive(Debug)]
pub enum Balancer {
    /// Servers take turns.
    RoundRobin(RoundRobin),
}

impl Balancer {
    /// Builds the algorithm called `name` (`round_robin` when absent) for `servers`.
    ///
    /// # Errors
    ///
    /// `service_not_built` for a planned algorithm, `invalid_service` for an unknown name or
    /// servers the algorithm cannot take.
    pub fn compile(name: Option<&str>, servers: &[Server]) -> Result<Self, Invalid> {
        match name.unwrap_or("round_robin") {
            "round_robin" => RoundRobin::compile(servers).map(Self::RoundRobin),
            other if UNBUILT.contains(&other) => Err(Invalid::new(
                "service_not_built",
                format!("algorithm {other} is planned and not built yet"),
            )),
            other => Err(Invalid::new(
                "invalid_service",
                format!("unknown algorithm {other}"),
            )),
        }
    }

    /// The algorithm's name, as written in a snapshot.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::RoundRobin(_) => "round_robin",
        }
    }

    /// The index in `servers` of the server a new request goes to.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>, servers: &[Server]) -> Option<usize> {
        match self {
            Self::RoundRobin(algorithm) => algorithm.pick(cx, servers),
        }
    }
}
