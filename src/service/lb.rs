//! Load balancing algorithms, one file each in `lb/`.
//!
//! [`Balancer`] picks the index of one server per request. Built: `round_robin`,
//! `weighted_round_robin`, `least_conn`, `p2c_ewma` (power of two choices on the EWMA of response
//! latency), `random`, and the hashing ones `ip_hash`, `uri_hash`, `header_hash` (consistent
//! hashing on a ring, `ring.rs`) and `hrw` (rendezvous hashing). Any other name is
//! `invalid_service`. `algorithm` is a name or an object `{"type": "header_hash", "header":
//! "x-tenant"}`; the options an algorithm does not take are refused.
//!
//! Adding an algorithm: a file in `lb/` with a type that has `compile` and `pick`, one variant
//! in [`Balancer`] and one arm in each of its `match` statements. Every algorithm skips servers
//! that [`PickCx::allows`] refuses (not [`Server::available`], or already tried by this request)
//! and returns `None` when none is left.
//! A pick reads atomics only: it takes no lock and allocates nothing, which `tests/lb_alloc.rs`
//! pins. Whatever must outlive a snapshot push (the turn counter, the random stream, the secret
//! key of the hashing algorithms) is in the [`ServiceState`] passed to `pick`, whatever belongs
//! to one server in its [`super::ServerState`]; see [`super::state`].

mod header_hash;
mod hrw;
mod ip_hash;
mod least_conn;
mod p2c_ewma;
mod random;
mod ring;
mod round_robin;
mod uri_hash;
mod weighted_round_robin;

use std::net::{IpAddr, SocketAddr};

use pingora::http::RequestHeader;
use serde::Deserialize;
use serde_json::Value;

use super::state::Observe;
use super::{Server, ServiceState};
use crate::compile::Invalid;
use header_hash::HeaderHash;
use hrw::Hrw;
use ip_hash::IpHash;
use least_conn::LeastConn;
use p2c_ewma::P2cEwma;
use random::Random;
use round_robin::RoundRobin;
use uri_hash::UriHash;
use weighted_round_robin::WeightedRoundRobin;

/// What a balancer may look at to pick a server.
#[derive(Debug, Clone, Copy)]
pub struct PickCx<'a> {
    /// The request head, for the hashing algorithms.
    pub request: &'a RequestHeader,
    /// The addresses this request already went to, which a retry must not choose again.
    pub excluded: &'a [SocketAddr],
    /// The client address the entry point's forwarding policy resolved
    /// ([`crate::client_ip::ForwardedView::known_client`]), for `ip_hash` and `hrw`; `None` when
    /// the connection had no IP peer. Never read from a header here.
    pub client: Option<IpAddr>,
}

impl<'a> PickCx<'a> {
    /// A first attempt at `request`: nothing is excluded, the client is not known.
    #[must_use]
    pub fn new(request: &'a RequestHeader) -> Self {
        Self {
            request,
            excluded: &[],
            client: None,
        }
    }

    /// The same pick for the client `client`.
    #[must_use]
    pub fn with_client(self, client: Option<IpAddr>) -> Self {
        Self { client, ..self }
    }

    /// Whether `server` may take this request: available and not excluded.
    #[must_use]
    pub fn allows(&self, server: &Server) -> bool {
        server.available() && !self.excluded.contains(&server.addr)
    }
}

/// A compiled algorithm.
#[derive(Debug)]
pub enum Balancer {
    /// Servers take turns.
    RoundRobin(RoundRobin),
    /// Servers take turns in proportion to their weight, interleaved smoothly.
    WeightedRoundRobin(WeightedRoundRobin),
    /// The server with the fewest requests in flight.
    LeastConn(LeastConn),
    /// Of two random servers, the one with the lower latency-weighted load.
    P2cEwma(P2cEwma),
    /// A uniformly random server.
    Random(Random),
    /// The same client address always goes to the same server (consistent hashing).
    IpHash(IpHash),
    /// The same path always goes to the same server (consistent hashing).
    UriHash(UriHash),
    /// The same header value always goes to the same server (consistent hashing).
    HeaderHash(HeaderHash),
    /// Rendezvous hashing of the client address.
    Hrw(Hrw),
}

/// Refuses a weight other than `1` for an algorithm that does not use weights: ignoring a
/// setting is how a configuration silently stops meaning what it says.
fn unweighted(algorithm: &str, servers: &[Server]) -> Result<(), Invalid> {
    match servers.iter().find(|server| server.weight != 1) {
        Some(server) => Err(Invalid::new(
            "invalid_service",
            format!(
                "server {} has a weight: {algorithm} ignores weights, use weighted_round_robin",
                server.url
            ),
        )),
        None => Ok(()),
    }
}

/// The index of the first server at or after `from` (wrapping) that `cx` allows.
fn usable_from(cx: PickCx<'_>, servers: &[Server], from: usize) -> Option<usize> {
    let (before, from_here) = servers.split_at(from.min(servers.len()));
    from_here
        .iter()
        .chain(before)
        .position(|server| cx.allows(server))
        .map(|offset| (from + offset) % servers.len())
}

/// The index below `n` that the random number `random` stands for; `n` must not be `0`.
fn below(random: u64, n: usize) -> usize {
    usize::try_from(random % n as u64).unwrap_or(0)
}

/// Two distinct allowed servers chosen at random, or the same one twice when it is the only one
/// left; `None` when none is.
fn pair(cx: PickCx<'_>, servers: &[Server], shared: &ServiceState) -> Option<(usize, usize)> {
    let count = servers.len();
    if count == 0 {
        return None;
    }
    let first = usable_from(cx, servers, below(shared.random(), count))?;
    let second = usable_from(cx, servers, below(shared.random(), count))
        .filter(|index| *index != first)
        .or_else(|| usable_from(cx, servers, (first + 1) % count).filter(|index| *index != first))
        .unwrap_or(first);
    Some((first, second))
}

/// The object form of `algorithm`: the name as `type`, and the options of the algorithms that
/// have any.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    header: Option<String>,
    #[serde(default)]
    include_query: Option<bool>,
}

impl Balancer {
    /// Builds the algorithm `algorithm` declares for `servers`: a name or an object
    /// `{"type": name, ...options}`, `round_robin` when absent.
    ///
    /// # Errors
    ///
    /// `invalid_service` for an unknown name or option, an option the algorithm does not take,
    /// a missing required option (`header` of `header_hash`), or servers the algorithm cannot
    /// take (a weight where weights are not used, no weight above `0` where they are).
    pub fn compile(algorithm: Option<&Value>, servers: &[Server]) -> Result<Self, Invalid> {
        let object;
        let (name, header, include_query) = match algorithm {
            None => ("round_robin", None, None),
            Some(Value::String(name)) => (name.as_str(), None, None),
            Some(value @ Value::Object(_)) => {
                object = Object::deserialize(value)
                    .map_err(|err| Invalid::new("invalid_service", format!("algorithm: {err}")))?;
                (
                    object.kind.as_str(),
                    object.header.as_deref(),
                    object.include_query,
                )
            }
            Some(_) => {
                return Err(Invalid::new(
                    "invalid_service",
                    "algorithm must be a name or an object with a type",
                ));
            }
        };
        if header.is_some() && name != "header_hash" {
            return Err(Invalid::new(
                "invalid_service",
                format!("algorithm {name} takes no header option, only header_hash does"),
            ));
        }
        if include_query.is_some() && name != "uri_hash" {
            return Err(Invalid::new(
                "invalid_service",
                format!("algorithm {name} takes no include_query option, only uri_hash does"),
            ));
        }
        match name {
            "round_robin" => RoundRobin::compile(servers).map(Self::RoundRobin),
            "weighted_round_robin" => {
                WeightedRoundRobin::compile(servers).map(Self::WeightedRoundRobin)
            }
            "least_conn" => LeastConn::compile(servers).map(Self::LeastConn),
            "p2c_ewma" => P2cEwma::compile(servers).map(Self::P2cEwma),
            "random" => Random::compile(servers).map(Self::Random),
            "ip_hash" => IpHash::compile(servers).map(Self::IpHash),
            "uri_hash" => {
                UriHash::compile(servers, include_query.unwrap_or(false)).map(Self::UriHash)
            }
            "header_hash" => HeaderHash::compile(servers, header).map(Self::HeaderHash),
            "hrw" => Hrw::compile(servers).map(Self::Hrw),
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
            Self::WeightedRoundRobin(_) => "weighted_round_robin",
            Self::LeastConn(_) => "least_conn",
            Self::P2cEwma(_) => "p2c_ewma",
            Self::Random(_) => "random",
            Self::IpHash(_) => "ip_hash",
            Self::UriHash(_) => "uri_hash",
            Self::HeaderHash(_) => "header_hash",
            Self::Hrw(_) => "hrw",
        }
    }

    /// The index in `servers` of the server a new request goes to.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>, servers: &[Server], shared: &ServiceState) -> Option<usize> {
        match self {
            Self::RoundRobin(algorithm) => algorithm.pick(cx, servers, shared),
            Self::WeightedRoundRobin(algorithm) => algorithm.pick(cx, servers, shared),
            Self::LeastConn(algorithm) => algorithm.pick(cx, servers, shared),
            Self::P2cEwma(algorithm) => algorithm.pick(cx, servers, shared),
            Self::Random(algorithm) => algorithm.pick(cx, servers, shared),
            Self::IpHash(algorithm) => algorithm.pick(cx, servers, shared),
            Self::UriHash(algorithm) => algorithm.pick(cx, servers, shared),
            Self::HeaderHash(algorithm) => algorithm.pick(cx, servers, shared),
            Self::Hrw(algorithm) => algorithm.pick(cx, servers, shared),
        }
    }

    /// What the algorithm does with the latency of a finished response, for the
    /// [`super::Lease`] of the request; `None` for an algorithm that ignores latency.
    pub(super) fn observe(&self) -> Option<Observe> {
        match self {
            Self::P2cEwma(_) => Some(p2c_ewma::done),
            Self::RoundRobin(_)
            | Self::WeightedRoundRobin(_)
            | Self::LeastConn(_)
            | Self::Random(_)
            | Self::IpHash(_)
            | Self::UriHash(_)
            | Self::HeaderHash(_)
            | Self::Hrw(_) => None,
        }
    }
}

/// Helpers for the unit tests of the algorithms: servers that are up, a request, an injected
/// state.
#[cfg(test)]
mod test_support {
    use std::sync::atomic::Ordering;

    use pingora::http::RequestHeader;

    use std::sync::Arc;

    use super::Server;
    use crate::service::ServerState;

    /// `count` available servers of weight `1`, on ports `1..=count`.
    pub(super) fn servers(count: u16) -> Vec<Server> {
        weighted(&vec![1; usize::from(count)])
    }

    /// Available servers with the given weights, on ports `1..`.
    pub(super) fn weighted(weights: &[u32]) -> Vec<Server> {
        weights
            .iter()
            .zip(1_u16..)
            .map(|(weight, port)| Server {
                url: format!("http://127.0.0.1:{port}").into(),
                addr: ([127, 0, 0, 1], port).into(),
                tls: false,
                weight: *weight,
                state: Arc::new(ServerState::default()),
            })
            .collect()
    }

    pub(super) fn request() -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request.insert_header("x-key", "k").expect("header");
        request
    }

    pub(super) fn set_active(server: &Server, active: u32) {
        server.state.active.store(active, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::Ordering;

    use super::test_support::{request, servers};
    use super::*;
    use crate::service::{Lease, ServerState};
    use serde_json::json;

    fn header_hash() -> Value {
        json!({"type": "header_hash", "header": "x-key"})
    }

    fn all(servers: &[Server]) -> [Balancer; 9] {
        let compile =
            |algorithm: Value| Balancer::compile(Some(&algorithm), servers).expect("compiles");
        [
            compile(json!("round_robin")),
            compile(json!("weighted_round_robin")),
            compile(json!("least_conn")),
            compile(json!("p2c_ewma")),
            compile(json!("random")),
            compile(json!("ip_hash")),
            compile(json!("uri_hash")),
            compile(header_hash()),
            compile(json!("hrw")),
        ]
    }

    #[test]
    fn balancer_skips_unhealthy_ejected_excluded() {
        let up = servers(4);
        let request = request();
        let shared = ServiceState::default();
        for balancer in all(&up) {
            let name = balancer.name();
            // Server 0 is unhealthy, 1 is ejected, 2 was already tried: only 3 is left.
            up[0].state.healthy.store(false, Ordering::Relaxed);
            up[1]
                .state
                .ejected_until_ms
                .store(u64::MAX, Ordering::Relaxed);
            let tried = [up[2].addr];
            let cx = PickCx {
                request: &request,
                excluded: &tried,
                client: Some([192, 0, 2, 1].into()),
            };
            for _ in 0..50 {
                assert_eq!(balancer.pick(cx, &up, &shared), Some(3), "{name}");
            }
            // Nothing left once the last one is excluded too.
            let tried = [up[2].addr, up[3].addr];
            let cx = PickCx {
                request: &request,
                excluded: &tried,
                client: Some([192, 0, 2, 1].into()),
            };
            assert_eq!(balancer.pick(cx, &up, &shared), None, "{name}");
            for server in &up {
                server.state.healthy.store(true, Ordering::Relaxed);
                server.state.ejected_until_ms.store(0, Ordering::Relaxed);
            }
            assert!(
                balancer.pick(PickCx::new(&request), &up, &shared).is_some(),
                "{name}"
            );
        }
        assert!(
            all(&[])
                .iter()
                .all(|balancer| balancer.pick(PickCx::new(&request), &[], &shared).is_none())
        );
    }

    #[test]
    fn unweighted_algorithms_refuse_a_weight() {
        let mut up = servers(2);
        up[1].weight = 3;
        for name in ["round_robin", "least_conn", "p2c_ewma", "random"] {
            let err = Balancer::compile(Some(&json!(name)), &up).expect_err("refused");
            assert_eq!(err.code, "invalid_service", "{name}");
        }
        for name in ["weighted_round_robin", "ip_hash", "uri_hash", "hrw"] {
            assert!(Balancer::compile(Some(&json!(name)), &up).is_ok(), "{name}");
        }
        assert!(Balancer::compile(Some(&header_hash()), &up).is_ok());
    }

    #[test]
    fn names_are_checked() {
        let up = servers(1);
        assert_eq!(
            Balancer::compile(Some(&json!("fastest")), &up)
                .expect_err("unknown")
                .code,
            "invalid_service"
        );
        assert_eq!(
            Balancer::compile(None, &up).expect("default").name(),
            "round_robin"
        );
    }

    #[test]
    fn hash_algorithm_options_strict() {
        let up = servers(2);
        let refused = |algorithm: Value| {
            Balancer::compile(Some(&algorithm), &up)
                .expect_err("refused")
                .code
        };
        // A missing header, a header that is no name, an unknown field, a missing type.
        assert_eq!(refused(json!("header_hash")), "invalid_service");
        assert_eq!(refused(json!({"type": "header_hash"})), "invalid_service");
        assert_eq!(
            refused(json!({"type": "header_hash", "header": "not a name"})),
            "invalid_service"
        );
        assert_eq!(
            refused(json!({"type": "header_hash", "header": "x-tenant", "extra": "x"})),
            "invalid_service"
        );
        assert_eq!(refused(json!({"header": "x-tenant"})), "invalid_service");
        assert_eq!(refused(json!(7)), "invalid_service");
        // An option of another algorithm is refused, not ignored.
        assert_eq!(
            refused(json!({"type": "ip_hash", "header": "x-tenant"})),
            "invalid_service"
        );
        assert_eq!(
            refused(json!({"type": "header_hash", "header": "x", "include_query": true})),
            "invalid_service"
        );
        assert_eq!(
            refused(json!({"type": "round_robin", "include_query": true})),
            "invalid_service"
        );
        assert!(
            Balancer::compile(
                Some(&json!({"type": "uri_hash", "include_query": true})),
                &up
            )
            .is_ok()
        );
        assert!(Balancer::compile(Some(&json!({"type": "random"})), &up).is_ok());
    }

    #[test]
    fn a_lease_counts_the_request_until_it_is_dropped() {
        let state = std::sync::Arc::new(ServerState::default());
        let lease = Lease::take(&state, None);
        assert_eq!(state.active.load(Ordering::Relaxed), 1);
        drop(lease);
        assert_eq!(state.active.load(Ordering::Relaxed), 0);
    }
}
