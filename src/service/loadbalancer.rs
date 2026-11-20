//! The `loadbalancer` service: a set of servers and an algorithm that picks one per request.
//!
//! ```json
//! { "name": "web", "type": "loadbalancer", "algorithm": "round_robin",
//!   "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" } ] }
//! ```
//!
//! `servers` may be empty: the service then has no server, and a `scale_to_zero` app wakes on
//! the first request. Built today: plain `http://ip:port` servers and the algorithms
//! `round_robin`, `weighted_round_robin`, `least_conn`, `p2c_ewma` and `random` (see
//! [`super::lb`]); only `weighted_round_robin` takes server weights, and a weight of `0` there
//! means the server receives nothing. Planned fields (`health_check`, `passive`, `sticky`,
//! `transport`, a `false` `pass_host_header`), planned algorithms and `https://` or `h2c://`
//! servers are refused with `service_not_built`; a server named by host name is
//! `dns_upstream_not_built`.
//!
//! The runtime state of the servers (`healthy`, `ejected_until_ms`, `active`, `ewma_us`) and of
//! the service (its turn counter) is in [`super::state`], outside the table, so a push that
//! leaves the service alone keeps it. `pick` of every balancer reads [`Server::available`] and
//! nothing else about health.

use std::net::SocketAddr;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use super::lb::{Balancer, PickCx};
use super::state::{self, Lease, ServerState, ServiceState};
use crate::compile::Invalid;
use podgate_model::Declared;

/// The configuration of a `loadbalancer`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    servers: Vec<ServerConfig>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    health_check: Option<Value>,
    #[serde(default)]
    passive: Option<Value>,
    #[serde(default)]
    sticky: Option<Value>,
    #[serde(default)]
    pass_host_header: Option<bool>,
    #[serde(default)]
    transport: Option<Box<str>>,
}

/// One server as declared.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    url: String,
    #[serde(default)]
    weight: Option<u32>,
}

/// One upstream server of a load balancer.
#[derive(Debug)]
pub struct Server {
    /// The URL as declared.
    pub url: Box<str>,
    /// The address to connect to.
    pub addr: SocketAddr,
    /// The relative weight, `1` by default; only `weighted_round_robin` uses it, and there `0`
    /// means no requests.
    pub weight: u32,
    /// The state the balancer and its helpers share; shared with the previous table's server of
    /// the same service, see [`super::state`].
    pub state: Arc<ServerState>,
}

impl Server {
    /// Whether the server may take a new request: healthy and not ejected.
    #[must_use]
    pub fn available(&self) -> bool {
        self.state.available()
    }
}

/// A compiled `loadbalancer`.
#[derive(Debug)]
pub struct LoadBalancer {
    servers: Box<[Server]>,
    balancer: Balancer,
    shared: Arc<ServiceState>,
    fingerprint: u64,
}

fn not_built(what: &str) -> Invalid {
    Invalid::new(
        "service_not_built",
        format!("loadbalancer {what} is planned and not built yet"),
    )
}

/// Parses `http://ip:port`.
fn parse_server(config: &ServerConfig) -> Result<Server, Invalid> {
    let url = config.url.as_str();
    let invalid = |why: &str| Invalid::new("invalid_service", format!("server {url}: {why}"));
    let rest = match url.split_once("://") {
        Some(("http", rest)) => rest,
        Some(("https" | "h2c", _)) => {
            return Err(not_built(
                "upstream TLS and h2c (https:// and h2c:// servers)",
            ));
        }
        _ => return Err(invalid("expected http://ip:port")),
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let addr: SocketAddr = match rest.parse() {
        Ok(addr) => addr,
        Err(_) => {
            let named = rest.rsplit_once(':').is_some_and(|(host, port)| {
                !host.is_empty()
                    && port.parse::<u16>().is_ok()
                    && host
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
            });
            return Err(if named {
                Invalid::new(
                    "dns_upstream_not_built",
                    format!(
                        "server {url}: servers by host name need the resolver, use an IP address"
                    ),
                )
            } else {
                invalid("expected http://ip:port")
            });
        }
    };
    Ok(Server {
        url: url.into(),
        addr,
        weight: config.weight.unwrap_or(1),
        state: Arc::default(),
    })
}

impl LoadBalancer {
    pub(super) fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_service", format!("loadbalancer: {err}")))?;
        if config.health_check.is_some() {
            return Err(not_built("health_check"));
        }
        if config.passive.is_some() {
            return Err(not_built("passive"));
        }
        if config.sticky.is_some() {
            return Err(not_built("sticky"));
        }
        if config.transport.is_some() {
            return Err(not_built("transport"));
        }
        if config.pass_host_header == Some(false) {
            return Err(not_built("pass_host_header: false"));
        }
        let servers: Box<[Server]> = config
            .servers
            .iter()
            .map(parse_server)
            .collect::<Result<_, _>>()?;
        let balancer = Balancer::compile(config.algorithm.as_deref(), &servers)?;
        Ok(Self {
            servers,
            balancer,
            shared: Arc::default(),
            fingerprint: state::fingerprint(declared),
        })
    }

    /// The servers, in declaration order.
    #[must_use]
    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// The name of the algorithm.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.balancer.name()
    }

    /// The address of the server a new request goes to, with the [`Lease`] that counts the
    /// request on it until dropped. Lock-free and allocation-free.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<(SocketAddr, Lease)> {
        let index = self.balancer.pick(cx, &self.servers, &self.shared)?;
        let server = self.servers.get(index)?;
        Some((
            server.addr,
            Lease::take(&server.state, self.balancer.observe()),
        ))
    }

    /// The service's fingerprint, its shared state and its servers, for [`state::Registry`] to
    /// swap in the state of the previous table.
    pub(super) fn state_mut(&mut self) -> (u64, &mut Arc<ServiceState>, &mut [Server]) {
        (self.fingerprint, &mut self.shared, &mut self.servers)
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn compile(value: Value) -> Result<LoadBalancer, Invalid> {
        let declared: Declared = serde_json::from_value(value).expect("declared");
        LoadBalancer::compile(&declared)
    }

    fn code(value: Value) -> &'static str {
        compile(value).expect_err("refused").code
    }

    fn lb(servers: &Value) -> Value {
        json!({ "name": "web", "type": "loadbalancer", "servers": servers })
    }

    #[test]
    fn plain_http_servers_compile_and_an_empty_list_is_allowed() {
        let balancer = compile(lb(&json!([
            { "url": "http://127.0.0.1:1" },
            { "url": "http://[::1]:2/" },
        ])))
        .expect("compiles");
        assert_eq!(balancer.servers().len(), 2);
        assert_eq!(balancer.algorithm(), "round_robin");
        assert!(compile(lb(&json!([]))).expect("empty").servers().is_empty());
    }

    #[test]
    fn planned_and_malformed_settings_are_refused_with_their_codes() {
        assert_eq!(
            code(lb(&json!([{ "url": "https://127.0.0.1:1" }]))),
            "service_not_built"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "h2c://127.0.0.1:1" }]))),
            "service_not_built"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "http://app.internal:80" }]))),
            "dns_upstream_not_built"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "ftp://127.0.0.1:1" }]))),
            "invalid_service"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "http://127.0.0.1:1", "weight": 0 }]))),
            "invalid_service",
            "round_robin does not use weights"
        );
        assert_eq!(
            code(lb(&json!([{ "url": "http://127.0.0.1:1", "priority": 2 }]))),
            "invalid_service"
        );
        let mut sticky = lb(&json!([]));
        sticky["sticky"] = json!({});
        assert_eq!(code(sticky), "service_not_built");
        let mut misspelt = lb(&json!([]));
        misspelt["algorithms"] = json!("round_robin");
        assert_eq!(code(misspelt), "invalid_service");
    }

    #[test]
    fn only_weighted_round_robin_takes_weights_and_zero_means_nothing() {
        let mut weighted = lb(&json!([
            { "url": "http://127.0.0.1:1", "weight": 3 },
            { "url": "http://127.0.0.1:2", "weight": 0 },
        ]));
        weighted["algorithm"] = json!("weighted_round_robin");
        let balancer = compile(weighted.clone()).expect("compiles");
        assert_eq!(balancer.algorithm(), "weighted_round_robin");
        let request = pingora::http::RequestHeader::build("GET", b"/", None).expect("request");
        for _ in 0..10 {
            let (addr, _lease) = balancer.pick(PickCx::new(&request)).expect("a server");
            assert_eq!(addr.port(), 1);
        }
        weighted["algorithm"] = json!("random");
        assert_eq!(code(weighted), "invalid_service");
    }
}
