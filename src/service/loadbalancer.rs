//! The `loadbalancer` service: a set of servers and an algorithm that picks one per request.
//!
//! ```json
//! { "name": "web", "type": "loadbalancer", "algorithm": "round_robin",
//!   "servers": [ { "url": "http://10.0.0.5:8080" }, { "url": "http://10.0.0.6:8080" } ] }
//! ```
//!
//! `servers` may be empty: the service then has no server, and a `scale_to_zero` app wakes on
//! the first request. Built today: plain `http://ip:port` servers and the `round_robin`
//! algorithm. Planned fields (`health_check`, `passive`, `sticky`, `transport`, a `false`
//! `pass_host_header`), planned algorithms and `https://` or `h2c://` servers are refused with
//! `service_not_built`; a server named by host name is `dns_upstream_not_built`.
//!
//! [`ServerState`] is fixed here for the specs that fill it: health checks write `healthy`, the
//! outlier detector writes `ejected_until_ms`, least-connections reads and writes `active`,
//! and the EWMA balancer writes `ewma_us`. All are atomics, so none of those specs reshapes the
//! struct, and `pick` of every balancer reads [`Server::available`] and nothing else about
//! health.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use serde::Deserialize;
use serde_json::Value;

use super::lb::{Balancer, PickCx};
use crate::compile::Invalid;
use crate::snapshot::Declared;

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

/// What the balancer, the health checker and the outlier detector share about one server.
#[derive(Debug)]
pub struct ServerState {
    /// Cleared by an active health check that fails.
    pub healthy: AtomicBool,
    /// Milliseconds since the process started until which the server is ejected; `0`: not
    /// ejected. Written by passive outlier detection.
    pub ejected_until_ms: AtomicU64,
    /// Requests in flight to the server, for least-connections.
    pub active: AtomicU32,
    /// Exponentially weighted moving average of response latency in microseconds, for the EWMA
    /// balancer; `0`: no sample yet.
    pub ewma_us: AtomicU64,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(true),
            ejected_until_ms: AtomicU64::new(0),
            active: AtomicU32::new(0),
            ewma_us: AtomicU64::new(0),
        }
    }
}

/// One upstream server of a load balancer.
#[derive(Debug)]
pub struct Server {
    /// The URL as declared.
    pub url: Box<str>,
    /// The address to connect to.
    pub addr: SocketAddr,
    /// The relative weight, `1` by default.
    pub weight: u32,
    /// The state the balancer and its helpers share.
    pub state: ServerState,
}

impl Server {
    /// Whether the server may take a new request: healthy and not ejected.
    #[must_use]
    pub fn available(&self) -> bool {
        self.state.healthy.load(Ordering::Relaxed)
            && self.state.ejected_until_ms.load(Ordering::Relaxed) == 0
    }
}

/// A compiled `loadbalancer`.
#[derive(Debug)]
pub struct LoadBalancer {
    servers: Box<[Server]>,
    balancer: Balancer,
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
    if config.weight == Some(0) {
        return Err(invalid("weight must be at least 1"));
    }
    Ok(Server {
        url: url.into(),
        addr,
        weight: config.weight.unwrap_or(1),
        state: ServerState::default(),
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
        Ok(Self { servers, balancer })
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

    /// The address of the server a new request goes to.
    #[must_use]
    pub fn pick(&self, cx: PickCx<'_>) -> Option<SocketAddr> {
        let index = self.balancer.pick(cx, &self.servers)?;
        self.servers.get(index).map(|server| server.addr)
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
            "invalid_service"
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
}
