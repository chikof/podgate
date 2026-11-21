//! Active health checks of TCP services: `health_check` on a TCP `loadbalancer`
//! makes podgate probe each of its servers from the background service of
//! [`crate::service::health`] and write [`crate::service::ServerState::healthy`], which every
//! balancer already reads.
//!
//! ```json
//! { "name": "primary", "type": "loadbalancer",
//!   "health_check": { "interval_secs": 5, "timeout_secs": 2,
//!                     "send": "UElORwo=", "expect": "UE9ORw==",
//!                     "unhealthy_threshold": 3, "unhealthy_interval_secs": 1 },
//!   "servers": [ { "address": "10.0.1.5:5432" }, { "address": "db.internal:5432" } ] }
//! ```
//!
//! The reference for the fields and the rules is `docs/ref/l4-health.md`.
//!
//! # Pieces
//!
//! - [`Check`]: the compiled `health_check`, built by the TCP service's compile step (every
//!   problem is a `422`).
//! - [`TcpProbe`]: one probe of one server. It dials through Pingora's `TransportConnector`,
//!   writes the PROXY header and `send`, reads at most [`MAX_PAYLOAD`] bytes to compare with
//!   `expect`, and judges the result as a [`Verdict`].
//! - `reconcile`: registers one probe per server of every TCP service with a check in the
//!   scheduler of [`crate::service::health::HealthService`] and stops the probes of servers that
//!   are gone. The scheduler owns the jitter, the global concurrency cap, the timeout and the
//!   write of the verdict, exactly as for HTTP checks; the balancers need no code.
//!
//! # Rules the probes obey
//!
//! - **Targets.** Only the servers of the service, as the balancer holds them (a name expanded
//!   into the addresses it resolved to, an SRV owner into its targets), on the server's port or
//!   `port` when the check sets one.
//! - **Policy.** [`TcpProbe::run`] calls [`UpstreamPolicy::check`] with the tenant and the exact
//!   IP it is about to dial, on every probe.
//! - **Bounds.** A probe is cut at `timeout_secs`, takes a permit of the global cap, writes at
//!   most [`MAX_PAYLOAD`] bytes of `send`, and never reads more than the length of `expect`
//!   (at most [`MAX_PAYLOAD`]). Probes are not connections: they take no tenant slot and no
//!   buffer budget.
//! - **State.** The streak lives in the scheduler under the key `(owner, app, service, server
//!   address, fingerprint of the check)`: a push that leaves the check alone keeps it, a changed
//!   check starts fresh and healthy.

use std::collections::HashSet;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pingora::connectors::TransportConnector;
use pingora::upstreams::peer::HttpPeer;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::budget::Escaped;
use crate::compile::Invalid;
use crate::entry::proxy_protocol::{Header, Version};
use crate::router::digest;
use crate::service::health::{
    Key, MAX_INTERVAL_SECS, MAX_THRESHOLD, MAX_TIMEOUT_SECS, ProbeFn, Schedule, Scheduler, Verdict,
};
use crate::service::upstream_policy::UpstreamPolicy;
use crate::service::{Server, ServerState, Upstream};
use crate::table::RoutingTable;

/// The `owner` of the probes this module registers; see [`Key::owner`].
pub const OWNER: &str = "tcp";
/// The most bytes `send` and `expect` hold each once decoded, and the most a probe ever reads.
pub const MAX_PAYLOAD: usize = 256;

/// The base64 text of [`MAX_PAYLOAD`] bytes: a longer string is refused before it is decoded.
const MAX_PAYLOAD_TEXT: usize = MAX_PAYLOAD.div_ceil(3) * 4;

/// The fields of a TCP `health_check`, as written.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    /// Seconds from the end of one probe to the start of the next: 1 to 3600.
    interval_secs: u64,
    /// A probe that has not finished by then fails: 1 to 300.
    timeout_secs: u64,
    /// Seconds between probes of a server that is marked down: 1 to 3600. Absent: `interval_secs`.
    #[serde(default)]
    unhealthy_interval_secs: Option<u64>,
    /// Probe this port of the server's IP instead of the server's own port.
    #[serde(default)]
    port: Option<u16>,
    /// Base64 of the bytes (1 to 256) written after the connect.
    #[serde(default)]
    send: Option<String>,
    /// Base64 of the bytes (1 to 256) the reply must start with. Without `send`, the server
    /// speaks first (a banner).
    #[serde(default)]
    expect: Option<String>,
    /// Consecutive passes that mark a down server up: 1 to 100, default 1.
    #[serde(default)]
    healthy_threshold: Option<u32>,
    /// Consecutive failures that mark an up server down: 1 to 100, default 1.
    #[serde(default)]
    unhealthy_threshold: Option<u32>,
    /// Probe over TLS with the service's transport; the probe passes on a completed handshake
    /// (and the reply, when `expect` is set). Not with `send_proxy_header`.
    #[serde(default)]
    tls: Option<bool>,
    /// Write a PROXY protocol v2 `LOCAL` header first.
    #[serde(default)]
    send_proxy_header: Option<bool>,
}

/// A compiled TCP `health_check`.
#[derive(Debug)]
pub struct Check {
    schedule: Schedule,
    port: Option<u16>,
    /// The PROXY header, then `send`: written in one go after the connect.
    opening: Box<[u8]>,
    expect: Option<Box<[u8]>>,
    tls: bool,
    fingerprint: u64,
}

fn invalid(why: impl fmt::Display) -> Invalid {
    Invalid::new(
        "invalid_service",
        format!("tcp loadbalancer health_check: {why}"),
    )
}

/// The decoded bytes of the base64 `text` of field `name`; `None` when the field is absent.
fn payload(name: &str, text: Option<&str>) -> Result<Option<Vec<u8>>, Invalid> {
    let Some(text) = text else {
        return Ok(None);
    };
    let too_long = || invalid(format!("{name} is longer than {MAX_PAYLOAD} bytes"));
    if text.len() > MAX_PAYLOAD_TEXT {
        return Err(too_long());
    }
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| invalid(format!("{name} is not base64")))?;
    if bytes.is_empty() {
        return Err(invalid(format!("{name} is empty")));
    }
    if bytes.len() > MAX_PAYLOAD {
        return Err(too_long());
    }
    Ok(Some(bytes))
}

impl Check {
    /// Compiles the `health_check` object of a TCP service.
    ///
    /// # Errors
    ///
    /// `invalid_service` for a field that is missing, unknown, out of range or malformed: a
    /// `send` or `expect` that is not base64, is empty or decodes to more than 256 bytes, a port
    /// of `0`, `tls` together with `send_proxy_header`.
    pub fn compile(value: &Value) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(value.clone()).map_err(invalid)?;
        let seconds = |name: &str, value: u64, max: u64| {
            if (1..=max).contains(&value) {
                Ok(Duration::from_secs(value))
            } else {
                Err(invalid(format!("{name} must be in 1..={max}")))
            }
        };
        let threshold = |name: &str, value: Option<u32>| match value.unwrap_or(1) {
            count @ 1..=MAX_THRESHOLD => Ok(count),
            _ => Err(invalid(format!("{name} must be in 1..={MAX_THRESHOLD}"))),
        };
        let schedule = Schedule {
            interval: seconds("interval_secs", config.interval_secs, MAX_INTERVAL_SECS)?,
            unhealthy_interval: config
                .unhealthy_interval_secs
                .map(|secs| seconds("unhealthy_interval_secs", secs, MAX_INTERVAL_SECS))
                .transpose()?,
            timeout: seconds("timeout_secs", config.timeout_secs, MAX_TIMEOUT_SECS)?,
            healthy_threshold: threshold("healthy_threshold", config.healthy_threshold)?,
            unhealthy_threshold: threshold("unhealthy_threshold", config.unhealthy_threshold)?,
        };
        if config.port == Some(0) {
            return Err(invalid("port must be in 1..=65535"));
        }
        let tls = config.tls.unwrap_or(false);
        let proxy_header = config.send_proxy_header.unwrap_or(false);
        if tls && proxy_header {
            // On the wire the header precedes the TLS handshake; the connector does the
            // handshake inside the dial, so the probe cannot put anything before it.
            return Err(invalid(
                "tls and send_proxy_header cannot be combined: the PROXY header goes before the TLS handshake",
            ));
        }
        let mut opening = Vec::new();
        if proxy_header {
            Header::Local
                .encode(Version::V2, &mut opening)
                .map_err(|err| invalid(format!("send_proxy_header: {err}")))?;
        }
        if let Some(send) = payload("send", config.send.as_deref())? {
            opening.extend_from_slice(&send);
        }
        let expect = payload("expect", config.expect.as_deref())?.map(Vec::into_boxed_slice);
        Ok(Self {
            schedule,
            port: config.port,
            opening: opening.into_boxed_slice(),
            expect,
            tls,
            fingerprint: digest(value.to_string()),
        })
    }

    /// How often servers are probed and how many results flip them.
    #[must_use]
    pub fn schedule(&self) -> Schedule {
        self.schedule
    }

    /// A digest of the check as declared: part of the key of the probe state, so a changed
    /// check starts fresh and an equal one keeps its streak.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// The peer a probe of `upstream` dials: its server's IP on `port` when the check sets one,
    /// over TLS when the check says `tls`, with the transport of the service (SNI, trust anchors,
    /// client certificate). Timeouts are the check's `timeout_secs`.
    #[must_use]
    pub fn peer(&self, upstream: Upstream<'_>) -> HttpPeer {
        let server = upstream.server;
        let mut addr = server.addr;
        if let Some(port) = self.port {
            addr.set_port(port);
        }
        let probed = Server {
            url: server.url.clone(),
            addr,
            tls: self.tls,
            h2c: false,
            weight: server.weight,
            state: Arc::clone(&server.state),
        };
        let mut peer = Upstream {
            server: &probed,
            transport: upstream.transport,
        }
        .peer();
        let timeout = self.schedule.timeout;
        peer.options.connection_timeout = Some(timeout);
        peer.options.total_connection_timeout = Some(timeout);
        peer.options.read_timeout = Some(timeout);
        peer.options.write_timeout = Some(timeout);
        peer
    }
}

/// Writes what the check opens with and compares the reply with `expect`. At most
/// [`MAX_PAYLOAD`] bytes are read, never more than `expect` is long.
async fn exchange<S>(stream: &mut S, check: &Check) -> Verdict
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !check.opening.is_empty() {
        if let Err(err) = stream.write_all(&check.opening).await {
            return Verdict::Fail(format!("send: {err}").into());
        }
        if let Err(err) = stream.flush().await {
            return Verdict::Fail(format!("send: {err}").into());
        }
    }
    let Some(expect) = check.expect.as_deref() else {
        return Verdict::Pass;
    };
    let mut reply = [0_u8; MAX_PAYLOAD];
    let mut filled = 0;
    while filled < expect.len() {
        match stream.read(&mut reply[filled..expect.len()]).await {
            Ok(0) => {
                return Verdict::Fail("the server closed the connection before the reply".into());
            }
            Ok(read) => filled += read,
            Err(err) => return Verdict::Fail(format!("read: {err}").into()),
        }
        // A reply that has already gone wrong fails now instead of at the timeout.
        if reply[..filled] != expect[..filled] {
            return Verdict::Fail("the reply does not start with the expected bytes".into());
        }
    }
    Verdict::Pass
}

/// The probe of one server of a TCP service.
pub struct TcpProbe {
    check: Arc<Check>,
    tenant: Box<str>,
    peer: HttpPeer,
    policy: UpstreamPolicy,
    connector: Arc<TransportConnector>,
}

impl fmt::Debug for TcpProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpProbe")
            .field("tenant", &self.tenant)
            .field("peer", &self.peer._address)
            .field("tls", &self.peer.is_tls())
            .finish_non_exhaustive()
    }
}

impl TcpProbe {
    /// A probe by `check` of the server that `peer` (from [`Check::peer`]) points at, for an app
    /// of `tenant`, subject to `policy`, dialling through `connector` (see
    /// [`crate::service::health::HttpProbe::connector`]).
    #[must_use]
    pub fn new(
        check: Arc<Check>,
        tenant: &str,
        peer: HttpPeer,
        policy: UpstreamPolicy,
        connector: Arc<TransportConnector>,
    ) -> Self {
        Self {
            check,
            tenant: tenant.into(),
            peer,
            policy,
            connector,
        }
    }

    /// Probes the server once. The caller bounds the time (the scheduler does).
    pub async fn run(&self) -> Verdict {
        let Some(target) = self.peer._address.as_inet().copied() else {
            return Verdict::Fail("the probe target is not an IP address".into());
        };
        // The exact address about to be dialled, every time.
        if let Err(refused) = self.policy.check(&self.tenant, target.ip()) {
            return Verdict::Fail(
                format!("refused by the upstream address policy: {refused}").into(),
            );
        }
        let mut stream = match Box::pin(self.connector.new_stream(&self.peer)).await {
            Ok(stream) => stream,
            Err(err) => return Verdict::Fail(format!("connect: {err}").into()),
        };
        exchange(&mut stream, &self.check).await
    }
}

/// Makes the probes registered under [`OWNER`] those `table` calls for: one per server of every
/// TCP service with a `health_check`, as the balancer holds the servers now. Probes of servers
/// and services that are gone stop. Called by `HealthService` at start and after every swap or
/// change of a DNS answer.
pub(crate) fn reconcile(
    scheduler: &Scheduler,
    policy: &UpstreamPolicy,
    connector: &Arc<TransportConnector>,
    table: &RoutingTable,
) {
    let mut wanted: Vec<(Key, Schedule, Arc<ServerState>, ProbeFn)> = Vec::new();
    for app in table.apps() {
        for service in app.l4().tcp().services() {
            let Some(check) = service.health_check() else {
                continue;
            };
            let balancer = service.balancer();
            for server in &balancer.servers() {
                let Some(peer) =
                    balancer.with_upstream(server.addr, |upstream| check.peer(upstream))
                else {
                    continue;
                };
                let probe = Arc::new(TcpProbe::new(
                    Arc::clone(check),
                    app.tenant(),
                    peer,
                    policy.clone(),
                    Arc::clone(connector),
                ));
                let run: ProbeFn = Arc::new(move || {
                    let probe = Arc::clone(&probe);
                    Box::pin(async move { probe.run().await })
                });
                let key = Key {
                    owner: OWNER,
                    app: app.id().into(),
                    revision: None,
                    service: service.name().into(),
                    server: server.addr.to_string().into(),
                    fingerprint: check.fingerprint(),
                };
                wanted.push((key, check.schedule(), Arc::clone(&server.state), run));
            }
        }
    }
    // Stale probes stop before the new ones register: a probe of a replaced check must not write
    // into the state its successor has just reset.
    let keep: HashSet<&Key> = wanted.iter().map(|(key, ..)| key).collect();
    scheduler.retain(OWNER, |key| keep.contains(key));
    for (key, schedule, state, probe) in wanted {
        scheduler.register(key, schedule, state, probe);
    }
}

/// Prometheus text exposition: how many servers of each TCP service with a `health_check` may
/// take a connection now and how many may not.
#[must_use]
pub(crate) fn render(table: &RoutingTable) -> String {
    let name = "podgate_l4_service_servers";
    let mut out = format!(
        "# HELP {name} Servers of a TCP service with a health_check, by whether they may take a new connection.\n# TYPE {name} gauge\n"
    );
    for app in table.apps() {
        for service in app.l4().tcp().services() {
            if service.health_check().is_none() {
                continue;
            }
            let servers = service.balancer().servers();
            let up = servers.iter().filter(|server| server.available()).count();
            let down = servers.len() - up;
            for (state, count) in [("up", up), ("down", down)] {
                // Writing to a `String` cannot fail.
                let _ = writeln!(
                    out,
                    "{name}{{app=\"{}\",service=\"{}\",state=\"{state}\"}} {count}",
                    Escaped(app.id()),
                    Escaped(service.name()),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use tokio::io::{DuplexStream, duplex};

    use super::*;

    fn rule(extra: &Value) -> Result<Check, Invalid> {
        let mut value = json!({ "interval_secs": 1, "timeout_secs": 1 });
        if let (Some(base), Some(more)) = (value.as_object_mut(), extra.as_object()) {
            base.extend(more.clone());
        }
        Check::compile(&value)
    }

    fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    #[test]
    fn defaults_and_fingerprint() {
        let check = rule(&json!({})).expect("compiles");
        let schedule = check.schedule();
        assert_eq!(schedule.interval, Duration::from_secs(1));
        assert_eq!(schedule.unhealthy_interval, None);
        assert_eq!(
            (schedule.healthy_threshold, schedule.unhealthy_threshold),
            (1, 1)
        );
        assert!(check.opening.is_empty() && check.expect.is_none() && !check.tls);
        let same = rule(&json!({})).expect("compiles");
        let other = rule(&json!({ "port": 9 })).expect("compiles");
        assert_eq!(check.fingerprint(), same.fingerprint());
        assert_ne!(check.fingerprint(), other.fingerprint());
    }

    #[test]
    fn refuses_what_it_cannot_honour() {
        let long = b64(&[1; MAX_PAYLOAD + 1]);
        let huge = "A".repeat(MAX_PAYLOAD_TEXT + 4);
        let cases = [
            json!({ "interval_secs": 0 }),
            json!({ "interval_secs": 3601 }),
            json!({ "timeout_secs": 301 }),
            json!({ "unhealthy_interval_secs": 0 }),
            json!({ "healthy_threshold": 0 }),
            json!({ "unhealthy_threshold": 101 }),
            json!({ "port": 0 }),
            json!({ "send": "not base64!" }),
            json!({ "send": "" }),
            json!({ "expect": long }),
            json!({ "send": huge }),
            json!({ "tls": true, "send_proxy_header": true }),
            json!({ "path": "/healthz" }),
        ];
        for extra in cases {
            let err = rule(&extra).expect_err("refused");
            assert_eq!(err.code, "invalid_service", "{extra}");
        }
        assert!(Check::compile(&json!({ "interval_secs": 1 })).is_err());
        assert!(
            rule(&json!({ "send": b64(&[1; MAX_PAYLOAD]), "expect": b64(&[2; MAX_PAYLOAD]) }))
                .is_ok()
        );
    }

    #[test]
    fn the_proxy_header_comes_before_send() {
        let check =
            rule(&json!({ "send_proxy_header": true, "send": b64(b"PING") })).expect("compiles");
        let mut header = Vec::new();
        Header::Local
            .encode(Version::V2, &mut header)
            .expect("local header");
        assert_eq!(&check.opening[..header.len()], &header[..]);
        assert_eq!(&check.opening[header.len()..], b"PING");
    }

    /// Runs `exchange` against a server that is `server`.
    async fn judged(check: &Check, server: impl AsyncFnOnce(DuplexStream)) -> Verdict {
        let (mut client, far) = duplex(4096);
        let (_, verdict) = tokio::join!(server(far), exchange(&mut client, check));
        verdict
    }

    #[tokio::test]
    async fn exchange_sends_then_matches_a_prefix() {
        let check =
            rule(&json!({ "send": b64(b"PING\n"), "expect": b64(b"PO") })).expect("compiles");
        let verdict = judged(&check, async |mut far| {
            let mut got = [0_u8; 5];
            far.read_exact(&mut got).await.expect("the probe sent");
            assert_eq!(&got, b"PING\n");
            far.write_all(b"PONG\n").await.expect("reply");
        })
        .await;
        assert_eq!(verdict, Verdict::Pass);
    }

    #[tokio::test]
    async fn exchange_waits_for_a_banner_and_fails_a_wrong_or_missing_one() {
        let check = rule(&json!({ "expect": b64(b"220 ") })).expect("compiles");
        let verdict = judged(&check, async |mut far| {
            far.write_all(b"22").await.expect("half");
            far.write_all(b"0 mail ready\r\n").await.expect("rest");
        })
        .await;
        assert_eq!(verdict, Verdict::Pass);

        let verdict = judged(&check, async |mut far| {
            far.write_all(b"421 go away\r\n").await.expect("wrong");
        })
        .await;
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");

        let verdict = judged(&check, async |far| drop(far)).await;
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    }

    #[tokio::test]
    async fn exchange_never_reads_more_than_expect() {
        let check = rule(&json!({ "expect": b64(b"AB") })).expect("compiles");
        let (mut client, mut far) = duplex(64 * 1024);
        let flood = b"AB".repeat(8 * 1024);
        far.write_all(&flood).await.expect("flood");
        drop(far);
        assert_eq!(exchange(&mut client, &check).await, Verdict::Pass);
        let mut left = Vec::new();
        client.read_to_end(&mut left).await.expect("drain");
        assert_eq!(
            left.len(),
            flood.len() - 2,
            "the probe read the two bytes it needed"
        );
    }
}
