//! SRV upstreams end to end. The names resolve against `common::dns::Dns`, a UDP
//! responder on a loopback port the test controls (`DNS_SERVERS`), so no test touches a real
//! resolver. Targets are `127.0.0.x` addresses with a backend on a free port each (the port is
//! what the SRV record says), and a policy file that denies one of them tells an allowed target
//! from a refused one.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::dns::Dns;
use common::{Podgate, Response, app, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const OWNER: &str = "_web._tcp.shop.test";

/// An operator policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-srv-policy-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, contents).expect("write policy file");
        Self { dir, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("utf-8 path")
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        // Best effort: a leftover temp directory is harmless.
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

/// A backend on a free port of one loopback address that answers with its own body and counts
/// the requests it gets.
struct Backend {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

impl Backend {
    async fn start(ip: &str, body: &'static str) -> Self {
        let listener = TcpListener::bind(format!("{ip}:0"))
            .await
            .expect("bind backend");
        let addr = listener.local_addr().expect("backend address");
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(stream, body, Arc::clone(&counter)));
            }
        });
        Self { addr, hits }
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

/// Answers each request on `stream` (keep-alive) with `body` until the peer closes.
async fn answer(mut stream: TcpStream, body: &'static str, hits: Arc<AtomicUsize>) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            seen.drain(..end + 4);
            hits.fetch_add(1, Ordering::SeqCst);
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The settings that make podgate ask `dns` and re-resolve fast.
fn resolver_env(dns: &Dns) -> Vec<(&'static str, String)> {
    vec![
        ("DNS_SERVERS", dns.servers()),
        ("DNS_MIN_TTL_SECS", "1".to_owned()),
        ("DNS_MAX_TTL_SECS", "60".to_owned()),
        ("DNS_TIMEOUT_MS", "1000".to_owned()),
    ]
}

/// Starts podgate with `env` and then `extra`, which wins.
async fn start(env: &[(&'static str, String)], extra: &[(&'static str, &str)]) -> Podgate {
    let mut all: Vec<(&str, &str)> = env
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    all.extend_from_slice(extra);
    Podgate::start_with_env(&all).await
}

/// An app of tenant `t1` on `host` whose service `web` has `servers` and balances by
/// `algorithm`.
fn app_with(id: &str, host: &str, servers: &[Value], algorithm: &str) -> Value {
    app(
        id,
        &[host],
        &[json!({
            "id": "r1", "state": "serving", "weight": 100,
            "services": [{
                "name": "web", "type": "loadbalancer",
                "algorithm": algorithm, "servers": servers,
            }],
        })],
    )
}

/// The server entry that names `owner` by SRV.
fn srv_server(owner: &str) -> Value {
    json!({ "url": format!("http://{owner}"), "resolve": "srv" })
}

/// An app on `a.test` with one SRV server named `OWNER`.
fn srv_app(algorithm: &str) -> Value {
    app_with("a", "a.test", &[srv_server(OWNER)], algorithm)
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
}

/// Retries `condition` every 100 ms for `secs` seconds.
async fn eventually(what: &str, secs: u64, mut condition: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if condition().await {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("not within {secs}s: {what}");
}

/// The bodies of `count` requests for `host`, 503 as `"503"`.
async fn bodies(podgate: &Podgate, host: &str, count: usize) -> Vec<String> {
    let mut seen = Vec::new();
    for _ in 0..count {
        let response = podgate.get(host, "/").await;
        seen.push(match response.status {
            200 => response.body,
            other => other.to_string(),
        });
    }
    seen
}

/// The value of `podgate_upstream_refused_total` with `labels`; 0 while the series is absent.
async fn refused(podgate: &Podgate, labels: &str) -> u64 {
    let metrics = podgate.admin_get("/metrics").await;
    let prefix = format!("podgate_upstream_refused_total{{{labels}}} ");
    metrics
        .body
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

/// The `conflicts` of a `422`, as one string to search.
fn rejection(response: &Response) -> String {
    assert_eq!(response.status, 422, "{response:?}");
    let body = response.json();
    assert_eq!(body["error"], "snapshot rejected", "{body}");
    body["conflicts"].to_string()
}

/// A policy that allows loopback, as the harness's own does, plus `extra` keys (a JSON object
/// body without the braces, such as `"srv_deny_ports": [1]`).
fn loopback_policy(extra: &str) -> PolicyFile {
    let sep = if extra.is_empty() { "" } else { "," };
    PolicyFile::write(&format!(
        r#"{{"deny": ["0.0.0.0/8", "169.254.0.0/16"]{sep}{extra}}}"#
    ))
}

#[tokio::test]
async fn srv_targets_become_servers() {
    let dns = Dns::start().await;
    let one = Backend::start("127.0.0.2", "one").await;
    let two = Backend::start("127.0.0.3", "two").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, one.port(), "a.shop.test"),
            (10, 1, two.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    let mut seen = BTreeSet::new();
    eventually("requests reach both targets", 10, async || {
        seen.extend(bodies(&podgate, "a.test", 4).await);
        seen.contains("one") && seen.contains("two")
    })
    .await;
    assert!(dns.srv_queries_for(OWNER) >= 1);
    assert!(
        dns.a_queries_for("a.shop.test") >= 1,
        "without glue the target host is resolved by a follow-up lookup"
    );
}

#[tokio::test]
async fn srv_additional_section_reused() {
    let dns = Dns::start().await;
    let one = Backend::start("127.0.0.2", "one").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set_srv(OWNER, &[(10, 1, one.port(), "a.shop.test")], 30);
    dns.glue(true);
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the target is reached", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["one"]
    })
    .await;
    assert_eq!(
        dns.queries_for("a.shop.test"),
        0,
        "the addresses of the additional section are used, not asked for"
    );
}

#[tokio::test]
async fn srv_weights_respected() {
    let dns = Dns::start().await;
    let heavy = Backend::start("127.0.0.2", "heavy").await;
    let light = Backend::start("127.0.0.3", "light").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 300, heavy.port(), "a.shop.test"),
            (10, 100, light.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("weighted_round_robin")])).await;
    eventually("both targets serve", 10, async || {
        let seen: BTreeSet<String> = bodies(&podgate, "a.test", 4).await.into_iter().collect();
        seen.contains("heavy") && seen.contains("light")
    })
    .await;

    // Weights 300 and 100 are a cycle of 3 and 1: any 40 consecutive picks hold exactly 30 and 10.
    let (heavy_before, light_before) = (heavy.hits(), light.hits());
    assert!(
        bodies(&podgate, "a.test", 40)
            .await
            .iter()
            .all(|body| body != "503")
    );
    assert_eq!(heavy.hits() - heavy_before, 30);
    assert_eq!(light.hits() - light_before, 10);
}

#[tokio::test]
async fn srv_lowest_priority_group_used() {
    let dns = Dns::start().await;
    let primary = Backend::start("127.0.0.2", "primary").await;
    let spare = Backend::start("127.0.0.3", "spare").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (20, 1, spare.port(), "b.shop.test"),
            (10, 1, primary.port(), "a.shop.test"),
        ],
        30,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the primary serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["primary"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["primary"; 20]);
    assert_eq!(spare.hits(), 0, "a higher priority value is not used");
}

#[tokio::test]
async fn srv_next_priority_when_lower_empty() {
    // The priority 10 target answers 127.0.0.2, which the policy denies: after the checks the
    // group is empty and the priority 20 target serves.
    let policy = PolicyFile::write(r#"{"deny": ["127.0.0.2/32", "::1/128"]}"#);
    let dns = Dns::start().await;
    let primary = Backend::start("127.0.0.2", "primary").await;
    let spare = Backend::start("127.0.0.3", "spare").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, primary.port(), "a.shop.test"),
            (20, 1, spare.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the spare serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["spare"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["spare"; 10]);
    assert_eq!(primary.hits(), 0, "the refused target was never dialled");
    assert!(refused(&podgate, r#"tenant="t1""#).await >= 1);
}

#[tokio::test]
async fn srv_reresolve_follows_ttl() {
    let dns = Dns::start().await;
    let old = Backend::start("127.0.0.2", "old").await;
    let new = Backend::start("127.0.0.3", "new").await;
    dns.set("a.shop.test", &["127.0.0.2"], 1);
    dns.set("b.shop.test", &["127.0.0.3"], 1);
    dns.set_srv(OWNER, &[(10, 1, old.port(), "a.shop.test")], 1);
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;
    eventually("the first answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["old"]
    })
    .await;

    // A target is added: both serve.
    dns.set_srv(
        OWNER,
        &[
            (10, 1, old.port(), "a.shop.test"),
            (10, 1, new.port(), "b.shop.test"),
        ],
        1,
    );
    let mut seen = BTreeSet::new();
    eventually("the added target serves", 10, async || {
        seen.extend(bodies(&podgate, "a.test", 4).await);
        seen.contains("new")
    })
    .await;

    // The first is removed: only the second serves.
    dns.set_srv(OWNER, &[(10, 1, new.port(), "b.shop.test")], 1);
    eventually("the removed target stops serving", 10, async || {
        bodies(&podgate, "a.test", 6).await == vec!["new"; 6]
    })
    .await;
    assert!(
        dns.srv_queries_for(OWNER) >= 3,
        "the name is resolved again on its TTL, not once"
    );
}

#[tokio::test]
async fn srv_failure_keeps_last_good() {
    let dns = Dns::start().await;
    let one = Backend::start("127.0.0.2", "one").await;
    dns.set("a.shop.test", &["127.0.0.2"], 1);
    dns.set_srv(OWNER, &[(10, 1, one.port(), "a.shop.test")], 1);
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;
    eventually("the answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["one"]
    })
    .await;

    dns.fail();
    let asked = dns.srv_queries_for(OWNER);
    sleep(Duration::from_secs(3)).await;
    assert!(
        dns.srv_queries_for(OWNER) > asked,
        "the resolver kept asking while it failed"
    );
    assert_eq!(bodies(&podgate, "a.test", 5).await, vec!["one"; 5]);
    dns.recover();
    sleep(Duration::from_millis(1500)).await;
    assert_eq!(bodies(&podgate, "a.test", 5).await, vec!["one"; 5]);
}

#[tokio::test]
async fn srv_stale_expires() {
    let dns = Dns::start().await;
    let one = Backend::start("127.0.0.2", "one").await;
    dns.set("a.shop.test", &["127.0.0.2"], 1);
    dns.set_srv(OWNER, &[(10, 1, one.port(), "a.shop.test")], 1);
    let podgate = start(&resolver_env(&dns), &[("DNS_MAX_STALE_SECS", "2")]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;
    eventually("the answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["one"]
    })
    .await;

    dns.fail();
    eventually("the stale set is dropped", 15, async || {
        bodies(&podgate, "a.test", 1).await == ["503"]
    })
    .await;
}

#[tokio::test]
async fn srv_target_loopback_refused() {
    // `{}` is the built-in policy: loopback is refused.
    let policy = PolicyFile::write("{}");
    let dns = Dns::start().await;
    let own = Backend::start("127.0.0.1", "reached").await;
    dns.set("self.shop.test", &["127.0.0.1"], 30);
    dns.set_srv(OWNER, &[(10, 1, own.port(), "self.shop.test")], 30);
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the target is refused and counted", 10, async || {
        refused(&podgate, r#"tenant="t1""#).await >= 1
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 5).await, vec!["503"; 5]);
    assert_eq!(own.hits(), 0, "loopback was never dialled");
}

#[tokio::test]
async fn srv_rebind_to_loopback_refused() {
    // 127.0.0.1 stands for loopback the policy denies; 127.0.0.2 is the first, allowed answer.
    let policy = PolicyFile::write(r#"{"deny": ["127.0.0.1/32", "::1/128"]}"#);
    let dns = Dns::start().await;
    let evil = Backend::start("127.0.0.1", "evil").await;
    let good = Backend::start("127.0.0.2", "good").await;
    dns.set("a.shop.test", &["127.0.0.2"], 1);
    dns.set("b.shop.test", &["127.0.0.2"], 1);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, good.port(), "a.shop.test"),
            (10, 1, evil.port(), "b.shop.test"),
        ],
        1,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;
    eventually("the first answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["good"]
    })
    .await;
    assert_eq!(refused(&podgate, r#"tenant="t1""#).await, 0);

    // The target host of the second record now answers loopback.
    dns.set("b.shop.test", &["127.0.0.1"], 1);
    eventually(
        "the rebinding answer is refused and counted",
        10,
        async || refused(&podgate, r#"tenant="t1""#).await >= 1,
    )
    .await;
    sleep(Duration::from_millis(1500)).await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["good"; 20]);
    assert_eq!(evil.hits(), 0, "the refused address was never dialled");
}

#[tokio::test]
async fn upstream_outside_allowlist_rejected_srv() {
    let policy =
        PolicyFile::write(r#"{"deny": ["10.9.0.0/16"], "default": {"allow": ["127.0.0.2/32"]}}"#);
    let dns = Dns::start().await;
    let inside = Backend::start("127.0.0.2", "inside").await;
    let outside = Backend::start("127.0.0.3", "outside").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, inside.port(), "a.shop.test"),
            (10, 1, outside.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the allowed target serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["inside"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["inside"; 20]);
    assert_eq!(
        outside.hits(),
        0,
        "an address outside the allow list is dropped"
    );
    assert!(refused(&podgate, r#"tenant="t1""#).await >= 1);
}

#[tokio::test]
async fn srv_denied_port_dropped() {
    let dns = Dns::start().await;
    let shell = Backend::start("127.0.0.2", "shell").await;
    let web = Backend::start("127.0.0.3", "web").await;
    // The operator's list names the port of the first backend, as it would name 22.
    let policy = loopback_policy(&format!(r#""srv_deny_ports": [{}]"#, shell.port()));
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, shell.port(), "a.shop.test"),
            (10, 1, web.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the target on an allowed port serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["web"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["web"; 20]);
    assert_eq!(shell.hits(), 0, "a denied port is never dialled");
    assert!(refused(&podgate, r#"tenant="t1",reason="port""#).await >= 1);
}

#[tokio::test]
async fn srv_default_denied_ports_apply_without_a_list() {
    // The harness policy has no `srv_deny_ports`: the default list (22, 5432, ...) is in force.
    let dns = Dns::start().await;
    let web = Backend::start("127.0.0.3", "web").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, 5432, "a.shop.test"),
            (10, 1, web.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually(
        "only the target on an allowed port serves",
        10,
        async || bodies(&podgate, "a.test", 1).await == ["web"],
    )
    .await;
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["web"; 10]);
    assert!(refused(&podgate, r#"tenant="t1",reason="port""#).await >= 1);
}

#[tokio::test]
async fn srv_tenant_port_allowlist() {
    let dns = Dns::start().await;
    let other = Backend::start("127.0.0.2", "other").await;
    let allowed = Backend::start("127.0.0.3", "allowed").await;
    let policy = loopback_policy(&format!(
        r#""tenants": {{"t1": {{"allow": ["127.0.0.0/8"], "srv_allow_ports": [{}]}}}}"#,
        allowed.port()
    ));
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, other.port(), "a.shop.test"),
            (10, 1, allowed.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the allowed port serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["allowed"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["allowed"; 20]);
    assert_eq!(
        other.hits(),
        0,
        "a port outside srv_allow_ports is never dialled"
    );
    assert!(refused(&podgate, r#"tenant="t1",reason="port""#).await >= 1);
}

#[tokio::test]
async fn srv_cname_target_refused() {
    let dns = Dns::start().await;
    let alias = Backend::start("127.0.0.2", "alias").await;
    let plain = Backend::start("127.0.0.3", "plain").await;
    dns.set("real.shop.test", &["127.0.0.2"], 1);
    dns.set_cname("alias.shop.test", "real.shop.test", 1);
    dns.set("b.shop.test", &["127.0.0.3"], 1);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, alias.port(), "alias.shop.test"),
            (10, 1, plain.port(), "b.shop.test"),
        ],
        1,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    // Found by a follow-up lookup.
    eventually("the plain target serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["plain"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["plain"; 10]);
    assert!(dns.queries_for("alias.shop.test") >= 1);

    // Found in the additional section.
    dns.glue(true);
    let asked = dns.srv_queries_for(OWNER);
    eventually("the answer is resolved again", 10, async || {
        dns.srv_queries_for(OWNER) >= asked + 2
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["plain"; 10]);
    assert_eq!(alias.hits(), 0, "a CNAME target is never used");
}

#[tokio::test]
async fn srv_port_zero_dropped() {
    let dns = Dns::start().await;
    let off = Backend::start("127.0.0.2", "off").await;
    let on = Backend::start("127.0.0.3", "on").await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.3"], 30);
    dns.set_srv(
        OWNER,
        &[(10, 1, 0, "a.shop.test"), (10, 1, on.port(), "b.shop.test")],
        1,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(&podgate, &snapshot(1, &[srv_app("round_robin")])).await;

    eventually("the target with a port serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["on"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["on"; 10]);
    assert_eq!(off.hits(), 0);

    // Records that are all at port 0 say the service is not available: the name has no target
    // and requests get 503.
    dns.set_srv(OWNER, &[(10, 1, 0, "a.shop.test")], 1);
    eventually(
        "an answer of port 0 only leaves no target",
        15,
        async || bodies(&podgate, "a.test", 1).await == ["503"],
    )
    .await;
}

#[tokio::test]
async fn srv_url_with_port_rejected() {
    let dns = Dns::start().await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    for (server, expect) in [
        (
            json!({ "url": format!("http://{OWNER}:8080"), "resolve": "srv" }),
            "no port",
        ),
        (
            json!({ "url": "http://bad owner.test", "resolve": "srv" }),
            "SRV owner name",
        ),
        (
            json!({ "url": "http://-bad.test", "resolve": "srv" }),
            "SRV owner name",
        ),
        (
            json!({ "url": "http://10.0.0.1", "resolve": "srv" }),
            "SRV owner name",
        ),
        (
            json!({ "url": format!("http://{OWNER}"), "resolve": "srv", "weight": 3 }),
            "weight",
        ),
        (
            json!({ "url": format!("http://{OWNER}"), "resolve": "mx" }),
            "unknown variant",
        ),
    ] {
        let rejected = podgate
            .push_snapshot(&snapshot(
                1,
                &[app_with(
                    "a",
                    "a.test",
                    std::slice::from_ref(&server),
                    "round_robin",
                )],
            ))
            .await;
        let text = rejection(&rejected);
        assert!(
            text.contains("invalid_service") && text.contains(expect),
            "{server}: {text}"
        );
    }
    // The same URL under `resolve: "a"` keeps its port.
    push(
        &podgate,
        &snapshot(
            2,
            &[app_with(
                "a",
                "a.test",
                &[json!({ "url": "http://api.shop.test:8080", "resolve": "a" })],
                "round_robin",
            )],
        ),
    )
    .await;
}

#[tokio::test]
async fn srv_name_caps() {
    let dns = Dns::start().await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    let owners = |from: usize, count: usize| -> Vec<Value> {
        (from..from + count)
            .map(|at| srv_server(&format!("_s._tcp.n{at}.shop.test")))
            .collect()
    };

    // 32 distinct names in one app are allowed; repeating one does not count twice.
    let mut at_cap = owners(0, 32);
    at_cap.push(srv_server("_s._tcp.n0.shop.test"));
    push(
        &podgate,
        &snapshot(1, &[app_with("a", "a.test", &at_cap, "round_robin")]),
    )
    .await;
    let over = podgate
        .push_snapshot(&snapshot(
            2,
            &[app_with("a", "a.test", &owners(0, 33), "round_robin")],
        ))
        .await;
    let text = rejection(&over);
    assert!(
        text.contains("invalid_service") && text.contains("SRV names") && text.contains("32"),
        "{text}"
    );

    // 128 per tenant: four apps of 32 names are allowed, a fifth name is not.
    let four: Vec<Value> = (0..4)
        .map(|app_at| {
            app_with(
                &format!("t{app_at}"),
                &format!("t{app_at}.test"),
                &owners(100 * (app_at + 1), 32),
                "round_robin",
            )
        })
        .collect();
    push(&podgate, &snapshot(3, &four)).await;
    let mut five = four.clone();
    five.push(app_with("t4", "t4.test", &owners(900, 1), "round_robin"));
    let over = podgate.push_snapshot(&snapshot(4, &five)).await;
    let text = rejection(&over);
    assert!(
        text.contains("invalid_service") && text.contains("SRV names") && text.contains("128"),
        "{text}"
    );
}

#[tokio::test]
async fn srv_named_hash_service_charged_for_largest_ring() {
    // 16 services of a hash algorithm each with an SRV name hold 16 largest rings (40 960
    // points each): 655 360 is under the tenant cap of 1 048 576, 26 are not.
    let dns = Dns::start().await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    let revision = |services: usize| -> Value {
        let list: Vec<Value> = (0..services)
            .map(|at| {
                json!({
                    "name": format!("s{at}"), "type": "loadbalancer", "algorithm": "ip_hash",
                    "servers": [srv_server(&format!("_s._tcp.n{at}.shop.test"))],
                })
            })
            .collect();
        json!({ "id": "r1", "state": "serving", "weight": 100, "services": list })
    };
    let mut few = app("a", &["a.test"], &[revision(16)]);
    few["routers"] = json!([common::router(
        "default",
        json!({ "host": ["a.test"] }),
        "s0"
    )]);
    push(&podgate, &snapshot(1, &[few])).await;
    let mut many = app("a", &["a.test"], &[revision(26)]);
    many["routers"] = json!([common::router(
        "default",
        json!({ "host": ["a.test"] }),
        "s0"
    )]);
    let over = podgate.push_snapshot(&snapshot(2, &[many])).await;
    let text = rejection(&over);
    assert!(
        text.contains("invalid_service") && text.contains("ring points"),
        "{text}"
    );
}

#[tokio::test]
async fn srv_retry_moves_to_another_target() {
    // Nothing listens on the first target's port, so an attempt there is refused. The retry
    // reselects among the resolved, checked targets, excluding the one tried.
    let dns = Dns::start().await;
    let dead = common::refused();
    let good = Backend::start("127.0.0.2", "good").await;
    dns.set("a.shop.test", &["127.0.0.1"], 30);
    dns.set("b.shop.test", &["127.0.0.2"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, dead.addr.port(), "a.shop.test"),
            (10, 1, good.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(&resolver_env(&dns), &[]).await;
    let web = common::with_middleware(
        srv_app("round_robin"),
        "r",
        "retry",
        json!({ "attempts": 3, "initial_interval_ms": 1 }),
    );
    push(&podgate, &snapshot(1, &[web])).await;
    eventually("both targets resolved", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["good"]
    })
    .await;

    // Round robin alternates between the targets, so half of these first meet the dead one;
    // every one is answered.
    assert_eq!(bodies(&podgate, "a.test", 10).await, vec!["good"; 10]);
    assert!(good.hits() >= 11);
}

#[tokio::test]
async fn srv_mirror_dials_checked_target() {
    // The main service is a literal on 127.0.0.3. The mirror target is named by SRV and has two
    // targets, 127.0.0.2 (allowed) and 127.0.0.1 (denied by the policy): the copy goes to the
    // first, and the denied one is never dialled, so a mirror cannot reach what a request cannot.
    let policy = PolicyFile::write(r#"{"deny": ["127.0.0.1/32", "::1/128"]}"#);
    let main = Backend::start("127.0.0.3", "main").await;
    let allowed = Backend::start("127.0.0.2", "shadow").await;
    let denied = Backend::start("127.0.0.1", "denied").await;
    let dns = Dns::start().await;
    dns.set("a.shop.test", &["127.0.0.2"], 30);
    dns.set("b.shop.test", &["127.0.0.1"], 30);
    dns.set_srv(
        OWNER,
        &[
            (10, 1, allowed.port(), "a.shop.test"),
            (10, 1, denied.port(), "b.shop.test"),
        ],
        30,
    );
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    let mut mirrored = app(
        "a",
        &["a.test"],
        &[json!({
            "id": "r1", "state": "serving", "weight": 100,
            "services": [
                { "name": "web", "type": "loadbalancer",
                  "servers": [{ "url": format!("http://127.0.0.3:{}", main.port()) }] },
                { "name": "shadow", "type": "loadbalancer", "servers": [srv_server(OWNER)] },
                { "name": "m", "type": "mirroring", "service": "web",
                  "mirrors": [{ "service": "shadow", "percent": 100 }] },
            ],
        })],
    );
    mirrored["routers"] = json!([common::router(
        "default",
        json!({ "host": ["a.test"] }),
        "m"
    )]);
    push(&podgate, &snapshot(1, &[mirrored])).await;

    eventually(
        "a copy reaches the resolved, allowed target",
        10,
        async || {
            assert_eq!(bodies(&podgate, "a.test", 1).await, ["main"]);
            allowed.hits() >= 1
        },
    )
    .await;
    for _ in 0..10 {
        assert_eq!(bodies(&podgate, "a.test", 1).await, ["main"]);
    }
    sleep(Duration::from_millis(500)).await;
    assert_eq!(denied.hits(), 0, "the denied target was never dialled");
    assert!(refused(&podgate, r#"tenant="t1""#).await >= 1);
}
