//! Servers named by DNS end to end. The names resolve against `common::dns::Dns`, a
//! UDP responder on a loopback port the test controls (`DNS_SERVERS`), so no test touches a
//! real resolver. The addresses the names resolve to are `127.0.0.1` and `127.0.0.2`: both are
//! loopback, so a backend can listen on the same port on each, and a policy file that denies
//! one of them tells an allowed answer from a refused one.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use common::dns::Dns;
use common::{Podgate, Response, TestCert, app, snapshot};
use rustls::ServerConfig;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

/// An operator policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-dns-policy-{}-{}",
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

/// Backends that listen on the same port on each of several loopback addresses and answer with
/// their own body, counting the requests they get.
struct Backends {
    port: u16,
    hits: Vec<Arc<AtomicUsize>>,
}

impl Backends {
    /// One backend per `(ip, body)`, all on one free port. A port taken on one of the addresses
    /// by someone else makes the whole set start again on another.
    async fn start(listen: &[(&str, &'static str)]) -> Self {
        for _ in 0..50 {
            let Ok(first) = TcpListener::bind(format!("{}:0", listen[0].0)).await else {
                continue;
            };
            let port = first.local_addr().expect("backend address").port();
            let mut listeners = vec![first];
            for (ip, _) in &listen[1..] {
                match TcpListener::bind(format!("{ip}:{port}")).await {
                    Ok(listener) => listeners.push(listener),
                    Err(_) => break,
                }
            }
            if listeners.len() != listen.len() {
                continue;
            }
            let mut hits = Vec::new();
            for (listener, (_, body)) in listeners.into_iter().zip(listen) {
                let counter = Arc::new(AtomicUsize::new(0));
                hits.push(Arc::clone(&counter));
                let body = *body;
                tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        tokio::spawn(answer(stream, body, Arc::clone(&counter)));
                    }
                });
            }
            return Self { port, hits };
        }
        panic!("no port was free on every backend address");
    }

    /// How many requests the backend at `index` (as in `start`) has answered.
    fn hits(&self, index: usize) -> usize {
        self.hits[index].load(Ordering::SeqCst)
    }

    /// `http://name:port`, the URL of a server named `name`.
    fn url(&self, name: &str) -> String {
        format!("http://{name}:{}", self.port)
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

/// An app of tenant `t1` on `host` whose service `web` has one server per URL.
fn named_app(id: &str, host: &str, urls: &[String]) -> Value {
    let servers: Vec<Value> = urls.iter().map(|url| json!({ "url": url })).collect();
    app(
        id,
        &[host],
        &[json!({
            "id": "r1", "state": "serving", "weight": 100,
            "services": [{ "name": "web", "type": "loadbalancer", "servers": servers }],
        })],
    )
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

/// The value of `podgate_upstream_refused_total` for `tenant`; 0 while the series is absent.
async fn refused_total(podgate: &Podgate, tenant: &str) -> u64 {
    let metrics = podgate.admin_get("/metrics").await;
    let prefix = format!("podgate_upstream_refused_total{{tenant=\"{tenant}\"}} ");
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

#[tokio::test]
async fn dns_named_server_reaches_all_addresses() {
    let dns = Dns::start().await;
    dns.set("api.internal", &["127.0.0.1", "127.0.0.2"], 30);
    let backends = Backends::start(&[("127.0.0.1", "one"), ("127.0.0.2", "two")]).await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("api.internal")])],
        ),
    )
    .await;

    let mut seen = BTreeSet::new();
    eventually("requests reach both addresses", 10, async || {
        seen.extend(bodies(&podgate, "a.test", 4).await);
        seen.contains("one") && seen.contains("two")
    })
    .await;
    assert!(dns.a_queries_for("api.internal") >= 1);
}

#[tokio::test]
async fn dns_rebind_to_loopback_refused() {
    // 127.0.0.1 stands for loopback the policy denies; 127.0.0.2 is the first, allowed answer.
    let policy = PolicyFile::write(r#"{"deny": ["127.0.0.1/32", "::1/128"]}"#);
    let dns = Dns::start().await;
    dns.set("rebind.internal", &["127.0.0.2"], 1);
    let backends = Backends::start(&[("127.0.0.1", "evil"), ("127.0.0.2", "good")]).await;
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("rebind.internal")])],
        ),
    )
    .await;
    eventually("the first answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["good"]
    })
    .await;
    assert_eq!(refused_total(&podgate, "t1").await, 0);

    dns.set("rebind.internal", &["127.0.0.2", "127.0.0.1"], 1);
    eventually(
        "the rebinding answer is refused and counted",
        10,
        async || refused_total(&podgate, "t1").await >= 1,
    )
    .await;
    sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        bodies(&podgate, "a.test", 20).await,
        vec!["good"; 20],
        "the refused address is dropped from the set"
    );
    assert_eq!(backends.hits(0), 0, "the refused address was never dialled");
}

#[tokio::test]
async fn dns_localhost_refused_by_default_policy() {
    // `{}` has no `deny`, so the built-in default applies: loopback is refused.
    let policy = PolicyFile::write("{}");
    let dns = Dns::start().await;
    dns.set("self.internal", &["127.0.0.1"], 30);
    let backends = Backends::start(&[("127.0.0.1", "reached")]).await;
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("self.internal")])],
        ),
    )
    .await;

    eventually("the answer is refused and counted", 10, async || {
        refused_total(&podgate, "t1").await >= 1
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 5).await, vec!["503"; 5]);
    assert_eq!(backends.hits(0), 0, "loopback was never dialled");
}

#[tokio::test]
async fn dns_answer_outside_allowlist_dropped() {
    let policy =
        PolicyFile::write(r#"{"deny": ["10.9.0.0/16"], "default": {"allow": ["127.0.0.2/32"]}}"#);
    let dns = Dns::start().await;
    dns.set("mixed.internal", &["127.0.0.2", "127.0.0.1"], 30);
    let backends = Backends::start(&[("127.0.0.2", "allowed"), ("127.0.0.1", "outside")]).await;
    let podgate = start(
        &resolver_env(&dns),
        &[("UPSTREAM_POLICY_FILE", policy.path())],
    )
    .await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("mixed.internal")])],
        ),
    )
    .await;

    eventually("the allowed address serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["allowed"]
    })
    .await;
    assert_eq!(bodies(&podgate, "a.test", 20).await, vec!["allowed"; 20]);
    assert_eq!(
        backends.hits(1),
        0,
        "the address outside the allow list was never dialled"
    );
    assert!(refused_total(&podgate, "t1").await >= 1);
}

#[tokio::test]
async fn dns_ttl_respected() {
    let dns = Dns::start().await;
    dns.set("short.internal", &["127.0.0.1"], 2);
    // A TTL above the maximum and one of 0 are clamped to the settings.
    dns.set("long.internal", &["127.0.0.1"], 3600);
    dns.set("zero.internal", &["127.0.0.1"], 0);
    let backends = Backends::start(&[("127.0.0.1", "ok")]).await;
    let podgate = start(&resolver_env(&dns), &[("DNS_MAX_TTL_SECS", "3")]).await;
    let urls: Vec<String> = ["short", "long", "zero"]
        .iter()
        .map(|name| backends.url(&format!("{name}.internal")))
        .collect();
    push(&podgate, &snapshot(1, &[named_app("a", "a.test", &urls)])).await;

    sleep(Duration::from_millis(6500)).await;
    let short = dns.a_queries_for("short.internal");
    assert!(
        (2..=4).contains(&short),
        "TTL 2 over 6.5 s: {short} queries"
    );
    let long = dns.a_queries_for("long.internal");
    assert!(
        (2..=3).contains(&long),
        "TTL 3600 clamped to 3 s: {long} queries"
    );
    let zero = dns.a_queries_for("zero.internal");
    assert!(
        (4..=8).contains(&zero),
        "TTL 0 clamped to the 1 s minimum: {zero} queries"
    );
}

#[tokio::test]
async fn dns_reresolve_adds_removes_servers() {
    let dns = Dns::start().await;
    dns.set("moving.internal", &["127.0.0.1"], 1);
    let backends = Backends::start(&[("127.0.0.1", "one"), ("127.0.0.2", "two")]).await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("moving.internal")])],
        ),
    )
    .await;
    eventually("the first answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["one"]
    })
    .await;

    dns.set("moving.internal", &["127.0.0.2"], 1);
    eventually(
        "the first address is removed, the second added",
        10,
        async || bodies(&podgate, "a.test", 6).await == vec!["two"; 6],
    )
    .await;

    dns.set("moving.internal", &["127.0.0.1", "127.0.0.2"], 1);
    let mut seen = BTreeSet::new();
    eventually("both addresses serve again", 10, async || {
        seen.extend(bodies(&podgate, "a.test", 4).await);
        seen.contains("one") && seen.contains("two")
    })
    .await;
}

#[tokio::test]
async fn dns_failure_keeps_last_good() {
    let dns = Dns::start().await;
    dns.set("flaky.internal", &["127.0.0.1"], 1);
    let backends = Backends::start(&[("127.0.0.1", "ok")]).await;
    let podgate = start(&resolver_env(&dns), &[("DNS_MAX_STALE_SECS", "300")]).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("flaky.internal")])],
        ),
    )
    .await;
    eventually("the answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["ok"]
    })
    .await;

    dns.fail();
    let asked = dns.queries_for("flaky.internal");
    sleep(Duration::from_millis(3500)).await;
    assert!(
        dns.queries_for("flaky.internal") > asked,
        "the resolver kept trying while it failed"
    );
    assert_eq!(
        bodies(&podgate, "a.test", 5).await,
        vec!["ok"; 5],
        "the last good set serves through SERVFAIL"
    );

    // A resolver that does not answer at all is the same.
    dns.silence();
    sleep(Duration::from_millis(3500)).await;
    assert_eq!(bodies(&podgate, "a.test", 5).await, vec!["ok"; 5]);
}

#[tokio::test]
async fn dns_stale_expires() {
    let dns = Dns::start().await;
    dns.set("gone.internal", &["127.0.0.1"], 1);
    let backends = Backends::start(&[("127.0.0.1", "ok")]).await;
    let podgate = start(&resolver_env(&dns), &[("DNS_MAX_STALE_SECS", "2")]).await;
    push(
        &podgate,
        &snapshot(
            1,
            &[named_app("a", "a.test", &[backends.url("gone.internal")])],
        ),
    )
    .await;
    eventually("the answer serves", 10, async || {
        bodies(&podgate, "a.test", 1).await == ["ok"]
    })
    .await;

    dns.fail();
    eventually(
        "the set is empty once the stale time ran out",
        15,
        async || bodies(&podgate, "a.test", 1).await == ["503"],
    )
    .await;

    dns.recover();
    eventually(
        "a recovered resolver brings the server back",
        10,
        async || bodies(&podgate, "a.test", 1).await == ["ok"],
    )
    .await;
}

#[tokio::test]
async fn dns_single_flight() {
    let dns = Dns::start().await;
    dns.set("shared.internal", &["127.0.0.1"], 30);
    let backends = Backends::start(&[("127.0.0.1", "ok")]).await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    let url = backends.url("shared.internal");
    // Ten apps of one tenant and one of another name the same host.
    let mut apps: Vec<Value> = (0..10)
        .map(|at| {
            named_app(
                &format!("a{at}"),
                &format!("a{at}.test"),
                std::slice::from_ref(&url),
            )
        })
        .collect();
    let mut other = named_app("b", "b.test", std::slice::from_ref(&url));
    other["tenant"] = json!("t2");
    apps.push(other);
    let mut first = snapshot(1, &apps);
    first["tenants"].as_array_mut().expect("tenants").push(json!({
        "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 },
    }));
    push(&podgate, &first).await;
    eventually("the name resolves", 10, async || {
        bodies(&podgate, "a0.test", 1).await == ["ok"]
    })
    .await;

    // A second snapshot with the same names asks nothing new either.
    let mut second = first.clone();
    second["version"] = json!(2);
    push(&podgate, &second).await;
    sleep(Duration::from_millis(1500)).await;
    assert_eq!(bodies(&podgate, "a9.test", 1).await, ["ok"]);
    assert_eq!(bodies(&podgate, "b.test", 1).await, ["ok"]);
    assert_eq!(dns.a_queries_for("shared.internal"), 1);
    // The name has no AAAA record: an empty answer is retried after the minimum TTL, once for
    // the whole node, not once per app.
    let aaaa = dns.aaaa_queries_for("shared.internal");
    assert!(
        (1..=2).contains(&aaaa),
        "{aaaa} AAAA lookups for eleven apps"
    );
}

#[tokio::test]
async fn dns_query_rate_capped() {
    let dns = Dns::start().await;
    let urls: Vec<String> = (0..20)
        .map(|at| {
            let name = format!("n{at}.internal");
            dns.set(&name, &["127.0.0.1"], 1);
            format!("http://{name}:9")
        })
        .collect();
    let podgate = start(&resolver_env(&dns), &[("DNS_MAX_QUERIES_PER_SEC", "5")]).await;
    push(&podgate, &snapshot(1, &[named_app("a", "a.test", &urls)])).await;

    // 20 names at a 1 s TTL ask for 40 lookups a second (A and AAAA); the node sends 5.
    let started = Instant::now();
    sleep(Duration::from_secs(4)).await;
    let asked = dns.total_queries();
    let elapsed = started.elapsed().as_secs_f64();
    let allowed = 5.0 * elapsed + 5.0;
    assert!(asked > 0, "the resolver asked nothing");
    assert!(
        (asked as f64) <= allowed,
        "{asked} lookups in {elapsed:.1} s, at most {allowed:.0} expected at 5 a second"
    );
}

#[tokio::test]
async fn dns_names_per_app_capped() {
    let dns = Dns::start().await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    let urls = |from: usize, count: usize| -> Vec<String> {
        (from..from + count)
            .map(|at| format!("http://n{at}.internal:80"))
            .collect()
    };

    // 64 distinct names in one app are allowed, repeating one does not count twice.
    let mut at_cap = urls(0, 64);
    at_cap.push("http://n0.internal:81".to_owned());
    push(&podgate, &snapshot(1, &[named_app("a", "a.test", &at_cap)])).await;

    let over = podgate
        .push_snapshot(&snapshot(2, &[named_app("a", "a.test", &urls(0, 65))]))
        .await;
    let text = rejection(&over);
    assert!(
        text.contains("invalid_service") && text.contains("64"),
        "{text}"
    );

    // 256 per tenant: four apps of 64 names are allowed, a fifth name is not.
    let four: Vec<Value> = (0..4)
        .map(|app_at| {
            named_app(
                &format!("t{app_at}"),
                &format!("t{app_at}.test"),
                &urls(100 * (app_at + 1), 64),
            )
        })
        .collect();
    push(&podgate, &snapshot(3, &four)).await;
    let mut five = four.clone();
    five.push(named_app("t4", "t4.test", &urls(900, 1)));
    let over = podgate.push_snapshot(&snapshot(4, &five)).await;
    let text = rejection(&over);
    assert!(
        text.contains("invalid_service") && text.contains("256"),
        "{text}"
    );

    // A name that is not a host name is refused too.
    let bad = podgate
        .push_snapshot(&snapshot(
            5,
            &[named_app(
                "a",
                "a.test",
                &["http://bad_name!.internal:80".to_owned()],
            )],
        ))
        .await;
    assert!(rejection(&bad).contains("invalid_service"));
}

#[tokio::test]
async fn dns_unresolved_is_503_not_wake() {
    let dns = Dns::start().await;
    // `nowhere.internal` is not set: NXDOMAIN.
    let podgate = start(&resolver_env(&dns), &[]).await;
    let mut sleepy = named_app("a", "a.test", &["http://nowhere.internal:8080".to_owned()]);
    sleepy["scale_to_zero"] = json!({ "idle_secs": 3600, "wake_timeout_secs": 20 });
    push(&podgate, &snapshot(1, &[sleepy])).await;
    eventually("the name was asked", 10, async || {
        dns.queries_for("nowhere.internal") >= 1
    })
    .await;

    let started = Instant::now();
    let response = podgate.get("a.test", "/").await;
    assert_eq!(response.status, 503, "{response:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "answered at once, not held for a wake"
    );
    let events = podgate.admin_get("/v1/events?after=0&timeout_secs=0").await;
    assert_eq!(events.json()["events"], json!([]), "no wake_requested");
}

/// What a TLS backend saw: `(path, Host header, SNI)` of every request.
type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

/// A TLS backend on `127.0.0.1` with `cert` that records what each request carried.
async fn tls_backend(cert: &TestCert) -> (u16, Seen) {
    let provider = Arc::new(default_provider());
    let chain = vec![CertificateDer::from_pem_slice(cert.cert_pem.as_bytes()).expect("chain")];
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).expect("key");
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend address").port();
    let seen: Seen = Arc::default();
    let record = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve_tls(acceptor.clone(), tcp, Arc::clone(&record)));
        }
    });
    (port, seen)
}

async fn serve_tls(acceptor: TlsAcceptor, tcp: TcpStream, seen: Seen) {
    let Ok(mut stream) = acceptor.accept(tcp).await else {
        return;
    };
    let sni = stream
        .get_ref()
        .1
        .server_name()
        .unwrap_or("none")
        .to_owned();
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        while let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            buffer.drain(..end + 4);
            let path = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or_default()
                .to_owned();
            let host = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("host:")
                        .then(|| line[5..].trim().to_owned())
                })
                .unwrap_or_default();
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((path, host, sni.clone()));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{sni}",
                sni.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
}

#[tokio::test]
async fn dns_connects_to_checked_ip_with_name_sni() {
    // The certificate names only `secure.internal`, which nothing but the test's DNS resolves.
    // A connection that works therefore dialled the address the resolver returned (checked
    // against the policy) and sent the name as SNI and verified the certificate against it.
    let cert = TestCert::new(&["secure.internal"]);
    let (port, seen) = tls_backend(&cert).await;
    let dns = Dns::start().await;
    dns.set("secure.internal", &["127.0.0.1"], 30);
    let podgate = start(&resolver_env(&dns), &[]).await;

    let mut web = app(
        "a",
        &["a.test"],
        &[json!({
            "id": "r1", "state": "serving", "weight": 100,
            "services": [{
                "name": "web", "type": "loadbalancer", "transport": "tls",
                "servers": [{ "url": format!("https://secure.internal:{port}") }],
                "health_check": { "path": "/probe", "interval_secs": 1, "timeout_secs": 1 },
            }],
        })],
    );
    web["transports"] =
        json!([{ "name": "tls", "type": "servers_transport", "ca_pem": cert.cert_pem }]);
    push(&podgate, &snapshot(1, &[web])).await;

    eventually("the request reaches the backend over TLS", 10, async || {
        let answer = podgate.get("a.test", "/data").await;
        answer.status == 200 && answer.body == "secure.internal"
    })
    .await;
    eventually("a health probe arrived", 10, async || {
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(path, _, _)| path == "/probe")
    })
    .await;
    let seen = seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let probe = seen
        .iter()
        .find(|(path, _, _)| path == "/probe")
        .expect("a probe");
    assert_eq!(
        (probe.1.as_str(), probe.2.as_str()),
        (&*format!("secure.internal:{port}"), "secure.internal"),
        "the probe names the server in Host and SNI, and dials the address"
    );
}

#[tokio::test]
async fn dns_named_hash_service_charged_for_largest_ring() {
    let dns = Dns::start().await;
    let podgate = start(&resolver_env(&dns), &[]).await;
    let hashed = |at: usize, url: &str| {
        let mut declared = named_app(&format!("h{at}"), &format!("h{at}.test"), &[url.to_owned()]);
        declared["revisions"][0]["services"][0]["algorithm"] = json!("ip_hash");
        declared
    };
    // One tenant may hold 1 048 576 ring points; a service named by DNS counts the largest
    // ring it could ever hold (40 960 points) because its addresses are not known at compile,
    // so 25 fit and the 26th does not. The same 26 services over IP literals (160 points each)
    // fit easily.
    let named: Vec<Value> = (0..25)
        .map(|at| hashed(at, "http://ring.internal:80"))
        .collect();
    push(&podgate, &snapshot(1, &named)).await;
    let mut over = named.clone();
    over.push(hashed(25, "http://ring.internal:80"));
    let rejected = podgate.push_snapshot(&snapshot(2, &over)).await;
    let text = rejection(&rejected);
    assert!(
        text.contains("invalid_service") && text.contains("ring points"),
        "{text}"
    );
    let literal: Vec<Value> = (0..26)
        .map(|at| hashed(at, "http://127.0.0.1:80"))
        .collect();
    push(&podgate, &snapshot(3, &literal)).await;
}
