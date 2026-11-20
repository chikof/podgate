//! Active health checks through the real proxy: servers that fail their probe stop taking
//! traffic and start again when they pass, the probe is bounded (timeout, body, concurrency),
//! obeys the upstream policy and never follows a redirect, and its state follows the rules of the
//! registry (kept across unrelated pushes, fresh for a changed check).

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Podgate, app, snapshot};
use podgate::service::health::{Check, HttpProbe, Verdict};
use podgate::service::upstream_policy::UpstreamPolicy;
use podgate::service::{Server, Transport, Upstream};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

/// The path the backends treat as the health endpoint; everything else is traffic.
const HEALTH_PATH: &str = "/healthz";

/// What a backend answers on its health path.
struct Behaviour {
    status: AtomicU16,
    body: Mutex<Vec<u8>>,
    location: Mutex<Option<String>>,
    hang: AtomicBool,
}

/// Counts of the probe connections a backend (or several sharing one) saw.
#[derive(Default)]
struct Gauge {
    current: AtomicUsize,
    peak: AtomicUsize,
    accepted: AtomicUsize,
    closed: AtomicUsize,
}

/// A backend: `name` for every request outside the health path, a controllable answer on it.
struct Backend {
    addr: SocketAddr,
    behaviour: Arc<Behaviour>,
    probes: Arc<Mutex<Vec<String>>>,
    gauge: Arc<Gauge>,
}

impl Backend {
    async fn start(name: &'static str) -> Self {
        Self::start_on(name, Arc::default(), None).await
    }

    async fn start_with(name: &'static str, gauge: Arc<Gauge>) -> Self {
        Self::start_on(name, gauge, None).await
    }

    async fn start_tls(name: &'static str, acceptor: TlsAcceptor) -> Self {
        Self::start_on(name, Arc::default(), Some(acceptor)).await
    }

    async fn start_on(name: &'static str, gauge: Arc<Gauge>, tls: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let behaviour = Arc::new(Behaviour {
            status: AtomicU16::new(200),
            body: Mutex::new(b"ok".to_vec()),
            location: Mutex::new(None),
            hang: AtomicBool::new(false),
        });
        let probes = Arc::new(Mutex::new(Vec::new()));
        let (shared, seen, counts) = (
            Arc::clone(&behaviour),
            Arc::clone(&probes),
            Arc::clone(&gauge),
        );
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(accept(
                    tls.clone(),
                    tcp,
                    name,
                    Arc::clone(&shared),
                    Arc::clone(&seen),
                    Arc::clone(&counts),
                ));
            }
        });
        Self {
            addr,
            behaviour,
            probes,
            gauge,
        }
    }

    fn answer(&self, status: u16, body: &[u8]) {
        self.behaviour.status.store(status, Ordering::Relaxed);
        *self.behaviour.body.lock().expect("lock") = body.to_vec();
    }

    fn set_status(&self, status: u16) {
        self.behaviour.status.store(status, Ordering::Relaxed);
    }

    fn probed(&self) -> usize {
        self.probes.lock().expect("lock").len()
    }

    fn first_probe(&self) -> String {
        self.probes.lock().expect("lock")[0].clone()
    }
}

/// Serves one connection, over TLS when the backend has an acceptor.
async fn accept(
    tls: Option<TlsAcceptor>,
    tcp: TcpStream,
    name: &'static str,
    behaviour: Arc<Behaviour>,
    probes: Arc<Mutex<Vec<String>>>,
    gauge: Arc<Gauge>,
) {
    match tls {
        None => serve(tcp, name, behaviour, probes, gauge).await,
        Some(acceptor) => {
            if let Ok(stream) = acceptor.accept(tcp).await {
                Box::pin(serve(stream, name, behaviour, probes, gauge)).await;
            }
        }
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    name: &'static str,
    behaviour: Arc<Behaviour>,
    probes: Arc<Mutex<Vec<String>>>,
    gauge: Arc<Gauge>,
) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).into_owned();
            seen.drain(..end + 4);
            let path = head
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            if !path.starts_with(HEALTH_PATH) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{name}",
                    name.len()
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                continue;
            }
            probes.lock().expect("lock").push(head);
            gauge.accepted.fetch_add(1, Ordering::SeqCst);
            let now = gauge.current.fetch_add(1, Ordering::SeqCst) + 1;
            gauge.peak.fetch_max(now, Ordering::SeqCst);
            if behaviour.hang.load(Ordering::Relaxed) {
                // Silent until the prober gives up and closes.
                while matches!(stream.read(&mut chunk).await, Ok(read) if read > 0) {}
            } else {
                let body = behaviour.body.lock().expect("lock").clone();
                let location = behaviour.location.lock().expect("lock").clone();
                let mut response = format!(
                    "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    behaviour.status.load(Ordering::Relaxed),
                    body.len()
                );
                if let Some(location) = location {
                    response.push_str(&format!("Location: {location}\r\n"));
                }
                response.push_str("\r\n");
                let mut bytes = response.into_bytes();
                bytes.extend_from_slice(&body);
                // A prober that stops reading makes this fail: that is the point of the cap.
                let _ = stream.write_all(&bytes).await;
            }
            gauge.current.fetch_sub(1, Ordering::SeqCst);
            gauge.closed.fetch_add(1, Ordering::SeqCst);
            return;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

fn check(extra: &Value) -> Value {
    let mut value = json!({ "path": HEALTH_PATH, "interval_secs": 1, "timeout_secs": 1 });
    if let (Some(base), Some(more)) = (value.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    value
}

fn revision(servers: &[SocketAddr], health_check: Value) -> Value {
    let servers: Vec<Value> = servers
        .iter()
        .map(|addr| json!({ "url": format!("http://{addr}") }))
        .collect();
    let mut revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
        { "name": "web", "type": "loadbalancer", "servers": servers }
    ] });
    revision["services"][0]["health_check"] = health_check;
    revision
}

fn health_app(id: &str, host: &str, servers: &[SocketAddr], health_check: Value) -> Value {
    app(id, &[host], &[revision(servers, health_check)])
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let pushed = podgate.push_snapshot(snapshot).await;
    assert_eq!(pushed.status, 200, "{pushed:?}");
}

/// Polls `condition` until it holds, up to `secs` seconds.
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

async fn answers_503(podgate: &Podgate, host: &str) -> bool {
    podgate.get(host, "/").await.status == 503
}

#[tokio::test]
async fn health_marks_down_and_up() {
    let podgate = Podgate::start().await;
    let (a, b) = (Backend::start("a").await, Backend::start("b").await);
    let rule = check(&json!({ "healthy_threshold": 2, "unhealthy_threshold": 2 }));
    push(
        &podgate,
        &snapshot(1, &[health_app("x", "x.test", &[a.addr, b.addr], rule)]),
    )
    .await;

    // Healthy from the start: both take traffic before any probe ran.
    let first = podgate.get("x.test", "/").await;
    assert_eq!(first.status, 200, "{first:?}");

    a.set_status(503);
    eventually("traffic leaves the failing server", 20, async || {
        let mut bodies = Vec::new();
        for _ in 0..6 {
            bodies.push(podgate.get("x.test", "/").await.body);
        }
        bodies.iter().all(|body| body == "b")
    })
    .await;
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains(&format!(
            "podgate_service_server_up{{app=\"x\",revision=\"r1\",service=\"web\",server=\"http://{}\"}} 0",
            a.addr
        )),
        "{metrics}"
    );

    a.set_status(200);
    eventually("traffic returns to the recovered server", 20, async || {
        let mut seen_a = false;
        for _ in 0..6 {
            seen_a |= podgate.get("x.test", "/").await.body == "a";
        }
        seen_a
    })
    .await;
}

#[tokio::test]
async fn health_expect_status_ranges() {
    let podgate = Podgate::start().await;
    let redirect = Backend::start("redirect").await;
    redirect.set_status(301);
    let missing = Backend::start("missing").await;
    missing.set_status(404);
    let custom = Backend::start("custom").await;
    custom.set_status(404);
    let narrow = Backend::start("narrow").await;
    narrow.set_status(301);
    push(
        &podgate,
        &snapshot(
            1,
            &[
                health_app(
                    "redirect",
                    "redirect.test",
                    &[redirect.addr],
                    check(&json!({})),
                ),
                health_app(
                    "missing",
                    "missing.test",
                    &[missing.addr],
                    check(&json!({})),
                ),
                health_app(
                    "custom",
                    "custom.test",
                    &[custom.addr],
                    check(&json!({ "expect_status": [404] })),
                ),
                health_app(
                    "narrow",
                    "narrow.test",
                    &[narrow.addr],
                    check(&json!({ "expect_status": ["200-299"] })),
                ),
            ],
        ),
    )
    .await;

    // 200 to 399 is the default: a 301 passes, a 404 fails; a listed code or range replaces it.
    eventually("the 404 and the narrow range fail", 20, async || {
        answers_503(&podgate, "missing.test").await && answers_503(&podgate, "narrow.test").await
    })
    .await;
    eventually("the passing servers were probed twice", 20, async || {
        redirect.probed() >= 2 && custom.probed() >= 2
    })
    .await;
    assert_eq!(podgate.get("redirect.test", "/").await.body, "redirect");
    assert_eq!(podgate.get("custom.test", "/").await.body, "custom");
}

#[tokio::test]
async fn health_expect_body() {
    let podgate = Podgate::start().await;
    let up = Backend::start("up").await;
    up.answer(200, br#"{"status": "up", "db": "ok"}"#);
    let down = Backend::start("down").await;
    down.answer(200, br#"{"status":"down"}"#);
    let rule = check(&json!({ "expect_body_regex": r#""status":\s*"up""# }));
    push(
        &podgate,
        &snapshot(
            1,
            &[
                health_app("up", "up.test", &[up.addr], rule.clone()),
                health_app("down", "down.test", &[down.addr], rule),
            ],
        ),
    )
    .await;
    eventually("a body that does not match fails", 20, async || {
        answers_503(&podgate, "down.test").await
    })
    .await;
    eventually("the matching server was probed twice", 20, async || {
        up.probed() >= 2
    })
    .await;
    assert_eq!(podgate.get("up.test", "/").await.body, "up");
}

#[tokio::test]
async fn health_sends_method_headers_host() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("b").await;
    let rule = check(&json!({
        "path": "/healthz?deep=1", "method": "OPTIONS",
        "headers": { "X-Probe": "yes" }, "hostname": "app.internal",
    }));
    push(
        &podgate,
        &snapshot(1, &[health_app("x", "x.test", &[backend.addr], rule)]),
    )
    .await;
    eventually("the first probe arrives", 10, async || {
        backend.probed() >= 1
    })
    .await;
    let head = backend.first_probe().to_ascii_lowercase();
    assert!(
        head.starts_with("options /healthz?deep=1 http/1.1\r\n"),
        "{head}"
    );
    assert!(head.contains("\r\nhost: app.internal\r\n"), "{head}");
    assert!(head.contains("\r\nx-probe: yes"), "{head}");
}

#[tokio::test]
async fn health_probe_timeout() {
    let podgate = Podgate::start().await;
    let silent = Backend::start("silent").await;
    silent.behaviour.hang.store(true, Ordering::Relaxed);
    push(
        &podgate,
        &snapshot(
            1,
            &[health_app("x", "x.test", &[silent.addr], check(&json!({})))],
        ),
    )
    .await;
    // A probe that never answers is a failure, and the prober closes the connection.
    eventually("the silent server is marked down", 10, async || {
        answers_503(&podgate, "x.test").await
    })
    .await;
    eventually("the prober gave up on the connection", 5, async || {
        silent.gauge.closed.load(Ordering::SeqCst) >= 1
    })
    .await;
}

#[tokio::test]
async fn health_probe_body_capped() {
    let podgate = Podgate::start().await;
    let late = Backend::start("late").await;
    let mut late_body = vec![b'a'; 64 * 1024];
    late_body.extend_from_slice(b"needle");
    late.answer(200, &late_body);
    let early = Backend::start("early").await;
    let mut early_body = b"needle".to_vec();
    early_body.extend(vec![b'a'; 64 * 1024]);
    early.answer(200, &early_body);
    let rule = check(&json!({ "expect_body_regex": "needle" }));
    push(
        &podgate,
        &snapshot(
            1,
            &[
                health_app("late", "late.test", &[late.addr], rule.clone()),
                health_app("early", "early.test", &[early.addr], rule),
            ],
        ),
    )
    .await;
    // The word past the 4 KiB the probe reads is never seen; the one inside the cap is.
    eventually("the match past the cap fails the probe", 20, async || {
        answers_503(&podgate, "late.test").await
    })
    .await;
    eventually("the early match was probed twice", 20, async || {
        early.probed() >= 2
    })
    .await;
    assert_eq!(podgate.get("early.test", "/").await.body, "early");
}

#[tokio::test]
async fn health_all_unhealthy_503_not_wake() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("b").await;
    backend.set_status(503);
    let mut sleepy = health_app("x", "x.test", &[backend.addr], check(&json!({})));
    sleepy["scale_to_zero"] = json!({ "idle_secs": 3600, "wake_timeout_secs": 20 });
    push(&podgate, &snapshot(1, &[sleepy])).await;
    eventually("the only server is marked down", 10, async || {
        answers_503(&podgate, "x.test").await
    })
    .await;

    let started = Instant::now();
    let response = podgate.get("x.test", "/").await;
    assert_eq!(response.status, 503, "{response:?}");
    assert_eq!(response.json()["error"], "no healthy upstream available");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "answered at once, not held for a wake"
    );
    let events = podgate.admin_get("/v1/events?after=0&timeout_secs=0").await;
    assert_eq!(events.json()["events"], json!([]), "no wake_requested");
}

/// Pushes `a` (host `x.test`, one server that fails its probe) at version 1 and waits for the
/// server to be marked down.
async fn marked_down(podgate: &Podgate, backend: &Backend, rule: &Value) {
    backend.set_status(503);
    push(
        podgate,
        &snapshot(
            1,
            &[health_app("x", "x.test", &[backend.addr], rule.clone())],
        ),
    )
    .await;
    eventually("the server is marked down", 10, async || {
        answers_503(podgate, "x.test").await
    })
    .await;
}

#[tokio::test]
async fn health_state_survives_unrelated_push() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("b").await;
    let rule = check(&json!({}));
    marked_down(&podgate, &backend, &rule).await;

    // Another app changes; the check of `x` does not: the down verdict is kept, so no request
    // reaches the server in between (a fresh state would be healthy until the next probe).
    let mut other = health_app("y", "y.test", &[backend.addr], rule.clone());
    other["declared_by"] = json!("bumped");
    push(
        &podgate,
        &snapshot(
            2,
            &[health_app("x", "x.test", &[backend.addr], rule), other],
        ),
    )
    .await;
    for _ in 0..5 {
        assert_eq!(podgate.get("x.test", "/").await.status, 503);
    }
}

#[tokio::test]
async fn health_state_resets_on_change() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("b").await;
    marked_down(&podgate, &backend, &check(&json!({}))).await;

    // A different check is a different object: it starts healthy, and its first probe is up to a
    // timeout away, so the very next request goes through.
    let changed = check(&json!({ "path": "/ok", "interval_secs": 2 }));
    push(
        &podgate,
        &snapshot(2, &[health_app("x", "x.test", &[backend.addr], changed)]),
    )
    .await;
    let response = podgate.get("x.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
}

#[tokio::test]
async fn health_probe_concurrency_capped() {
    let podgate = Podgate::start_with_env(&[("HEALTH_MAX_CONCURRENT", "2")]).await;
    let gauge = Arc::new(Gauge::default());
    let mut servers = Vec::new();
    let mut backends = Vec::new();
    for _ in 0..8 {
        let backend = Backend::start_with("b", Arc::clone(&gauge)).await;
        backend.behaviour.hang.store(true, Ordering::Relaxed);
        servers.push(backend.addr);
        backends.push(backend);
    }
    push(
        &podgate,
        &snapshot(1, &[health_app("x", "x.test", &servers, check(&json!({})))]),
    )
    .await;
    eventually("every server was probed", 20, async || {
        gauge.accepted.load(Ordering::SeqCst) >= 8
    })
    .await;
    assert_eq!(
        gauge.peak.load(Ordering::SeqCst),
        2,
        "eight silent probes run two at a time"
    );
}

/// A probe by a check with `extra` fields of the plain-HTTP server at `addr`, through the
/// default transport.
fn probe_of(addr: SocketAddr, extra: &Value, policy: UpstreamPolicy) -> HttpProbe {
    let rule = Arc::new(Check::compile(&check(extra)).expect("compiles"));
    let server = Server {
        url: Box::default(),
        addr,
        tls: false,
        h2c: false,
        weight: 1,
        state: Arc::default(),
    };
    let transport = Transport::default();
    let peer = rule.peer(Upstream {
        server: &server,
        transport: &transport,
    });
    HttpProbe::new(rule, "t1", peer, policy, HttpProbe::connector())
}

#[tokio::test]
async fn health_probe_obeys_upstream_policy() {
    let backend = Backend::start("b").await;
    let probe = |policy: UpstreamPolicy| probe_of(backend.addr, &json!({}), policy);

    let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
    let verdict = probe(denying.clone()).run().await;
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    assert_eq!(backend.probed(), 0, "nothing was dialled");
    assert!(
        denying
            .render()
            .contains("podgate_upstream_refused_total{tenant=\"t1\"} 1"),
        "{}",
        denying.render()
    );

    // The same probe with a policy that allows the address connects and passes.
    let allowing = UpstreamPolicy::allow_all();
    assert_eq!(probe(allowing).run().await, Verdict::Pass);
    assert_eq!(backend.probed(), 1);
}

#[tokio::test]
async fn health_redirect_not_followed() {
    let podgate = Podgate::start().await;
    let elsewhere = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend = Backend::start("b").await;
    backend.set_status(302);
    *backend.behaviour.location.lock().expect("lock") =
        Some(format!("http://{}/", elsewhere.local_addr().expect("addr")));
    push(
        &podgate,
        &snapshot(
            1,
            &[health_app(
                "x",
                "x.test",
                &[backend.addr],
                check(&json!({})),
            )],
        ),
    )
    .await;
    eventually("the redirecting server was probed twice", 20, async || {
        backend.probed() >= 2
    })
    .await;
    // A 3xx is a pass by default and its Location is never dialled.
    assert_eq!(podgate.get("x.test", "/").await.status, 200);
    let dialled = tokio::time::timeout(Duration::from_millis(300), elsewhere.accept()).await;
    assert!(dialled.is_err(), "the redirect target was contacted");
}

#[tokio::test]
async fn health_port_override_probes_the_other_port() {
    let podgate = Podgate::start().await;
    let traffic = Backend::start("traffic").await;
    let management = Backend::start("mgmt").await;
    management.set_status(503);
    let rule = check(&json!({ "port": management.addr.port() }));
    push(
        &podgate,
        &snapshot(1, &[health_app("x", "x.test", &[traffic.addr], rule)]),
    )
    .await;
    // The server's own health path answers 200; the check asks the management port.
    eventually("the management port fails the check", 20, async || {
        answers_503(&podgate, "x.test").await
    })
    .await;
    assert_eq!(traffic.probed(), 0);
    assert!(management.probed() >= 1);
}

#[tokio::test]
async fn health_metric_server_up() {
    let podgate = Podgate::start().await;
    let (good, bad) = (Backend::start("good").await, Backend::start("bad").await);
    bad.set_status(500);
    push(
        &podgate,
        &snapshot(
            1,
            &[health_app(
                "x",
                "x.test",
                &[good.addr, bad.addr],
                check(&json!({})),
            )],
        ),
    )
    .await;
    let row = |addr: SocketAddr, up: u8| {
        format!(
            "podgate_service_server_up{{app=\"x\",revision=\"r1\",service=\"web\",server=\"http://{addr}\"}} {up}\n"
        )
    };
    eventually("each server has its row", 20, async || {
        let text = podgate.admin_get("/metrics").await.body;
        text.contains("# TYPE podgate_service_server_up gauge\n")
            && text.contains(&row(good.addr, 1))
            && text.contains(&row(bad.addr, 0))
    })
    .await;
}

#[tokio::test]
async fn too_many_servers_rejected() {
    let podgate = Podgate::start().await;
    let servers = |count: u16| -> Vec<SocketAddr> {
        (1..=count)
            .map(|port| ([127, 0, 0, 1], port).into())
            .collect()
    };
    let service = |count: u16| {
        let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
            { "name": "web", "type": "loadbalancer", "servers": servers(count).iter()
                .map(|addr| json!({ "url": format!("http://{addr}") })).collect::<Vec<_>>() }
        ] });
        snapshot(u64::from(count), &[app("x", &["x.test"], &[revision])])
    };
    let refused = podgate.push_snapshot(&service(257)).await;
    assert_eq!(refused.status, 422, "{refused:?}");
    assert_eq!(refused.json()["conflicts"][0]["code"], "invalid_service");
    let allowed = podgate.push_snapshot(&service(256)).await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
}

#[tokio::test]
async fn health_check_invalid_rejected() {
    let podgate = Podgate::start().await;
    let backend = Backend::start("b").await;
    let cases = [
        (json!({ "path": "healthz" }), "invalid_service"),
        (json!({ "interval_secs": 0 }), "invalid_service"),
        (json!({ "expect_status": ["x"] }), "invalid_service"),
        (json!({ "headers": { "Host": "evil" } }), "invalid_service"),
    ];
    for (version, (extra, code)) in (1_u64..).zip(cases) {
        let pushed = podgate
            .push_snapshot(&snapshot(
                version,
                &[health_app("x", "x.test", &[backend.addr], check(&extra))],
            ))
            .await;
        assert_eq!(pushed.status, 422, "{extra}: {pushed:?}");
        assert_eq!(pushed.json()["conflicts"][0]["code"], code, "{extra}");
    }
}

/// A private certificate authority and what it issues for the TLS backends.
struct Ca {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pem: String,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer = rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("CA key"),
        )
        .expect("self-signed CA");
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    /// An acceptor presenting a certificate for 127.0.0.1 issued by this CA.
    fn acceptor(&self) -> TlsAcceptor {
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("leaf params");
        let cert = params.signed_by(&key, &self.issuer).expect("sign leaf");
        let chain = vec![cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).expect("key");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("server config");
        TlsAcceptor::from(Arc::new(config))
    }
}

/// An app whose service `web` has one `https://` server and trusts `ca` through a transport.
fn tls_app(backend: &Backend, ca: &Ca, health_check: Value) -> Value {
    let mut tls = health_app("x", "x.test", &[backend.addr], health_check);
    tls["revisions"][0]["services"][0]["servers"][0]["url"] =
        json!(format!("https://{}", backend.addr));
    tls["revisions"][0]["services"][0]["transport"] = json!("private");
    tls["transports"] =
        json!([{ "name": "private", "type": "servers_transport", "ca_pem": ca.pem }]);
    tls
}

#[tokio::test]
async fn health_https_probe_uses_the_transport() {
    let podgate = Podgate::start().await;
    let ca = Ca::new("private ca");
    let backend = Backend::start_tls("secure", ca.acceptor()).await;
    push(
        &podgate,
        &snapshot(1, &[tls_app(&backend, &ca, check(&json!({})))]),
    )
    .await;

    // A probe is recorded only after the TLS handshake with the private CA succeeded.
    eventually("the TLS server was probed twice", 20, async || {
        backend.probed() >= 2
    })
    .await;
    assert_eq!(podgate.get("x.test", "/").await.body, "secure");
    backend.set_status(503);
    eventually("the failing TLS server is marked down", 20, async || {
        answers_503(&podgate, "x.test").await
    })
    .await;
}

#[tokio::test]
async fn health_https_probe_verifies_the_certificate() {
    let podgate = Podgate::start().await;
    let trusted = Ca::new("trusted");
    let stranger = Ca::new("stranger");
    // The server's certificate comes from a CA the transport does not trust.
    let backend = Backend::start_tls("secure", stranger.acceptor()).await;
    push(
        &podgate,
        &snapshot(1, &[tls_app(&backend, &trusted, check(&json!({})))]),
    )
    .await;
    eventually("the untrusted server is marked down", 20, async || {
        answers_503(&podgate, "x.test").await
    })
    .await;
    assert_eq!(backend.probed(), 0, "no probe got past the handshake");
}

#[tokio::test]
async fn health_https_scheme_override_obeys_policy() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let rule = json!({ "scheme": "https" });
    let denying = UpstreamPolicy::parse(r#"{"deny": ["127.0.0.0/8"]}"#).expect("policy");
    let verdict = probe_of(addr, &rule, denying).run().await;
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    let dialled = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(dialled.is_err(), "a TLS probe dialled a denied address");

    // Allowed, the override makes the probe speak TLS to the plain listener: it connects and
    // the handshake fails.
    let allowed = probe_of(addr, &rule, UpstreamPolicy::allow_all());
    let probe = tokio::spawn(async move { allowed.run().await });
    let (mut tcp, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("connected")
        .expect("accept");
    let mut hello = [0_u8; 3];
    tcp.read_exact(&mut hello).await.expect("a TLS record");
    assert_eq!(hello[0], 0x16, "the probe opened with a TLS handshake");
    drop(tcp);
    assert!(matches!(probe.await.expect("probe"), Verdict::Fail(_)));
}
