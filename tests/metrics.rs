//! Prometheus metrics per entry point, router and service: end to end through the real binary
//! (requests, status classes, latency, open requests, the `METRICS_ADDR` listener), and in
//! process through [`podgate::observe::metrics`] for what needs a clock or a server state the
//! binary cannot be told about (the series cap, expiry, server health, certificates).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{Podgate, TestCert, app, router, serving, snapshot};
use podgate::observe::metrics::{self, EntrySeries, InFlight, Registry};
use podgate::router::Matched;
use podgate::service::upstream_policy::UpstreamPolicy;
use podgate::{AccessLog, Backends, Budgets, TableHandle};
use podgate_model::Snapshot;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// A backend that answers `/status/<code>` with that status, `/slow` after 300 ms, and anything
/// else with 200; every response closes the connection.
async fn upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => seen.extend_from_slice(&chunk[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&seen).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let status = path
                    .strip_prefix("/status/")
                    .and_then(|code| code.parse::<u16>().ok())
                    .unwrap_or(200);
                if path == "/slow" {
                    sleep(Duration::from_millis(300)).await;
                }
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

/// The value of the sample whose name and labels are exactly `series`.
fn value(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

async fn scrape(podgate: &Podgate) -> String {
    let response = podgate.admin_get("/metrics").await;
    assert_eq!(response.status, 200);
    response.body
}

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
}

/// What an HTTP exchange with the metrics listener returned.
struct Reply {
    status: u16,
    content_type: String,
    body: String,
}

async fn raw(addr: SocketAddr, request: &str) -> Option<Reply> {
    let mut stream = TcpStream::connect(addr).await.ok()?;
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head.split_whitespace().nth(1)?.parse().ok()?;
    let content_type = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-type:")
                .map(|value| value.trim().to_owned())
        })
        .unwrap_or_default();
    Some(Reply {
        status,
        content_type,
        body: body.to_owned(),
    })
}

fn request(method: &str, path: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

/// Waits until the listener at `addr` answers.
async fn reachable(addr: SocketAddr) {
    for _ in 0..100 {
        if raw(addr, &request("GET", "/metrics")).await.is_some() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listens on {addr}");
}

#[tokio::test]
async fn metrics_request_counts_by_router() {
    let podgate = Podgate::start().await;
    let backend = upstream().await;
    let mut api = app("a.test", &["a.test"], &[serving("r1", backend)]);
    api["routers"] = json!([
        router(
            "api",
            json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}),
            "web"
        ),
        router("site", json!({"host": "a.test"}), "web"),
    ]);
    let pushed = podgate.push_snapshot(&snapshot(1, &[api])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    for _ in 0..3 {
        assert_eq!(podgate.get("a.test", "/api/x").await.status, 200);
    }
    assert_eq!(podgate.get("a.test", "/home").await.status, 200);
    assert_eq!(podgate.get("nobody.test", "/").await.status, 404);

    let body = scrape(&podgate).await;
    let counted = |series: &str| value(&body, series);
    assert_eq!(
        counted("podgate_router_requests_total{app=\"a.test\",router=\"api\",code_class=\"2xx\"}"),
        Some(3.0),
        "{body}"
    );
    assert_eq!(
        counted("podgate_router_requests_total{app=\"a.test\",router=\"site\",code_class=\"2xx\"}"),
        Some(1.0)
    );
    assert_eq!(
        counted(
            "podgate_service_requests_total{app=\"a.test\",service=\"web\",code_class=\"2xx\"}"
        ),
        Some(4.0),
        "both routers name service web"
    );
    assert_eq!(
        counted("podgate_service_request_duration_seconds_count{app=\"a.test\",service=\"web\"}"),
        Some(4.0)
    );
    assert!(
        !body.contains("router=\"other\""),
        "no tenant is over its cap: {body}"
    );
}

#[tokio::test]
async fn metrics_latency_histogram_buckets_end_to_end() {
    let podgate = Podgate::start().await;
    let backend = upstream().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", backend)])],
        ))
        .await;
    assert_eq!(pushed.status, 200);
    assert_eq!(podgate.get("a.test", "/slow").await.status, 200);

    let body = scrape(&podgate).await;
    let bucket = |le: &str| {
        value(
            &body,
            &format!(
                "podgate_router_request_duration_seconds_bucket{{app=\"a.test\",router=\"default\",le=\"{le}\"}}"
            ),
        )
    };
    assert_eq!(
        bucket("0.1"),
        Some(0.0),
        "a 300 ms request is not under 100 ms: {body}"
    );
    assert_eq!(bucket("0.25"), Some(0.0));
    assert_eq!(bucket("0.5"), Some(1.0));
    assert_eq!(bucket("10"), Some(1.0));
    assert_eq!(bucket("+Inf"), Some(1.0));
    let sum = value(
        &body,
        "podgate_router_request_duration_seconds_sum{app=\"a.test\",router=\"default\"}",
    )
    .expect("sum");
    assert!((0.3..2.0).contains(&sum), "sum {sum}");
}

#[tokio::test]
async fn metrics_status_class_labels() {
    let podgate = Podgate::start().await;
    let backend = upstream().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", backend)])],
        ))
        .await;
    assert_eq!(pushed.status, 200);
    for status in [200, 204, 404, 404, 404, 502] {
        let response = podgate.get("a.test", &format!("/status/{status}")).await;
        assert_eq!(response.status, status);
    }

    let body = scrape(&podgate).await;
    let class = |class: &str| {
        value(
            &body,
            &format!(
                "podgate_router_requests_total{{app=\"a.test\",router=\"default\",code_class=\"{class}\"}}"
            ),
        )
    };
    assert_eq!(class("2xx"), Some(2.0), "{body}");
    assert_eq!(class("4xx"), Some(3.0));
    assert_eq!(class("5xx"), Some(1.0));
    assert_eq!(class("3xx"), None, "a class never seen has no sample");
    assert!(
        !body.contains("code=\""),
        "the exact status is never a label: {body}"
    );
    assert!(
        !body.contains("method=\""),
        "the method is never a label: {body}"
    );
}

#[tokio::test]
async fn metrics_entry_point_series() {
    let podgate =
        Podgate::start_with_entry_points(&[("public", "http"), ("internal", "http")], &[]).await;
    let backend = upstream().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", backend)])],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    for _ in 0..2 {
        assert_eq!(podgate.get_on("public", "a.test", "/").await.status, 200);
    }
    assert_eq!(podgate.get_on("internal", "a.test", "/").await.status, 200);
    assert_eq!(
        podgate.get_on("internal", "nobody.test", "/").await.status,
        404
    );

    let body = scrape(&podgate).await;
    let counted = |series: &str| value(&body, series);
    assert_eq!(
        counted("podgate_entry_point_requests_total{entry_point=\"public\",code_class=\"2xx\"}"),
        Some(2.0),
        "{body}"
    );
    assert_eq!(
        counted("podgate_entry_point_requests_total{entry_point=\"internal\",code_class=\"2xx\"}"),
        Some(1.0)
    );
    assert_eq!(
        counted("podgate_entry_point_requests_total{entry_point=\"internal\",code_class=\"4xx\"}"),
        Some(1.0),
        "an unrouted request counts on its entry point"
    );
    assert_eq!(
        counted("podgate_entry_point_request_duration_seconds_count{entry_point=\"public\"}"),
        Some(2.0)
    );
    assert_eq!(
        counted(
            "podgate_router_requests_total{app=\"a.test\",router=\"default\",code_class=\"2xx\"}"
        ),
        Some(3.0),
        "the router series does not carry the entry point, only the entry point's own does"
    );
}

#[tokio::test]
async fn metrics_open_connections() {
    let podgate = Podgate::start().await;
    let backend = upstream().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", backend)])],
        ))
        .await;
    assert_eq!(pushed.status, 200);
    let open = "podgate_entry_point_open_connections{entry_point=\"web\"}";
    assert_eq!(value(&scrape(&podgate).await, open), Some(0.0));

    let watch = async {
        for _ in 0..200 {
            if value(&scrape(&podgate).await, open) == Some(1.0) {
                return true;
            }
            sleep(Duration::from_millis(10)).await;
        }
        false
    };
    let (response, saw_it) = tokio::join!(podgate.get("a.test", "/slow"), watch);
    assert_eq!(response.status, 200);
    assert!(saw_it, "the slow request was never seen open");
    assert_eq!(
        value(&scrape(&podgate).await, open),
        Some(0.0),
        "and is not open once it finished"
    );
}

#[tokio::test]
async fn metrics_addr_serves_only_metrics() {
    let addr = free_addr();
    let podgate = Podgate::start_with_env(&[("METRICS_ADDR", &addr.to_string())]).await;
    reachable(addr).await;

    let reply = raw(addr, &request("GET", "/metrics")).await.expect("reply");
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.content_type,
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(
        reply
            .body
            .contains("# TYPE podgate_entry_point_requests_total counter\n")
    );

    for path in [
        "/",
        "/healthz",
        "/readyz",
        "/v1/snapshot",
        "/v1/events",
        "/metrics/x",
    ] {
        let reply = raw(addr, &request("GET", path)).await.expect("reply");
        assert_eq!(reply.status, 404, "GET {path}");
    }
    for method in ["PUT", "POST", "DELETE"] {
        let reply = raw(addr, &request(method, "/v1/snapshot"))
            .await
            .expect("reply");
        assert_eq!(reply.status, 404, "{method} /v1/snapshot");
        let reply = raw(addr, &request(method, "/metrics"))
            .await
            .expect("reply");
        assert_eq!(reply.status, 405, "{method} /metrics");
    }
    // Nothing a request to the listener did reached the table.
    let health = podgate.admin_get("/readyz").await;
    assert_eq!(health.status, 200);
    let admin = scrape(&podgate).await;
    assert!(admin.contains("podgate_snapshot_version 0\n"), "{admin}");
}

#[tokio::test]
async fn existing_series_unchanged() {
    let addr = free_addr();
    let podgate = Podgate::start_with_env(&[("METRICS_ADDR", &addr.to_string())]).await;
    reachable(addr).await;
    let backend = upstream().await;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[app("a.test", &["a.test"], &[serving("r1", backend)])],
        ))
        .await;
    assert_eq!(pushed.status, 200);
    assert_eq!(podgate.get("a.test", "/").await.status, 200);

    let admin = scrape(&podgate).await;
    for line in [
        "# TYPE podgate_tenant_buffer_bytes gauge",
        "# TYPE podgate_tenant_buffer_bytes_peak gauge",
        "# TYPE podgate_tenant_inflight gauge",
        "# TYPE podgate_tenant_inflight_rejected_total counter",
        "# TYPE podgate_tenant_compression_skipped_total counter",
        "# TYPE podgate_backend_limit gauge",
        "# TYPE podgate_backend_inflight gauge",
        "# TYPE podgate_backend_queued gauge",
        "# TYPE podgate_backend_waited_total counter",
        "# TYPE podgate_backend_refused_total counter",
        "# TYPE podgate_upstream_refused_total counter",
        "podgate_tenant_inflight{tenant=\"t1\"} 0",
        "podgate_tenant_buffer_bytes{tenant=\"t1\"} 0",
    ] {
        assert!(
            admin.lines().any(|found| found == line),
            "missing {line:?} in {admin}"
        );
    }
    assert_eq!(
        value(
            &admin,
            &format!("podgate_backend_limit{{backend=\"{backend}\"}}")
        ),
        Some(32.0)
    );
    let old_end = admin
        .find("# HELP podgate_upstream_refused_total")
        .expect("the policy series");
    let new_start = admin
        .find("# HELP podgate_entry_point_requests_total")
        .expect("the entry point series");
    assert!(
        old_end < new_start,
        "the existing series come first: {admin}"
    );

    let tcp = raw(addr, &request("GET", "/metrics")).await.expect("reply");
    assert_eq!(tcp.body, admin, "both endpoints render the same text");
}

// In process from here: a table with a registry whose cap and retention the test sets.

fn handle(registry: Registry) -> TableHandle {
    TableHandle::new().with_metrics(registry)
}

fn cap(cap: u32) -> Registry {
    Registry::new(std::num::NonZeroU32::new(cap).expect("a cap"))
}

/// An app of `tenant` with one router per name in `routers` (host `<name>.<id>.test`), all of
/// them answered by service `web` with `servers` in its one revision.
fn app_of(id: &str, tenant: &str, routers: &[&str], servers: &[&str]) -> Value {
    let servers: Vec<Value> = servers.iter().map(|url| json!({ "url": url })).collect();
    json!({
        "id": id, "tenant": tenant, "declared_by": "test", "tls": { "mode": "acme" },
        "routers": routers.iter().map(|name| router(
            name, json!({ "host": format!("{name}.{id}.test") }), "web")).collect::<Vec<_>>(),
        "revisions": [{ "id": "r1", "weight": 100, "state": "serving", "services": [
            { "name": "web", "type": "loadbalancer", "servers": servers }] }],
    })
}

fn snapshot_of(version: u64, apps: &[Value]) -> Snapshot {
    let budget = json!({ "max_inflight": 100, "max_buffer_bytes": 1_048_576 });
    serde_json::from_value(json!({
        "version": version,
        "tenants": [
            { "id": "t1", "weight": 1, "budget": budget },
            { "id": "t2", "weight": 1, "budget": budget },
        ],
        "apps": apps,
    }))
    .expect("snapshot")
}

fn render(table: &TableHandle) -> String {
    metrics::render(
        table,
        &Budgets::new(),
        &Backends::new(),
        &UpstreamPolicy::builtin(),
        &AccessLog::new(),
    )
}

/// Finishes one request that matched router `router` of app `app` and was answered `status`.
fn hit(table: &TableHandle, entry: &Arc<EntrySeries>, app: usize, router: usize, status: u16) {
    InFlight::begin(entry).finish(&table.load(), Some(Matched { app, router }), true, status);
}

const SERVER: &str = "http://10.0.0.1:80";

#[test]
fn metrics_series_cap_collapses_to_other() {
    let table = handle(cap(3));
    let entry = table.metrics().entry_point("web");
    // Tenant t1: five routers and one service is six series against a cap of three. Tenant t2
    // has one of each and is not affected.
    let apps = [
        app_of("a", "t1", &["r0", "r1", "r2", "r3", "r4"], &[SERVER]),
        app_of("b", "t2", &["only"], &[SERVER]),
    ];
    table.apply(&snapshot_of(1, &apps)).expect("applies");
    for router in 0..5 {
        hit(&table, &entry, 0, router, 200);
    }
    hit(&table, &entry, 0, 3, 500);
    hit(&table, &entry, 1, 0, 200);

    let body = render(&table);
    let counted = |series: &str| value(&body, series);
    for own in ["r0", "r1", "r2"] {
        assert_eq!(
            counted(&format!(
                "podgate_router_requests_total{{app=\"a\",router=\"{own}\",code_class=\"2xx\"}}"
            )),
            Some(1.0),
            "{body}"
        );
    }
    assert_eq!(
        counted("podgate_router_requests_total{app=\"a\",router=\"other\",code_class=\"2xx\"}"),
        Some(2.0),
        "r3 and r4 share the app's other series: {body}"
    );
    assert_eq!(
        counted("podgate_router_requests_total{app=\"a\",router=\"other\",code_class=\"5xx\"}"),
        Some(1.0)
    );
    assert!(!body.contains("router=\"r3\"") && !body.contains("router=\"r4\""));
    assert_eq!(
        counted("podgate_service_requests_total{app=\"a\",service=\"other\",code_class=\"2xx\"}"),
        Some(5.0),
        "the service did not fit either"
    );
    assert_eq!(
        counted("podgate_router_requests_total{app=\"b\",router=\"only\",code_class=\"2xx\"}"),
        Some(1.0),
        "another tenant keeps its own"
    );
    assert_eq!(
        counted("podgate_metrics_collapsed_total{tenant=\"t1\"}"),
        Some(4.0),
        "r3, r4, the service and the server that no longer fit"
    );
    assert_eq!(
        counted("podgate_metrics_collapsed_total{tenant=\"t2\"}"),
        None
    );
    let up = |app: &str| {
        counted(&format!(
            "podgate_service_server_up{{app=\"{app}\",revision=\"r1\",service=\"web\",server=\"{SERVER}\"}}"
        ))
    };
    assert_eq!(
        up("a"),
        None,
        "the over-cap tenant's server is not reported: {body}"
    );
    assert_eq!(up("b"), Some(1.0));

    // A push that changes nothing for t1 does not count the same objects again.
    table.apply(&snapshot_of(2, &apps)).expect("applies");
    assert_eq!(
        value(
            &render(&table),
            "podgate_metrics_collapsed_total{tenant=\"t1\"}"
        ),
        Some(4.0)
    );
}

#[test]
fn metrics_names_cannot_grow_the_registry_by_churn() {
    let table = handle(cap(4).with_retention(Duration::from_secs(3600)));
    let entry = table.metrics().entry_point("web");
    // Each push declares four new router names; the old ones are retained but must make room.
    for version in 1..=6 {
        let names: Vec<String> = (0..4).map(|n| format!("v{version}n{n}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        table
            .apply(&snapshot_of(version, &[app_of("a", "t1", &names, &[])]))
            .expect("applies");
        for router in 0..4 {
            hit(&table, &entry, 0, router, 200);
        }
    }
    let body = render(&table);
    let routers = body
        .lines()
        .filter(|line| line.starts_with("podgate_router_requests_total{"))
        .count();
    assert!(
        routers <= 4 + 1,
        "four series plus other, not one set per push: {routers} lines in {body}"
    );
}

#[test]
fn metrics_survive_unrelated_push() {
    let table = handle(Registry::default());
    let entry = table.metrics().entry_point("web");
    let before = [
        app_of("a", "t1", &["x"], &[SERVER]),
        app_of("b", "t1", &["y"], &[SERVER]),
    ];
    table.apply(&snapshot_of(1, &before)).expect("applies");
    for _ in 0..3 {
        hit(&table, &entry, 0, 0, 200);
    }
    hit(&table, &entry, 1, 0, 200);

    // App b gets a second router and a new server; app a is untouched.
    let after = [
        app_of("a", "t1", &["x"], &[SERVER]),
        app_of("b", "t1", &["y", "z"], &[SERVER, "http://10.0.0.2:80"]),
    ];
    table.apply(&snapshot_of(2, &after)).expect("applies");
    hit(&table, &entry, 0, 0, 200);
    hit(&table, &entry, 1, 0, 200);

    let body = render(&table);
    let counted = |series: &str| value(&body, series);
    assert_eq!(
        counted("podgate_router_requests_total{app=\"a\",router=\"x\",code_class=\"2xx\"}"),
        Some(4.0),
        "{body}"
    );
    assert_eq!(
        counted("podgate_router_requests_total{app=\"b\",router=\"y\",code_class=\"2xx\"}"),
        Some(2.0),
        "an app that grew keeps the counters of what it already had"
    );
    assert_eq!(
        counted("podgate_service_requests_total{app=\"a\",service=\"web\",code_class=\"2xx\"}"),
        Some(4.0)
    );

    // A router whose match changed is another route and starts again.
    let mut moved = after.clone();
    moved[0]["routers"][0]["match"] = json!({ "host": "elsewhere.test" });
    table.apply(&snapshot_of(3, &moved)).expect("applies");
    hit(&table, &entry, 0, 0, 200);
    assert_eq!(
        value(
            &render(&table),
            "podgate_router_requests_total{app=\"a\",router=\"x\",code_class=\"2xx\"}"
        ),
        Some(1.0)
    );
}

#[test]
fn metrics_removed_objects_expire() {
    let table = handle(Registry::default().with_retention(Duration::from_millis(300)));
    let entry = table.metrics().entry_point("web");
    let apps = [
        app_of("a", "t1", &["x"], &[SERVER]),
        app_of("b", "t1", &["y"], &[SERVER]),
    ];
    table.apply(&snapshot_of(1, &apps)).expect("applies");
    hit(&table, &entry, 0, 0, 200);
    hit(&table, &entry, 1, 0, 200);

    // App b leaves the snapshot.
    table.apply(&snapshot_of(2, &apps[..1])).expect("applies");
    let body = render(&table);
    let series = "podgate_router_requests_total{app=\"b\",router=\"y\",code_class=\"2xx\"}";
    assert_eq!(value(&body, series), Some(1.0), "still reported: {body}");

    std::thread::sleep(Duration::from_millis(500));
    let body = render(&table);
    assert_eq!(
        value(&body, series),
        None,
        "gone after the retention: {body}"
    );
    assert_eq!(
        value(
            &body,
            "podgate_router_requests_total{app=\"a\",router=\"x\",code_class=\"2xx\"}"
        ),
        Some(1.0),
        "what is still declared stays"
    );
}

#[test]
fn metrics_server_up() {
    let table = handle(Registry::default());
    let second = "http://10.0.0.2:80";
    table
        .apply(&snapshot_of(
            1,
            &[app_of("a", "t1", &["x"], &[SERVER, second])],
        ))
        .expect("applies");
    let up = |server: &str| {
        format!(
            "podgate_service_server_up{{app=\"a\",revision=\"r1\",service=\"web\",server=\"{server}\"}}"
        )
    };
    let body = render(&table);
    assert_eq!(value(&body, &up(SERVER)), Some(1.0), "{body}");
    assert_eq!(value(&body, &up(second)), Some(1.0));

    let live = table.load();
    let servers = live
        .app(0)
        .and_then(|app| app.service(0, 0))
        .expect("service")
        .servers();
    let state = &servers[1].state;
    state.healthy.store(false, Ordering::Relaxed);
    let body = render(&table);
    assert_eq!(value(&body, &up(SERVER)), Some(1.0));
    assert_eq!(
        value(&body, &up(second)),
        Some(0.0),
        "a failed check is down"
    );

    state.healthy.store(true, Ordering::Relaxed);
    state.ejected_until_ms.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        value(&render(&table), &up(second)),
        Some(0.0),
        "so is an ejection"
    );

    state.ejected_until_ms.store(0, Ordering::Relaxed);
    assert_eq!(value(&render(&table), &up(second)), Some(1.0));
}

#[test]
fn metrics_cert_not_after() {
    let cert = TestCert::new(&["a.test", "*.b.test"]);
    let snapshot: Snapshot = serde_json::from_value(json!({
        "version": 1,
        "tenants": [{ "id": "t1", "weight": 1,
            "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } }],
        "apps": [],
        "certificates": [cert.entry(&["a.test", "*.b.test"])],
    }))
    .expect("snapshot");
    let table = handle(Registry::default());
    table.apply(&snapshot).expect("applies");

    let body = render(&table);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    for host in ["a.test", "*.b.test"] {
        let not_after = value(
            &body,
            &format!("podgate_tls_cert_not_after_seconds{{host=\"{host}\"}}"),
        )
        .unwrap_or_else(|| panic!("no expiry for {host} in {body}"));
        // `rcgen`'s default certificate is valid for decades; what matters is that it is a Unix
        // time in the future and not a duration.
        assert!(not_after > now as f64, "{host}: {not_after}");
    }
}

#[test]
fn metrics_snapshot_gauges() {
    let table = handle(Registry::default());
    let body = render(&table);
    assert_eq!(value(&body, "podgate_snapshot_version"), Some(0.0));
    assert_eq!(
        value(&body, "podgate_snapshot_applied_timestamp_seconds"),
        Some(0.0)
    );

    table
        .apply(&snapshot_of(7, &[app_of("a", "t1", &["x"], &[SERVER])]))
        .expect("applies");
    let body = render(&table);
    assert_eq!(
        value(&body, "podgate_snapshot_version"),
        Some(7.0),
        "{body}"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as f64;
    let applied = value(&body, "podgate_snapshot_applied_timestamp_seconds").expect("timestamp");
    assert!(
        (now - 60.0..=now + 1.0).contains(&applied),
        "{applied} vs {now}"
    );

    // A stale version, and two apps that claim one host, are refused and counted by code.
    assert!(table.apply(&snapshot_of(7, &[])).is_err());
    let mut clash = [
        app_of("a", "t1", &["x"], &[SERVER]),
        app_of("c", "t1", &["x"], &[SERVER]),
    ];
    clash[1]["routers"][0]["match"] = clash[0]["routers"][0]["match"].clone();
    assert!(table.apply(&snapshot_of(8, &clash)).is_err());

    let body = render(&table);
    assert_eq!(
        value(&body, "podgate_snapshot_version"),
        Some(7.0),
        "{body}"
    );
    assert_eq!(
        value(&body, "podgate_snapshot_rejected_total{code=\"stale\"}"),
        Some(1.0)
    );
    assert_eq!(
        value(
            &body,
            "podgate_snapshot_rejected_total{code=\"host_conflict\"}"
        ),
        Some(1.0),
        "{body}"
    );
}

#[test]
fn metrics_revision_services_share_one_series() {
    // A deploy replaces the service of a revision; the series of the service name carries on.
    let table = handle(Registry::default());
    let entry = table.metrics().entry_point("web");
    let mut first = app_of("a", "t1", &["x"], &[SERVER]);
    table
        .apply(&snapshot_of(1, std::slice::from_ref(&first)))
        .expect("applies");
    hit(&table, &entry, 0, 0, 200);
    first["revisions"] = json!([
        { "id": "r2", "weight": 100, "state": "serving", "services": [
            { "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://10.0.0.9:80" }] }] }
    ]);
    table
        .apply(&snapshot_of(2, std::slice::from_ref(&first)))
        .expect("applies");
    hit(&table, &entry, 0, 0, 200);
    assert_eq!(
        value(
            &render(&table),
            "podgate_service_requests_total{app=\"a\",service=\"web\",code_class=\"2xx\"}"
        ),
        Some(2.0)
    );
}
