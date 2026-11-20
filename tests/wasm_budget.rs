//! End to end: WASM filter runs are charged to the tenant's buffer budget and run on their own
//! bounded pool, on the real binary.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{Podgate, Upstream, serving};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

/// A filter that runs `body` (the text of `proxy_on_request_headers`) in one page of memory.
fn filter(body: &str, fuel: u64, max_memory_bytes: u64) -> Value {
    let wat = format!(
        r#"(module
  (memory (export "memory") 1)
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32) (i32.const 1024))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    {body}))"#
    );
    let wasm = wat::parse_str(wat).expect("valid WAT");
    json!({ "wasm_base64": STANDARD.encode(wasm), "fuel": fuel, "max_memory_bytes": max_memory_bytes })
}

const NOTHING: &str = "(i32.const 0)";
const FOREVER: &str = "(loop $again (br $again)) (i32.const 0)";

fn app(id: &str, tenant: &str, host: &str, upstream: SocketAddr, filters: &[Value]) -> Value {
    json!({
        "id": id,
        "tenant": tenant,
        "declared_by": format!("tests/{id}"),
        "hosts": [host],
        "tls": { "mode": "acme" },
        "revisions": [serving("r1", upstream)],
        "filters": filters,
    })
}

/// Tenants `t1` and `t2`, each with 1 MiB of buffer budget.
fn snapshot(version: u64, apps: &[Value]) -> Value {
    let tenant = |id: &str| json!({ "id": id, "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } });
    json!({ "version": version, "tenants": [tenant("t1"), tenant("t2")], "apps": apps })
}

/// Value of the series `name{tenant="t1"}` in a Prometheus text body.
fn series(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

#[tokio::test]
async fn wasm_memory_charged() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("ok").await;
    let twelve_pages = 12 * 65_536;
    let pushed = podgate
        .push_snapshot(&snapshot(
            1,
            &[
                // One filter's memory limit above the tenant's whole 1 MiB budget.
                app(
                    "big",
                    "t1",
                    "big.test",
                    upstream.addr,
                    &[filter(NOTHING, 1_000, 2 * 1_048_576)],
                ),
                app(
                    "small",
                    "t1",
                    "small.test",
                    upstream.addr,
                    &[filter(NOTHING, 1_000, twelve_pages)],
                ),
            ],
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let refused = podgate.get("big.test", "/").await;
    assert_eq!(refused.status, 503, "{}", refused.body);
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        refused.json(),
        json!({"error": "wasm filters are over capacity"})
    );

    let served = podgate.get("small.test", "/").await;
    assert_eq!((served.status, served.body.as_str()), (200, "ok"));

    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(series(&metrics, "podgate_tenant_wasm_refused_total"), 1);
    assert_eq!(
        series(&metrics, "podgate_tenant_buffer_bytes_peak"),
        twelve_pages,
        "only the run that fit was charged, at the filter's limit: {metrics}"
    );
    assert_eq!(
        series(&metrics, "podgate_tenant_buffer_bytes"),
        0,
        "the charge ends with the run: {metrics}"
    );
}

#[tokio::test]
async fn wasm_pool_bounded() {
    let podgate = Podgate::start_with_env(&[
        ("WASM_MAX_CONCURRENT", "1"),
        ("WASM_QUEUE_TIMEOUT_MS", "200"),
    ])
    .await;
    let upstream = Upstream::start("ok").await;
    // Fuel far beyond what the test lasts: the run holds the only worker until podgate is killed.
    let hog = filter(FOREVER, 1_000_000_000_000, 65_536);
    let apps = |extra: &[Value]| -> Vec<Value> {
        let mut apps = vec![
            app(
                "hog",
                "t1",
                "hog.test",
                upstream.addr,
                std::slice::from_ref(&hog),
            ),
            app("plain", "t2", "plain.test", upstream.addr, &[]),
        ];
        apps.extend_from_slice(extra);
        apps
    };
    let pushed = podgate.push_snapshot(&snapshot(1, &apps(&[]))).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let mut held = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy");
    held.write_all(b"GET / HTTP/1.1\r\nHost: hog.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("send the request that takes the worker");
    sleep(Duration::from_millis(500)).await;

    let started = Instant::now();
    let queued = podgate.get("hog.test", "/").await;
    assert_eq!(queued.status, 503, "{}", queued.body);
    assert_eq!(queued.header("retry-after"), Some("1"));
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "the request queued for a worker first"
    );

    let other = timeout(Duration::from_secs(3), podgate.get("plain.test", "/"))
        .await
        .expect("another tenant's request is not stuck behind the filter");
    assert_eq!((other.status, other.body.as_str()), (200, "ok"));

    let extra = app("extra", "t2", "extra.test", upstream.addr, &[]);
    let pushed = timeout(
        Duration::from_secs(3),
        podgate.push_snapshot(&snapshot(2, &apps(&[extra]))),
    )
    .await
    .expect("a snapshot push is not stuck behind the filter");
    assert_eq!(pushed.status, 200, "{}", pushed.body);

    let metrics = podgate.admin_get("/metrics").await.body;
    assert_eq!(
        series(&metrics, "podgate_tenant_buffer_bytes"),
        65_536,
        "the run holding the worker is charged, the queued one was not: {metrics}"
    );
    drop(held);
}
