//! End to end: `POST /v1/snapshot/plan` lists what a snapshot would change and applies nothing.

mod common;

use common::{Podgate, TestCa, Upstream, app, serving, snapshot};
use serde_json::{Value, json};

/// `app` with the fields of `extra` set. A `filters` list becomes `wasm` middlewares.
fn with(mut app: Value, extra: &Value) -> Value {
    let Some(extra) = extra.as_object() else {
        return app;
    };
    let mut extra = extra.clone();
    let filters = extra.remove("filters");
    if let Some(base) = app.as_object_mut() {
        base.extend(extra);
    }
    match filters {
        Some(Value::Array(filters)) => common::with_filters(app, &filters),
        _ => app,
    }
}

#[tokio::test]
async fn plan_diff() {
    let podgate = Podgate::start().await;
    let one = Upstream::start("one").await;
    let two = Upstream::start("two").await;
    let live = snapshot(
        1,
        &[
            app("a", &["a.test"], &[serving("r1", one.addr)]),
            app("b", &["b.test"], &[serving("r1", one.addr)]),
            app("keep", &["keep.test"], &[serving("r1", one.addr)]),
        ],
    );
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let candidate = snapshot(
        2,
        &[
            app("a", &["a.test"], &[serving("r1", two.addr)]),
            app("c", &["c.test", "*.c.test"], &[serving("r1", two.addr)]),
            app("keep", &["keep.test"], &[serving("r1", one.addr)]),
        ],
    );
    let response = podgate.admin_post("/v1/snapshot/plan", &candidate).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.json(),
        json!({
            "from_version": 1,
            "to_version": 2,
            "added": ["*.c.test", "c.test"],
            "removed": ["b.test"],
            "changed": ["a.test"],
            "posture_changes": [],
        })
    );

    // Nothing was applied: the old routes serve, the new host does not, version 2 is still free.
    assert_eq!(podgate.get("a.test", "/").await.body, "one");
    assert_eq!(podgate.get("b.test", "/").await.body, "one");
    assert_eq!(podgate.get("c.test", "/").await.status, 404);
    assert_eq!(podgate.push_snapshot(&candidate).await.status, 200);
    assert_eq!(podgate.get("a.test", "/").await.body, "two");
}

#[tokio::test]
async fn plan_refuses_what_put_refuses() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let live = snapshot(5, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let stale = snapshot(5, &[app("a", &["a.test"], &[serving("r1", up.addr)])]);
    assert_eq!(
        podgate.admin_post("/v1/snapshot/plan", &stale).await.status,
        409
    );

    let clash = snapshot(
        6,
        &[
            app("a", &["x.test"], &[serving("r1", up.addr)]),
            app("b", &["x.test"], &[serving("r1", up.addr)]),
        ],
    );
    let response = podgate.admin_post("/v1/snapshot/plan", &clash).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(response.json()["conflicts"][0]["code"], "host_conflict");

    assert_eq!(podgate.get("a.test", "/").await.body, "up");
}

#[tokio::test]
async fn plan_posture_changes() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let ca = |pem: &str| json!({ "tls": { "mode": "acme", "client_ca_pem": pem } });
    let (ca1, ca2) = (TestCa::new("ca1").pem, TestCa::new("ca2").pem);
    let rev = [serving("r1", up.addr)];
    let live = snapshot(
        1,
        &[
            with(app("drop", &["drop.test"], &rev), &ca(&ca1)),
            with(app("swap", &["swap.test"], &rev), &ca(&ca1)),
            app("front", &["front.test"], &rev),
            app("lazy", &["lazy.test"], &rev),
            with(
                app("tight", &["tight.test"], &rev),
                &json!({ "allow_domain_fronting": true }),
            ),
        ],
    );
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let candidate = snapshot(
        2,
        &[
            app("drop", &["drop.test"], &rev),
            with(app("swap", &["swap.test"], &rev), &ca(&ca2)),
            with(
                app("front", &["front.test"], &rev),
                &json!({ "allow_domain_fronting": true }),
            ),
            with(
                app("lazy", &["lazy.test"], &rev),
                &json!({ "tls": { "mode": "on_demand" } }),
            ),
            with(app("tight", &["tight.test"], &rev), &ca(&ca1)),
            with(
                app("fresh", &["fresh.test"], &rev),
                &json!({ "allow_domain_fronting": true }),
            ),
        ],
    );
    let response = podgate.admin_post("/v1/snapshot/plan", &candidate).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let plan = response.json();
    assert_eq!(
        plan["posture_changes"],
        json!([
            { "host": "drop.test", "app": "drop", "kind": "client_ca_removed" },
            { "host": "front.test", "app": "front", "kind": "domain_fronting_enabled" },
            { "host": "lazy.test", "app": "lazy", "kind": "on_demand_tls_enabled" },
            { "host": "swap.test", "app": "swap", "kind": "client_ca_changed" },
        ])
    );
    assert_eq!(plan["added"], json!(["fresh.test"]));
}

/// A WASM filter that does nothing; `fuel` tells two of them apart.
fn filter(fuel: u64) -> Value {
    use base64::Engine as _;
    let wasm = wat::parse_str(
        r#"(module
  (memory (export "memory") 1)
  (global $heap (mut i32) (i32.const 1024))
  (func (export "proxy_abi_version_0_2_1"))
  (func (export "proxy_on_memory_allocate") (param i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $heap))
    (global.set $heap (i32.add (global.get $heap) (local.get 0)))
    (local.get $p))
  (func (export "proxy_on_request_headers") (param i32 i32 i32) (result i32)
    (i32.const 0)))"#,
    )
    .expect("valid WAT");
    json!({
        "wasm_base64": base64::engine::general_purpose::STANDARD.encode(wasm),
        "fuel": fuel,
        "max_memory_bytes": 1_048_576,
    })
}

#[tokio::test]
async fn plan_filter_posture() {
    let podgate = Podgate::start().await;
    let up = Upstream::start("up").await;
    let rev = [serving("r1", up.addr)];
    let live = snapshot(
        1,
        &[
            with(
                app("gone", &["gone.test"], &rev),
                &json!({ "filters": [filter(1000)] }),
            ),
            with(
                app("tuned", &["tuned.test"], &rev),
                &json!({ "filters": [filter(1000)] }),
            ),
            with(
                app("same", &["same.test"], &rev),
                &json!({ "filters": [filter(1000)] }),
            ),
            app("bare", &["bare.test"], &rev),
        ],
    );
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let candidate = snapshot(
        2,
        &[
            app("gone", &["gone.test"], &rev),
            with(
                app("tuned", &["tuned.test"], &rev),
                &json!({ "filters": [filter(9)] }),
            ),
            with(
                app("same", &["same.test"], &rev),
                &json!({ "filters": [filter(1000)] }),
            ),
            with(
                app("bare", &["bare.test"], &rev),
                &json!({ "filters": [filter(1000)] }),
            ),
        ],
    );
    let response = podgate.admin_post("/v1/snapshot/plan", &candidate).await;
    assert_eq!(response.status, 200, "{}", response.body);
    let plan = response.json();
    assert_eq!(
        plan["posture_changes"],
        json!([
            { "host": "gone.test", "app": "gone", "kind": "filters_removed" },
            { "host": "tuned.test", "app": "tuned", "kind": "filters_changed" },
        ])
    );
    assert_eq!(
        plan["changed"],
        json!(["bare.test", "gone.test", "tuned.test"])
    );
}
