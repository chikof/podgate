//! End to end: `POST /v1/snapshot/plan` lists what a snapshot would change and applies nothing.

mod common;

use common::{Podgate, Upstream, app, serving, snapshot};
use serde_json::{Value, json};

fn with(mut app: Value, extra: &Value) -> Value {
    if let (Some(base), Some(extra)) = (app.as_object_mut(), extra.as_object()) {
        base.extend(extra.clone());
    }
    app
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
    let rev = [serving("r1", up.addr)];
    let live = snapshot(
        1,
        &[
            with(app("drop", &["drop.test"], &rev), &ca("CA1")),
            with(app("swap", &["swap.test"], &rev), &ca("CA1")),
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
            with(app("swap", &["swap.test"], &rev), &ca("CA2")),
            with(
                app("front", &["front.test"], &rev),
                &json!({ "allow_domain_fronting": true }),
            ),
            with(
                app("lazy", &["lazy.test"], &rev),
                &json!({ "tls": { "mode": "on_demand" } }),
            ),
            with(app("tight", &["tight.test"], &rev), &ca("CA1")),
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
