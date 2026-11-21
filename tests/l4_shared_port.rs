//! TLS passthrough beside HTTP routers on one port: refused at compile with
//! `unsupported_setting`, because the front it would need costs 40 to 46 percent more CPU per
//! request. TLS routers live on `tcp` entry points.

mod common;

use common::{Podgate, snapshot};
use serde_json::{Value, json};

const ENTRY_POINTS: [(&str, &str); 3] = [("web", "http"), ("secure", "https"), ("edge", "tcp")];

/// An app of tenant `t1` with one TCP router on `entry` whose `tls` is `tls`.
fn tcp_app(entry: &str, tls: &Value) -> Value {
    json!({
        "id": "p", "tenant": "t1", "declared_by": "tests/p",
        "tls": { "mode": "acme" }, "routers": [], "revisions": [],
        "tcp": {
            "routers": [{ "name": "pass", "entry_points": [entry], "service": "svc",
                         "match": { "sni": "p.test" }, "tls": tls }],
            "services": [{ "name": "svc", "type": "loadbalancer",
                           "servers": [{ "address": "127.0.0.1:9" }] }],
        },
    })
}

#[tokio::test]
async fn shared_port_passthrough_refused() {
    let podgate = Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await;
    for entry in ["secure", "web"] {
        for tls in [json!({ "passthrough": true }), json!({})] {
            let refused = podgate
                .push_snapshot(&snapshot(1, &[tcp_app(entry, &tls)]))
                .await;
            assert_eq!(refused.status, 422, "{entry} {tls}: {refused:?}");
            let conflicts = refused.json()["conflicts"].clone();
            assert_eq!(
                conflicts[0]["code"], "unsupported_setting",
                "{entry} {tls}: {conflicts}"
            );
            let message = conflicts[0]["message"].as_str().unwrap_or_default();
            assert!(
                message.contains("own `tcp` entry point") && message.contains(entry),
                "{message}"
            );
        }
    }
    // The same router on a `tcp` entry point is what change 0059 builds.
    let accepted = podgate
        .push_snapshot(&snapshot(
            1,
            &[tcp_app("edge", &json!({ "passthrough": true }))],
        ))
        .await;
    assert_eq!(accepted.status, 200, "{accepted:?}");
}
