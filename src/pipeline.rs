//! The request-path stages, as `GET /v1/explain` reports them.
//!
//! `Gateway::request_filter` runs the platform stages in a fixed order; the stages of the
//! middleware chain run in the `chain` slot. [`describe`] lists them in that order, so it must
//! match the code. A feature that adds a platform stage to `request_filter` adds one line here,
//! in the same position as its call; a middleware kind adds nothing (the chain lists itself).
//!
//! Order, with the reason each stage sits where it does:
//!
//! 1. `acme_http01`: answers a validation request before any route exists.
//! 2. `entry_point`: normalizes the path (the path that is matched is the path that is served),
//!    so a request with an unsafe path is refused first, then settles who the client is: the
//!    forwarding headers of a peer the entry point does not trust are removed ([`crate::client_ip`]).
//! 3. `route`: picks the router. No match is `404`.
//! 4. `sni_check`: over TLS, the matched app decides whether a request may name a host other
//!    than the SNI. It runs for requests no router matched too (they get `421`, not `404`).
//! 5. `failure_capture`: a request that reaches here and ends in a `5xx` may be recorded.
//! 6. `chain`: the router's middlewares, before any slot is taken or app woken, so
//!    unauthenticated or rate-limited traffic cannot hold a tenant slot, queue for a backend or
//!    wake a sleeping app.
//! 7. `select`: revision (skew cookie, canary, weights), service and server; `wake_hold` when a
//!    `scale_to_zero` app has none.
//! 8. `inflight_admit`, `tenant_admit`, `backend_admit`.

use serde_json::{Value, json};

use crate::router::CompiledRouter;
use crate::table::CompiledApp;

fn stage(name: &str) -> Value {
    json!({ "stage": name })
}

/// The stages a request that matched `router` of `app` goes through, in order; `tls` says it
/// arrived over a TLS connection. A stage that cannot act for this app is left out:
/// `sni_check` never refuses an app that sets `allow_domain_fronting`, `wake_hold` only exists
/// for a `scale_to_zero` app.
#[must_use]
pub fn describe(app: &CompiledApp, router: &CompiledRouter, tls: bool) -> Vec<Value> {
    let mut stages = Vec::new();
    if !tls {
        stages.push(stage("acme_http01"));
    }
    stages.push(stage("entry_point"));
    stages.push(stage("route"));
    if tls && !app.allow_domain_fronting() {
        stages.push(stage("sni_check"));
    }
    if app.client_auth().is_some() {
        stages.push(stage("client_cert"));
    }
    stages.push(stage("failure_capture"));
    for index in router.chain() {
        let Some(named) = app.stages().get(*index) else {
            continue;
        };
        let mut entry = json!({
            "stage": "chain", "middleware": named.name, "type": named.stage.kind(),
        });
        if let (Some(object), Value::Object(extra)) =
            (entry.as_object_mut(), named.stage.describe())
        {
            object.extend(extra);
        }
        stages.push(entry);
    }
    stages.push(stage("select"));
    if app.scale_to_zero().is_some() {
        stages.push(stage("wake_hold"));
    }
    stages.push(stage("inflight_admit"));
    stages.push(stage("tenant_admit"));
    stages.push(stage("backend_admit"));
    stages
}
