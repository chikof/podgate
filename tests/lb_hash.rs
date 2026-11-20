//! The hashing balancers of a `loadbalancer` service (`ip_hash`, `uri_hash`, `header_hash`,
//! `hrw`) through the real proxy: a key keeps its server across requests and across an unrelated
//! push, the client address is the resolved one and never a forged header, and a request without
//! the key still gets a server. Where a key lands when servers come and go is pinned by the unit
//! tests next to the ring (`src/service/lb/ring.rs`).

mod common;

use std::collections::HashSet;

use common::{Podgate, Upstream, app, snapshot};
use serde_json::{Value, json};

const BODIES: [&str; 4] = ["a", "b", "c", "d"];

async fn backends() -> Vec<Upstream> {
    let mut started = Vec::new();
    for body in BODIES {
        started.push(Upstream::start(body).await);
    }
    started
}

/// A snapshot whose app `a` (`a.test`) balances four backends by `algorithm`, and an unrelated app
/// `b` declared by `bump`; with `trusted`, the `web` entry point trusts the local peer.
fn balanced(
    version: u64,
    algorithm: &Value,
    backends: &[Upstream],
    bump: &str,
    trusted: bool,
) -> Value {
    let servers: Vec<Value> = backends
        .iter()
        .map(|backend| json!({ "url": format!("http://{}", backend.addr) }))
        .collect();
    let revision = json!({ "id": "r1", "state": "serving", "weight": 100, "services": [
        { "name": "web", "type": "loadbalancer", "algorithm": algorithm, "servers": servers }] });
    let mut other = app("b", &["b.test"], &[]);
    other["declared_by"] = json!(bump);
    other["revisions"] = json!([{ "id": "r1", "state": "serving", "weight": 1, "services": [
        { "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:9" }] }] }]);
    let mut snapshot = snapshot(version, &[app("a", &["a.test"], &[revision]), other]);
    if trusted {
        snapshot["entry_points"] =
            json!([{"name": "web", "forwarded_headers": {"trusted_ips": ["127.0.0.0/8"]}}]);
    }
    snapshot
}

fn header_hash() -> Value {
    json!({ "type": "header_hash", "header": "x-tenant" })
}

async fn pushed(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

/// The backend that answers each of `paths`.
async fn by_path(podgate: &Podgate, paths: &[String]) -> Vec<String> {
    let mut bodies = Vec::new();
    for path in paths {
        let response = podgate.get("a.test", path).await;
        assert_eq!(response.status, 200, "{}", response.body);
        bodies.push(response.body);
    }
    bodies
}

fn paths() -> Vec<String> {
    (0..40).map(|n| format!("/assets/{n}.css")).collect()
}

#[tokio::test]
async fn hash_stable_across_requests() {
    let podgate = Podgate::start().await;
    let backends = backends().await;

    // The same path, and the same header value, always reach the same backend, and the keys
    // are spread over several of them.
    pushed(
        &podgate,
        &balanced(1, &json!("uri_hash"), &backends, "x", false),
    )
    .await;
    let first = by_path(&podgate, &paths()).await;
    assert_eq!(first, by_path(&podgate, &paths()).await);
    assert!(first.iter().collect::<HashSet<_>>().len() >= 3, "{first:?}");

    pushed(
        &podgate,
        &balanced(2, &header_hash(), &backends, "x", false),
    )
    .await;
    let mut seen = HashSet::new();
    for tenant in 0..30 {
        let value = format!("tenant-{tenant}");
        let mut answers = HashSet::new();
        for _ in 0..3 {
            let response = podgate
                .get_with_headers("a.test", "/", &[("X-Tenant", &value)])
                .await;
            answers.insert(response.body);
        }
        assert_eq!(answers.len(), 1, "{value}: {answers:?}");
        seen.extend(answers);
    }
    assert!(seen.len() >= 3, "{seen:?}");

    // The query is not part of the key unless asked for.
    pushed(
        &podgate,
        &balanced(3, &json!("uri_hash"), &backends, "x", false),
    )
    .await;
    let plain = by_path(&podgate, &paths()).await;
    let queried: Vec<String> = paths().iter().map(|path| format!("{path}?v=2")).collect();
    assert_eq!(plain, by_path(&podgate, &queried).await);
}

#[tokio::test]
async fn hash_stable_across_unrelated_push() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    let algorithm = json!("uri_hash");
    pushed(
        &podgate,
        &balanced(1, &algorithm, &backends, "before", false),
    )
    .await;
    let before = by_path(&podgate, &paths()).await;
    pushed(
        &podgate,
        &balanced(2, &algorithm, &backends, "after", false),
    )
    .await;
    assert_eq!(before, by_path(&podgate, &paths()).await);
}

#[tokio::test]
async fn ip_hash_ignores_untrusted_xff() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    pushed(
        &podgate,
        &balanced(1, &json!("ip_hash"), &backends, "x", false),
    )
    .await;
    // Every request comes from 127.0.0.1, which is not trusted: its forwarding headers are
    // dropped, so a different forged address on each request changes nothing.
    let mut answers = HashSet::new();
    for n in 0..40 {
        let forged = format!("198.51.100.{n}");
        let response = podgate
            .get_with_headers(
                "a.test",
                "/",
                &[("X-Forwarded-For", &forged), ("X-Real-IP", &forged)],
            )
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        answers.insert(response.body);
    }
    assert_eq!(answers.len(), 1, "{answers:?}");
}

#[tokio::test]
async fn ip_hash_follows_the_xff_of_a_trusted_peer() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    for (version, algorithm) in [(1, json!("ip_hash")), (2, json!("hrw"))] {
        pushed(
            &podgate,
            &balanced(version, &algorithm, &backends, "x", true),
        )
        .await;
        let mut answers = HashSet::new();
        for n in 0..40 {
            let client = format!("198.51.100.{n}");
            let first = podgate
                .get_with_headers("a.test", "/", &[("X-Forwarded-For", &client)])
                .await;
            let again = podgate
                .get_with_headers("a.test", "/", &[("X-Forwarded-For", &client)])
                .await;
            assert_eq!(first.body, again.body, "{algorithm} {client}");
            answers.insert(first.body);
        }
        assert!(answers.len() >= 3, "{algorithm}: {answers:?}");
    }
}

#[tokio::test]
async fn header_hash_missing_header_falls_back() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    pushed(
        &podgate,
        &balanced(1, &header_hash(), &backends, "x", false),
    )
    .await;
    let mut answers = HashSet::new();
    for _ in 0..40 {
        let response = podgate.get("a.test", "/").await;
        assert_eq!(response.status, 200, "{}", response.body);
        answers.insert(response.body);
    }
    assert!(
        answers.len() >= 3,
        "a request without the header goes to a random server: {answers:?}"
    );
}

#[tokio::test]
async fn hash_algorithm_options_strict_push() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    for (version, algorithm) in [
        (1, json!({ "type": "header_hash" })),
        (
            2,
            json!({ "type": "header_hash", "header": "x-tenant", "extra": "x" }),
        ),
        (3, json!({ "type": "ip_hash", "header": "x-tenant" })),
        (4, json!("header_hash")),
    ] {
        let response = podgate
            .push_snapshot(&balanced(version, &algorithm, &backends, "x", false))
            .await;
        assert_eq!(response.status, 422, "{algorithm}: {}", response.body);
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_service",
            "{algorithm}"
        );
    }
}

/// The `name=value` pair of the cookie `name` that `response` sets.
fn cookie_pair(response: &common::Response, name: &str) -> String {
    let header = response
        .headers
        .iter()
        .find(|(header, value)| header == "set-cookie" && value.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no {name} cookie in {:?}", response.headers));
    header.1.split(';').next().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn sticky_cookie_wins_over_the_hash_and_no_cookie_falls_to_it() {
    let podgate = Podgate::start().await;
    let backends = backends().await;
    let mut pushed_snapshot = balanced(1, &json!("uri_hash"), &backends, "x", false);
    pushed_snapshot["skew_secret"] = json!("a-secret-of-at-least-16-bytes");
    pushed_snapshot["apps"][0]["revisions"][0]["services"][0]["sticky"] = json!({ "cookie": {} });
    pushed(&podgate, &pushed_snapshot).await;

    // Two paths the hash sends to different backends.
    let paths = paths();
    let answers = by_path(&podgate, &paths).await;
    let (first, other) = answers
        .iter()
        .enumerate()
        .find(|(_, body)| **body != answers[0])
        .map(|(n, _)| (0, n))
        .expect("the hash spreads the paths");

    let pinned = podgate.get("a.test", &paths[first]).await;
    assert_eq!(pinned.body, answers[first]);
    let cookie = cookie_pair(&pinned, "__podgate_srv");

    // The cookie is applied before the algorithm: the other path still goes to the pinned server.
    let with_cookie = podgate
        .get_with_headers("a.test", &paths[other], &[("Cookie", &cookie)])
        .await;
    assert_eq!(with_cookie.body, answers[first]);
    // Without it the hash decides.
    let without = podgate.get("a.test", &paths[other]).await;
    assert_eq!(without.body, answers[other]);
}
