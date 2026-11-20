//! End to end: the admin API's tools for snapshot builders. `GET /v1/schema` describes a
//! snapshot, `POST /v1/snapshot/validate` compiles one without applying it, `GET
//! /v1/snapshot/version` says where a writer's sequence stands, and the `podgate-writer` header
//! keeps a second writer from replacing the snapshot of the first.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Podgate, Upstream, app, revision, serving, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UnixStream};
use tokio::time::{Instant, sleep, timeout};

/// An admin API answer.
struct Reply {
    status: u16,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|err| panic!("not JSON ({err}): {:?}", self.body))
    }
}

/// One request on the admin socket, with any headers.
async fn call(
    podgate: &Podgate,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut stream = UnixStream::connect(&podgate.admin_socket)
        .await
        .expect("connect to the admin socket");
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), async {
        stream.write_all(request.as_bytes()).await.expect("send");
        stream.read_to_end(&mut raw).await.expect("read");
    })
    .await
    .expect("an answer in time");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("a response head");
    let status = head
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    Reply {
        status,
        body: body.to_owned(),
    }
}

/// `PUT /v1/snapshot` from `writer` (`None`: no header) with `query` after the path.
async fn push(podgate: &Podgate, snapshot: &Value, writer: Option<&str>, query: &str) -> Reply {
    let headers: Vec<(&str, &str)> = writer
        .map(|name| ("podgate-writer", name))
        .into_iter()
        .collect();
    call(
        podgate,
        "PUT",
        &format!("/v1/snapshot{query}"),
        &headers,
        &snapshot.to_string(),
    )
    .await
}

async fn validate(podgate: &Podgate, snapshot: &Value) -> Reply {
    call(
        podgate,
        "POST",
        "/v1/snapshot/validate",
        &[],
        &snapshot.to_string(),
    )
    .await
}

async fn version(podgate: &Podgate) -> Value {
    let reply = call(podgate, "GET", "/v1/snapshot/version", &[], "").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    reply.json()
}

/// One app `a.test` with one serving revision on `addr`.
fn simple(version: u64, addr: SocketAddr) -> Value {
    snapshot(version, &[app("a", &["a.test"], &[serving("r1", addr)])])
}

/// A bound socket nobody listens on: connections to it are refused for as long as it lives.
fn refusing() -> (TcpSocket, SocketAddr) {
    let socket = TcpSocket::new_v4().expect("socket");
    socket
        .bind("127.0.0.1:0".parse().expect("addr"))
        .expect("bind");
    let addr = socket.local_addr().expect("local addr");
    (socket, addr)
}

async fn events_of(podgate: &Podgate, kind: &str) -> Vec<Value> {
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    events["events"]
        .as_array()
        .expect("events list")
        .iter()
        .filter(|event| event["kind"] == kind)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------------------------
// GET /v1/schema

async fn schema(podgate: &Podgate) -> Value {
    let reply = podgate.admin_get("/v1/schema").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(
        reply.header("content-type"),
        Some("application/schema+json")
    );
    reply.json()
}

/// A validator for the pointer `target` of `document`, which keeps the document's `$defs`.
fn validator_at(document: &Value, target: &str) -> jsonschema::Validator {
    jsonschema::validator_for(&json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": document["$defs"],
        "$ref": target,
    }))
    .unwrap_or_else(|err| panic!("{target}: {err}"))
}

/// A snapshot that uses most of the model: nested matchers, middlewares, a service with health
/// checks, passive ejection and a sticky cookie, a transport, a canary and an entry point policy.
fn rich_snapshot(addr: SocketAddr) -> Value {
    let mut web = app(
        "web",
        &["web.test"],
        &[
            revision("r1", addr, 90, "serving"),
            revision("r2", addr, 10, "serving"),
        ],
    );
    web["routers"] = json!([
        {
            "name": "api",
            "priority": 5,
            "match": {"all": [
                {"host": ["web.test", "*.web.test"]},
                {"any": [{"path_prefix": "/api"}, {"path": "/health"}]},
                {"not": {"method": ["DELETE"]}},
                {"header": {"name": "x-env", "value": "prod"}},
                {"header_regexp": {"name": "x-id", "regex": "^[0-9]+$"}},
                {"query": {"name": "debug"}},
                {"query_regexp": {"name": "q", "regex": "a+"}},
                {"client_ip": ["10.0.0.0/8", "::1"]},
                {"host_regexp": "^web\\."},
                {"path_regexp": "^/v[0-9]+/"},
            ]},
            "chain": ["strip", "limit"],
            "service": "web",
        },
        {"name": "rest", "match": {"host": "web.test"}, "service": "web"},
    ]);
    web["middlewares"] = json!([
        {"name": "strip", "type": "strip_prefix", "prefixes": ["/api"]},
        {"name": "limit", "type": "ip_allow_list", "source_range": ["10.0.0.0/8"],
         "ip_strategy": {"depth": 1, "excluded": ["10.1.0.0/16"]}},
        {"name": "hdr", "type": "headers", "response": {"set": {"x-served-by": "podgate"}}},
    ]);
    web["default_chain"] = json!(["hdr"]);
    web["services"] = json!([{
        "name": "shared", "type": "loadbalancer", "algorithm": "weighted_round_robin",
        "servers": [{"url": format!("http://{addr}"), "weight": 2}],
        "health_check": {"path": "/up", "interval_secs": 5, "timeout_secs": 2, "expect_status": [200, "200-299"]},
        "passive": {"consecutive_failures": 5, "ejection_secs": 30, "max_ejection_percent": 50},
        "sticky": {"cookie": {"name": "route", "same_site": "lax"}},
        "transport": "internal",
    }]);
    web["transports"] =
        json!([{"name": "internal", "type": "servers_transport", "insecure_skip_verify": false}]);
    web["canary"] = json!({"revision": "r2", "step_percent": 10, "interval_secs": 60, "max_error_permille": 20});
    web["forwarded"] =
        json!({"x_forwarded": true, "real_ip": false, "rfc7239": true, "server": true});
    let mut rich = snapshot(1, &[web]);
    rich["skew_secret"] = json!("0123456789abcdef0123");
    rich["revert_window_secs"] = json!(30);
    rich
}

#[tokio::test]
async fn schema_validates_good_snapshot() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let document = schema(&podgate).await;

    jsonschema::meta::validate(&document).expect("the document is a valid JSON Schema");
    assert_eq!(
        document["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(document["podgate_version"], env!("CARGO_PKG_VERSION"));

    let validator = jsonschema::validator_for(&document).expect("compiles as a schema");
    for good in [
        json!({"version": 1, "tenants": [], "apps": []}),
        simple(7, upstream.addr),
        rich_snapshot(upstream.addr),
    ] {
        let errors: Vec<String> = validator
            .iter_errors(&good)
            .map(|err| format!("{} at {}", err, err.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{errors:?} in {good}");
    }
    // The schema and the compiler agree: what the schema accepts here compiles.
    let checked = validate(&podgate, &rich_snapshot(upstream.addr)).await;
    assert_eq!(checked.status, 200, "{}", checked.body);

    // Every matcher leaf, alone, parses and satisfies its entry.
    let matcher = validator_at(&document, "#/$defs/matcher");
    for leaf in [
        json!({"host": "a.test"}),
        json!({"host": ["a.test", "*.b.test"]}),
        json!({"host_regexp": "^a"}),
        json!({"path": "/a"}),
        json!({"path_prefix": "/a"}),
        json!({"path_regexp": "^/a"}),
        json!({"method": "GET"}),
        json!({"method": ["GET", "POST"]}),
        json!({"client_ip": "10.0.0.0/8"}),
        json!({"header": {"name": "x"}}),
        json!({"header": {"name": "x", "value": "y"}}),
        json!({"header_regexp": {"name": "x", "regex": "y"}}),
        json!({"query": {"name": "x"}}),
        json!({"query_regexp": {"name": "x", "regex": "y"}}),
        json!({"all": [{"host": "a.test"}, {"not": {"path": "/x"}}]}),
        json!({"any": [{"host": "a.test"}]}),
        json!({"not": {"host": "a.test"}}),
    ] {
        assert!(matcher.is_valid(&leaf), "the schema refuses {leaf}");
        assert!(
            podgate::router::matcher::parse(&leaf).is_ok(),
            "the parser refuses {leaf}"
        );
    }

    // A declared object is validated by its type.
    let sample = |pointer: &str, declared: Value| {
        let found = validator_at(&document, pointer);
        assert!(found.is_valid(&declared), "{pointer} refuses {declared}");
    };
    sample(
        "#/$defs/middleware.add_prefix",
        json!({"name": "p", "type": "add_prefix", "prefix": "/x"}),
    );
    sample(
        "#/$defs/middleware.ip_allow_list",
        json!({"name": "p", "type": "ip_allow_list", "source_range": ["10.0.0.0/8", "::1"]}),
    );
    sample(
        "#/$defs/service.static",
        json!({"name": "s", "type": "static", "root": "site", "index": ["index.html"]}),
    );
    sample(
        "#/$defs/transport.servers_transport",
        json!({"name": "t", "type": "servers_transport", "server_name": "x.test",
               "client_cert": {"cert_pem": "c", "key_pem": "k"}}),
    );
}

#[tokio::test]
async fn schema_rejects_bad_snapshot() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let document = schema(&podgate).await;
    let validator = jsonschema::validator_for(&document).expect("compiles as a schema");

    let broken = |edit: &dyn Fn(&mut Value)| {
        let mut bad = simple(7, upstream.addr);
        edit(&mut bad);
        bad
    };
    let cases = [
        (
            "a string version",
            broken(&|s| s["version"] = json!("seven")),
        ),
        ("a negative version", broken(&|s| s["version"] = json!(-1))),
        (
            "no tenants",
            broken(&|s| {
                s.as_object_mut().expect("object").remove("tenants");
            }),
        ),
        (
            "a tenant weight that is text",
            broken(&|s| s["tenants"][0]["weight"] = json!("heavy")),
        ),
        (
            "an unknown tls mode",
            broken(&|s| s["apps"][0]["tls"]["mode"] = json!("sometimes")),
        ),
        (
            "a revision state that does not exist",
            broken(&|s| s["apps"][0]["revisions"][0]["state"] = json!("asleep")),
        ),
        (
            "a revision weight that is text",
            broken(&|s| s["apps"][0]["revisions"][0]["weight"] = json!("x")),
        ),
        (
            "a matcher with two keys",
            broken(&|s| s["apps"][0]["routers"][0]["match"] = json!({"host": "a", "path": "/"})),
        ),
        (
            "a host that is a number",
            broken(&|s| s["apps"][0]["routers"][0]["match"] = json!({"host": 5})),
        ),
        (
            "an unknown matcher key",
            broken(&|s| s["apps"][0]["routers"][0]["match"] = json!({"hots": "a.test"})),
        ),
        (
            "an empty combinator",
            broken(&|s| s["apps"][0]["routers"][0]["match"] = json!({"all": []})),
        ),
        (
            "a router with no service",
            broken(&|s| {
                s["apps"][0]["routers"][0]
                    .as_object_mut()
                    .expect("object")
                    .remove("service");
            }),
        ),
        (
            "a canary step that is text",
            broken(
                &|s| s["apps"][0]["canary"] = json!({"revision": "r1", "step_percent": "ten", "interval_secs": 1, "max_error_permille": 1}),
            ),
        ),
        (
            "a forwarded switch that is text",
            broken(&|s| s["apps"][0]["forwarded"] = json!({"real_ip": "no"})),
        ),
        (
            "a misspelt forwarded switch",
            broken(&|s| s["apps"][0]["forwarded"] = json!({"realip": false})),
        ),
    ];
    for (what, bad) in cases {
        assert!(
            !validator.is_valid(&bad),
            "the schema accepts {what}: {bad}"
        );
    }

    // A kind's fields are checked, by type and by name.
    let refuses = |pointer: &str, declared: Value| {
        let found = validator_at(&document, pointer);
        assert!(!found.is_valid(&declared), "{pointer} accepts {declared}");
    };
    refuses(
        "#/$defs/middleware.add_prefix",
        json!({"name": "p", "type": "add_prefix", "prefix": 5}),
    );
    refuses(
        "#/$defs/middleware.add_prefix",
        json!({"name": "p", "type": "add_prefix", "prefixx": "/x"}),
    );
    refuses(
        "#/$defs/middleware.add_prefix",
        json!({"name": "p", "type": "strip_prefix", "prefix": "/x"}),
    );
    refuses(
        "#/$defs/service.loadbalancer",
        json!({"name": "s", "type": "loadbalancer", "servers": [{"url": 5}]}),
    );
}

#[tokio::test]
async fn schema_lists_unbuilt_kinds() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let document = schema(&podgate).await;
    let defs = document["$defs"].as_object().expect("$defs");

    let kinds = document["kinds"].as_object().expect("kinds");
    for category in ["middleware", "service", "transport", "matcher"] {
        assert!(
            !kinds[category].as_object().expect("a category").is_empty(),
            "{category} has no kind"
        );
    }
    for (category, planned) in document["unbuilt"].as_object().expect("unbuilt") {
        for kind in planned.as_array().expect("a list") {
            let kind = kind.as_str().expect("a name");
            assert!(
                kinds[category].get(kind).is_none()
                    && !defs.contains_key(&format!("{category}.{kind}")),
                "{category}.{kind} is listed as unbuilt and has a schema"
            );
            // The compiler agrees: it refuses the kind as planned, not as unknown.
            let mut declared = json!({"name": "planned", "type": kind});
            let mut candidate = simple(1, upstream.addr);
            let expected = match category.as_str() {
                "middleware" => {
                    candidate["apps"][0]["middlewares"] = json!([declared]);
                    "middleware_not_built"
                }
                "service" => {
                    declared["servers"] = json!([]);
                    candidate["apps"][0]["revisions"][0]["services"] = json!([declared]);
                    "service_not_built"
                }
                _ => {
                    candidate["apps"][0]["routers"][0]["match"] = json!({ kind: "x" });
                    "matcher_not_built"
                }
            };
            let reply = validate(&podgate, &candidate).await;
            assert_eq!(reply.status, 422, "{category}.{kind}: {}", reply.body);
            assert!(
                reply.body.contains(expected),
                "{category}.{kind} is not {expected}: {}",
                reply.body
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// GET /v1/snapshot/version

#[tokio::test]
async fn version_endpoint() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;

    let fresh = version(&podgate).await;
    assert_eq!(fresh["version"], 0);
    assert_eq!(fresh["writer"], Value::Null);
    let boot_id = fresh["boot_id"].as_str().expect("boot_id");
    assert_eq!(boot_id.len(), 32, "{boot_id}");
    let events = podgate.admin_get("/v1/events?after=0").await.json();
    assert_eq!(events["boot_id"], boot_id, "the same id as the event feed");

    let pushed = push(
        &podgate,
        &simple(5, upstream.addr),
        Some("podkit-agent"),
        "",
    )
    .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    let now = version(&podgate).await;
    assert_eq!(now["version"], 5);
    assert_eq!(now["writer"], "podkit-agent");
    assert_eq!(now["boot_id"], boot_id);

    // A refused snapshot moves nothing.
    let stale = push(
        &podgate,
        &simple(4, upstream.addr),
        Some("podkit-agent"),
        "",
    )
    .await;
    assert_eq!(stale.status, 409);
    assert_eq!(version(&podgate).await["version"], 5);

    // Only GET answers.
    assert_eq!(
        call(&podgate, "POST", "/v1/snapshot/version", &[], "")
            .await
            .status,
        405
    );

    // A restart is a new boot id and an empty table, so the writer finds its sequence at 0.
    drop(podgate);
    let restarted = Podgate::start().await;
    let after = version(&restarted).await;
    assert_eq!(after["version"], 0);
    assert_ne!(after["boot_id"], boot_id);
}

// ---------------------------------------------------------------------------------------------
// POST /v1/snapshot/validate

/// Two apps that claim one host: the compiler refuses the whole snapshot.
fn conflicting(version: u64, addr: SocketAddr) -> Value {
    snapshot(
        version,
        &[
            app("a", &["x.test"], &[serving("r1", addr)]),
            app("b", &["x.test"], &[serving("r1", addr)]),
        ],
    )
}

#[tokio::test]
async fn validate_reports_conflicts() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;

    let mut bad_kind = simple(1, upstream.addr);
    bad_kind["apps"][0]["middlewares"] = json!([{"name": "m", "type": "no_such_kind"}]);
    let mut unbuilt = simple(1, upstream.addr);
    unbuilt["apps"][0]["revisions"][0]["services"] =
        json!([{"name": "web", "type": "weighted", "servers": []}]);
    let mut bad_matcher = simple(1, upstream.addr);
    bad_matcher["apps"][0]["routers"][0]["match"] = json!({"path": "no-slash"});

    let candidates = [
        (422, conflicting(1, upstream.addr).to_string()),
        (422, bad_kind.to_string()),
        (422, unbuilt.to_string()),
        (422, bad_matcher.to_string()),
        (400, "{ not json".to_owned()),
        (400, r#"{"version": "one"}"#.to_owned()),
    ];
    for (status, body) in &candidates {
        let checked = call(&podgate, "POST", "/v1/snapshot/validate", &[], body).await;
        let pushed = call(&podgate, "PUT", "/v1/snapshot", &[], body).await;
        assert_eq!(checked.status, *status, "validate: {}", checked.body);
        assert_eq!(
            (pushed.status, &pushed.body),
            (checked.status, &checked.body),
            "validate and PUT answer {body} differently"
        );
    }

    let conflicts = validate(&podgate, &conflicting(1, upstream.addr))
        .await
        .json();
    assert_eq!(conflicts["error"], "snapshot rejected");
    let list = conflicts["conflicts"].as_array().expect("conflicts");
    assert_eq!(list[0]["code"], "host_conflict", "{conflicts}");
    assert!(
        list[0].to_string().contains("tests/a") && list[0].to_string().contains("tests/b"),
        "both sources are named: {conflicts}"
    );

    // A snapshot that compiles is valid, and nothing was applied by the refusals above.
    let good = validate(&podgate, &simple(1, upstream.addr)).await;
    assert_eq!(good.status, 200);
    assert_eq!(good.json(), json!({"valid": true, "warnings": []}));
    assert_eq!(version(&podgate).await["version"], 0);
}

#[tokio::test]
async fn validate_ignores_version() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    assert_eq!(
        push(&podgate, &simple(10, upstream.addr), None, "")
            .await
            .status,
        200
    );

    for candidate in [3, 10, 11] {
        let checked = validate(&podgate, &simple(candidate, upstream.addr)).await;
        assert_eq!(checked.status, 200, "version {candidate}: {}", checked.body);
    }
    // The same candidates are refused by PUT when they are not newer: only validate ignores it.
    assert_eq!(
        push(&podgate, &simple(3, upstream.addr), None, "")
            .await
            .status,
        409
    );
    assert_eq!(
        push(&podgate, &simple(10, upstream.addr), None, "")
            .await
            .status,
        409
    );
    assert_eq!(version(&podgate).await["version"], 10);
}

#[tokio::test]
async fn validate_applies_nothing() {
    let podgate = Podgate::start().await;
    let live = Upstream::start("live").await;
    let candidate = Upstream::start("candidate").await;
    let first = simple(1, live.addr);
    assert_eq!(
        push(&podgate, &first, Some("podkit-agent"), "")
            .await
            .status,
        200
    );
    assert_eq!(podgate.get("a.test", "/").await.body, "live");

    // A valid candidate that would route differently, and a refused one.
    let newer = snapshot(
        2,
        &[app("b", &["b.test"], &[serving("r1", candidate.addr)])],
    );
    assert_eq!(validate(&podgate, &newer).await.status, 200);
    assert_eq!(
        validate(&podgate, &conflicting(3, candidate.addr))
            .await
            .status,
        422
    );

    assert_eq!(version(&podgate).await["version"], 1);
    let served = podgate.get("a.test", "/").await;
    assert_eq!((served.status, served.body.as_str()), (200, "live"));
    assert_eq!(
        podgate.get("b.test", "/").await.status,
        404,
        "the candidate is not live"
    );
    // The next push of the owner is still the next version, not refused as stale.
    assert_eq!(
        push(&podgate, &newer, Some("podkit-agent"), "")
            .await
            .status,
        200
    );
}

/// The canary of app `a` between a base and a canary revision. A long interval keeps its share
/// where the policy puts it, so any change is a change by someone else.
fn canary_snapshot(version: u64, step: u32, base: SocketAddr, canary: SocketAddr) -> Value {
    let mut a = app(
        "a",
        &["a.test"],
        &[
            serving("base", base),
            revision("canary", canary, 1, "serving"),
        ],
    );
    a["canary"] = json!({"revision": "canary", "step_percent": step, "interval_secs": 3600, "max_error_permille": 100});
    snapshot(version, &[a])
}

#[tokio::test]
async fn validate_has_no_side_effects() {
    let podgate = Podgate::start().await;
    let base = Upstream::start("base").await;
    let canary = Upstream::start("canary").await;
    let (_held, refused) = refusing();
    assert_eq!(
        push(
            &podgate,
            &canary_snapshot(1, 10, base.addr, canary.addr),
            Some("podkit-agent"),
            ""
        )
        .await
        .status,
        200
    );

    let observe = async || {
        (
            podgate.admin_get("/metrics").await.body,
            podgate
                .admin_get("/v1/explain?url=http://a.test/")
                .await
                .body,
            podgate.admin_get("/v1/overview").await.body,
            podgate.admin_get("/v1/events?after=0").await.body,
            version(&podgate).await,
        )
    };
    let before = observe().await;
    assert_eq!(
        observe().await,
        before,
        "the observations are stable on their own"
    );
    assert!(
        before.1.contains("\"share_percent\":10"),
        "the canary starts at its step: {}",
        before.1
    );

    // A candidate that resets the canary (another step), one the compiler refuses, a stale one,
    // and a body that is not a snapshot. None may touch what the live snapshot keeps.
    let rewritten = canary_snapshot(2, 50, base.addr, refused);
    let mut refused_candidate = canary_snapshot(3, 50, base.addr, canary.addr);
    refused_candidate["apps"][0]["middlewares"] = json!([{"name": "m", "type": "no_such_kind"}]);
    let stale = canary_snapshot(1, 90, base.addr, canary.addr);
    for candidate in [&rewritten, &refused_candidate, &stale] {
        validate(&podgate, candidate).await;
    }
    call(&podgate, "POST", "/v1/snapshot/validate", &[], "{ nope").await;
    assert_eq!(observe().await, before, "validate left the node as it was");

    // The comparison can tell: a refused push does move the snapshot counters.
    assert_eq!(
        push(&podgate, &refused_candidate, Some("podkit-agent"), "")
            .await
            .status,
        422
    );
    assert_ne!(
        podgate.admin_get("/metrics").await.body,
        before.0,
        "a refused PUT is counted, so an unchanged metric page after validate means something"
    );
    assert!(events_of(&podgate, "writer_changed").await.is_empty());
}

// ---------------------------------------------------------------------------------------------
// The writer guard

fn refusal(reply: &Reply, owner: impl Into<Value>) {
    let owner: Value = owner.into();
    assert_eq!(reply.status, 409, "{}", reply.body);
    let body = reply.json();
    assert_eq!(body["writer"], owner, "{body}");
    let expected = match &owner {
        Value::String(name) => format!("snapshot is owned by writer {name}"),
        _ => "snapshot is owned by an unnamed writer".to_owned(),
    };
    assert_eq!(body["error"], expected);
}

#[tokio::test]
async fn second_writer_refused() {
    let podgate = Podgate::start().await;
    let one = Upstream::start("one").await;
    let two = Upstream::start("two").await;
    assert_eq!(
        push(&podgate, &simple(1, one.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );

    let intruder = push(&podgate, &simple(2, two.addr), Some("podgate-provider"), "").await;
    refusal(&intruder, json!("podkit-agent"));
    // Nothing changed: not the table, not the owner, not the sequence.
    assert_eq!(podgate.get("a.test", "/").await.body, "one");
    let state = version(&podgate).await;
    assert_eq!(
        (state["version"].clone(), state["writer"].clone()),
        (json!(1), json!("podkit-agent"))
    );
    // The owner goes on with the next version.
    assert_eq!(
        push(&podgate, &simple(2, two.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );
    assert_eq!(podgate.get("a.test", "/").await.body, "two");

    // A plan is a push that applies nothing, and is checked the same way.
    let plan = |writer: &'static str| {
        let body = simple(3, two.addr).to_string();
        let podgate = &podgate;
        async move {
            call(
                podgate,
                "POST",
                "/v1/snapshot/plan",
                &[("podgate-writer", writer)],
                &body,
            )
            .await
        }
    };
    refusal(&plan("podgate-provider").await, json!("podkit-agent"));
    assert_eq!(plan("podkit-agent").await.status, 200);
}

#[tokio::test]
async fn unnamed_writer_refused_when_pinned() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    assert_eq!(
        push(
            &podgate,
            &simple(1, upstream.addr),
            Some("podkit-agent"),
            ""
        )
        .await
        .status,
        200
    );

    refusal(
        &push(&podgate, &simple(2, upstream.addr), None, "").await,
        json!("podkit-agent"),
    );
    let plan = call(
        &podgate,
        "POST",
        "/v1/snapshot/plan",
        &[],
        &simple(2, upstream.addr).to_string(),
    )
    .await;
    refusal(&plan, json!("podkit-agent"));
    assert_eq!(version(&podgate).await["version"], 1);
}

#[tokio::test]
async fn named_writer_refused_after_unnamed_pin() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    // Existing clients send no name, and keep working while nobody else has pinned.
    assert_eq!(
        push(&podgate, &simple(1, upstream.addr), None, "")
            .await
            .status,
        200
    );
    assert_eq!(
        push(&podgate, &simple(2, upstream.addr), None, "")
            .await
            .status,
        200
    );
    assert_eq!(version(&podgate).await["writer"], Value::Null);

    refusal(
        &push(
            &podgate,
            &simple(3, upstream.addr),
            Some("podkit-agent"),
            "",
        )
        .await,
        Value::Null,
    );
    assert_eq!(version(&podgate).await["version"], 2);
    // The way to a name is the operator's takeover.
    assert_eq!(
        push(
            &podgate,
            &simple(3, upstream.addr),
            Some("podkit-agent"),
            "?takeover=true"
        )
        .await
        .status,
        200
    );
    assert_eq!(version(&podgate).await["writer"], "podkit-agent");
    refusal(
        &push(&podgate, &simple(4, upstream.addr), None, "").await,
        json!("podkit-agent"),
    );
}

#[tokio::test]
async fn takeover_replaces_writer() {
    let podgate = Podgate::start_logged(&[("RUST_LOG", "warn")]).await;
    let one = Upstream::start("one").await;
    let two = Upstream::start("two").await;
    assert_eq!(
        push(&podgate, &simple(1, one.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );

    // A takeover is still a push: it needs a newer version, and a refused one replaces nobody.
    let stale = push(
        &podgate,
        &simple(1, two.addr),
        Some("podgate-provider"),
        "?takeover=true",
    )
    .await;
    assert_eq!(stale.status, 409, "{}", stale.body);
    assert_eq!(version(&podgate).await["writer"], "podkit-agent");
    let mut broken = simple(2, two.addr);
    broken["apps"][0]["middlewares"] = json!([{"name": "m", "type": "no_such_kind"}]);
    let rejected = push(
        &podgate,
        &broken,
        Some("podgate-provider"),
        "?takeover=true",
    )
    .await;
    assert_eq!(rejected.status, 422);
    assert_eq!(version(&podgate).await["writer"], "podkit-agent");

    let taken = push(
        &podgate,
        &simple(2, two.addr),
        Some("podgate-provider"),
        "?takeover=true",
    )
    .await;
    assert_eq!(taken.status, 200, "{}", taken.body);
    assert_eq!(podgate.get("a.test", "/").await.body, "two");
    let state = version(&podgate).await;
    assert_eq!(
        (state["version"].clone(), state["writer"].clone()),
        (json!(2), json!("podgate-provider"))
    );
    refusal(
        &push(&podgate, &simple(3, one.addr), Some("podkit-agent"), "").await,
        json!("podgate-provider"),
    );
    assert!(
        podgate.log().contains("snapshot writer taken over"),
        "the takeover is logged at warn level: {}",
        podgate.log()
    );

    // Takeover needs a name, and takes `true` or `false` only.
    let anonymous = push(&podgate, &simple(3, one.addr), None, "?takeover=true").await;
    assert_eq!(anonymous.status, 400, "{}", anonymous.body);
    let unclear = push(
        &podgate,
        &simple(3, one.addr),
        Some("podgate-provider"),
        "?takeover=maybe",
    )
    .await;
    assert_eq!(unclear.status, 400, "{}", unclear.body);
    let refused = push(
        &podgate,
        &simple(3, one.addr),
        Some("podkit-agent"),
        "?takeover=false",
    )
    .await;
    refusal(&refused, json!("podgate-provider"));
}

#[tokio::test]
async fn writer_changed_event() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    assert_eq!(
        push(
            &podgate,
            &simple(1, upstream.addr),
            Some("podkit-agent"),
            ""
        )
        .await
        .status,
        200
    );
    // The first push only pins, and a takeover by the owner changes nothing hands.
    assert!(events_of(&podgate, "writer_changed").await.is_empty());
    assert_eq!(
        push(
            &podgate,
            &simple(2, upstream.addr),
            Some("podkit-agent"),
            "?takeover=true"
        )
        .await
        .status,
        200
    );
    assert!(events_of(&podgate, "writer_changed").await.is_empty());
    // A refused push says nothing either.
    assert_eq!(
        push(
            &podgate,
            &simple(3, upstream.addr),
            Some("podgate-provider"),
            ""
        )
        .await
        .status,
        409
    );
    assert!(events_of(&podgate, "writer_changed").await.is_empty());

    let taken = push(
        &podgate,
        &simple(3, upstream.addr),
        Some("podgate-provider"),
        "?takeover=true",
    )
    .await;
    assert_eq!(taken.status, 200);
    let seen = events_of(&podgate, "writer_changed").await;
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        (seen[0]["from"].clone(), seen[0]["to"].clone()),
        (json!("podkit-agent"), json!("podgate-provider"))
    );

    // From an unnamed first writer, `from` is null.
    let second = Podgate::start().await;
    assert_eq!(
        push(&second, &simple(1, upstream.addr), None, "")
            .await
            .status,
        200
    );
    assert_eq!(
        push(
            &second,
            &simple(2, upstream.addr),
            Some("podkit-agent"),
            "?takeover=true"
        )
        .await
        .status,
        200
    );
    let seen = events_of(&second, "writer_changed").await;
    assert_eq!(
        (seen[0]["from"].clone(), seen[0]["to"].clone()),
        (Value::Null, json!("podkit-agent"))
    );
}

#[tokio::test]
async fn writer_names_are_checked() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let body = simple(1, upstream.addr);
    for bad in ["", "Podkit", "pod kit", "pod/kit", &"x".repeat(65)] {
        let reply = push(&podgate, &body, Some(bad), "").await;
        assert_eq!(reply.status, 400, "{bad:?}: {}", reply.body);
    }
    let twice = call(
        &podgate,
        "PUT",
        "/v1/snapshot",
        &[("podgate-writer", "a"), ("podgate-writer", "b")],
        &body.to_string(),
    )
    .await;
    assert_eq!(twice.status, 400, "{}", twice.body);
    assert_eq!(version(&podgate).await["version"], 0);
    let longest = "a-._0".repeat(12) + "abcd";
    assert_eq!(longest.len(), 64);
    assert_eq!(push(&podgate, &body, Some(&longest), "").await.status, 200);
    // validate is open to every tool: it takes no writer and never pins.
    let other = validate(&podgate, &simple(9, upstream.addr)).await;
    assert_eq!(other.status, 200);
    assert_eq!(version(&podgate).await["writer"], longest.as_str());
}

#[tokio::test]
async fn writer_survives_auto_revert() {
    let podgate = Podgate::start().await;
    let good = Upstream::start("good").await;
    let (_held, dead) = refusing();
    assert_eq!(
        push(&podgate, &simple(1, good.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );

    let mut broken = simple(2, dead);
    broken["revert_window_secs"] = json!(20);
    assert_eq!(
        push(&podgate, &broken, Some("podkit-agent"), "")
            .await
            .status,
        200
    );
    for _ in 0..30 {
        assert_eq!(podgate.get("a.test", "/").await.status, 502);
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    while events_of(&podgate, "config_reverted").await.is_empty() {
        assert!(Instant::now() < deadline, "no revert");
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(podgate.get("a.test", "/").await.body, "good");

    // The revert is podgate's act, not a new writer: the owner stays, at the version it had.
    let state = version(&podgate).await;
    assert_eq!(
        (state["version"].clone(), state["writer"].clone()),
        (json!(2), json!("podkit-agent"))
    );
    refusal(
        &push(
            &podgate,
            &simple(3, good.addr),
            Some("podgate-provider"),
            "",
        )
        .await,
        json!("podkit-agent"),
    );
    refusal(
        &push(&podgate, &simple(3, good.addr), None, "").await,
        json!("podkit-agent"),
    );
    assert_eq!(
        push(&podgate, &simple(3, good.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn restart_resets_the_writer() {
    let upstream = Upstream::start("up").await;
    let first = Podgate::start().await;
    assert_eq!(
        push(&first, &simple(1, upstream.addr), Some("podkit-agent"), "")
            .await
            .status,
        200
    );
    assert_eq!(version(&first).await["writer"], "podkit-agent");
    drop(first);

    // The new process has an empty table and no owner: any writer pins again, at any version.
    let restarted = Podgate::start().await;
    let state = version(&restarted).await;
    assert_eq!(
        (state["version"].clone(), state["writer"].clone()),
        (json!(0), Value::Null)
    );
    assert_eq!(
        push(
            &restarted,
            &simple(1, upstream.addr),
            Some("podgate-provider"),
            ""
        )
        .await
        .status,
        200
    );
    assert_eq!(version(&restarted).await["writer"], "podgate-provider");
}

#[tokio::test]
async fn concurrent_first_pushes_pin_one_writer() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let names = [
        "podkit-agent",
        "podgate-provider",
        "operator-a",
        "operator-b",
    ];
    let body = simple(1, upstream.addr);
    let (a, b, c, d) = tokio::join!(
        push(&podgate, &body, Some(names[0]), ""),
        push(&podgate, &body, Some(names[1]), ""),
        push(&podgate, &body, Some(names[2]), ""),
        push(&podgate, &body, Some(names[3]), ""),
    );
    let statuses = [a.status, b.status, c.status, d.status];
    let accepted = statuses.iter().filter(|status| **status == 200).count();
    assert_eq!(accepted, 1, "exactly one first push wins: {statuses:?}");
    assert!(
        statuses.iter().all(|status| matches!(status, 200 | 409)),
        "{statuses:?}"
    );
    let owner = version(&podgate).await["writer"].clone();
    assert!(names.contains(&owner.as_str().expect("a name")), "{owner}");
}

#[tokio::test]
async fn overview_summary_shows_the_writer() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("up").await;
    let summary = || async {
        let reply = podgate.admin_get("/v1/overview?section=summary").await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        reply.json()["summary"].clone()
    };
    assert!(
        summary().await.get("writer").is_none(),
        "no snapshot, no writer"
    );
    assert_eq!(
        push(&podgate, &simple(1, upstream.addr), None, "")
            .await
            .status,
        200
    );
    assert!(
        summary().await.get("writer").is_none(),
        "an unnamed writer is not shown"
    );
    assert_eq!(
        push(
            &podgate,
            &simple(2, upstream.addr),
            Some("podkit-agent"),
            "?takeover=true"
        )
        .await
        .status,
        200
    );
    assert_eq!(summary().await["writer"], "podkit-agent");
}
