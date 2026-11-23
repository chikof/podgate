//! `tool_access` of the `mcp_gateway` middleware through the real binary: which tools
//! a caller sees and calls by the claims of its verified token, and that a denied tool answers
//! exactly like one nobody registered. The pure rules (matching, shapes, posture) are
//! unit-tested in `src/middleware/mcp/access.rs` and `src/middleware/mcp.rs`; the same test names
//! appear there.

mod common;

#[path = "fixtures/mcp/fake.rs"]
mod fake;
#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;

use common::{Podgate, app, serving, with_jwt_auth, with_middleware};
use fake::{BIG_BUDGET, Behavior, Client, Fake, budgeted, push, server, text};
use serde_json::{Value, json};
use signer::{Signer, now};

/// A token of `key` with `extra` claims over a subject and an expiry.
fn token(key: &Signer, extra: &Value) -> String {
    let mut claims = json!({"sub": "ann", "exp": now() + 600});
    if let (Some(all), Some(extra)) = (claims.as_object_mut(), extra.as_object()) {
        all.extend(extra.clone());
    }
    key.sign("ES256", &json!({}), &claims)
}

fn jwt_config(key: &Signer) -> Value {
    json!({"keys": {"keys": [key.jwk()]}, "algorithms": ["ES256"]})
}

/// An app of tenant `t1` for `host` whose chain is `jwt_auth` then a gateway over `servers`
/// with `tool_access` `rules` (none: the field is absent).
fn app_of(id: &str, host: &str, servers: &[Value], rules: Option<&Value>, key: &Signer) -> Value {
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let base = with_jwt_auth(app(id, &[host], &[serving("r1", unused)]), jwt_config(key));
    let mut config = json!({ "servers": servers });
    if let Some(rules) = rules {
        config["tool_access"] = rules.clone();
    }
    let mut declared = with_middleware(base, "mcp", "mcp_gateway", config);
    declared["tenant"] = json!("t1");
    declared
}

/// The rules most tests use: developers get the tools of `alpha`, admins also `beta`'s `search`.
fn roles() -> Value {
    json!([
        {"tools": ["alpha__*"], "allow": {"roles": ["dev", "admin"]}},
        {"tools": ["beta__search"], "allow": {"roles": ["admin"]}},
    ])
}

struct Rig {
    podgate: Podgate,
    key: Signer,
    alpha: Fake,
    beta: Fake,
}

impl Rig {
    /// A gateway `mcp.test` over `alpha` (`search`, `read`) and `beta` (`search`, `alpha__search`,
    /// `only-beta`).
    async fn start(rules: Option<&Value>) -> Self {
        Self::start_with(rules, &[]).await
    }

    async fn start_with(rules: Option<&Value>, env: &[(&str, &str)]) -> Self {
        let podgate = Podgate::start_with_env(env).await;
        let key = Signer::es256("k");
        let alpha = Fake::mcp(&Behavior::new("alpha", &["search", "read"])).await;
        let beta = Fake::mcp(&Behavior::new(
            "beta",
            &["search", "alpha__search", "only-beta"],
        ))
        .await;
        let servers = [server("alpha", alpha.addr), server("beta", beta.addr)];
        let pushed = budgeted(
            1,
            &[app_of("mcp", "mcp.test", &servers, rules, &key)],
            BIG_BUDGET,
        );
        push(&podgate, &pushed).await;
        Self {
            podgate,
            key,
            alpha,
            beta,
        }
    }

    fn servers(&self) -> [Value; 2] {
        [
            server("alpha", self.alpha.addr),
            server("beta", self.beta.addr),
        ]
    }

    /// A client of the gateway holding a token with `claims`.
    fn client(&self, claims: &Value) -> Client {
        Client::new(&self.podgate, "mcp.test").with_token(&token(&self.key, claims))
    }

    /// Opens a session as `claims`.
    async fn session(&self, claims: &Value) -> (Client, String) {
        let client = self.client(claims);
        let session = client.initialize().await;
        (client, session)
    }

    async fn metrics(&self) -> String {
        self.podgate.admin_get("/metrics").await.body
    }
}

/// The raw body of a `tools/call` answer, with the id fixed, to compare byte for byte.
async fn raw_call(client: &Client, session: &str, name: &str) -> String {
    let answer = client
        .post(
            Some(session),
            &[("MCP-Protocol-Version", "2025-11-25")],
            &json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                    "params": {"name": name, "arguments": {}}}),
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    answer.body
}

fn code(answer: &Value) -> i64 {
    answer["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("no error in {answer}"))
}

#[tokio::test]
async fn tbac_list_filtered_by_claims() {
    let rig = Rig::start(Some(&roles())).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    assert_eq!(dev.list(&session).await, ["alpha__search", "alpha__read"]);
    let (admin, session) = rig.session(&json!({"roles": "admin"})).await;
    assert_eq!(
        admin.list(&session).await,
        ["alpha__search", "alpha__read", "beta__search"]
    );
    let (other, session) = rig.session(&json!({"roles": ["guest"]})).await;
    assert!(other.list(&session).await.is_empty());
}

#[tokio::test]
async fn tbac_call_allowed() {
    let rig = Rig::start(Some(&roles())).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    dev.list(&session).await;
    let answer = dev.call(&session, "alpha__search", json!({"q": "x"})).await;
    assert_eq!(text(&answer), "alpha:search");
    assert_eq!(rig.alpha.calls("tools/call").len(), 1);
    let (admin, session) = rig.session(&json!({"roles": ["admin"]})).await;
    let answer = admin.call(&session, "beta__search", json!({})).await;
    assert_eq!(text(&answer), "beta:search");
    assert_eq!(rig.beta.calls("tools/call").len(), 1);
}

#[tokio::test]
async fn tbac_denied_equals_unknown() {
    let rules = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    dev.list(&session).await;
    // A tool of a server the caller reaches that no rule lists, a tool of a server it does not
    // reach, and the names that lead nowhere for everyone: one answer, byte for byte.
    let denied_here = raw_call(&dev, &session, "alpha__search").await;
    let denied_server = raw_call(&dev, &session, "beta__search").await;
    let missing_tool = raw_call(&dev, &session, "alpha__nothing").await;
    let missing_server = raw_call(&dev, &session, "gamma__search").await;
    let unprefixed = raw_call(&dev, &session, "search").await;
    assert!(denied_here.contains("-32602"), "{denied_here}");
    assert!(denied_here.contains("unknown tool"), "{denied_here}");
    for other in [denied_server, missing_tool, missing_server, unprefixed] {
        assert_eq!(denied_here, other);
    }
}

#[tokio::test]
async fn tbac_denied_dials_nothing() {
    let rules = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    dev.list(&session).await;
    let (alpha_before, beta_before) = (rig.alpha.requests().len(), rig.beta.requests().len());
    assert_eq!(
        beta_before, 0,
        "a server the caller reaches no tool of is not asked"
    );
    for name in ["alpha__search", "beta__search", "beta__only-beta"] {
        assert_eq!(code(&dev.call(&session, name, json!({})).await), -32602);
    }
    assert!(rig.alpha.calls("tools/call").is_empty());
    assert_eq!(rig.alpha.requests().len(), alpha_before);
    assert_eq!(rig.beta.requests().len(), 0);
}

#[tokio::test]
async fn tbac_default_deny() {
    let rules = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    // A tool no rule lists is closed, in the list and in a call.
    assert_eq!(dev.list(&session).await, ["alpha__read"]);
    assert_eq!(
        code(&dev.call(&session, "alpha__search", json!({})).await),
        -32602
    );
    // An empty `tool_access` opens nothing.
    let empty = Rig::start(Some(&json!([]))).await;
    let (admin, session) = empty.session(&json!({"roles": ["admin"]})).await;
    assert!(admin.list(&session).await.is_empty());
    assert_eq!(
        code(&admin.call(&session, "alpha__read", json!({})).await),
        -32602
    );
    assert!(empty.alpha.calls("tools/call").is_empty());
}

#[tokio::test]
async fn tbac_empty_tool_access_denies_all() {
    let rig = Rig::start(Some(&json!([]))).await;
    let (client, session) = rig.session(&json!({"roles": ["admin"]})).await;
    assert!(client.list(&session).await.is_empty());
    assert!(rig.alpha.requests().is_empty() && rig.beta.requests().is_empty());
}

#[tokio::test]
async fn tbac_absent_tool_access_is_open() {
    let rig = Rig::start(None).await;
    let (client, session) = rig.session(&json!({})).await;
    assert_eq!(client.list(&session).await.len(), 5);
    let answer = client.call(&session, "beta__only-beta", json!({})).await;
    assert_eq!(text(&answer), "beta:only-beta");
}

#[tokio::test]
async fn tbac_missing_claim_denies() {
    let rig = Rig::start(Some(&roles())).await;
    for claims in [
        json!({}),
        json!({"role": ["admin"]}),
        json!({"groups": ["admin"]}),
    ] {
        let (client, session) = rig.session(&claims).await;
        assert!(client.list(&session).await.is_empty(), "{claims}");
        assert_eq!(
            code(&client.call(&session, "alpha__search", json!({})).await),
            -32602
        );
    }
    assert!(rig.alpha.calls("tools/call").is_empty());
}

#[tokio::test]
async fn tbac_claim_wrong_type_denies() {
    let rig = Rig::start(Some(&roles())).await;
    for roles in [
        json!(1),
        json!(true),
        json!(null),
        json!({"admin": true}),
        json!([]),
        json!([1, {"admin": 1}]),
        json!("Admin"),
        json!("dev admin"),
    ] {
        let (client, session) = rig.session(&json!({ "roles": roles })).await;
        assert!(client.list(&session).await.is_empty(), "{roles}");
        assert_eq!(
            code(&client.call(&session, "alpha__search", json!({})).await),
            -32602,
            "{roles}"
        );
    }
    assert!(rig.alpha.calls("tools/call").is_empty());
}

#[tokio::test]
async fn tbac_same_name_on_two_servers_is_two_tools() {
    // Both servers have `search`; the rule names alpha's.
    let rules = json!([{"tools": ["alpha__search"], "allow": {"roles": ["admin"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (admin, session) = rig.session(&json!({"roles": ["admin"]})).await;
    assert_eq!(admin.list(&session).await, ["alpha__search"]);
    assert_eq!(
        text(&admin.call(&session, "alpha__search", json!({})).await),
        "alpha:search"
    );
    assert_eq!(
        code(&admin.call(&session, "beta__search", json!({})).await),
        -32602
    );
    assert!(rig.beta.requests().is_empty());
}

#[tokio::test]
async fn tbac_client_cannot_pick_server() {
    // The rule opens alpha's `search`. Beta has a tool called `alpha__search` of its own.
    let rules = json!([{"tools": ["alpha__search"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    // Nothing but the name picks the server: not a param, a header or `_meta`.
    let answer = dev
        .post(
            Some(&session),
            &[("X-Mcp-Server", "beta"), ("MCP-Server", "beta")],
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "alpha__search", "server": "beta", "serverName": "beta",
                "arguments": {"server": "beta"}, "_meta": {"server": "beta"}}}),
        )
        .await;
    assert_eq!(text(&answer.json()), "alpha:search");
    assert_eq!(
        (
            rig.alpha.calls("tools/call").len(),
            rig.beta.requests().len()
        ),
        (1, 0)
    );
    // The first separator ends the server: this is beta's tool, which no rule opens.
    for name in [
        "beta__alpha__search",
        "beta__search",
        "search",
        "alpha_search",
        "ALPHA__search",
    ] {
        assert_eq!(
            code(&dev.call(&session, name, json!({})).await),
            -32602,
            "{name}"
        );
    }
    assert_eq!(rig.alpha.calls("tools/call").len(), 1);
    assert!(rig.beta.requests().is_empty());
}

#[tokio::test]
async fn tbac_wildcard_covers_server() {
    let rules = json!([{"tools": ["beta__*"], "allow": {"team": ["ops"]}}]);
    let rig = Rig::start(Some(&rules)).await;
    let (ops, session) = rig.session(&json!({"team": "ops"})).await;
    assert_eq!(
        ops.list(&session).await,
        ["beta__search", "beta__alpha__search", "beta__only-beta"]
    );
    assert_eq!(
        text(&ops.call(&session, "beta__only-beta", json!({})).await),
        "beta:only-beta"
    );
}

#[tokio::test]
async fn tbac_headers_cannot_grant() {
    let rig = Rig::start(Some(&roles())).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    let forged: &[(&str, &str)] = &[
        ("X-Roles", "admin"),
        ("X-Jwt-Claim-Roles", "admin"),
        ("X-Forwarded-User", "admin"),
        ("X-Mcp-Role", "admin"),
        ("Roles", "admin"),
    ];
    let list = dev
        .post(
            Some(&session),
            forged,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        )
        .await
        .json();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names, ["alpha__search", "alpha__read"]);
    let call = dev
        .post(
            Some(&session),
            forged,
            &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "beta__search", "arguments": {"roles": ["admin"]},
                "roles": ["admin"], "claims": {"roles": ["admin"]},
                "_meta": {"roles": ["admin"], "claims": {"roles": ["admin"]}}}}),
        )
        .await
        .json();
    assert_eq!(code(&call), -32602);
    assert!(rig.beta.requests().is_empty());
}

#[tokio::test]
async fn tbac_no_token_is_401_before_rules() {
    let rig = Rig::start(Some(&roles())).await;
    let anonymous = Client::new(&rig.podgate, "mcp.test");
    let other_key = Signer::es256("other");
    let forged = Client::new(&rig.podgate, "mcp.test")
        .with_token(&token(&other_key, &json!({"roles": ["admin"]})));
    let unsigned = Client::new(&rig.podgate, "mcp.test").with_token(&signer::unsigned(
        "none",
        &json!({"roles": ["admin"], "exp": now() + 600}),
    ));
    for client in [&anonymous, &forged, &unsigned] {
        let answer = client
            .post(
                None,
                &[],
                &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "0"}}}),
            )
            .await;
        assert_eq!(answer.status, 401, "{answer:?}");
        assert!(answer.header("mcp-session-id").is_none());
    }
    assert!(rig.alpha.requests().is_empty() && rig.beta.requests().is_empty());
    // The rules never ran: nothing was counted as a denial.
    let metrics = rig.metrics().await;
    assert!(
        metrics.contains("podgate_mcp_denied_total{tenant=\"t1\",app=\"mcp\"} 0\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn tbac_rules_follow_the_token_not_the_session() {
    let rig = Rig::start(Some(&roles())).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    assert_eq!(dev.list(&session).await.len(), 2);
    // The same session id with an admin's token is judged by the admin's claims, and back.
    let admin = rig.client(&json!({"roles": ["admin"]}));
    assert_eq!(admin.list(&session).await.len(), 3);
    assert_eq!(dev.list(&session).await.len(), 2);
}

#[tokio::test]
async fn tbac_requires_identity() {
    let podgate = Podgate::start().await;
    let key = Signer::es256("k");
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let servers = [server("alpha", unused)];
    let rules = json!([{"tools": ["alpha__x"], "allow": {"roles": ["a"]}}]);
    let plain = |chain_jwt_first: bool| {
        let base = app("mcp", &["mcp.test"], &[serving("r1", unused)]);
        let config = json!({"servers": servers, "tool_access": rules});
        let mut declared = if chain_jwt_first {
            with_middleware(
                with_jwt_auth(base, jwt_config(&key)),
                "mcp",
                "mcp_gateway",
                config,
            )
        } else {
            with_jwt_auth(
                with_middleware(base, "mcp", "mcp_gateway", config),
                jwt_config(&key),
            )
        };
        declared["tenant"] = json!("t1");
        declared
    };
    let mut no_jwt = with_middleware(
        app("mcp", &["mcp.test"], &[serving("r1", unused)]),
        "mcp",
        "mcp_gateway",
        json!({"servers": servers, "tool_access": [{"tools": ["alpha__x"], "allow": {"roles": ["a"]}}]}),
    );
    no_jwt["tenant"] = json!("t1");
    for (declared, why) in [
        (&no_jwt, "no jwt_auth"),
        (&plain(false), "jwt_auth after the gateway"),
    ] {
        let answer = podgate
            .push_snapshot(&budgeted(1, std::slice::from_ref(declared), BIG_BUDGET))
            .await;
        assert_eq!(answer.status, 422, "{why}: {answer:?}");
        assert!(
            answer.body.contains("tool_access_requires_identity"),
            "{why}: {}",
            answer.body
        );
    }
    // An empty `tool_access` needs the identity too; without `tool_access` the gateway does not.
    let mut empty = no_jwt.clone();
    empty["middlewares"][0]["config"]["tool_access"] = json!([]);
    assert_eq!(
        podgate
            .push_snapshot(&budgeted(1, &[empty], BIG_BUDGET))
            .await
            .status,
        422
    );
    let mut open = no_jwt.clone();
    open["middlewares"][0]["config"]
        .as_object_mut()
        .expect("config")
        .remove("tool_access");
    push(&podgate, &budgeted(1, &[open], BIG_BUDGET)).await;
    // With a `jwt_auth` before it, the snapshot is accepted.
    push(&podgate, &budgeted(2, &[plain(true)], BIG_BUDGET)).await;
}

#[tokio::test]
async fn tbac_rule_shapes_rejected() {
    let podgate = Podgate::start().await;
    let key = Signer::es256("k");
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let servers = [server("alpha", unused)];
    let ok = json!({"roles": ["dev"]});
    for (version, bad) in (1_u64..).zip([
        json!([{"tools": ["read"], "allow": ok}]),
        json!([{"tools": ["gamma__read"], "allow": ok}]),
        json!([{"tools": ["alpha__re*"], "allow": ok}]),
        json!([{"tools": [], "allow": ok}]),
        json!([{"tools": ["alpha__read"], "allow": {}}]),
        json!([{"tools": ["alpha__read"], "allow": {"roles": []}}]),
        json!([{"tools": ["alpha__read"], "allow": {"roles": [""]}}]),
        json!([{"tools": ["alpha__read"], "allow": {"roles": [1]}}]),
        json!([{"tools": ["alpha__read"], "allow": ok, "extra": true}]),
    ]) {
        let declared = app_of("mcp", "mcp.test", &servers, Some(&bad), &key);
        let answer = podgate
            .push_snapshot(&budgeted(version, &[declared], BIG_BUDGET))
            .await;
        assert_eq!(answer.status, 422, "{bad}: {answer:?}");
        assert!(
            answer.body.contains("invalid_middleware"),
            "{bad}: {}",
            answer.body
        );
    }
    let good = json!([{"tools": ["alpha__read", "alpha__*"], "allow": ok}]);
    let declared = app_of("mcp", "mcp.test", &servers, Some(&good), &key);
    push(&podgate, &budgeted(100, &[declared], BIG_BUDGET)).await;
}

/// The `kind`s of the posture changes of planning `declared` as version 2.
async fn plan(rig: &Rig, rules: Option<&Value>) -> Vec<String> {
    let declared = app_of("mcp", "mcp.test", &rig.servers(), rules, &rig.key);
    let answer = rig
        .podgate
        .admin_post("/v1/snapshot/plan", &budgeted(2, &[declared], BIG_BUDGET))
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    answer.json()["posture_changes"]
        .as_array()
        .expect("list")
        .iter()
        .map(|change| change["kind"].as_str().expect("kind").to_owned())
        .collect()
}

#[tokio::test]
async fn tbac_widening_is_a_posture_change() {
    let base = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&base)).await;
    for (wider, why) in [
        (
            json!([{"tools": ["alpha__read", "alpha__search"], "allow": {"roles": ["dev"]}}]),
            "a tool",
        ),
        (
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev", "ops"]}}]),
            "a value",
        ),
        (
            json!([{"tools": ["alpha__*"], "allow": {"roles": ["dev"]}}]),
            "a wildcard",
        ),
        (
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}},
                   {"tools": ["beta__search"], "allow": {"roles": ["dev"]}}]),
            "a rule",
        ),
    ] {
        assert_eq!(
            plan(&rig, Some(&wider)).await,
            ["mcp_tool_access_widened"],
            "{why}"
        );
    }
    // The same, tighter and an empty `tool_access` are not listed.
    for (same, why) in [
        (base.clone(), "the same"),
        (
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"], "org": ["acme"]}}]),
            "a claim added",
        ),
        (json!([]), "no rules"),
    ] {
        assert!(plan(&rig, Some(&same)).await.is_empty(), "{why}");
    }
}

#[tokio::test]
async fn tbac_removing_rules_is_a_posture_change() {
    let base = json!([{"tools": ["alpha__read"], "allow": {"roles": ["dev"]}}]);
    let rig = Rig::start(Some(&base)).await;
    assert_eq!(plan(&rig, None).await, ["mcp_tool_access_removed"]);
    // Adding `tool_access` to a gateway that had none tightens it.
    let open = Rig::start(None).await;
    assert!(plan(&open, Some(&base)).await.is_empty());
}

#[tokio::test]
async fn tbac_explain_shows_rules() {
    let rig = Rig::start(Some(&roles())).await;
    let answer = rig
        .podgate
        .admin_get("/v1/explain?url=http://mcp.test/mcp&method=POST")
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let explained = answer.json();
    let gateway = explained["pipeline"]
        .as_array()
        .expect("pipeline")
        .iter()
        .find(|stage| stage["type"] == "mcp_gateway")
        .unwrap_or_else(|| panic!("no mcp_gateway in {explained}"));
    assert_eq!(gateway["tool_access"], roles());
    let open = Rig::start(None).await;
    let explained = open
        .podgate
        .admin_get("/v1/explain?url=http://mcp.test/mcp&method=POST")
        .await
        .json();
    let gateway = explained["pipeline"]
        .as_array()
        .expect("pipeline")
        .iter()
        .find(|stage| stage["type"] == "mcp_gateway")
        .unwrap_or_else(|| panic!("no mcp_gateway in {explained}"));
    assert_eq!(gateway["tool_access"], Value::Null);
}

#[tokio::test]
async fn tbac_denied_counted() {
    let rig = Rig::start(Some(&roles())).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"], "sub": "ann"})).await;
    dev.list(&session).await;
    // Two denials (a server the caller reaches nothing of, and one tool it may not call) and
    // two names that lead nowhere for everyone.
    for name in ["beta__search", "beta__only-beta"] {
        dev.call(&session, name, json!({})).await;
    }
    for name in ["gamma__search", "alpha__nothing"] {
        dev.call(&session, name, json!({})).await;
    }
    let metrics = rig.metrics().await;
    assert!(
        metrics.contains("# TYPE podgate_mcp_denied_total counter\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("podgate_mcp_denied_total{tenant=\"t1\",app=\"mcp\"} 2\n"),
        "{metrics}"
    );
    assert!(!metrics.contains("ann"), "the subject is not a label");
}

#[tokio::test]
async fn tbac_denied_counter_series_cap() {
    let rig = Rig::start_with(Some(&roles()), &[("METRICS_SERIES_PER_TENANT", "1")]).await;
    let one = app_of("mcp", "mcp.test", &rig.servers(), Some(&roles()), &rig.key);
    let two = app_of(
        "mcp2",
        "mcp2.test",
        &rig.servers(),
        Some(&roles()),
        &rig.key,
    );
    let three = app_of(
        "mcp3",
        "mcp3.test",
        &rig.servers(),
        Some(&roles()),
        &rig.key,
    );
    push(&rig.podgate, &budgeted(2, &[one, two, three], BIG_BUDGET)).await;
    for host in ["mcp2.test", "mcp3.test"] {
        let client = Client::new(&rig.podgate, host)
            .with_token(&token(&rig.key, &json!({"roles": ["dev"]})));
        let session = client.initialize().await;
        client.call(&session, "beta__search", json!({})).await;
    }
    let metrics = rig.metrics().await;
    let series: Vec<&str> = metrics
        .lines()
        .filter(|line| line.starts_with("podgate_mcp_denied_total{"))
        .collect();
    assert_eq!(
        series,
        [
            "podgate_mcp_denied_total{tenant=\"t1\",app=\"mcp\"} 0",
            "podgate_mcp_denied_total{tenant=\"t1\",app=\"other\"} 2",
        ]
    );
}

#[tokio::test]
async fn tbac_unreachable_server_is_not_dialled() {
    // A caller with no rule on beta cannot tell it exists: beta is never asked, and a call under
    // its name is answered as a name nobody registered.
    let rules = json!([
        {"tools": ["alpha__read"], "allow": {"roles": ["dev"]}},
        {"tools": ["beta__search"], "allow": {"roles": ["admin"]}},
    ]);
    let rig = Rig::start(Some(&rules)).await;
    let (dev, session) = rig.session(&json!({"roles": ["dev"]})).await;
    let missing = raw_call(&dev, &session, "gamma__search").await;
    assert_eq!(raw_call(&dev, &session, "beta__search").await, missing);
    assert_eq!(raw_call(&dev, &session, "beta__whatever").await, missing);
    assert!(rig.beta.requests().is_empty());
}
