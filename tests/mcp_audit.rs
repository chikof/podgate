//! The MCP audit log and its replay through the real binary: one record for every
//! `tools/call` of an `mcp_gateway`, what a record holds and never holds, who can read it, the
//! file sink, and the operator's replay. The record, the redaction and the ring bounds are
//! unit-tested in `src/mcp_audit.rs`; the same test names appear there.

mod common;

#[path = "fixtures/mcp/fake.rs"]
mod fake;
#[path = "fixtures/jwt/signer.rs"]
mod signer;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, app, serving, with_jwt_auth, with_middleware};
use fake::{
    BIG_BUDGET, Behavior, Client, Fake, ONE_CALL, Out, Seen, budgeted, gateway_app, push,
    refused_addr, server, tool_object,
};
use podgate::Config;
use serde_json::{Value, json};
use signer::{Signer, now};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

// ---- helpers -------------------------------------------------------------------------------

/// A temp directory removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "podgate-mcp-audit-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn text(&self, name: &str) -> String {
        self.file(name).to_str().expect("utf-8 path").to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

fn json_out(body: String) -> (Duration, Out) {
    (
        Duration::ZERO,
        Out::Json {
            status: 200,
            content_type: "application/json",
            headers: Vec::new(),
            body,
        },
    )
}

/// A tool as a server lists it; `hint` is its `annotations.readOnlyHint`.
fn tool(name: &str, hint: Option<bool>) -> Value {
    let mut object = tool_object(name);
    if let Some(hint) = hint {
        object["annotations"] = json!({"readOnlyHint": hint});
    }
    object
}

/// A fake server over `behavior` whose tool `oops` answers `isError: true` with a text that must
/// never reach the audit, and whose tool `fail` answers a JSON-RPC error.
async fn quirky(behavior: &Arc<Behavior>) -> Fake {
    let behavior = Arc::clone(behavior);
    Fake::start(move |seen: &Seen| {
        let request = seen.json();
        if request["method"] == "tools/call" {
            let id = request["id"].to_string();
            match request["params"]["name"].as_str() {
                Some("oops") => {
                    return json_out(format!(
                        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"RESULT-NEEDLE"}}],"isError":true}}}}"#
                    ));
                }
                Some("fail") => {
                    return json_out(format!(
                        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32000,"message":"the server says no"}}}}"#
                    ));
                }
                _ => {}
            }
        }
        behavior.answer(seen)
    })
    .await
}

/// The tools most tests list: a read-only `search`, a `write` with no hint, a `danger` hinted
/// `false`, and the two quirky ones.
fn alpha_tools() -> Vec<Value> {
    vec![
        tool("search", Some(true)),
        tool("write", None),
        tool("danger", Some(false)),
        tool("oops", None),
        tool("fail", None),
    ]
}

/// A running daemon with one gateway app `mcp` (`mcp.test`, tenant `t1`, middleware `mcp`) over
/// `alpha`, with `extra` as more of the gateway's fields.
async fn rig(extra: &Value, env: &[(&str, &str)]) -> (Podgate, Fake, Client) {
    let podgate = Podgate::start_with_env(env).await;
    let alpha = quirky(&Behavior::with_tools("alpha", alpha_tools())).await;
    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", alpha.addr)],
        extra,
    );
    push(&podgate, &budgeted(1, &[declared], BIG_BUDGET)).await;
    let client = Client::new(&podgate, "mcp.test");
    (podgate, alpha, client)
}

/// `GET /v1/apps/{app}/mcp/audit{query}`, which must answer `200`.
async fn audit(podgate: &Podgate, app: &str, query: &str) -> Value {
    let answer = podgate
        .admin_get(&format!("/v1/apps/{app}/mcp/audit{query}"))
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    answer.json()
}

fn records(listed: &Value) -> Vec<Value> {
    listed["records"].as_array().expect("records").clone()
}

async fn replay(podgate: &Podgate, app: &str, seq: u64, query: &str) -> Response {
    podgate
        .admin_post(
            &format!("/v1/apps/{app}/mcp/audit/{seq}/replay{query}"),
            &json!({}),
        )
        .await
}

fn is_hex16(text: &str) -> bool {
    text.len() == 16 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// ---- JWT: who called -----------------------------------------------------------------------

fn token(key: &Signer, claims: &Value) -> String {
    let mut all = json!({"sub": "ann", "exp": now() + 600});
    if let (Some(all), Some(extra)) = (all.as_object_mut(), claims.as_object()) {
        all.extend(extra.clone());
    }
    key.sign("ES256", &json!({}), &all)
}

/// An app of tenant `t1` for `mcp.test` whose chain is `jwt_auth` then a gateway over `servers`
/// with `tool_access` `rules` (none: absent) and `extra`.
fn jwt_app(servers: &[Value], rules: Option<&Value>, key: &Signer, extra: &Value) -> Value {
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let config = json!({"keys": {"keys": [key.jwk()]}, "algorithms": ["ES256"]});
    let base = with_jwt_auth(app("mcp", &["mcp.test"], &[serving("r1", unused)]), config);
    let mut gateway = json!({ "servers": servers });
    if let Some(rules) = rules {
        gateway["tool_access"] = rules.clone();
    }
    if let (Some(gateway), Some(extra)) = (gateway.as_object_mut(), extra.as_object()) {
        gateway.extend(extra.clone());
    }
    let mut declared = with_middleware(base, "mcp", "mcp_gateway", gateway);
    declared["tenant"] = json!("t1");
    declared
}

// ---- what a record is ----------------------------------------------------------------------

#[tokio::test]
async fn mcp_audit_records_each_outcome() {
    let podgate = Podgate::start().await;
    let key = Signer::es256("k");
    let alpha = quirky(&Behavior::with_tools("alpha", alpha_tools())).await;
    let servers = [server("alpha", alpha.addr), server("beta", refused_addr())];
    let rules = json!([{"tools": ["alpha__*", "beta__*"], "allow": {"roles": ["dev"]}}]);
    push(
        &podgate,
        &budgeted(
            1,
            &[jwt_app(&servers, Some(&rules), &key, &json!({}))],
            BIG_BUDGET,
        ),
    )
    .await;
    let dev =
        Client::new(&podgate, "mcp.test").with_token(&token(&key, &json!({"roles": ["dev"]})));
    let ops =
        Client::new(&podgate, "mcp.test").with_token(&token(&key, &json!({"roles": ["ops"]})));
    let session = dev.initialize().await;
    let other = ops.initialize().await;

    dev.call(&session, "alpha__search", json!({"q": "cats"}))
        .await;
    dev.call(&session, "alpha__oops", json!({})).await;
    dev.call(&session, "alpha__fail", json!({})).await;
    ops.call(&other, "alpha__search", json!({})).await;
    dev.call(&session, "beta__anything", json!({})).await;

    let listed = audit(&podgate, "mcp", "").await;
    let all = records(&listed);
    assert_eq!(all.len(), 5, "{listed}");
    let seqs: Vec<u64> = all.iter().filter_map(|r| r["seq"].as_u64()).collect();
    assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]), "{seqs:?}");

    let (ok, tool_error, rpc_error, denied, failed) = (&all[0], &all[1], &all[2], &all[3], &all[4]);
    assert_eq!(ok["outcome"], "ok");
    assert_eq!(ok["tenant"], "t1");
    assert_eq!(ok["app"], "mcp");
    assert_eq!(ok["middleware"], "mcp");
    assert!(
        ok["router"]
            .as_str()
            .is_some_and(|router| !router.is_empty())
    );
    assert_eq!(ok["name"], "alpha__search");
    assert_eq!(ok["server"], "alpha");
    assert_eq!(ok["tool"], "search");
    assert_eq!(ok["sub"], "ann");
    assert!(is_hex16(ok["session"].as_str().expect("session")), "{ok}");
    assert!(
        ok["at_unix_ms"]
            .as_u64()
            .is_some_and(|at| at > 1_700_000_000_000)
    );
    assert!(ok["duration_ms"].is_u64());
    assert!(ok["request_bytes"].as_u64().is_some_and(|bytes| bytes > 0));
    assert!(ok["response_bytes"].as_u64().is_some_and(|bytes| bytes > 0));
    assert!(ok["reason"].is_null() && ok["rpc_code"].is_null() && ok["replay_of"].is_null());

    assert_eq!(tool_error["outcome"], "tool_error", "{tool_error}");
    assert_eq!(tool_error["tool"], "oops");
    assert_eq!(rpc_error["outcome"], "rpc_error", "{rpc_error}");
    assert_eq!(rpc_error["reason"], "server");
    assert_eq!(rpc_error["rpc_code"], -32000);
    assert_eq!(denied["outcome"], "denied", "{denied}");
    assert!(denied["server"].is_null() && denied["tool"].is_null());
    assert_eq!(denied["name"], "alpha__search");
    assert_eq!(failed["outcome"], "upstream_failed", "{failed}");
    assert_eq!(failed["reason"], "connect");
    assert_eq!(failed["server"], "beta");
    assert!(failed["tool"].is_null());
    assert_eq!(
        alpha.calls("tools/call").len(),
        3,
        "the denied call dialled nothing"
    );
}

#[tokio::test]
async fn mcp_audit_records_unresolved_calls() {
    let (podgate, alpha, client) = rig(&json!({}), &[]).await;
    let session = client.initialize().await;
    client.list(&session).await;
    let long = "x".repeat(300);
    for name in ["nothing", "gamma__search", "alpha__missing", long.as_str()] {
        let answer = client.call(&session, name, json!({})).await;
        assert_eq!(answer["error"]["code"], -32602, "{name}: {answer}");
    }
    let bad = client
        .rpc(&session, "tools/call", json!({"arguments": {}}))
        .await;
    assert_eq!(bad["error"]["code"], -32602);

    let all = records(&audit(&podgate, "mcp", "").await);
    assert_eq!(all.len(), 5);
    for record in &all[..4] {
        assert_eq!(record["outcome"], "rpc_error", "{record}");
        assert_eq!(record["reason"], "unknown_tool");
        assert!(record["server"].is_null() && record["tool"].is_null());
    }
    assert_eq!(all[3]["name"].as_str().map(str::len), Some(128));
    assert_eq!(all[4]["reason"], "invalid_params");
    assert_eq!(all[4]["name"], "");
    assert!(alpha.calls("tools/call").is_empty(), "nothing was dialled");
}

#[tokio::test]
async fn mcp_audit_sub_from_verified_claims_only() {
    let podgate = Podgate::start().await;
    let key = Signer::es256("k");
    let alpha = quirky(&Behavior::with_tools("alpha", alpha_tools())).await;
    let servers = [server("alpha", alpha.addr)];
    let secured = jwt_app(&servers, None, &key, &json!({}));
    let mut plain = gateway_app("open", "t1", "open.test", &servers, &json!({}));
    plain["revisions"] = secured["revisions"].clone();
    push(&podgate, &budgeted(1, &[secured, plain], BIG_BUDGET)).await;

    let verified =
        Client::new(&podgate, "mcp.test").with_token(&token(&key, &json!({"sub": "ann"})));
    let session = verified.initialize().await;
    // A header the client sends says nothing about who it is.
    let forged = verified
        .post(
            Some(&session),
            &[
                ("MCP-Protocol-Version", "2025-11-25"),
                ("X-User", "mallory"),
                ("X-Forwarded-User", "mallory"),
            ],
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "alpha__search", "arguments": {}}}),
        )
        .await;
    assert_eq!(forged.status, 200, "{forged:?}");
    // A gateway with no `jwt_auth` before it has no verified claims, whatever the client sends.
    let open = Client::new(&podgate, "open.test").with_token("not-a-token");
    let open_session = open.initialize().await;
    open.call(&open_session, "alpha__search", json!({})).await;
    open.post(
        Some(&open_session),
        &[
            ("MCP-Protocol-Version", "2025-11-25"),
            ("X-User", "mallory"),
        ],
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "alpha__search", "arguments": {}}}),
    )
    .await;

    let secured = records(&audit(&podgate, "mcp", "").await);
    assert_eq!(secured.len(), 1);
    assert_eq!(secured[0]["sub"], "ann");
    let open = records(&audit(&podgate, "open", "").await);
    assert_eq!(open.len(), 2);
    assert!(
        open.iter().all(|record| record["sub"].is_null()),
        "{open:?}"
    );
    assert!(
        !audit(&podgate, "open", "")
            .await
            .to_string()
            .contains("mallory")
    );
}

#[tokio::test]
async fn mcp_audit_session_is_hashed() {
    let (podgate, _alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    let other = client.initialize().await;
    client.call(&session, "alpha__search", json!({})).await;
    client.call(&session, "alpha__search", json!({})).await;
    client.call(&other, "alpha__search", json!({})).await;
    let listed = audit(&podgate, "mcp", "").await;
    let all = records(&listed);
    let hash = |at: usize| all[at]["session"].as_str().expect("session").to_owned();
    assert!(is_hex16(&hash(0)));
    assert_eq!(hash(0), hash(1), "one session is one hash");
    assert_ne!(hash(0), hash(2));
    for id in [&session, &other] {
        assert!(
            !listed.to_string().contains(id.as_str()),
            "the id is never kept"
        );
        assert!(!hash(0).contains(&id[..8]));
    }
}

// ---- arguments and results -----------------------------------------------------------------

#[tokio::test]
async fn mcp_audit_arguments_off_by_default() {
    let (podgate, _alpha, client) = rig(&json!({}), &[]).await;
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "ARGUMENT-NEEDLE"}))
        .await;
    client
        .rpc(&session, "tools/call", json!({"name": "alpha__search"}))
        .await;
    let listed = audit(&podgate, "mcp", "").await;
    let all = records(&listed);
    assert_eq!(all[0]["arguments_state"], "not_recorded");
    assert!(all[0]["arguments"].is_null());
    assert_eq!(all[1]["arguments_state"], "absent");
    assert!(!listed.to_string().contains("ARGUMENT-NEEDLE"));
}

#[tokio::test]
async fn mcp_audit_arguments_recorded_when_opted_in() {
    let (podgate, _alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    client
        .call(
            &session,
            "alpha__search",
            json!({"q": "cats", "api_key": "KEY-NEEDLE",
                   "nested": [{"Password": "PW-NEEDLE", "keep": 1}]}),
        )
        .await;
    client
        .call(&session, "alpha__search", json!({"q": "dogs"}))
        .await;
    client
        .call(
            &session,
            "alpha__search",
            json!({"q": "x".repeat(17 * 1024)}),
        )
        .await;
    let listed = audit(&podgate, "mcp", "").await;
    let all = records(&listed);
    assert_eq!(all[0]["arguments_state"], "redacted", "{}", all[0]);
    assert_eq!(all[0]["arguments"]["q"], "cats");
    assert_eq!(all[0]["arguments"]["api_key"], "[redacted]");
    assert_eq!(all[0]["arguments"]["nested"][0]["Password"], "[redacted]");
    assert_eq!(all[0]["arguments"]["nested"][0]["keep"], 1);
    assert_eq!(all[1]["arguments_state"], "kept");
    assert_eq!(all[1]["arguments"], json!({"q": "dogs"}));
    assert_eq!(all[2]["arguments_state"], "too_large");
    assert!(all[2]["arguments"].is_null());
    let text = listed.to_string();
    assert!(!text.contains("KEY-NEEDLE") && !text.contains("PW-NEEDLE"));
    assert!(
        all[2]["request_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 17 * 1024)
    );
}

#[tokio::test]
async fn mcp_audit_never_stores_results() {
    let dir = Dir::new();
    let (podgate, _alpha, client) = rig(
        &json!({"record_arguments": true}),
        &[("MCP_AUDIT_FILE", &dir.text("audit.log"))],
    )
    .await;
    let session = client.initialize().await;
    let answer = client
        .call(&session, "alpha__search", json!({"q": "cats"}))
        .await;
    assert_eq!(answer["result"]["content"][0]["text"], "alpha:search");
    let oops = client.call(&session, "alpha__oops", json!({})).await;
    assert!(oops.to_string().contains("RESULT-NEEDLE"));
    let listed = audit(&podgate, "mcp", "").await;
    wait_for_lines(&dir.file("audit.log"), 2).await;
    let file = std::fs::read_to_string(dir.file("audit.log")).expect("audit file");
    for text in [listed.to_string(), file] {
        assert!(!text.contains("alpha:search"), "{text}");
        assert!(!text.contains("RESULT-NEEDLE"), "{text}");
        assert!(!text.contains("structuredContent"), "{text}");
    }
}

// ---- reading it ----------------------------------------------------------------------------

#[tokio::test]
async fn mcp_audit_list_paging() {
    let (podgate, _alpha, client) = rig(&json!({}), &[]).await;
    let session = client.initialize().await;
    for _ in 0..5 {
        client.call(&session, "alpha__search", json!({})).await;
    }
    let first = audit(&podgate, "mcp", "?limit=2").await;
    let boot = first["boot_id"].as_str().expect("boot id").to_owned();
    assert!(!boot.is_empty());
    let seqs = |listed: &Value| -> Vec<u64> {
        records(listed)
            .iter()
            .filter_map(|record| record["seq"].as_u64())
            .collect()
    };
    let one = seqs(&first);
    assert_eq!(one.len(), 2);
    assert_eq!(first["next_after"], one[1]);
    assert_eq!(first["evicted_through"], 0);
    let second = audit(&podgate, "mcp", &format!("?after={}&limit=2", one[1])).await;
    let two = seqs(&second);
    assert_eq!(two, [one[1] + 1, one[1] + 2], "no gap and no repeat");
    assert_eq!(second["boot_id"], boot);
    let last = audit(&podgate, "mcp", &format!("?after={}", two[1])).await;
    assert_eq!(seqs(&last), [two[1] + 1]);
    let end = audit(&podgate, "mcp", &format!("?after={}", two[1] + 1)).await;
    assert!(records(&end).is_empty());
    assert_eq!(end["next_after"], two[1] + 1, "the cursor stays");
    for bad in [
        "?limit=0",
        "?limit=1001",
        "?limit=x",
        "?after=x",
        "?after=-1",
    ] {
        let answer = podgate
            .admin_get(&format!("/v1/apps/mcp/mcp/audit{bad}"))
            .await;
        assert_eq!(answer.status, 400, "{bad}: {answer:?}");
    }
    let unknown = podgate.admin_get("/v1/apps/nothing/mcp/audit").await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.json()["error"], "not found");
}

#[tokio::test]
async fn mcp_audit_removed_app_drops_ring() {
    let (podgate, alpha, client) = rig(&json!({}), &[]).await;
    let session = client.initialize().await;
    client.call(&session, "alpha__search", json!({})).await;
    assert_eq!(records(&audit(&podgate, "mcp", "").await).len(), 1);

    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let other = app("other", &["other.test"], &[serving("r1", unused)]);
    push(&podgate, &budgeted(2, &[other], BIG_BUDGET)).await;
    assert_eq!(
        podgate.admin_get("/v1/apps/mcp/mcp/audit").await.status,
        404
    );

    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", alpha.addr)],
        &json!({}),
    );
    push(&podgate, &budgeted(3, &[declared], BIG_BUDGET)).await;
    assert!(
        records(&audit(&podgate, "mcp", "").await).is_empty(),
        "an app that comes back starts empty"
    );
}

/// One `GET` on the dashboard listener, or a `POST` when `post`.
async fn dashboard(addr: SocketAddr, method: &str, target: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("an answer")
        .expect("read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status");
    (status, text)
}

#[tokio::test]
async fn mcp_audit_not_on_dashboard() {
    let mut started = None;
    for _ in 0..5 {
        let ports = common::free_ports(3);
        let addr = SocketAddr::from(([127, 0, 0, 1], ports[2]));
        let env = [("DASHBOARD_ADDR", addr.to_string())];
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        if let Ok(podgate) = Podgate::try_start(&env, (ports[0], ports[1]), &[], false).await {
            started = Some((podgate, addr));
            break;
        }
    }
    let (podgate, addr) = started.expect("podgate with a dashboard");
    let alpha = quirky(&Behavior::with_tools("alpha", alpha_tools())).await;
    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", alpha.addr)],
        &json!({"record_arguments": true}),
    );
    push(&podgate, &budgeted(1, &[declared], BIG_BUDGET)).await;
    let client = Client::new(&podgate, "mcp.test");
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "DASH-NEEDLE"}))
        .await;
    // The log has the record and nothing reaches it from the dashboard.
    assert_eq!(records(&audit(&podgate, "mcp", "").await).len(), 1);
    for path in [
        "/v1/apps/mcp/mcp/audit",
        "/v1/apps/mcp/mcp/audit/1/replay",
        "/api/mcp/audit",
        "/api/audit",
        "/api/overview/mcp/audit",
    ] {
        for method in ["GET", "POST"] {
            let (status, text) = dashboard(addr, method, path).await;
            assert_eq!(status, 404, "{method} {path}: {text}");
            assert!(!text.contains("DASH-NEEDLE") && !text.contains("alpha__search"));
        }
    }
    // The overview the dashboard shows carries the configuration, never a call.
    let (status, text) = dashboard(addr, "GET", "/api/overview").await;
    assert_eq!(status, 200);
    assert!(
        !text.contains("DASH-NEEDLE") && !text.contains("\"seq\""),
        "{text}"
    );
    // Nor does the event feed.
    let events = podgate.admin_get("/v1/events?after=0&timeout_secs=1").await;
    assert_eq!(events.status, 200);
    for word in ["audit", "alpha__search", "DASH-NEEDLE", "tools/call"] {
        assert!(!events.body.contains(word), "{word}: {}", events.body);
    }
}

#[tokio::test]
async fn mcp_audit_admin_socket_only() {
    let (podgate, _alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "PROXY-NEEDLE"}))
        .await;
    assert_eq!(records(&audit(&podgate, "mcp", "").await).len(), 1);
    // The proxy listener never serves the routes, under the app's own host or any other.
    for host in ["mcp.test", "x", "localhost"] {
        for path in ["/v1/apps/mcp/mcp/audit", "/v1/apps/mcp/mcp/audit/1/replay"] {
            let answer = podgate.get(host, path).await;
            assert_ne!(answer.status, 200, "{host}{path}: {answer:?}");
            assert!(
                !answer.body.contains("PROXY-NEEDLE") && !answer.body.contains("boot_id"),
                "{host}{path}: {answer:?}"
            );
        }
    }
    let mut stream = TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect");
    stream
        .write_all(
            b"POST /v1/apps/mcp/mcp/audit/1/replay HTTP/1.1\r\nHost: mcp.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
        .await
        .expect("write");
    let mut raw = Vec::new();
    drop(timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await);
    assert!(!String::from_utf8_lossy(&raw).contains("audit_seq"));
}

// ---- the file ------------------------------------------------------------------------------

async fn wait_for_lines(path: &Path, count: usize) -> Vec<String> {
    for _ in 0..200 {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= count {
            return lines;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("{} has fewer than {count} lines", path.display());
}

#[tokio::test]
async fn mcp_audit_file_sink() {
    use std::os::unix::fs::PermissionsExt;

    let dir = Dir::new();
    let file = dir.file("audit.log");
    let (podgate, _alpha, client) =
        rig(&json!({}), &[("MCP_AUDIT_FILE", &dir.text("audit.log"))]).await;
    let session = client.initialize().await;
    for name in ["alpha__search", "alpha__oops", "alpha__fail"] {
        client.call(&session, name, json!({"q": "x"})).await;
    }
    let lines = wait_for_lines(&file, 3).await;
    let parsed: Vec<Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("one JSON object a line"))
        .collect();
    assert_eq!(
        parsed
            .iter()
            .map(|r| r["outcome"].clone())
            .collect::<Vec<_>>(),
        [json!("ok"), json!("tool_error"), json!("rpc_error")]
    );
    assert_eq!(
        parsed,
        records(&audit(&podgate, "mcp", "").await),
        "the file and the list hold the same records"
    );
    let mode = std::fs::metadata(&file)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "an operator's file");
    // The counter moves after the write returns.
    let mut metrics = String::new();
    for _ in 0..100 {
        metrics = podgate.admin_get("/metrics").await.body;
        if metrics.contains("podgate_mcp_audit_lines_total 3") {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        metrics.contains("podgate_mcp_audit_lines_total 3"),
        "{metrics}"
    );
    assert!(
        metrics.contains("podgate_mcp_audit_dropped_total 0"),
        "{metrics}"
    );
}

#[tokio::test]
async fn mcp_audit_sink_stall_does_not_slow_calls() {
    let dir = Dir::new();
    let fifo = dir.file("sink");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo")
            .success()
    );
    // Nobody reads the pipe, so the writer is stuck on its first write for the whole test.
    let (podgate, _alpha, client) = rig(&json!({}), &[("MCP_AUDIT_FILE", &dir.text("sink"))]).await;
    let client = Arc::new(client);
    let session = Arc::new(client.initialize().await);
    let total = 1_300;
    let started = Instant::now();
    let mut sent = 0;
    while sent < total {
        // Each call reserves its result cap of the tenant's buffer budget: 8 fit.
        let batch = 8.min(total - sent);
        let answers = futures_util::future::join_all((0..batch).map(|_| {
            let (client, session) = (Arc::clone(&client), Arc::clone(&session));
            async move { client.call(&session, "alpha__search", json!({})).await }
        }))
        .await;
        for answer in answers {
            assert_eq!(
                answer["result"]["content"][0]["text"], "alpha:search",
                "{answer}"
            );
        }
        sent += batch;
    }
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{total} calls took {:?}",
        started.elapsed()
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    let dropped: u64 = metrics
        .lines()
        .find_map(|line| line.strip_prefix("podgate_mcp_audit_dropped_total "))
        .and_then(|value| value.trim().parse().ok())
        .expect("the drop counter is in /metrics");
    assert!(
        dropped >= 100,
        "{total} lines into a 1024 queue behind a stuck sink must drop, dropped {dropped}"
    );
    let listed = audit(&podgate, "mcp", "?limit=1000").await;
    assert_eq!(records(&listed).len(), 1000, "the ring is not the file");
}

#[tokio::test]
async fn mcp_audit_bad_file_stops_startup() {
    let dir = Dir::new();
    let missing_parent = dir.file("no/such/dir/audit.log");
    for (path, why) in [
        (dir.0.clone(), "a directory"),
        (missing_parent, "a missing parent"),
    ] {
        let config = Config {
            mcp_audit_file: Some(path.clone()),
            ..Config::default()
        };
        let refused = config.mcp_audit_sink().expect_err(why);
        assert_eq!(refused.var, "MCP_AUDIT_FILE", "{why}");
        assert!(
            refused.to_string().contains("MCP_AUDIT_FILE"),
            "{why}: {refused}"
        );
        let ports = common::free_ports(2);
        let started = Podgate::try_start(
            &[("MCP_AUDIT_FILE", path.to_str().expect("utf-8 path"))],
            (ports[0], ports[1]),
            &[],
            false,
        )
        .await;
        assert!(
            started.is_err(),
            "podgate started with {why} as MCP_AUDIT_FILE"
        );
    }
    let fine = Config {
        mcp_audit_file: Some(dir.file("fine.log")),
        ..Config::default()
    };
    assert!(fine.mcp_audit_sink().expect("a new file").is_some());
    assert!(dir.file("fine.log").exists(), "checked by opening it");
    assert!(Config::default().mcp_audit_sink().expect("unset").is_none());
}

// ---- replay --------------------------------------------------------------------------------

#[tokio::test]
async fn mcp_replay_read_only_tool() {
    let (podgate, alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "cats"}))
        .await;
    let before = alpha.calls("tools/call").len();
    let answer = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["outcome"], "ok");
    assert_eq!(body["replay_of"], 1);
    assert_eq!(body["result"]["content"][0]["text"], "alpha:search");
    assert_eq!(
        body["result"]["structuredContent"]["arguments"],
        json!({"q": "cats"})
    );
    let calls = alpha.calls("tools/call");
    assert_eq!(calls.len(), before + 1);
    let sent = calls[calls.len() - 1].json();
    assert_eq!(sent["params"]["name"], "search", "the server's own name");
    assert_eq!(sent["params"]["arguments"], json!({"q": "cats"}));
    assert!(sent["params"].get("_meta").is_none());
}

#[tokio::test]
async fn mcp_replay_needs_force() {
    let (podgate, alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    for name in ["alpha__write", "alpha__danger"] {
        client.call(&session, name, json!({"x": 1})).await;
    }
    let sent = alpha.calls("tools/call").len();
    for seq in [1, 2] {
        let refused = replay(&podgate, "mcp", seq, "").await;
        assert_eq!(refused.status, 409, "{refused:?}");
        assert_eq!(refused.json()["code"], "needs_force");
        assert!(refused.json()["error"].is_string());
        let still = replay(&podgate, "mcp", seq, "?force=false").await;
        assert_eq!(still.status, 409);
    }
    assert_eq!(alpha.calls("tools/call").len(), sent, "nothing was sent");
    let forced = replay(&podgate, "mcp", 1, "?force=true").await;
    assert_eq!(forced.status, 200, "{forced:?}");
    assert_eq!(forced.json()["result"]["content"][0]["text"], "alpha:write");
    assert_eq!(alpha.calls("tools/call").len(), sent + 1);
    let bad = replay(&podgate, "mcp", 1, "?force=maybe").await;
    assert_eq!(bad.status, 400);
    assert_eq!(replay(&podgate, "mcp", 99, "").await.status, 404);
    assert_eq!(replay(&podgate, "nothing", 1, "").await.status, 404);
}

#[tokio::test]
async fn mcp_replay_redacted_arguments_422() {
    let (podgate, alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    client
        .call(
            &session,
            "alpha__search",
            json!({"q": "x", "token": "TOKEN-NEEDLE"}),
        )
        .await;
    client
        .call(
            &session,
            "alpha__search",
            json!({"q": "x".repeat(17 * 1024)}),
        )
        .await;
    client
        .call(&session, "alpha__search", json!({"q": "ok"}))
        .await;
    let sent = alpha.calls("tools/call").len();
    for seq in [1, 2] {
        let refused = replay(&podgate, "mcp", seq, "?force=true").await;
        assert_eq!(refused.status, 422, "{refused:?}");
        assert_eq!(refused.json()["code"], "redacted_arguments");
    }
    assert_eq!(alpha.calls("tools/call").len(), sent, "nothing was sent");
    assert_eq!(replay(&podgate, "mcp", 3, "").await.status, 200);

    // Arguments that were not recorded at all cannot be sent again either.
    let (podgate, _alpha, client) = rig(&json!({}), &[]).await;
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "x"}))
        .await;
    client
        .rpc(&session, "tools/call", json!({"name": "alpha__search"}))
        .await;
    let off = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(off.status, 422, "{off:?}");
    assert!(
        off.json()["error"]
            .as_str()
            .is_some_and(|text| text.contains("not recorded"))
    );
    // A call with no arguments has none to lose.
    assert_eq!(replay(&podgate, "mcp", 2, "").await.status, 200);
}

#[tokio::test]
async fn mcp_replay_refuses_a_call_that_never_reached_a_server() {
    let (podgate, alpha, client) = rig(&json!({"record_arguments": true}), &[]).await;
    let session = client.initialize().await;
    client.call(&session, "alpha__nothing", json!({})).await;
    client.call(&session, "gamma__x", json!({})).await;
    let sent = alpha.calls("tools/call").len();
    for seq in [1, 2] {
        let refused = replay(&podgate, "mcp", seq, "?force=true").await;
        assert_eq!(refused.status, 409, "{refused:?}");
        assert_eq!(refused.json()["code"], "not_replayable");
    }
    assert_eq!(alpha.calls("tools/call").len(), sent);
}

/// An operator file that denies `10.0.0.0/8` besides what the harness always denies.
fn policy(dir: &Dir) -> String {
    std::fs::write(
        dir.file("policy.json"),
        r#"{"deny": ["0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "10.0.0.0/8"]}"#,
    )
    .expect("write the policy");
    dir.text("policy.json")
}

#[tokio::test]
async fn mcp_replay_goes_through_upstream_policy() {
    let dir = Dir::new();
    let (podgate, alpha, client) = rig(
        &json!({"record_arguments": true}),
        &[("UPSTREAM_POLICY_FILE", &policy(&dir))],
    )
    .await;
    let session = client.initialize().await;
    client
        .call(&session, "alpha__search", json!({"q": "x"}))
        .await;
    assert_eq!(alpha.calls("tools/call").len(), 1);
    // The server's address is now one the operator forbids.
    let refused: SocketAddr = "10.255.255.1:9".parse().expect("addr");
    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", refused)],
        &json!({"record_arguments": true}),
    );
    push(&podgate, &budgeted(2, &[declared], BIG_BUDGET)).await;
    let answer = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(answer.status, 502, "{answer:?}");
    assert_eq!(answer.json()["error"], "replay failed: policy");
    assert_eq!(alpha.calls("tools/call").len(), 1, "nothing was dialled");
    let newest = records(&audit(&podgate, "mcp", "").await)
        .pop()
        .expect("the failed replay is audited");
    assert_eq!(newest["outcome"], "upstream_failed");
    assert_eq!(newest["reason"], "policy");
    assert_eq!(newest["replay_of"], 1);
}

#[tokio::test]
async fn mcp_replay_counts_against_tenant_budget() {
    let podgate = Podgate::start().await;
    let behavior = Behavior::with_tools("alpha", alpha_tools());
    behavior.call_delay_ms.store(700, Ordering::SeqCst);
    let alpha = quirky(&behavior).await;
    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", alpha.addr)],
        &json!({"record_arguments": true}),
    );
    // A buffer budget that holds one call, not two.
    push(
        &podgate,
        &budgeted(1, std::slice::from_ref(&declared), ONE_CALL),
    )
    .await;
    let client = Arc::new(Client::new(&podgate, "mcp.test"));
    let session = Arc::new(client.initialize().await);
    client.list(&session).await;
    client
        .call(&session, "alpha__search", json!({"q": "x"}))
        .await;
    let sent = alpha.calls("tools/call").len();

    let live = tokio::spawn({
        let (client, session) = (Arc::clone(&client), Arc::clone(&session));
        async move {
            client
                .call(&session, "alpha__search", json!({"q": "y"}))
                .await
        }
    });
    sleep(Duration::from_millis(250)).await;
    let busy = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(busy.status, 503, "{busy:?}");
    assert_eq!(busy.header("retry-after"), Some("1"));
    live.await.expect("the live call");
    assert_eq!(
        alpha.calls("tools/call").len(),
        sent + 1,
        "the replay sent nothing"
    );
    // The refused replay is audited before the slow live call finishes.
    let refused = records(&audit(&podgate, "mcp", "").await)
        .into_iter()
        .find(|record| record["replay_of"] == 1)
        .expect("the refused replay is audited");
    assert_eq!(refused["outcome"], "upstream_failed");
    assert_eq!(refused["reason"], "busy");
    // The charge is released: a replay of its own fits.
    assert_eq!(replay(&podgate, "mcp", 1, "").await.status, 200);

    // A tenant at its in-flight limit has no slot for a second replay, and nothing is sent for
    // it. (A client's call to the gateway takes no tenant slot: the chain answers it first.)
    let mut one_slot = budgeted(2, &[declared], BIG_BUDGET);
    one_slot["tenants"][0]["budget"]["max_inflight"] = json!(1);
    push(&podgate, &one_slot).await;
    let before = records(&audit(&podgate, "mcp", "?limit=1000").await).len();
    let sent = alpha.calls("tools/call").len();
    let (first, second) = tokio::join!(replay(&podgate, "mcp", 1, ""), async {
        sleep(Duration::from_millis(250)).await;
        replay(&podgate, "mcp", 1, "").await
    });
    assert_eq!(first.status, 200, "{first:?}");
    assert_eq!(second.status, 503, "{second:?}");
    assert_eq!(second.header("retry-after"), Some("1"));
    assert_eq!(alpha.calls("tools/call").len(), sent + 1);
    assert_eq!(
        records(&audit(&podgate, "mcp", "?limit=1000").await).len(),
        before + 1,
        "only the replay that was sent was audited"
    );
}

#[tokio::test]
async fn mcp_replay_is_audited() {
    let dir = Dir::new();
    let (podgate, _alpha, client) = rig(
        &json!({"record_arguments": true}),
        &[("MCP_AUDIT_FILE", &dir.text("audit.log"))],
    )
    .await;
    let session = client.initialize().await;
    client
        .call(
            &session,
            "alpha__search",
            json!({"q": "cats", "token": "T-NEEDLE"}),
        )
        .await;
    client
        .call(&session, "alpha__search", json!({"q": "cats"}))
        .await;
    let first = replay(&podgate, "mcp", 2, "").await;
    assert_eq!(first.status, 200, "{first:?}");
    let seq = first.json()["audit_seq"].as_u64().expect("seq");
    // A replay can be replayed, and says which it sends again.
    let second = replay(&podgate, "mcp", seq, "").await;
    assert_eq!(second.status, 200, "{second:?}");
    assert_eq!(second.json()["replay_of"], seq);

    let all = records(&audit(&podgate, "mcp", "").await);
    assert_eq!(all.len(), 4);
    let (replayed, again) = (&all[2], &all[3]);
    assert_eq!(replayed["seq"], seq);
    assert_eq!(replayed["replay_of"], 2);
    assert_eq!(replayed["outcome"], "ok");
    assert_eq!(replayed["name"], "alpha__search");
    assert_eq!(replayed["server"], "alpha");
    assert_eq!(replayed["tool"], "search");
    assert_eq!(replayed["arguments"], json!({"q": "cats"}));
    assert_eq!(replayed["arguments_state"], "kept");
    assert!(replayed["sub"].is_null() && replayed["session"].is_null());
    assert!(
        replayed["request_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert!(
        replayed["response_bytes"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(again["replay_of"], seq);
    // The file has them as well.
    let lines = wait_for_lines(&dir.file("audit.log"), 4).await;
    let last: Value = serde_json::from_str(&lines[3]).expect("json line");
    assert_eq!(last["replay_of"], seq);
    assert!(!lines.join("\n").contains("T-NEEDLE"));
}

#[tokio::test]
async fn mcp_replay_server_or_tool_gone() {
    let podgate = Podgate::start().await;
    let old = quirky(&Behavior::with_tools(
        "alpha",
        vec![tool("search", Some(true)), tool("legacy", Some(true))],
    ))
    .await;
    let extra = json!({"record_arguments": true});
    let v1 = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", old.addr)],
        &extra,
    );
    push(&podgate, &budgeted(1, &[v1], BIG_BUDGET)).await;
    let client = Client::new(&podgate, "mcp.test");
    let session = client.initialize().await;
    client.call(&session, "alpha__search", json!({})).await;
    client.call(&session, "alpha__legacy", json!({})).await;
    assert_eq!(replay(&podgate, "mcp", 2, "").await.status, 200);

    // The server stays and loses a tool.
    let newer = quirky(&Behavior::with_tools(
        "alpha",
        vec![tool("search", Some(true))],
    ))
    .await;
    let v2 = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", newer.addr)],
        &extra,
    );
    push(&podgate, &budgeted(2, &[v2], BIG_BUDGET)).await;
    let gone = replay(&podgate, "mcp", 2, "").await;
    assert_eq!(gone.status, 409, "{gone:?}");
    assert_eq!(gone.json()["code"], "tool_gone");
    assert_eq!(replay(&podgate, "mcp", 1, "").await.status, 200);

    // The server is out of the registry.
    let beta = quirky(&Behavior::with_tools(
        "beta",
        vec![tool("search", Some(true))],
    ))
    .await;
    let v3 = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("beta", beta.addr)],
        &extra,
    );
    push(&podgate, &budgeted(3, &[v3], BIG_BUDGET)).await;
    let gone = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(gone.status, 409, "{gone:?}");
    assert_eq!(gone.json()["code"], "server_gone");

    // The app no longer has the gateway.
    let unused: SocketAddr = "127.0.0.1:9".parse().expect("addr");
    let bare = app("mcp", &["mcp.test"], &[serving("r1", unused)]);
    push(&podgate, &budgeted(4, &[bare], BIG_BUDGET)).await;
    let gone = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(gone.status, 409, "{gone:?}");
    assert_eq!(gone.json()["code"], "gateway_gone");
    assert_eq!(
        beta.calls("tools/call").len(),
        0,
        "nothing was sent to beta"
    );
}

#[tokio::test]
async fn mcp_replay_asks_the_authorization_seam() {
    let podgate = Podgate::start().await;
    let key = Signer::es256("k");
    let alpha = quirky(&Behavior::with_tools("alpha", alpha_tools())).await;
    let servers = [server("alpha", alpha.addr)];
    let extra = json!({"record_arguments": true});
    let rules = json!([{"tools": ["alpha__*"], "allow": {"roles": ["dev"]}}]);
    push(
        &podgate,
        &budgeted(
            1,
            &[jwt_app(&servers, Some(&rules), &key, &extra)],
            BIG_BUDGET,
        ),
    )
    .await;
    let dev =
        Client::new(&podgate, "mcp.test").with_token(&token(&key, &json!({"roles": ["dev"]})));
    let ops =
        Client::new(&podgate, "mcp.test").with_token(&token(&key, &json!({"roles": ["ops"]})));
    let (dev_session, ops_session) = (dev.initialize().await, ops.initialize().await);
    dev.call(&dev_session, "alpha__search", json!({"q": "x"}))
        .await;
    ops.call(&ops_session, "alpha__search", json!({"q": "x"}))
        .await;

    // A rule lists the tool: the operator's replay has no claims and needs none.
    let allowed = replay(&podgate, "mcp", 1, "").await;
    assert_eq!(allowed.status, 200, "{allowed:?}");
    // A denied call is never re-run with the operator's privilege.
    let denied = replay(&podgate, "mcp", 2, "?force=true").await;
    assert_eq!(denied.status, 409, "{denied:?}");
    assert_eq!(denied.json()["code"], "not_replayable");

    // The rules no longer list the tool for anyone.
    let rules = json!([{"tools": ["alpha__other"], "allow": {"roles": ["dev"]}}]);
    push(
        &podgate,
        &budgeted(
            2,
            &[jwt_app(&servers, Some(&rules), &key, &extra)],
            BIG_BUDGET,
        ),
    )
    .await;
    let sent = alpha.calls("tools/call").len();
    let refused = replay(&podgate, "mcp", 1, "?force=true").await;
    assert_eq!(refused.status, 409, "{refused:?}");
    assert_eq!(refused.json()["code"], "not_permitted");
    assert_eq!(alpha.calls("tools/call").len(), sent, "nothing was sent");
}
