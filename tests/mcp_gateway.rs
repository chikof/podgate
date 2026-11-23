//! The `mcp_gateway` middleware through the real binary: one MCP endpoint over fake MCP servers
//! on raw TCP. The pure parts (envelope, event parser, names, sessions table, config) are
//! unit-tested in `src/middleware/mcp.rs` and its submodules; here every way a call can reach a
//! server, or fail to, runs end to end.

mod common;

#[path = "fixtures/mcp/fake.rs"]
mod fake;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, serving};
use fake::*;
use serde_json::{Value, json};
use tokio::time::sleep;

// ---- the methods ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_initialize() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;

    let init = |version: &str| {
        json!({"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {
            "protocolVersion": version, "capabilities": {"sampling": {}},
            "clientInfo": {"name": "test", "version": "0"}}})
    };
    let answer = client.post(None, &[], &init("2025-06-18")).await;
    assert_eq!(answer.status, 200, "{answer:?}");
    let session = answer
        .header("mcp-session-id")
        .expect("a session id")
        .to_owned();
    assert_eq!(session.len(), 32);
    assert!(session.bytes().all(|byte| (0x21..=0x7e).contains(&byte)));
    assert_eq!(answer.header("content-type"), Some("application/json"));
    let body = answer.json();
    assert_eq!(body["id"], "init-1");
    assert_eq!(body["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        body["result"]["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(body["result"]["serverInfo"]["name"], "podgate");

    // A revision the gateway does not speak gets the newest it does.
    let older = client.post(None, &[], &init("2024-11-05")).await;
    assert_eq!(older.json()["result"]["protocolVersion"], "2025-11-25");
    // Another initialize is another session.
    assert_ne!(older.header("mcp-session-id"), Some(session.as_str()));

    let missing = client
        .post(
            None,
            &[],
            &json!({"jsonrpc": "2.0", "id": 2, "method": "initialize"}),
        )
        .await;
    assert_eq!(code(&missing.json()), -32602);

    let pong = client.rpc(&session, "ping", json!({})).await;
    assert_eq!(pong, json!({"jsonrpc": "2.0", "id": 7, "result": {}}));
    assert_eq!(
        alpha.sessions.load(Ordering::SeqCst),
        0,
        "initialize is answered by the gateway"
    );
}

#[tokio::test]
async fn mcp_tools_list_merged() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search", "read"]),
        Behavior::new("beta", &["write"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let (_podgate, client) = gateway(&[server("alpha", one.addr), server("beta", two.addr)]).await;

    let session = client.initialize().await;
    let answer = client.rpc(&session, "tools/list", json!({})).await;
    let tools = answer["result"]["tools"].as_array().expect("tools");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["alpha__search", "alpha__read", "beta__write"]);
    assert!(answer["result"].get("nextCursor").is_none());
    // Only the name changes.
    assert_eq!(tools[0]["title"], "The search tool");
    assert_eq!(tools[0]["description"], "search does a thing");
    assert_eq!(
        tools[0]["inputSchema"],
        tool_object("search")["inputSchema"]
    );

    // The servers were reached as an MCP client: initialize, initialized, then the list, all in
    // one upstream session of their own.
    for (fake, name) in [(&one, "alpha"), (&two, "beta")] {
        let methods: Vec<String> = fake.requests().iter().map(Seen::method).collect();
        assert_eq!(
            methods,
            ["initialize", "notifications/initialized", "tools/list"],
            "{name}"
        );
        let list = &fake.calls("tools/list")[0];
        assert_eq!(
            list.header("mcp-session-id"),
            Some(format!("{name}-s0").as_str())
        );
        assert_eq!(list.header("mcp-protocol-version"), Some("2025-11-25"));
        assert!(list.head.starts_with("POST /mcp HTTP/1.1\r\n"));
        assert!(
            list.header("accept")
                .is_some_and(|accept| accept.contains("application/json")
                    && accept.contains("text/event-stream"))
        );
    }
}

#[tokio::test]
async fn mcp_tools_call_routed() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search"]),
        Behavior::new("beta", &["write"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let (_podgate, client) = gateway(&[server("alpha", one.addr), server("beta", two.addr)]).await;
    let session = client.initialize().await;
    client.list(&session).await;

    let answer = client
        .post(
            Some(&session),
            &[
                ("MCP-Protocol-Version", "2025-11-25"),
                ("Authorization", "Bearer client-secret"),
            ],
            &json!({"jsonrpc": "2.0", "id": "call-9", "method": "tools/call", "params": {
                "name": "beta__write", "arguments": {"path": "/x", "n": 3},
                "_meta": {"progressToken": "p1"}}}),
        )
        .await;
    assert_eq!(answer.status, 200, "{answer:?}");
    // The result is the server's, untouched: its digits are not rewritten and the id is ours.
    assert!(
        answer.body.contains(r#""big":18446744073709551616"#),
        "{}",
        answer.body
    );
    assert!(answer.body.contains(r#""f":1.50"#), "{}", answer.body);
    let body = answer.json();
    assert_eq!(body["id"], "call-9");
    assert_eq!(text(&body), "beta:write");
    assert_eq!(
        body["result"]["structuredContent"]["arguments"],
        json!({"path": "/x", "n": 3})
    );
    assert_eq!(
        body["result"]["structuredContent"]["meta"],
        json!({"progressToken": "p1"})
    );
    assert_eq!(body["result"]["isError"], false);

    // It went to the owner, with the original name and everything else of the params.
    assert!(one.calls("tools/call").is_empty());
    let sent = two.calls("tools/call");
    assert_eq!(sent.len(), 1);
    let forwarded = sent[0].json();
    assert_eq!(forwarded["params"]["name"], "write");
    assert_eq!(
        forwarded["params"]["arguments"],
        json!({"path": "/x", "n": 3})
    );
    assert_eq!(forwarded["params"]["_meta"], json!({"progressToken": "p1"}));
    assert_eq!(sent[0].header("mcp-session-id"), Some("beta-s0"));
    assert_eq!(sent[0].header("mcp-protocol-version"), Some("2025-11-25"));
    // Nothing of the client's request reaches a server.
    assert!(sent[0].header("authorization").is_none());
    assert!(!sent[0].head.contains("mcp.test"));
    assert!(!sent[0].head.contains("client-secret"));
}

#[tokio::test]
async fn mcp_same_named_tool_routed_separately() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search", "only-alpha"]),
        Behavior::new("beta", &["search"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let (_podgate, client) = gateway(&[server("alpha", one.addr), server("beta", two.addr)]).await;
    let session = client.initialize().await;

    let names = client.list(&session).await;
    assert_eq!(
        names,
        ["alpha__search", "alpha__only-alpha", "beta__search"]
    );

    let from_alpha = client.call(&session, "alpha__search", json!({})).await;
    assert_eq!(text(&from_alpha), "alpha:search");
    assert_eq!(
        (one.calls("tools/call").len(), two.calls("tools/call").len()),
        (1, 0)
    );
    let from_beta = client.call(&session, "beta__search", json!({})).await;
    assert_eq!(text(&from_beta), "beta:search");
    assert_eq!(
        (one.calls("tools/call").len(), two.calls("tools/call").len()),
        (1, 1)
    );
    assert_eq!(
        one.calls("tools/call")[0].json()["params"]["name"],
        "search"
    );
    assert_eq!(
        two.calls("tools/call")[0].json()["params"]["name"],
        "search"
    );
}

#[tokio::test]
async fn mcp_client_cannot_pick_the_server() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search"]),
        Behavior::new("beta", &["search", "alpha__search"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let (_podgate, client) = gateway(&[server("alpha", one.addr), server("beta", two.addr)]).await;
    let session = client.initialize().await;
    client.list(&session).await;

    // Nothing but the name decides: not a `server` param, not a header, not `_meta`.
    let answer = client
        .post(
            Some(&session),
            &[("X-Mcp-Server", "beta"), ("MCP-Server", "beta"), ("X-Forwarded-Host", "beta")],
            &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "alpha__search", "server": "beta", "serverName": "beta",
                "arguments": {"server": "beta"}, "_meta": {"server": "beta", "podgate/server": "beta"}}}),
        )
        .await;
    assert_eq!(text(&answer.json()), "alpha:search");
    assert_eq!(
        (one.calls("tools/call").len(), two.calls("tools/call").len()),
        (1, 0)
    );

    // A name that is not exactly `<registered server>__<listed tool>` leads nowhere.
    for name in [
        "search",
        "ALPHA__search",
        "alpha_search",
        "alpha__",
        "__search",
        "gamma__search",
        "alpha__search ",
        "alpha__nope",
    ] {
        let refused = client.call(&session, name, json!({})).await;
        assert_eq!(code(&refused), -32602, "{name:?}: {refused}");
    }
    // The first separator ends the server: this is beta's own `alpha__search`, not alpha's `search`.
    let nested = client
        .call(&session, "beta__alpha__search", json!({}))
        .await;
    assert_eq!(text(&nested), "beta:alpha__search");
    assert_eq!(
        (one.calls("tools/call").len(), two.calls("tools/call").len()),
        (1, 1)
    );
    assert_eq!(
        two.calls("tools/call")[0].json()["params"]["name"],
        "alpha__search"
    );
}

// ---- upstream answers ----------------------------------------------------------------------

#[tokio::test]
async fn mcp_upstream_sse_response() {
    let events = Behavior::custom("events", &["stream"], true, true);
    let fake = Fake::mcp(&events).await;
    let (_podgate, client) = gateway(&[with_timeout(server("events", fake.addr), 5_000)]).await;

    // The server answers every request as an event stream: a notification first, then the
    // answer, and it leaves the stream open. The gateway stops at the answer.
    let started = Instant::now();
    let session = client.initialize().await;
    assert_eq!(client.list(&session).await, ["events__stream"]);
    let called = client
        .call(&session, "events__stream", json!({"q": "x"}))
        .await;
    assert_eq!(text(&called), "events:stream");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the gateway waited for the stream to end: {:?}",
        started.elapsed()
    );

    // A stream that ends after its answer works too.
    let closing = Behavior::custom("closing", &["tail"], true, false);
    let other = Fake::mcp(&closing).await;
    let (_podgate, client) = gateway(&[server("closing", other.addr)]).await;
    let session = client.initialize().await;
    assert_eq!(client.list(&session).await, ["closing__tail"]);
    assert_eq!(
        text(&client.call(&session, "closing__tail", json!({})).await),
        "closing:tail"
    );
}

#[tokio::test]
async fn mcp_server_down_omitted() {
    let up = Behavior::new("up", &["here"]);
    let slow = Behavior::new("slow", &["late"]);
    slow.delay_all_ms.store(1_500, Ordering::SeqCst);
    let (alive, late) = (Fake::mcp(&up).await, Fake::mcp(&slow).await);
    let dead = refused_addr();
    let (_podgate, client) = gateway(&[
        server("up", alive.addr),
        with_timeout(server("slow", late.addr), 300),
        server("dead", dead),
    ])
    .await;
    let session = client.initialize().await;

    // Down, refused and slow servers are left out of the list; the rest answers.
    let started = Instant::now();
    assert_eq!(client.list(&session).await, ["up__here"]);
    assert!(started.elapsed() < Duration::from_secs(5));

    // A call to them is -32603 with the reason, never a hang and never a guess.
    let slow_call = client.call(&session, "slow__late", json!({})).await;
    assert_eq!(code(&slow_call), -32603, "{slow_call}");
    assert_eq!(slow_call["error"]["data"]["server"], "slow");
    assert_eq!(slow_call["error"]["data"]["reason"], "timeout");
    let dead_call = client.call(&session, "dead__anything", json!({})).await;
    assert_eq!(code(&dead_call), -32603, "{dead_call}");
    assert_eq!(dead_call["error"]["data"]["reason"], "connect");

    // A server that goes away after it was listed fails its calls and leaves the next list.
    assert_eq!(
        text(&client.call(&session, "up__here", json!({})).await),
        "up:here"
    );
    alive.stop();
    sleep(Duration::from_millis(100)).await;
    let gone = client.call(&session, "up__here", json!({})).await;
    assert_eq!(code(&gone), -32603, "{gone}");
    assert_eq!(gone["error"]["data"]["reason"], "connect");
    assert!(client.list(&session).await.is_empty());
}

#[tokio::test]
async fn mcp_unknown_tool_dials_nothing() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search"]),
        Behavior::new("beta", &["write"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let (_podgate, client) = gateway(&[server("alpha", one.addr), server("beta", two.addr)]).await;
    let session = client.initialize().await;
    client.list(&session).await;
    let before = (one.accepted(), two.accepted());
    assert_eq!(
        before,
        (3, 3),
        "handshake, notification and list: three connections each"
    );

    for name in [
        "gamma__x",
        "alpha__nope",
        "search",
        "beta__search",
        "",
        "__",
        "alpha__beta__write",
    ] {
        let refused = client.call(&session, name, json!({})).await;
        assert_eq!(code(&refused), -32602, "{name:?}: {refused}");
        assert_eq!(refused["error"]["message"], "unknown tool");
        assert_eq!(refused["id"], 7);
    }
    assert_eq!(
        (one.accepted(), two.accepted()),
        before,
        "no connection for a tool nobody owns"
    );
    // Params that are not a call at all are refused the same way.
    for params in [json!({}), json!({"name": 5}), json!("x"), json!([])] {
        let refused = client.rpc(&session, "tools/call", params).await;
        assert_eq!(code(&refused), -32602, "{refused}");
    }
    assert_eq!((one.accepted(), two.accepted()), before);
}

#[tokio::test]
async fn mcp_malformed_upstream_result() {
    let bad = Behavior::new("bad", &["tool"]);
    let fake = Fake::mcp(&bad).await;
    let (_podgate, client) = gateway(&[server("bad", fake.addr)]).await;
    let session = client.initialize().await;
    assert_eq!(client.list(&session).await, ["bad__tool"]);
    assert_eq!(
        text(&client.call(&session, "bad__tool", json!({})).await),
        "bad:tool"
    );

    // A result that is not an object.
    bad.set_mode(STRING_RESULT);
    let refused = client.call(&session, "bad__tool", json!({})).await;
    assert_eq!(code(&refused), -32603, "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "malformed");

    // Every kind of answer that is not the answer: the server is left out and its calls fail.
    for (mode, reason) in [
        (NOT_JSON, "malformed"),
        (WRONG_ID, "malformed"),
        (HTML, "malformed"),
        (NO_ANSWER, "malformed"),
        (STATUS_500, "status"),
    ] {
        bad.set_mode(mode);
        assert!(client.list(&session).await.is_empty(), "mode {mode}");
        let refused = client.call(&session, "bad__tool", json!({})).await;
        assert_eq!(code(&refused), -32603, "mode {mode}: {refused}");
        assert_eq!(refused["error"]["data"]["reason"], reason, "mode {mode}");
    }
    // It recovers when it answers properly again.
    bad.set_mode(NORMAL);
    assert_eq!(client.list(&session).await, ["bad__tool"]);
}

// ---- the protocol --------------------------------------------------------------------------

#[tokio::test]
async fn mcp_batch_refused() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;

    let batch = json!([
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    ]);
    for session in [Some(session.as_str()), None] {
        let refused = client.post(session, &[], &batch).await;
        assert_eq!(refused.status, 400, "{refused:?}");
        let body = refused.json();
        assert_eq!(code(&body), -32600);
        assert_eq!(body["id"], Value::Null);
    }
    // Not JSON, and JSON that is not a message.
    let garbage = client
        .send(
            "POST",
            &[("Content-Type", "application/json")],
            b"{not json",
        )
        .await;
    assert_eq!((garbage.status, code(&garbage.json())), (400, -32700));
    for body in [
        json!(7),
        json!({"id": 1, "method": "ping"}),
        json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
    ] {
        let refused = client.post(Some(&session), &[], &body).await;
        assert_eq!(
            (refused.status, code(&refused.json())),
            (400, -32600),
            "{body}"
        );
    }
    let wrong_type = client
        .send("POST", &[("Content-Type", "text/plain")], b"{}")
        .await;
    assert_eq!(wrong_type.status, 415);
    assert!(
        fake.requests().is_empty(),
        "nothing of this reaches a server"
    );
}

#[tokio::test]
async fn mcp_get_405() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;

    // The standalone stream is declined, with or without a session and whatever it accepts.
    for headers in [
        vec![("Accept", "text/event-stream")],
        vec![
            ("Accept", "text/event-stream"),
            ("Mcp-Session-Id", session.as_str()),
        ],
    ] {
        let declined = client.send("GET", &headers, b"").await;
        assert_eq!(declined.status, 405, "{declined:?}");
        assert!(
            declined
                .header("allow")
                .is_some_and(|allow| allow.contains("POST"))
        );
    }
    for method in ["PUT", "PATCH", "OPTIONS"] {
        assert_eq!(client.send(method, &[], b"").await.status, 405, "{method}");
    }
}

#[tokio::test]
async fn mcp_unknown_method() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;

    for method in [
        "resources/list",
        "prompts/list",
        "sampling/createMessage",
        "tools/nope",
        "",
        "initialized",
    ] {
        let answer = client.rpc(&session, method, json!({})).await;
        assert_eq!(code(&answer), -32601, "{method:?}: {answer}");
        assert_eq!(answer["id"], 7);
    }
    // Cursors are not supported: the list is whole.
    let paged = client
        .rpc(&session, "tools/list", json!({"cursor": "next"}))
        .await;
    assert_eq!(code(&paged), -32602);
    let fine = client
        .rpc(&session, "tools/list", json!({"cursor": null, "_meta": {}}))
        .await;
    assert!(fine["result"]["tools"].is_array());
}

#[tokio::test]
async fn mcp_body_cap() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;

    let mut huge = String::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":""#);
    huge.push_str(&"a".repeat(1024 * 1024 + 1));
    huge.push_str(r#""}}"#);
    let refused = client
        .send(
            "POST",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session),
            ],
            huge.as_bytes(),
        )
        .await;
    assert_eq!(refused.status, 413, "{refused:?}");
    // Just under the cap is read and answered.
    let mut fits = String::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":""#);
    fits.push_str(&"a".repeat(1024 * 1024 - 200));
    fits.push_str(r#""}}"#);
    let accepted = client
        .send(
            "POST",
            &[
                ("Content-Type", "application/json"),
                ("Mcp-Session-Id", &session),
            ],
            fits.as_bytes(),
        )
        .await;
    assert_eq!(accepted.status, 200, "{:?}", accepted.status);
    assert_eq!(accepted.json()["result"], json!({}));
}

#[tokio::test]
async fn mcp_notification_202() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;

    for body in [
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}),
        json!({"jsonrpc": "2.0", "id": 5, "result": {}}),
        json!({"jsonrpc": "2.0", "id": 5, "error": {"code": -32000, "message": "no"}}),
    ] {
        let answer = client.post(Some(&session), &[], &body).await;
        assert_eq!(answer.status, 202, "{body}: {answer:?}");
        assert!(answer.body.is_empty(), "{answer:?}");
    }
    // A notification still needs a session, and none is forwarded.
    let orphan = client
        .post(
            None,
            &[],
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
    assert_eq!(orphan.status, 400);
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn mcp_origin_checked() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &budgeted(
            1,
            &[gateway_app(
                "mcp",
                "t1",
                "mcp.test",
                &[server("alpha", fake.addr)],
                &json!({"allowed_origins": ["https://app.example.com"]}),
            )],
            BIG_BUDGET,
        ),
    )
    .await;
    let client = Client::new(&podgate, "mcp.test");
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}});

    assert_eq!(
        client.post(None, &[], &init).await.status,
        200,
        "no Origin: not a browser"
    );
    for origin in [
        "http://mcp.test",
        "https://MCP.test",
        "https://app.example.com",
    ] {
        let allowed = client.post(None, &[("Origin", origin)], &init).await;
        assert_eq!(allowed.status, 200, "{origin}: {allowed:?}");
    }
    for origin in [
        "https://evil.test",
        "null",
        "https://mcp.test.evil.test",
        "https://app.example.com:8443",
    ] {
        let refused = client.post(None, &[("Origin", origin)], &init).await;
        assert_eq!(refused.status, 403, "{origin}: {refused:?}");
        assert_eq!(code(&refused.json()), -32600);
    }
    let delete = client
        .send(
            "DELETE",
            &[("Origin", "https://evil.test"), ("Mcp-Session-Id", "x")],
            b"",
        )
        .await;
    assert_eq!(delete.status, 403);
}

#[tokio::test]
async fn mcp_session_required() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});

    let none = client.post(None, &[], &ping).await;
    assert_eq!(none.status, 400, "{none:?}");
    let unknown = client
        .post(Some("0123456789abcdef0123456789abcdef"), &[], &ping)
        .await;
    assert_eq!(unknown.status, 404, "{unknown:?}");

    let session = client.initialize().await;
    assert_eq!(client.post(Some(&session), &[], &ping).await.status, 200);
    // The protocol version header: absent means the session's, a supported one is accepted, any
    // other is refused.
    for (version, status) in [
        ("2025-11-25", 200),
        ("2025-06-18", 200),
        ("2024-11-05", 400),
        ("nope", 400),
    ] {
        let answer = client
            .post(Some(&session), &[("MCP-Protocol-Version", version)], &ping)
            .await;
        assert_eq!(answer.status, status, "{version}: {answer:?}");
    }
}

#[tokio::test]
async fn mcp_session_delete() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let session = client.initialize().await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    assert_eq!(client.post(Some(&session), &[], &ping).await.status, 200);

    let ended = client
        .send("DELETE", &[("Mcp-Session-Id", &session)], b"")
        .await;
    assert_eq!(ended.status, 204, "{ended:?}");
    assert!(ended.body.is_empty());
    assert_eq!(client.post(Some(&session), &[], &ping).await.status, 404);
    assert_eq!(
        client
            .send("DELETE", &[("Mcp-Session-Id", &session)], b"")
            .await
            .status,
        404
    );
    assert_eq!(client.send("DELETE", &[], b"").await.status, 400);
}

// ---- sessions ------------------------------------------------------------------------------

/// Opens 1030 sessions on `client`, more than the 1024 a tenant may hold; the ids in order.
async fn flood(client: &Client) -> Vec<String> {
    let mut ids = Vec::new();
    for _ in 0..1030 {
        ids.push(client.initialize().await);
    }
    ids
}

#[tokio::test]
async fn mcp_sessions_bounded() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});

    let ids = flood(&client).await;
    // A tenant at its cap loses its oldest sessions (the first six of 1030), the newest all work.
    assert_eq!(client.post(Some(&ids[0]), &[], &ping).await.status, 404);
    assert_eq!(client.post(Some(&ids[5]), &[], &ping).await.status, 404);
    assert_eq!(client.post(Some(&ids[6]), &[], &ping).await.status, 200);
    assert_eq!(client.post(Some(&ids[1029]), &[], &ping).await.status, 200);
    // A session in use is not the oldest: opening more evicts the idle ones instead.
    for _ in 0..3 {
        client.initialize().await;
    }
    assert_eq!(client.post(Some(&ids[6]), &[], &ping).await.status, 200);
    assert_eq!(client.post(Some(&ids[7]), &[], &ping).await.status, 404);
}

#[tokio::test]
async fn mcp_sessions_isolated_by_tenant() {
    let (alpha, beta) = (
        Behavior::new("alpha", &["search"]),
        Behavior::new("beta", &["read"]),
    );
    let (one, two) = (Fake::mcp(&alpha).await, Fake::mcp(&beta).await);
    let podgate = Podgate::start().await;
    push(
        &podgate,
        &budgeted(
            1,
            &[
                gateway_app(
                    "loud",
                    "t1",
                    "loud.test",
                    &[server("alpha", one.addr)],
                    &json!({}),
                ),
                gateway_app(
                    "quiet",
                    "t2",
                    "quiet.test",
                    &[server("beta", two.addr)],
                    &json!({}),
                ),
            ],
            BIG_BUDGET,
        ),
    )
    .await;
    let (loud, quiet) = (
        Client::new(&podgate, "loud.test"),
        Client::new(&podgate, "quiet.test"),
    );
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});

    let before = quiet.initialize().await;
    let ids = flood(&loud).await;
    assert_eq!(
        loud.post(Some(&ids[0]), &[], &ping).await.status,
        404,
        "the flood evicted its own"
    );
    // The other tenant's session survived the flood and still works end to end.
    assert_eq!(quiet.post(Some(&before), &[], &ping).await.status, 200);
    assert_eq!(quiet.list(&before).await, ["beta__read"]);
    // A session id is good only for its own tenant's gateway.
    assert_eq!(quiet.post(Some(&ids[1029]), &[], &ping).await.status, 404);
    assert_eq!(loud.post(Some(&before), &[], &ping).await.status, 404);
}

#[tokio::test]
async fn mcp_upstream_session_per_gateway_session() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    let (_podgate, client) = gateway(&[server("alpha", fake.addr)]).await;

    // One handshake per server per gateway session, however many requests follow.
    let first = client.initialize().await;
    for _ in 0..3 {
        client.list(&first).await;
    }
    client.call(&first, "alpha__search", json!({})).await;
    assert_eq!(fake.calls("initialize").len(), 1);
    assert_eq!(fake.calls("notifications/initialized").len(), 1);
    // A second session of the client is a second session with the server.
    let second = client.initialize().await;
    client.list(&second).await;
    assert_eq!(fake.calls("initialize").len(), 2);
    let sessions: Vec<Option<String>> = fake
        .calls("tools/list")
        .iter()
        .map(|seen| seen.header("mcp-session-id").map(str::to_owned))
        .collect();
    assert_eq!(sessions[0].as_deref(), Some("alpha-s0"));
    assert_eq!(sessions[3].as_deref(), Some("alpha-s1"));

    // The server forgets the session (a restart): the gateway opens a new one, once, and the
    // client never sees it.
    alpha.expired_before.store(2, Ordering::SeqCst);
    alpha.sessions.store(2, Ordering::SeqCst);
    let names = client.list(&first).await;
    assert_eq!(names, ["alpha__search"]);
    assert_eq!(fake.calls("initialize").len(), 3);
    assert_eq!(client.list(&first).await, ["alpha__search"]);
    assert_eq!(fake.calls("initialize").len(), 3, "the new session is kept");
    let called = client.call(&first, "alpha__search", json!({})).await;
    assert_eq!(text(&called), "alpha:search");
}

#[tokio::test]
async fn mcp_server_max_concurrent() {
    let alpha = Behavior::new("alpha", &["slow"]);
    alpha.call_delay_ms.store(700, Ordering::SeqCst);
    let fake = Fake::mcp(&alpha).await;
    let mut limited = server("alpha", fake.addr);
    limited["max_concurrent"] = json!(1);
    let (_podgate, client) = gateway(&[limited]).await;
    let session = client.initialize().await;
    client.list(&session).await;

    let (first, second) = tokio::join!(client.call(&session, "alpha__slow", json!({})), async {
        sleep(Duration::from_millis(200)).await;
        client.call(&session, "alpha__slow", json!({})).await
    });
    assert_eq!(text(&first), "alpha:slow");
    assert_eq!(code(&second), -32000, "{second}");
    assert_eq!(second["error"]["message"], "server busy");
    assert_eq!(
        fake.calls("tools/call").len(),
        1,
        "the refused call never left"
    );
    // The permit comes back.
    assert_eq!(
        text(&client.call(&session, "alpha__slow", json!({})).await),
        "alpha:slow"
    );
}

// ---- policy, budget, overview --------------------------------------------------------------

/// An operator policy file in its own temp directory, removed on drop.
struct PolicyFile {
    dir: PathBuf,
    path: PathBuf,
}

impl PolicyFile {
    fn write(contents: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-mcp-policy-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, contents).expect("write the policy file");
        Self { dir, path }
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("utf-8 path")
    }
}

impl Drop for PolicyFile {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

#[tokio::test]
async fn mcp_address_policy_enforced() {
    let alpha = Behavior::new("alpha", &["search"]);
    let fake = Fake::mcp(&alpha).await;
    // The operator denies loopback: the fake server lives there.
    let policy = PolicyFile::write(r#"{"deny": ["127.0.0.0/8", "::1/128"]}"#);
    let podgate = Podgate::start_with_env(&[("UPSTREAM_POLICY_FILE", policy.path())]).await;
    let unused: SocketAddr = "10.255.255.1:9".parse().expect("addr");
    let mut declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", fake.addr)],
        &json!({}),
    );
    declared["revisions"] = json!([serving("r1", unused)]);
    push(&podgate, &budgeted(1, &[declared], BIG_BUDGET)).await;
    let client = Client::new(&podgate, "mcp.test");

    let session = client.initialize().await;
    assert!(
        client.list(&session).await.is_empty(),
        "a refused server is left out"
    );
    let refused = client.call(&session, "alpha__search", json!({})).await;
    assert_eq!(code(&refused), -32603, "{refused}");
    assert_eq!(refused["error"]["data"]["reason"], "policy");
    assert_eq!(fake.accepted(), 0, "nothing was dialled");
}

#[tokio::test]
async fn mcp_tenant_budget_checked() {
    let alpha = Behavior::new("alpha", &["slow"]);
    alpha.call_delay_ms.store(700, Ordering::SeqCst);
    let fake = Fake::mcp(&alpha).await;
    let podgate = Podgate::start().await;
    let declared = gateway_app(
        "mcp",
        "t1",
        "mcp.test",
        &[server("alpha", fake.addr)],
        &json!({}),
    );

    // A budget below what one call reserves is refused when the snapshot compiles.
    let refused = podgate
        .push_snapshot(&budgeted(1, std::slice::from_ref(&declared), ONE_CALL - 1))
        .await;
    assert_eq!(refused.status, 422, "{refused:?}");
    let conflict = &refused.json()["conflicts"][0];
    assert_eq!(conflict["code"], "invalid_middleware", "{conflict}");
    assert!(
        conflict.to_string().contains("max_buffer_bytes"),
        "{conflict}"
    );

    // A budget that holds one call but not two: the second at the same time is `server busy`.
    push(&podgate, &budgeted(2, &[declared], ONE_CALL)).await;
    let client = Client::new(&podgate, "mcp.test");
    let session = client.initialize().await;
    assert_eq!(client.list(&session).await, ["alpha__slow"]);
    let (first, second) = tokio::join!(client.call(&session, "alpha__slow", json!({})), async {
        sleep(Duration::from_millis(200)).await;
        client.call(&session, "alpha__slow", json!({})).await
    });
    assert_eq!(text(&first), "alpha:slow");
    assert_eq!(code(&second), -32000, "{second}");
    assert_eq!(fake.calls("tools/call").len(), 1);
    // The charge is released when the call ends.
    assert_eq!(
        text(&client.call(&session, "alpha__slow", json!({})).await),
        "alpha:slow"
    );
}

/// The `mcp_gateway` entry of the app's middlewares in the overview.
fn registry(overview: &Value) -> Value {
    overview["apps"]["items"][0]["middlewares"]
        .as_array()
        .expect("middlewares")
        .iter()
        .find(|declared| declared["type"] == "mcp_gateway")
        .unwrap_or_else(|| panic!("no mcp_gateway in {overview}"))["config"]
        .clone()
}

#[tokio::test]
async fn mcp_overview_shows_registry() {
    let alpha = Behavior::new("alpha", &["search", "read"]);
    let fake = Fake::mcp(&alpha).await;
    let dead = refused_addr();
    let mut keyed = server("alpha", fake.addr);
    keyed["address"] = json!(format!("http://{}/mcp?key=SECRET-KEY-123", fake.addr));
    let servers = [keyed, server("dead", dead)];
    let (podgate, client) = gateway(&servers).await;
    let overview = || async {
        let answer = podgate.admin_get("/v1/overview?section=apps").await;
        assert_eq!(answer.status, 200, "{answer:?}");
        assert!(
            !answer.body.contains("SECRET-KEY-123"),
            "a key of an address is shown"
        );
        answer.json()
    };

    // Declared, not yet contacted.
    let before = registry(&overview().await);
    assert_eq!(before["servers"][0]["name"], "alpha");
    assert_eq!(
        before["servers"][0]["address"],
        format!("http://{}/mcp", fake.addr)
    );
    assert_eq!(before["servers"][0]["max_concurrent"], 32);
    assert_eq!(before["servers"][0]["timeout_ms"], 30_000);
    assert_eq!(before["servers"][0]["health"], "unknown");
    assert_eq!(before["servers"][1]["health"], "unknown");

    // After a list: one healthy with its tools, one down with the reason.
    let session = client.initialize().await;
    assert_eq!(
        client.list(&session).await,
        ["alpha__search", "alpha__read"]
    );
    let after = registry(&overview().await);
    assert_eq!(after["servers"][0]["health"], "healthy");
    assert_eq!(after["servers"][0]["tools"], 2);
    assert_eq!(after["servers"][1]["health"], "down");
    assert_eq!(after["servers"][1]["reason"], "connect");
    assert!(after["servers"][1].get("tools").is_none());
    assert_eq!(after["allowed_origins"], json!([]));

    // A push that leaves the declaration alone keeps what the gateway learned.
    push(
        &podgate,
        &budgeted(
            2,
            &[gateway_app("mcp", "t1", "mcp.test", &servers, &json!({}))],
            BIG_BUDGET,
        ),
    )
    .await;
    let same = registry(&overview().await);
    assert_eq!(same["servers"][0]["health"], "healthy");
    assert_eq!(same["servers"][0]["tools"], 2);
    assert_eq!(same["servers"][1]["health"], "down");
    // A changed declaration starts over.
    push(
        &podgate,
        &budgeted(
            3,
            &[gateway_app(
                "mcp",
                "t1",
                "mcp.test",
                &[server("alpha", fake.addr), server("dead", dead)],
                &json!({}),
            )],
            BIG_BUDGET,
        ),
    )
    .await;
    let changed = registry(&overview().await);
    assert_eq!(changed["servers"][0]["health"], "unknown");
    assert_eq!(changed["servers"][1]["health"], "unknown");
}
