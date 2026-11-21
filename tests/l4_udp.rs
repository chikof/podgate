//! UDP routers and services through the real binary: sessions, bounds, the
//! spoofed-source cases and the compile rules.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{Podgate, Upstream, app, serving, snapshot};
use serde_json::{Value, json};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, timeout};

const ENTRY_POINTS: [(&str, &str); 2] = [("web", "http"), ("dns", "udp")];

/// What a test upstream answers to a datagram: the datagrams to send back.
type Answer = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

/// A UDP server on a free loopback port that answers each datagram with `answer`.
async fn server(answer: Answer) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind server");
    let addr = socket.local_addr().expect("server addr");
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            for reply in answer(&buf[..len]) {
                if socket.send_to(&reply, from).await.is_err() {
                    return;
                }
            }
        }
    });
    addr
}

/// A server that answers `tag:payload`, and nothing to a payload that starts with `flood`.
async fn echo(tag: &'static str) -> SocketAddr {
    server(Box::new(move |payload| {
        if payload.starts_with(b"flood") {
            Vec::new()
        } else {
            vec![format!("{tag}:{}", String::from_utf8_lossy(payload)).into_bytes()]
        }
    }))
    .await
}

fn udp_app(servers: &[SocketAddr], router: &Value, service: &Value) -> Value {
    let mut app = app("u", &["u.test"], &[]);
    app["routers"] = json!([]);
    let mut router_config = json!({ "name": "r", "entry_points": ["dns"], "service": "svc" });
    let mut service_config = json!({
        "name": "svc", "type": "loadbalancer",
        "servers": servers.iter().map(|addr| json!({ "address": addr.to_string() })).collect::<Vec<_>>(),
    });
    for (config, extra) in [(&mut router_config, router), (&mut service_config, service)] {
        if let (Some(config), Some(extra)) = (config.as_object_mut(), extra.as_object()) {
            config.extend(extra.clone());
        }
    }
    app["udp"] = json!({ "routers": [router_config], "services": [service_config] });
    app
}

/// A snapshot of tenant `t1` that reserves the `dns` entry point to it.
fn reserved(version: u64, apps: &[Value]) -> Value {
    let mut pushed = snapshot(version, apps);
    pushed["entry_points"] = json!([{ "name": "dns", "tenants": ["t1"] }]);
    pushed
}

async fn start() -> Podgate {
    Podgate::start_with_entry_points(&ENTRY_POINTS, &[]).await
}

async fn push(podgate: &Podgate, snapshot: &Value) {
    let response = podgate.push_snapshot(snapshot).await;
    assert_eq!(response.status, 200, "{}", response.body);
}

async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind client")
}

/// Sends `payload` to `to` and returns the reply and where it came from, `None` when nothing
/// arrives within `wait`.
async fn ask(
    socket: &UdpSocket,
    to: SocketAddr,
    payload: &[u8],
    wait: Duration,
) -> Option<(String, SocketAddr)> {
    socket.send_to(payload, to).await.expect("send");
    let mut buf = vec![0_u8; 65_536];
    let (len, from) = timeout(wait, socket.recv_from(&mut buf)).await.ok()?.ok()?;
    Some((String::from_utf8_lossy(&buf[..len]).into_owned(), from))
}

const WAIT: Duration = Duration::from_secs(2);
const SILENCE: Duration = Duration::from_millis(400);

/// The value of the sample `series` (a name with its labels) in the metrics of `podgate`.
async fn metric(podgate: &Podgate, series: &str) -> u64 {
    let body = podgate.admin_get("/metrics").await.body;
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("no sample {series} in:\n{body}"))
}

/// Waits until `series` satisfies `wanted`, up to ten seconds.
async fn wait_for(podgate: &Podgate, series: &str, wanted: impl Fn(u64) -> bool) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let value = metric(podgate, series).await;
        if wanted(value) || Instant::now() > deadline {
            return value;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn conflict_codes(body: &Value) -> Vec<String> {
    body["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|entry| entry["code"].as_str().expect("code").to_owned())
        .collect()
}

#[tokio::test]
async fn udp_roundtrip_two_clients() {
    let podgate = start().await;
    let up = echo("A").await;
    push(
        &podgate,
        &reserved(1, &[udp_app(&[up], &json!({}), &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let (one, two) = (client().await, client().await);
    let (first, second) = tokio::join!(
        ask(&one, entry, b"one", WAIT),
        ask(&two, entry, b"two", WAIT)
    );
    assert_eq!(first, Some(("A:one".to_owned(), entry)));
    assert_eq!(second, Some(("A:two".to_owned(), entry)));
    // The daemon counts a datagram after `send_to` returns, so a client can hold the reply first.
    let out = "podgate_udp_datagrams_total{direction=\"out\"}";
    assert_eq!(wait_for(&podgate, out, |sent| sent >= 2).await, 2);
}

#[tokio::test]
async fn udp_session_sticks() {
    let podgate = start().await;
    let (a, b) = (echo("A").await, echo("B").await);
    push(
        &podgate,
        &reserved(1, &[udp_app(&[a, b], &json!({}), &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let (one, two) = (client().await, client().await);
    let mut tags = Vec::new();
    for round in 0..5 {
        let (reply, _) = ask(&one, entry, format!("{round}").as_bytes(), WAIT)
            .await
            .expect("reply");
        tags.push(reply.split(':').next().unwrap_or_default().to_owned());
    }
    assert!(tags.iter().all(|tag| *tag == tags[0]), "{tags:?}");
    let (other, _) = ask(&two, entry, b"x", WAIT).await.expect("reply");
    assert!(
        !other.starts_with(&format!("{}:", tags[0])),
        "the second client goes to the next server, not {other}"
    );
}

#[tokio::test]
async fn udp_session_expires() {
    let podgate = start().await;
    let (a, b) = (echo("A").await, echo("B").await);
    let service = json!({ "session_timeout_secs": 1 });
    push(
        &podgate,
        &reserved(1, &[udp_app(&[a, b], &json!({}), &service)]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let one = client().await;
    let (first, _) = ask(&one, entry, b"1", WAIT).await.expect("reply");
    sleep(Duration::from_millis(1800)).await;
    let (second, _) = ask(&one, entry, b"2", WAIT).await.expect("reply");
    assert_ne!(
        first.split(':').next(),
        second.split(':').next(),
        "{first} {second}"
    );
    assert!(
        metric(
            &podgate,
            "podgate_udp_sessions_closed_total{reason=\"expired\"}"
        )
        .await
            >= 1
    );
    assert_eq!(
        wait_for(&podgate, "podgate_udp_sessions", |open| open == 1).await,
        1
    );
}

#[tokio::test]
async fn udp_session_table_bounded() {
    let podgate = start().await;
    let up = echo("A").await;
    let router = json!({ "max_sessions": 2 });
    push(
        &podgate,
        &reserved(1, &[udp_app(&[up], &router, &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let (one, two, three) = (client().await, client().await, client().await);
    assert!(ask(&one, entry, b"1", WAIT).await.is_some());
    assert!(ask(&two, entry, b"2", WAIT).await.is_some());
    // Two datagrams each: a client that keeps sending is never given up for a newcomer.
    assert!(ask(&one, entry, b"1b", WAIT).await.is_some());
    assert!(ask(&two, entry, b"2b", WAIT).await.is_some());
    assert!(ask(&three, entry, b"3", SILENCE).await.is_none());
    assert_eq!(
        metric(&podgate, "podgate_udp_dropped_total{reason=\"table_full\"}").await,
        1
    );
    for (socket, text) in [(&one, "again1"), (&two, "again2")] {
        let (reply, _) = ask(socket, entry, text.as_bytes(), WAIT)
            .await
            .expect("reply");
        assert_eq!(reply, format!("A:{text}"));
    }
    assert_eq!(metric(&podgate, "podgate_udp_sessions").await, 2);
}

#[tokio::test]
async fn udp_session_charges_tenant() {
    let podgate = start().await;
    let up = echo("A").await;
    let service = json!({ "session_timeout_secs": 1 });
    let mut pushed = reserved(1, &[udp_app(&[up], &json!({}), &service)]);
    pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(8192);
    push(&podgate, &pushed).await;
    let entry = podgate.entry_addr("dns");
    let (one, two, three) = (client().await, client().await, client().await);
    assert!(ask(&one, entry, b"1", WAIT).await.is_some());
    // Two datagrams each: a client that keeps sending is never given up for a newcomer.
    assert!(ask(&one, entry, b"1b", WAIT).await.is_some());
    assert!(ask(&two, entry, b"2", WAIT).await.is_some());
    assert!(ask(&two, entry, b"2b", WAIT).await.is_some());
    let charged = "podgate_tenant_buffer_bytes{tenant=\"t1\"}";
    assert_eq!(metric(&podgate, charged).await, 8192);
    assert!(ask(&three, entry, b"3", SILENCE).await.is_none());
    assert_eq!(
        metric(
            &podgate,
            "podgate_udp_dropped_total{reason=\"over_budget\"}"
        )
        .await,
        1
    );
    assert_eq!(wait_for(&podgate, charged, |bytes| bytes == 0).await, 0);
    assert!(
        ask(&three, entry, b"3", WAIT).await.is_some(),
        "the budget is back once the sessions expired"
    );
}

#[tokio::test]
async fn udp_removed_server_closes_sessions() {
    let podgate = start().await;
    let (a, b) = (echo("A").await, echo("B").await);
    push(
        &podgate,
        &reserved(1, &[udp_app(&[a, b], &json!({}), &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let (one, two) = (client().await, client().await);
    let (first, _) = ask(&one, entry, b"1", WAIT).await.expect("reply");
    let (second, _) = ask(&two, entry, b"2", WAIT).await.expect("reply");
    assert!(
        first.starts_with("A:") && second.starts_with("B:"),
        "{first} {second}"
    );
    assert_eq!(metric(&podgate, "podgate_udp_sessions").await, 2);
    push(
        &podgate,
        &reserved(2, &[udp_app(&[b], &json!({}), &json!({}))]),
    )
    .await;
    let closed = "podgate_udp_sessions_closed_total{reason=\"server_removed\"}";
    assert_eq!(wait_for(&podgate, closed, |count| count == 1).await, 1);
    assert_eq!(metric(&podgate, "podgate_udp_sessions").await, 1);
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffer_bytes{tenant=\"t1\"}").await,
        4096
    );
    let (again, _) = ask(&one, entry, b"3", WAIT).await.expect("reply");
    assert_eq!(
        again, "B:3",
        "the client starts a new session on the server that is left"
    );
}

#[tokio::test]
async fn udp_two_routers_ambiguous() {
    let podgate = start().await;
    let up = echo("A").await;
    let mut twice = udp_app(&[up], &json!({}), &json!({}));
    let second = json!({ "name": "r2", "entry_points": ["dns"], "service": "svc" });
    twice["udp"]["routers"]
        .as_array_mut()
        .expect("routers")
        .push(second);
    let response = podgate.push_snapshot(&reserved(1, &[twice])).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(conflict_codes(&response.json()), ["route_ambiguity"]);
    assert_eq!(response.json()["conflicts"][0]["entry_point"], "dns");

    let mut other = udp_app(&[up], &json!({}), &json!({}));
    other["id"] = json!("v");
    let response = podgate
        .push_snapshot(&reserved(
            1,
            &[udp_app(&[up], &json!({}), &json!({})), other],
        ))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(conflict_codes(&response.json()), ["route_ambiguity"]);
    assert_eq!(response.json()["conflicts"][0]["apps"], json!(["u", "v"]));
}

#[tokio::test]
async fn udp_dial_obeys_upstream_policy() {
    let dir = std::env::temp_dir().join(format!("podgate-udp-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("policy dir");
    let file = dir.join("policy.json");
    std::fs::write(&file, r#"{"deny": ["127.0.0.2/32"]}"#).expect("write policy");
    let path = file.to_str().expect("utf-8 path").to_owned();
    let podgate =
        Podgate::start_with_entry_points(&ENTRY_POINTS, &[("UPSTREAM_POLICY_FILE", path.as_str())])
            .await;
    let denied: SocketAddr = "127.0.0.2:5300".parse().expect("addr");
    let response = podgate
        .push_snapshot(&reserved(1, &[udp_app(&[denied], &json!({}), &json!({}))]))
        .await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "upstream_forbidden"
    );
    assert_eq!(response.json()["conflicts"][0]["rule"], "deny 127.0.0.2/32");
    std::fs::remove_dir_all(&dir).expect("remove policy dir");
}

#[tokio::test]
async fn udp_server_name_is_refused() {
    let podgate = start().await;
    let mut named = udp_app(&[], &json!({}), &json!({}));
    named["udp"]["services"][0]["servers"] = json!([{ "address": "dns.internal:53" }]);
    let response = podgate.push_snapshot(&reserved(1, &[named])).await;
    assert_eq!(response.status, 422, "{}", response.body);
    let entry = &response.json()["conflicts"][0];
    assert_eq!(entry["code"], "invalid_service");
    assert!(
        entry["message"]
            .as_str()
            .unwrap_or_default()
            .contains("resolver"),
        "{entry}"
    );
}

#[tokio::test]
async fn udp_entry_point_is_reserved_to_one_tenant() {
    let podgate = start().await;
    let up = echo("A").await;
    let one_app = udp_app(&[up], &json!({}), &json!({}));
    let open = snapshot(1, std::slice::from_ref(&one_app));
    let response = podgate.push_snapshot(&open).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "entry_point_forbidden"
    );

    let mut shared = reserved(1, std::slice::from_ref(&one_app));
    shared["entry_points"][0]["tenants"] = json!(["t1", "t2"]);
    let response = podgate.push_snapshot(&shared).await;
    assert_eq!(response.status, 422, "{}", response.body);

    let mut web = snapshot(1, &[app("h", &["h.test"], &[serving("r1", up)])]);
    web["apps"][0]["routers"][0]["entry_points"] = json!(["dns"]);
    let response = podgate.push_snapshot(&web).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "entry_point_protocol"
    );
}

#[tokio::test]
async fn udp_oversize_datagram_is_dropped_not_cut() {
    let podgate = start().await;
    let up = echo("A").await;
    push(
        &podgate,
        &reserved(1, &[udp_app(&[up], &json!({}), &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let one = client().await;
    assert!(ask(&one, entry, &vec![b'x'; 5000], SILENCE).await.is_none());
    assert_eq!(
        metric(&podgate, "podgate_udp_dropped_total{reason=\"oversize\"}").await,
        1
    );
    let (reply, _) = ask(&one, entry, b"small", WAIT).await.expect("reply");
    assert_eq!(reply, "A:small");
}

/// A server that answers every source with `A:payload`, as a DNS resolver does.
async fn echo_every_source() -> SocketAddr {
    server(Box::new(|payload| {
        vec![format!("A:{}", String::from_utf8_lossy(payload)).into_bytes()]
    }))
    .await
}

/// A flood of one-datagram sources against a router that holds 8 sessions: clients that keep
/// sending keep working, the tenant's HTTP is served, and a new real client still gets a session.
async fn flood_keeps_talking_clients(up: SocketAddr) {
    let podgate = start().await;
    let http = Upstream::start("page").await;
    let router = json!({ "max_sessions": 8 });
    let udp = udp_app(&[up], &router, &json!({}));
    let web = app("h", &["h.test"], &[serving("r1", http.addr)]);
    push(&podgate, &reserved(1, &[udp, web])).await;
    let entry = podgate.entry_addr("dns");

    let mut real = Vec::new();
    for name in ["a", "b", "c"] {
        let socket = client().await;
        for round in 0..2 {
            let text = format!("{name}{round}");
            let (reply, _) = ask(&socket, entry, text.as_bytes(), WAIT)
                .await
                .expect("reply");
            assert_eq!(reply, format!("A:{text}"));
        }
        real.push(socket);
    }
    let mut spoofed = Vec::new();
    for round in 0..300 {
        let socket = client().await;
        socket
            .send_to(format!("flood{round}").as_bytes(), entry)
            .await
            .expect("flood");
        spoofed.push(socket);
        if round == 150 {
            let page = podgate.get("h.test", "/").await;
            assert_eq!(
                page.status, 200,
                "HTTP traffic of the tenant during the flood"
            );
        }
    }
    sleep(SILENCE).await;
    for (socket, name) in real.iter().zip(["a2", "b2", "c2"]) {
        let (reply, _) = ask(socket, entry, name.as_bytes(), WAIT)
            .await
            .expect("a client that keeps sending keeps its session");
        assert_eq!(reply, format!("A:{name}"));
    }
    let late = client().await;
    assert!(
        ask(&late, entry, b"late", WAIT).await.is_some(),
        "a real newcomer evicts a single-datagram session"
    );
    assert!(metric(&podgate, "podgate_udp_sessions").await <= 8);
    assert!(
        metric(
            &podgate,
            "podgate_udp_sessions_closed_total{reason=\"evicted\"}"
        )
        .await
            >= 200
    );
    assert_eq!(podgate.get("h.test", "/").await.status, 200);
    drop(spoofed);
}

#[tokio::test]
async fn udp_spoofed_flood_keeps_established_sessions() {
    flood_keeps_talking_clients(echo("A").await).await;
    // DNS answers every source, so a reply proves nothing about the client's address.
    flood_keeps_talking_clients(echo_every_source().await).await;
}

#[tokio::test]
async fn udp_flood_sends_nothing_to_silent_clients() {
    let podgate = start().await;
    let up = echo("A").await;
    push(
        &podgate,
        &reserved(1, &[udp_app(&[up], &json!({}), &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let mut silent = Vec::new();
    for round in 0..200 {
        let socket = client().await;
        socket
            .send_to(format!("flood{round}").as_bytes(), entry)
            .await
            .expect("flood");
        silent.push(socket);
    }
    sleep(SILENCE).await;
    let mut buf = [0_u8; 64];
    for socket in &silent {
        assert!(
            timeout(Duration::from_millis(1), socket.recv_from(&mut buf))
                .await
                .is_err(),
            "podgate sent to an address its upstream never answered for"
        );
    }
    assert_eq!(
        metric(&podgate, "podgate_udp_datagrams_total{direction=\"out\"}").await,
        0
    );
    let real = client().await;
    for round in 0..3 {
        assert!(
            ask(&real, entry, format!("q{round}").as_bytes(), WAIT)
                .await
                .is_some()
        );
    }
    let out = "podgate_udp_datagrams_total{direction=\"out\"}";
    assert_eq!(
        wait_for(&podgate, out, |sent| sent >= 3).await,
        3,
        "one datagram out for each the upstream sent"
    );
}

#[tokio::test]
async fn udp_reply_bytes_bounded() {
    let podgate = start().await;
    let burst = server(Box::new(|payload| {
        if payload.starts_with(b"q") {
            vec![b"0123456789".to_vec(); 5]
        } else {
            Vec::new()
        }
    }))
    .await;
    let router = json!({ "max_reply_ratio": 3 });
    push(
        &podgate,
        &reserved(1, &[udp_app(&[burst], &router, &json!({}))]),
    )
    .await;
    let entry = podgate.entry_addr("dns");
    let one = client().await;
    one.send_to(b"q123456789", entry).await.expect("send");
    let mut buf = [0_u8; 64];
    let mut received = 0;
    while timeout(SILENCE, one.recv_from(&mut buf)).await.is_ok() {
        received += 1;
    }
    assert_eq!(received, 3, "30 bytes for a 10 byte query, no more");
    assert_eq!(
        metric(
            &podgate,
            "podgate_udp_dropped_total{reason=\"reply_ratio\"}"
        )
        .await,
        2
    );
    one.send_to(b"q-again", entry).await.expect("send");
    let mut received = 0;
    while timeout(SILENCE, one.recv_from(&mut buf)).await.is_ok() {
        received += 1;
    }
    assert_eq!(received, 5, "a second datagram lifts the limit");
}

#[tokio::test]
async fn udp_overview_lists_routers_and_services() {
    let podgate = start().await;
    let up = echo("A").await;
    let router = json!({ "max_reply_ratio": 3 });
    push(
        &podgate,
        &reserved(1, &[udp_app(&[up], &router, &json!({}))]),
    )
    .await;
    let answer = podgate.admin_get("/v1/overview?section=apps").await;
    assert_eq!(answer.status, 200, "{}", answer.body);
    let apps = answer.json()["apps"]["items"].clone();
    assert_eq!(
        apps[0]["udp"],
        json!({
            "routers": [{
                "name": "r", "entry_points": ["dns"], "service": "svc",
                "max_sessions": 4096, "max_reply_ratio": 3,
            }],
            "services": [{
                "name": "svc", "servers": [up.to_string()], "session_timeout_secs": 30,
            }],
        })
    );
}
