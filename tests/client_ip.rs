//! Client IP resolution end to end: forged forwarding headers from a peer the entry
//! point does not trust are removed, a trusted peer's chain is walked from the right, and the
//! `client_ip` matcher routes on the result.
//!
//! The test client connects from `127.0.0.1`, so `trusted_ips: ["127.0.0.0/8"]` makes it a
//! trusted proxy and the default (no policy) makes it an ordinary client. The upstreams here
//! echo the request headers they receive, which is how a test sees what survived.

mod common;

use std::net::SocketAddr;

use common::{Podgate, Response, app, router, service, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A backend that answers with its label, then every request header it saw as `name: value`.
struct Echo {
    addr: SocketAddr,
}

impl Echo {
    async fn start(label: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(echo(stream, label));
            }
        });
        Self { addr }
    }
}

async fn echo(mut stream: TcpStream, label: &'static str) {
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        while let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
            let mut body = format!("{label}\n");
            for line in head.split("\r\n").skip(1) {
                body.push_str(line);
                body.push('\n');
            }
            seen.drain(..end + 4);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen.extend_from_slice(&chunk[..read]),
        }
    }
}

/// The label line and the echoed header lines of an [`Echo`] response.
fn echoed(response: &Response) -> (&str, Vec<&str>) {
    let mut lines = response.body.lines();
    (lines.next().unwrap_or_default(), lines.collect())
}

fn has_header(response: &Response, name: &str) -> bool {
    echoed(response)
        .1
        .iter()
        .any(|line| line.starts_with(&format!("{name}:")))
}

/// One app `a.test`: requests from a client in `ranges` go to the `matched` echo, everyone else
/// to the `plain` one.
fn routed_app(ranges: &Value, plain: SocketAddr, matched: SocketAddr) -> Value {
    let mut app = app("a", &["a.test"], &[]);
    app["routers"] = json!([
        router("plain", json!({"host": "a.test"}), "plain"),
        router(
            "by-client",
            json!({"all": [{"host": "a.test"}, {"client_ip": ranges}]}),
            "matched"
        ),
    ]);
    app["revisions"] = json!([{
        "id": "r1", "state": "serving", "weight": 100,
        "services": [service("plain", &[plain]), service("matched", &[matched])],
    }]);
    app
}

/// A snapshot whose `web` entry point has `forwarded_headers` as its policy.
fn with_policy(mut snapshot: Value, forwarded_headers: Option<Value>) -> Value {
    if let Some(policy) = forwarded_headers {
        snapshot["entry_points"] = json!([{"name": "web", "forwarded_headers": policy}]);
    }
    snapshot
}

struct Setup {
    podgate: Podgate,
    _plain: Echo,
    _matched: Echo,
}

async fn setup(ranges: Value, policy: Option<Value>) -> Setup {
    let podgate = Podgate::start().await;
    let plain = Echo::start("plain").await;
    let matched = Echo::start("matched").await;
    let pushed = podgate
        .push_snapshot(&with_policy(
            snapshot(1, &[routed_app(&ranges, plain.addr, matched.addr)]),
            policy,
        ))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    Setup {
        podgate,
        _plain: plain,
        _matched: matched,
    }
}

const TRUST_LOCAL: &str = "127.0.0.0/8";

#[tokio::test]
async fn xff_from_untrusted_peer_ignored() {
    let setup = setup(json!(["203.0.113.7"]), None).await;
    let response = setup
        .podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Real-IP", "203.0.113.7"),
                ("Forwarded", "for=203.0.113.7"),
            ],
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        echoed(&response).0,
        "plain",
        "the forged address routed nothing"
    );
    for name in ["x-forwarded-for", "x-real-ip", "forwarded"] {
        assert!(
            !has_header(&response, name),
            "{name} reached the upstream: {}",
            response.body
        );
    }
}

#[tokio::test]
async fn untrusted_peer_matches_on_its_own_address() {
    let setup = setup(json!(["127.0.0.1"]), None).await;
    let response = setup.podgate.get("a.test", "/").await;
    assert_eq!(echoed(&response).0, "matched", "{}", response.body);
}

#[tokio::test]
async fn forwarded_proto_from_untrusted_ignored() {
    let setup = setup(
        json!(["203.0.113.7"]),
        Some(json!({"trusted_ips": ["10.0.0.0/8"]})),
    )
    .await;
    let response = setup
        .podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "evil.test"),
                ("X-Forwarded-Port", "443"),
                ("X-Forwarded-Server", "evil"),
                ("X-Forwarded-Tls-Client-Cert-Subject", "CN=admin"),
            ],
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    let leaked: Vec<_> = echoed(&response)
        .1
        .into_iter()
        .filter(|line| line.starts_with("x-forwarded-"))
        .collect();
    assert!(
        leaked.is_empty(),
        "forged headers reached the upstream: {leaked:?}"
    );
}

#[tokio::test]
async fn xff_walk_skips_trusted_hops() {
    let setup = setup(
        json!(["203.0.113.0/24"]),
        Some(json!({"trusted_ips": [TRUST_LOCAL, "10.0.0.0/8"]})),
    )
    .await;
    let route = |xff: &'static str| {
        let podgate = &setup.podgate;
        async move {
            let response = podgate
                .get_with_headers("a.test", "/", &[("X-Forwarded-For", xff)])
                .await;
            assert_eq!(response.status, 200, "{}", response.body);
            echoed(&response).0.to_owned()
        }
    };
    assert_eq!(route("203.0.113.7").await, "matched");
    assert_eq!(
        route("198.51.100.1, 203.0.113.7, 10.0.0.2, 127.0.0.2").await,
        "matched"
    );
    assert_eq!(
        route("203.0.113.7, 198.51.100.1, 10.0.0.2").await,
        "plain",
        "the first untrusted address from the right is the client, not the leftmost"
    );
    assert_eq!(route("::ffff:203.0.113.7").await, "matched");
}

#[tokio::test]
async fn trusted_peer_view_keeps_proto_and_host() {
    let setup = setup(
        json!(["203.0.113.7"]),
        Some(json!({"trusted_ips": [TRUST_LOCAL]})),
    )
    .await;
    let response = setup
        .podgate
        .get_with_headers(
            "a.test",
            "/",
            &[
                ("X-Forwarded-For", "203.0.113.7"),
                ("X-Forwarded-Proto", "https"),
                ("X-Forwarded-Host", "shop.example"),
            ],
        )
        .await;
    assert_eq!(echoed(&response).0, "matched", "{}", response.body);
    let lines = echoed(&response).1;
    for kept in [
        "x-forwarded-for: 203.0.113.7",
        "x-forwarded-proto: https",
        "x-forwarded-host: shop.example",
    ] {
        assert!(lines.contains(&kept), "{kept} missing in {lines:?}");
    }
}

#[tokio::test]
async fn xff_malformed_entries_ignored() {
    let setup = setup(
        json!(["203.0.113.7"]),
        Some(json!({"trusted_ips": [TRUST_LOCAL]})),
    )
    .await;
    for xff in [
        "garbage, 203.0.113.7, <script>",
        "203.0.113.7, , 999.999.1.1,",
        "203.0.113.7:4711, not-an-ip",
        "[203.0.113.7",
    ] {
        let response = setup
            .podgate
            .get_with_headers("a.test", "/", &[("X-Forwarded-For", xff)])
            .await;
        assert_eq!(response.status, 200, "{xff}: {}", response.body);
        let label = echoed(&response).0;
        assert_eq!(
            label,
            if xff == "[203.0.113.7" {
                "plain"
            } else {
                "matched"
            },
            "{xff}"
        );
    }
    let junk = setup
        .podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", "garbage")])
        .await;
    assert_eq!(
        echoed(&junk).0,
        "plain",
        "junk never becomes the client address"
    );
}

#[tokio::test]
async fn client_ip_leaf_cidr_routes_ipv4_and_ipv6_lists() {
    let setup = setup(
        json!(["2001:db8::/32", "198.51.100.0/24"]),
        Some(json!({"trusted_ips": [TRUST_LOCAL]})),
    )
    .await;
    for (xff, want) in [
        ("198.51.100.9", "matched"),
        ("2001:db8::5", "matched"),
        ("[2001:db8::5]:4711", "matched"),
        ("2001:db9::5", "plain"),
        ("198.51.101.9", "plain"),
    ] {
        let response = setup
            .podgate
            .get_with_headers("a.test", "/", &[("X-Forwarded-For", xff)])
            .await;
        assert_eq!(echoed(&response).0, want, "{xff}");
    }
}

#[tokio::test]
async fn client_ip_v4_mapped_normalized_in_the_peer_policy() {
    let setup = setup(
        json!(["203.0.113.7"]),
        Some(json!({"trusted_ips": ["::ffff:127.0.0.0/104"]})),
    )
    .await;
    let response = setup
        .podgate
        .get_with_headers("a.test", "/", &[("X-Forwarded-For", "::ffff:203.0.113.7")])
        .await;
    assert_eq!(echoed(&response).0, "matched", "{}", response.body);
}

#[tokio::test]
async fn invalid_client_ip_matchers_and_policies_are_rejected() {
    let podgate = Podgate::start().await;
    let up = Echo::start("x").await;
    for (matcher, code) in [
        (json!({"client_ip": []}), "invalid_matcher"),
        (json!({"client_ip": ["10.0.0.0/33"]}), "invalid_matcher"),
        (json!({"client_ip": [7]}), "invalid_matcher"),
        (json!({"client_ip": "nope"}), "invalid_matcher"),
    ] {
        let mut candidate = app("a", &["a.test"], &[]);
        candidate["routers"] = json!([router(
            "r",
            json!({"all": [{"host": "a.test"}, matcher]}),
            "web"
        )]);
        candidate["revisions"] = json!([{"id": "r1", "state": "serving", "weight": 100, "services": [service("web", &[up.addr])]}]);
        let response = podgate.push_snapshot(&snapshot(1, &[candidate])).await;
        assert_eq!(response.status, 422, "{matcher}: {}", response.body);
        assert!(response.body.contains(code), "{matcher}: {}", response.body);
    }
    for policy in [
        json!({"trusted": ["10.0.0.0/8"]}),
        json!({"trusted_ips": ["nope"]}),
        json!({"insecure": "yes"}),
    ] {
        let candidate = with_policy(snapshot(1, &[]), Some(policy.clone()));
        let response = podgate.push_snapshot(&candidate).await;
        assert_eq!(response.status, 422, "{policy}: {}", response.body);
        assert!(
            response.body.contains("invalid_forwarded_headers"),
            "{policy}: {}",
            response.body
        );
    }
}

#[tokio::test]
async fn client_ip_disjoint_ranges_are_not_ambiguous_and_overlapping_ones_are() {
    let podgate = Podgate::start().await;
    let up = Echo::start("x").await;
    let with_ranges = |first: Value, second: Value| {
        let mut candidate = app("a", &["a.test"], &[]);
        candidate["routers"] = json!([
            router(
                "one",
                json!({"all": [{"host": "a.test"}, {"client_ip": first}]}),
                "web"
            ),
            router(
                "two",
                json!({"all": [{"host": "a.test"}, {"client_ip": second}]}),
                "web"
            ),
        ]);
        candidate["revisions"] = json!([{"id": "r1", "state": "serving", "weight": 100, "services": [service("web", &[up.addr])]}]);
        snapshot(1, &[candidate])
    };
    let disjoint = podgate
        .push_snapshot(&with_ranges(
            json!(["10.0.0.0/8"]),
            json!(["192.168.0.0/16", "2001:db8::/32"]),
        ))
        .await;
    assert_eq!(disjoint.status, 200, "{}", disjoint.body);
    let overlapping = podgate
        .push_snapshot(&{
            let mut next = with_ranges(json!(["10.0.0.0/8"]), json!(["10.1.0.0/16"]));
            next["version"] = json!(2);
            next
        })
        .await;
    assert_eq!(overlapping.status, 422, "{}", overlapping.body);
    assert!(
        overlapping.body.contains("route_ambiguity"),
        "{}",
        overlapping.body
    );
}

#[tokio::test]
async fn plan_lists_forwarded_headers_insecure() {
    let podgate = Podgate::start().await;
    let up = Echo::start("x").await;
    let apps = [app("a", &["a.test"], &[common::serving("r1", up.addr)])];
    let live = with_policy(
        snapshot(1, &apps),
        Some(json!({"trusted_ips": ["10.0.0.0/8"]})),
    );
    assert_eq!(podgate.push_snapshot(&live).await.status, 200);

    let insecure = with_policy(snapshot(2, &apps), Some(json!({"insecure": true})));
    let response = podgate.admin_post("/v1/snapshot/plan", &insecure).await;
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        response.json()["posture_changes"],
        json!([{ "host": "entry_point:web", "app": "", "kind": "forwarded_headers_insecure" }])
    );

    let wider = with_policy(
        snapshot(2, &apps),
        Some(json!({"trusted_ips": ["10.0.0.0/8", "172.16.0.0/12"]})),
    );
    let response = podgate.admin_post("/v1/snapshot/plan", &wider).await;
    assert_eq!(
        response.json()["posture_changes"],
        json!([{ "host": "entry_point:web", "app": "", "kind": "forwarded_trusted_ips_widened" }])
    );

    let tighter = with_policy(snapshot(2, &apps), None);
    let response = podgate.admin_post("/v1/snapshot/plan", &tighter).await;
    assert_eq!(response.json()["posture_changes"], json!([]));
}

#[tokio::test]
async fn explain_takes_a_client_ip() {
    let setup = setup(json!(["203.0.113.0/24"]), None).await;
    let without = setup
        .podgate
        .admin_get("/v1/explain?url=http://a.test/")
        .await;
    assert_eq!(without.json()["matched"]["router"], "plain");
    let with = setup
        .podgate
        .admin_get("/v1/explain?url=http://a.test/&client_ip=203.0.113.9")
        .await;
    assert_eq!(
        with.json()["matched"]["router"],
        "by-client",
        "{}",
        with.body
    );
}
