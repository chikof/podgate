//! The exporter against a fake read socket: who may connect, what it serves, what it asks the
//! daemon, and what it never lets through.

#![allow(
    clippy::unwrap_used,
    reason = "an unwrap that fails is the test failing, and the message is the line"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::read_socket::{Daemon, FakeRead};
use common::{DEADLINE, Dir, Pki, anonymous_client, client_config, get, item, request};
use podgate_federation::admin_get::AdminError;
use podgate_federation::config::ExportFile;
use podgate_federation::export::{Exporter, StartError};
use serde_json::{Value, json};

struct Rig {
    dir: Dir,
    pki: Pki,
    exporter: Exporter,
    hub: Arc<rustls::ClientConfig>,
}

fn export_text(dir: &Dir, pki: &Pki, socket: &std::path::Path, extra: &str) -> String {
    let (cert, key) = pki.server_files(&dir.0, "exp");
    let ca = pki.ca_file(&dir.0, "hub-ca");
    format!(
        "read_socket = {socket:?}\n{extra}\n[serve]\naddr = \"127.0.0.1:0\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {ca:?}\n"
    )
}

async fn start(daemon: Daemon, extra: &str) -> (Rig, FakeRead) {
    let dir = Dir::new();
    let pki = Pki::new();
    let socket = dir.join("read.sock");
    let fake = FakeRead::start(socket.clone(), daemon);
    let file =
        ExportFile::from_text(&export_text(&dir, &pki, &socket, extra)).expect("export file");
    let exporter = Exporter::start(file).await.expect("exporter starts");
    let hub = client_config(&pki, &dir, "hub");
    (
        Rig {
            dir,
            pki,
            exporter,
            hub,
        },
        fake,
    )
}

fn catalog(count: usize) -> Vec<Value> {
    (0..count)
        .map(|n| item("acme", &format!("id{n:03}"), "1", "stable"))
        .collect()
}

impl Rig {
    async fn get(&self, target: &str) -> common::Got {
        get(self.exporter.addr(), &self.hub, target).await
    }
}

#[tokio::test]
async fn federation_export_requires_client_cert() {
    let (rig, _fake) = start(
        Daemon {
            items: catalog(2),
            ..Daemon::default()
        },
        "",
    )
    .await;
    let addr = rig.exporter.addr();
    assert_eq!(
        rig.get("/federation/v1/status").await.status,
        200,
        "the right certificate works"
    );
    let anon = anonymous_client(&rig.pki, &rig.dir);
    assert!(
        request(addr, anon, "GET", "/federation/v1/status", "")
            .await
            .is_err(),
        "no certificate"
    );
    let rogue = Pki::new();
    let ours = {
        let (cert, key) = rogue.client_files(&rig.dir.0, "rogue");
        let ca = rig.pki.ca_file(&rig.dir.0, "trust-ours");
        podgate_federation::tls::Identity::load("t", &cert, &key)
            .unwrap()
            .client_config("t", podgate_federation::tls::roots("t", &ca).unwrap())
            .unwrap()
    };
    assert!(
        request(addr, ours, "GET", "/federation/v1/status", "")
            .await
            .is_err(),
        "a certificate of another CA"
    );
    let expired = {
        let (cert, key) = rig.pki.expired_client_files(&rig.dir.0, "old");
        let ca = rig.pki.ca_file(&rig.dir.0, "trust-ours2");
        podgate_federation::tls::Identity::load("t", &cert, &key)
            .unwrap()
            .client_config("t", podgate_federation::tls::roots("t", &ca).unwrap())
            .unwrap()
    };
    assert!(
        request(addr, expired, "GET", "/federation/v1/status", "")
            .await
            .is_err(),
        "an expired certificate"
    );
    // A client that speaks no TLS gets nothing and costs nothing.
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut plain,
        b"GET /federation/v1/status HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await
    .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::io::AsyncReadExt::read_to_end(&mut plain, &mut answer),
    )
    .await;
    assert!(!String::from_utf8_lossy(&answer).contains("HTTP/1.1 200"));
}

#[tokio::test]
async fn federation_export_only_two_routes() {
    let (rig, fake) = start(
        Daemon {
            items: catalog(3),
            ..Daemon::default()
        },
        "",
    )
    .await;
    let addr = rig.exporter.addr();
    for path in [
        "/",
        "/v1/catalog",
        "/v1/snapshot",
        "/v1/events",
        "/healthz",
        "/federation/v1",
        "/federation/v1/status/",
        "/federation/v2/status",
        "/federation/v1/overview",
    ] {
        for method in ["GET", "POST"] {
            let got = request(addr, rig.hub.clone(), method, path, "")
                .await
                .unwrap();
            assert_eq!(got.status, 404, "{method} {path}");
            assert_eq!(got.json(), json!({"error": "not found"}));
        }
    }
    for path in ["/federation/v1/status", "/federation/v1/catalog"] {
        for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let got = request(addr, rig.hub.clone(), method, path, "")
                .await
                .unwrap();
            assert_eq!(got.status, 405, "{method} {path}");
            assert_eq!(got.header("allow").as_deref(), Some("GET"));
        }
    }
    let body = request(
        addr,
        rig.hub.clone(),
        "GET",
        "/federation/v1/status",
        "Content-Length: 2\r\n",
    )
    .await
    .unwrap();
    assert_eq!(body.status, 400);
    assert_eq!(
        rig.get("/federation/v1/status?x=1").await.status,
        400,
        "unknown parameter"
    );
    assert_eq!(
        rig.get("/federation/v1/catalog?limit=1&limit=2")
            .await
            .status,
        400,
        "repeated parameter"
    );
    assert_eq!(rig.get("/federation/v1/catalog?limit=0").await.status, 400);
    for got in [
        rig.get("/federation/v1/status").await,
        rig.get("/nowhere").await,
    ] {
        assert_eq!(
            got.header("x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(got.header("cache-control").as_deref(), Some("no-store"));
    }
    for seen in fake.seen() {
        assert!(
            seen.target == "/healthz"
                || seen.target == "/v1/overview?section=summary"
                || seen.target.starts_with("/v1/catalog?limit="),
            "the daemon saw {}",
            seen.target
        );
    }
}

#[tokio::test]
async fn federation_export_validates_cursor() {
    let (rig, fake) = start(
        Daemon {
            items: catalog(3),
            ..Daemon::default()
        },
        "",
    )
    .await;
    let long = "a/".repeat(300);
    for bad in [
        "a%0d%0aGET%20/v1/snapshot%20HTTP/1.1".to_owned(),
        "a/b/c%0d%0a".to_owned(),
        "a/b/c%00".to_owned(),
        "a/b/c%0a".to_owned(),
        podgate_federation::wire::percent_encode(&long),
        "a%2Fb".to_owned(),
        "%2F%2F".to_owned(),
        "a/b/c%".to_owned(),
        "%ff%fe".to_owned(),
    ] {
        let got = rig
            .get(&format!("/federation/v1/catalog?after={bad}"))
            .await;
        assert_eq!(got.status, 400, "after={bad}");
    }
    assert!(
        fake.seen()
            .iter()
            .all(|s| !s.target.starts_with("/v1/catalog")),
        "the daemon was never asked: {:?}",
        fake.seen()
    );
    assert_eq!(
        rig.get("/federation/v1/catalog?limit=5000").await.status,
        200
    );
    let paged = rig
        .get("/federation/v1/catalog?limit=1&after=acme%2Fid000%2F1")
        .await
        .json();
    assert_eq!(paged["items"][0]["id"], "id001");
    assert!(
        fake.seen().iter().any(|s| s.target.contains("limit=200")),
        "limit is clamped"
    );
}

#[tokio::test]
async fn federation_export_reencodes_closed_shape() {
    let mut items = catalog(2);
    items[0]["description"] = json!("d".repeat(5000));
    items[1]["tenant"] = json!("t".repeat(300));
    items[1]["id"] = json!("zzz");
    let (rig, _fake) = start(
        Daemon {
            items,
            extras: true,
            ..Daemon::default()
        },
        "",
    )
    .await;
    let status = rig.get("/federation/v1/status").await;
    assert_eq!(status.status, 200);
    let doc = status.json();
    let mut keys: Vec<&str> = doc
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "applied_at",
            "boot_id",
            "counts",
            "format_version",
            "snapshot_version",
            "writer"
        ]
    );
    assert_eq!(doc["snapshot_version"], 7);
    assert_eq!(doc["boot_id"], "daemon-boot");
    let catalog = rig.get("/federation/v1/catalog").await;
    let text = String::from_utf8_lossy(&catalog.body).into_owned();
    for planted in ["SECRET", "client_ca_pem", "nested", "metrics_addr"] {
        assert!(
            !text.contains(planted) && !String::from_utf8_lossy(&status.body).contains(planted),
            "{planted} got through"
        );
    }
    let doc = catalog.json();
    assert_eq!(doc["format_version"], 1);
    assert_eq!(
        doc["snapshot_version"], 7,
        "the daemon's version is renamed"
    );
    assert!(doc.get("version").is_none());
    let list = doc["items"].as_array().unwrap();
    assert_eq!(
        list.len(),
        1,
        "the entry with a 300 byte tenant is left out"
    );
    assert!(
        list[0]["description"].as_str().unwrap().len() <= 2048,
        "long text is cut"
    );
}

#[tokio::test]
async fn federation_export_steps_over_dropped_entries() {
    let mut items = catalog(5);
    for broken in [1, 2] {
        items[broken]["title"] = json!("bad\u{0}title");
    }
    let (rig, fake) = start(
        Daemon {
            items,
            page_cap: 2,
            ..Daemon::default()
        },
        "",
    )
    .await;
    let first = rig.get("/federation/v1/catalog?limit=2").await.json();
    assert_eq!(
        first["items"].as_array().unwrap().len(),
        1,
        "id000 and a dropped id001"
    );
    assert_eq!(first["truncated"], true);
    let next = first["next"].as_str().unwrap();
    assert_eq!(
        next, "acme/id000/1",
        "the cursor continues after the last entry that was sent"
    );
    let second = rig
        .get(&format!(
            "/federation/v1/catalog?limit=2&after={}",
            podgate_federation::wire::percent_encode(next)
        ))
        .await
        .json();
    let ids: Vec<&str> = second["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["id003", "id004"],
        "id001 and id002 are both dropped; the exporter stepped to the next daemon page"
    );
    assert!(
        fake.seen()
            .iter()
            .filter(|s| s.target.starts_with("/v1/catalog"))
            .count()
            >= 3
    );
}

#[tokio::test]
async fn federation_export_caps_admin_concurrency() {
    let (rig, fake) = start(
        Daemon {
            items: catalog(3),
            delay: Duration::from_millis(200),
            ..Daemon::default()
        },
        "admin_slots = 2\n",
    )
    .await;
    let addr = rig.exporter.addr();
    let hub = rig.hub.clone();
    let mut calls = Vec::new();
    for n in 0..6 {
        let hub = hub.clone();
        let target = if n % 2 == 0 {
            "/federation/v1/status"
        } else {
            "/federation/v1/catalog"
        };
        calls.push(tokio::spawn(
            async move { get(addr, &hub, target).await.status },
        ));
    }
    for call in calls {
        assert_eq!(call.await.unwrap(), 200);
    }
    let peak = fake.peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        (1..=2).contains(&peak),
        "never more than admin_slots requests at once, saw {peak}"
    );
}

#[tokio::test]
async fn federation_export_daemon_down_is_502() {
    let dir = Dir::new();
    let pki = Pki::new();
    let file =
        ExportFile::from_text(&export_text(&dir, &pki, &dir.join("absent.sock"), "")).unwrap();
    let exporter = Exporter::start(file)
        .await
        .expect("a daemon that is not up yet is not an error");
    let hub = client_config(&pki, &dir, "hub");
    let down = get(exporter.addr(), &hub, "/federation/v1/status").await;
    assert_eq!(down.status, 502);
    assert_eq!(down.json(), json!({"error": "the daemon is unavailable"}));
    let (rig, _fake) = start(
        Daemon {
            fail: Some(503),
            ..Daemon::default()
        },
        "",
    )
    .await;
    let busy = rig.get("/federation/v1/catalog").await;
    assert_eq!(
        (busy.status, busy.header("retry-after").as_deref()),
        (503, Some("1"))
    );
    let (rig, _fake) = start(
        Daemon {
            fail: Some(500),
            ..Daemon::default()
        },
        "",
    )
    .await;
    assert_eq!(rig.get("/federation/v1/status").await.status, 502);
}

#[tokio::test]
async fn federation_export_refuses_full_admin_socket() {
    let dir = Dir::new();
    let pki = Pki::new();
    let socket = dir.join("admin.sock");
    let fake = FakeRead::start(
        socket.clone(),
        Daemon {
            healthz: 200,
            items: catalog(2),
            ..Daemon::default()
        },
    );
    let file = ExportFile::from_text(&export_text(&dir, &pki, &socket, "")).unwrap();
    match Exporter::start(file).await {
        Err(StartError::FullSocket) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        fake.seen().iter().all(|s| s.target == "/healthz"),
        "nothing but the probe was sent: {:?}",
        fake.seen()
    );
    drop(fake);
    // The daemon is not up at start; the full socket shows up later: the first request refuses.
    let file = ExportFile::from_text(&export_text(&dir, &pki, &socket, "")).unwrap();
    let mut exporter = Exporter::start(file).await.expect("starts");
    let fake = FakeRead::start(
        socket.clone(),
        Daemon {
            healthz: 200,
            items: catalog(2),
            ..Daemon::default()
        },
    );
    let hub = client_config(&pki, &dir, "hub");
    let got = get(exporter.addr(), &hub, "/federation/v1/catalog").await;
    assert_eq!(got.status, 502);
    let fatal = tokio::time::timeout(DEADLINE, exporter.fatal())
        .await
        .expect("the exporter says it must stop");
    assert_eq!(fatal, AdminError::FullSocket);
    assert!(
        fake.seen().iter().all(|s| s.target == "/healthz"),
        "no catalog request was sent"
    );
    drop(exporter);
    drop(fake);
    // A read socket is accepted.
    let ok = FakeRead::start(socket.clone(), Daemon::default());
    let file = ExportFile::from_text(&export_text(&dir, &pki, &socket, "")).unwrap();
    assert!(Exporter::start(file).await.is_ok());
    drop(ok);
}

#[tokio::test]
async fn federation_does_not_touch_routing() {
    let (rig, fake) = start(
        Daemon {
            items: catalog(250),
            ..Daemon::default()
        },
        "",
    )
    .await;
    // The reader of the exporter tries everything a hub could say.
    for target in [
        "/federation/v1/status",
        "/federation/v1/catalog",
        "/federation/v1/catalog?limit=200&after=acme%2Fid099%2F1",
    ] {
        assert_eq!(rig.get(target).await.status, 200);
    }
    for method in ["POST", "PUT", "DELETE"] {
        let _ = request(
            rig.exporter.addr(),
            rig.hub.clone(),
            method,
            "/federation/v1/catalog",
            "",
        )
        .await;
    }
    let seen = fake.seen();
    assert!(!seen.is_empty());
    for request in &seen {
        assert_eq!(request.method, "GET", "{}", request.target);
        let allowed = request.target == "/healthz"
            || request.target == "/v1/overview?section=summary"
            || request.target.starts_with("/v1/catalog?limit=");
        assert!(allowed, "the daemon was asked {}", request.target);
    }
}
