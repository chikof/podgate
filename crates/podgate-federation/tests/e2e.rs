//! The exporter and the hub together over real mutual TLS, behind a fake read socket; and against
//! a real daemon.

#![allow(
    clippy::unwrap_used,
    reason = "an unwrap that fails is the test failing, and the message is the line"
)]

mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::read_socket::{Daemon, FakeRead};
use common::{Dir, Pki, client_config, eventually, get, item};
use podgate_federation::config::{ExportFile, PeersFile, Pull};
use podgate_federation::export::Exporter;
use podgate_federation::hub::Hub;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

struct Chain {
    _dir: Dir,
    _exporter: Exporter,
    hub: Hub,
    op: std::sync::Arc<rustls::ClientConfig>,
}

async fn chain(socket: PathBuf, dir: Dir, pki: Pki) -> Chain {
    let (cert, key) = pki.server_files(&dir.0, "exp");
    let hub_ca = pki.ca_file(&dir.0, "hub-ca");
    let export = ExportFile::from_text(&format!(
        "read_socket = {socket:?}\n[serve]\naddr = \"127.0.0.1:0\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {hub_ca:?}\n"
    ))
    .expect("export file");
    let exporter = Exporter::start(export).await.expect("exporter");
    let (hub_cert, hub_key) = pki.client_files(&dir.0, "hub");
    let (view_cert, view_key) = pki.server_files(&dir.0, "view");
    let ops = pki.ca_file(&dir.0, "ops");
    let peer_ca = pki.ca_file(&dir.0, "peer-ca");
    let text = format!(
        "[view]\naddr = \"127.0.0.1:0\"\ncert_file = {view_cert:?}\nkey_file = {view_key:?}\nclient_ca_file = {ops:?}\n[client]\ncert_file = {hub_cert:?}\nkey_file = {hub_key:?}\n[[peer]]\nname = \"live\"\nurl = \"https://127.0.0.1:{}\"\nca_file = {peer_ca:?}\n",
        exporter.addr().port()
    );
    let mut file = PeersFile::from_text(&text).expect("peers file");
    file.pull = Pull {
        poll: Duration::from_millis(100),
        ..file.pull
    };
    let hub = Hub::start(file).await.expect("hub");
    let op = client_config(&pki, &dir, "op");
    Chain {
        _dir: dir,
        _exporter: exporter,
        hub,
        op,
    }
}

#[tokio::test]
async fn federation_hub_reads_exporter() {
    let dir = Dir::new();
    let pki = Pki::new();
    let socket = dir.join("read.sock");
    let items: Vec<Value> = (0..250)
        .map(|n| item("acme", &format!("id{n:03}"), "1", "stable"))
        .collect();
    let fake = FakeRead::start(
        socket.clone(),
        Daemon {
            items: items.clone(),
            page_cap: 80,
            ..Daemon::default()
        },
    );
    let chain = chain(socket, dir, pki).await;
    let addr = chain.hub.view_addr();
    eventually("the live cluster is fresh", || async {
        get(addr, &chain.op, "/v1/clusters").await.json()["items"][0]["state"] == "fresh"
    })
    .await;
    let mut seen = Vec::new();
    let mut query = "limit=500".to_owned();
    loop {
        let page = get(addr, &chain.op, &format!("/v1/catalog?{query}"))
            .await
            .json();
        seen.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|i| i["id"].as_str().unwrap().to_owned()),
        );
        if page["truncated"] != json!(true) {
            break;
        }
        query = format!(
            "limit=500&after={}",
            podgate_federation::wire::percent_encode(page["next"].as_str().unwrap())
        );
    }
    let expected: Vec<String> = items
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        seen, expected,
        "every entry, in order, through two hops and three page sizes"
    );
    let row = &get(addr, &chain.op, "/v1/clusters").await.json()["items"][0];
    assert_eq!(row["snapshot_version"], 7);
    assert_eq!(row["entries"], 250);
    for request in fake.seen() {
        assert_eq!(request.method, "GET");
        assert!(
            request.target == "/healthz"
                || request.target == "/v1/overview?section=summary"
                || request.target.starts_with("/v1/catalog?limit="),
            "{}",
            request.target
        );
    }
}

/// A real `podgate` process, the binary the workspace build produces (`PODGATE_BIN`, else
/// `target/debug/podgate`); a missing binary fails the test.
struct Podgate {
    child: Child,
    _dir: Dir,
    admin: PathBuf,
    read: PathBuf,
}

impl Drop for Podgate {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn podgate() -> Podgate {
    let bin = std::env::var("PODGATE_BIN").map_or_else(
        |_| {
            let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
            let target = std::env::var("CARGO_TARGET_DIR")
                .map_or_else(|_| workspace.join("target"), PathBuf::from);
            target.join("debug/podgate")
        },
        PathBuf::from,
    );
    assert!(
        bin.exists(),
        "the podgate binary is missing at {}: run `cargo build -p podgate` or set PODGATE_BIN",
        bin.display()
    );
    let dir = Dir::new();
    let admin = dir.join("admin.sock");
    let read = dir.join("read.sock");
    let child = Command::new(bin)
        .env("ADMIN_SOCKET", &admin)
        .env("ADMIN_READ_SOCKET", &read)
        .env("ADMIN_READ_SOCKET_MODE", "0600")
        .env("PROXY_ADDR", format!("127.0.0.1:{}", free_port()))
        .env("METRICS_ADDR", format!("127.0.0.1:{}", free_port()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn podgate");
    Podgate {
        child,
        _dir: dir,
        admin,
        read,
    }
}

async fn unix_request(
    path: &std::path::Path,
    method: &str,
    target: &str,
    body: &str,
) -> (u16, Vec<u8>) {
    let mut stream = UnixStream::connect(path).await.expect("connect");
    let text = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(text.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("an answer");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, raw[split + 4..].to_vec())
}

async fn wait_for_sockets(daemon: &Podgate) {
    eventually("the daemon's sockets", || async {
        UnixStream::connect(&daemon.read).await.is_ok()
            && UnixStream::connect(&daemon.admin).await.is_ok()
    })
    .await;
}

#[tokio::test]
async fn federation_export_reads_live_summary() {
    let daemon = podgate();
    wait_for_sockets(&daemon).await;
    let dir = Dir::new();
    let pki = Pki::new();
    let (cert, key) = pki.server_files(&dir.0, "exp");
    let hub_ca = pki.ca_file(&dir.0, "hub-ca");
    let read = &daemon.read;
    let export = ExportFile::from_text(&format!(
        "read_socket = {read:?}\n[serve]\naddr = \"127.0.0.1:0\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {hub_ca:?}\n"
    ))
    .expect("export file");
    let exporter = Exporter::start(export)
        .await
        .expect("the daemon's read socket is accepted");
    let hub = client_config(&pki, &dir, "hub");
    let status = get(exporter.addr(), &hub, "/federation/v1/status").await;
    assert_eq!(
        status.status,
        200,
        "{}",
        String::from_utf8_lossy(&status.body)
    );
    let doc = status.json();
    let (_, summary) = unix_request(&daemon.admin, "GET", "/v1/overview?section=summary", "").await;
    let summary: Value = serde_json::from_slice(&summary).unwrap();
    assert_eq!(doc["snapshot_version"], summary["summary"]["version"]);
    assert_eq!(doc["boot_id"], summary["summary"]["boot_id"]);
    assert_eq!(doc["counts"]["tenants"], summary["summary"]["tenants"]);
    assert_eq!(doc["format_version"], 1);
    let other = get(exporter.addr(), &hub, "/federation/v1/snapshot").await;
    assert_eq!(other.status, 404);
}

#[tokio::test]
#[ignore = "needs 0135's GET /v1/catalog on the read socket"]
async fn federation_export_reads_live_daemon() {
    let daemon = podgate();
    wait_for_sockets(&daemon).await;
    let snapshot = json!({
        "version": 1,
        "tenants": [{"id": "acme", "weight": 1, "budget": {"max_inflight": 10, "max_buffer_bytes": 1_048_576}}],
        "apps": []
    });
    let (status, body) =
        unix_request(&daemon.admin, "PUT", "/v1/snapshot", &snapshot.to_string()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let dir = Dir::new();
    let chain = chain(daemon.read.clone(), dir, Pki::new()).await;
    let addr = chain.hub.view_addr();
    eventually("the live cluster is fresh", || async {
        get(addr, &chain.op, "/v1/clusters").await.json()["items"][0]["state"] == "fresh"
    })
    .await;
    let (_, direct) = unix_request(&daemon.admin, "GET", "/v1/catalog?limit=500", "").await;
    let direct: Value = serde_json::from_slice(&direct).unwrap();
    let viewed = get(addr, &chain.op, "/v1/catalog?limit=500").await.json();
    assert_eq!(viewed["total"], direct["total"]);
    assert_eq!(
        viewed["items"].as_array().unwrap().len(),
        direct["items"].as_array().unwrap().len()
    );
    let (_, local) = unix_request(&daemon.admin, "GET", "/v1/overview", "").await;
    assert!(
        !String::from_utf8_lossy(&local).contains("\"cluster\""),
        "the local overview holds no federated data"
    );
    let (_, version) = unix_request(&daemon.admin, "GET", "/v1/snapshot/version", "").await;
    assert!(
        String::from_utf8_lossy(&version).contains("\"version\":1"),
        "the pull changed nothing"
    );
}

#[tokio::test]
async fn federation_export_refuses_the_real_admin_socket() {
    let daemon = podgate();
    wait_for_sockets(&daemon).await;
    let dir = Dir::new();
    let pki = Pki::new();
    let (cert, key) = pki.server_files(&dir.0, "exp");
    let hub_ca = pki.ca_file(&dir.0, "hub-ca");
    for (socket, refused) in [(&daemon.admin, true), (&daemon.read, false)] {
        let export = ExportFile::from_text(&format!(
            "read_socket = {socket:?}\n[serve]\naddr = \"127.0.0.1:0\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {hub_ca:?}\n"
        ))
        .expect("export file");
        let started = Exporter::start(export).await;
        assert_eq!(
            matches!(
                started,
                Err(podgate_federation::export::StartError::FullSocket)
            ),
            refused,
            "{}",
            socket.display()
        );
    }
}
