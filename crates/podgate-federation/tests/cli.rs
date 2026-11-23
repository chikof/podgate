//! The binary: usage, `check`, and that no credential reaches a log, an error or the view.

#![allow(
    clippy::unwrap_used,
    reason = "an unwrap that fails is the test failing, and the message is the line"
)]

mod common;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{DEADLINE, Dir, FakePeer, Pki, catalog_script, client_config, get, item};

const BIN: &str = env!("CARGO_BIN_EXE_podgate-federation");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN)
        .args(args)
        .output()
        .expect("run the binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn federation_cli_usage_and_check() {
    for args in [
        &[][..],
        &["hub"],
        &["hub", "--config"],
        &["nope", "--config", "x"],
        &["check"],
        &["check", "hub"],
    ] {
        let (code, _, stderr) = run(args);
        assert_eq!(code, 2, "{args:?}");
        assert!(stderr.contains("usage:"), "{stderr}");
    }
    let dir = Dir::new();
    let pki = Pki::new();
    let (cert, key) = pki.server_files(&dir.0, "exp");
    let ca = pki.ca_file(&dir.0, "ca");
    let file = dir.join("export.toml");
    std::fs::write(&file, format!("read_socket = \"/x.sock\"\n[serve]\naddr = \"127.0.0.1:1\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {ca:?}\n")).unwrap();
    let (code, stdout, stderr) = run(&["check", "export", "--config", file.to_str().unwrap()]);
    assert_eq!((code, stdout.starts_with("ok")), (0, true), "{stderr}");
    let (code, _, stderr) = run(&["check", "hub", "--config", file.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(stderr.contains("peers file"), "{stderr}");
    let (code, _, stderr) = run(&["hub", "--config", "/nonexistent.toml"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("/nonexistent.toml"));
}

/// Lines of `pem` that carry key or certificate material.
fn secret_lines(pem: &str) -> Vec<String> {
    pem.lines()
        .filter(|l| l.len() > 20 && !l.starts_with("-----"))
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn federation_credentials_never_logged() {
    let dir = Dir::new();
    let pki = Pki::new();
    let (hub_cert, hub_key) = pki.client_files(&dir.0, "hub");
    let (view_cert, view_key) = pki.server_files(&dir.0, "view");
    let ops = pki.ca_file(&dir.0, "ops");
    let peer_ca = pki.ca_file(&dir.0, "peer-ca");
    // Text around the PEM blocks is ignored by the parser; plant a marker in each file.
    for path in [&hub_key, &view_key, &hub_cert, &view_cert] {
        let text = std::fs::read_to_string(path).unwrap();
        std::fs::write(
            path,
            format!(
                "PLANTED-MARKER-{}\n{text}",
                path.file_name().unwrap().to_string_lossy()
            ),
        )
        .unwrap();
    }
    let mut secrets: Vec<String> = Vec::new();
    for path in [&hub_key, &view_key] {
        secrets.extend(secret_lines(&std::fs::read_to_string(path).unwrap()));
    }
    secrets.extend([
        "PLANTED-MARKER-hub.key".into(),
        "PLANTED-MARKER-view.key".into(),
        "PLANTED-MARKER-hub.pem".into(),
    ]);
    let peer = FakePeer::start(
        &pki,
        &pki,
        catalog_script(vec![item("acme", "a", "1", "stable")], 1),
    )
    .await;
    let port = free_port();
    let file = dir.join("peers.toml");
    let good = format!(
        "[view]\naddr = \"127.0.0.1:{port}\"\ncert_file = {view_cert:?}\nkey_file = {view_key:?}\nclient_ca_file = {ops:?}\n[client]\ncert_file = {hub_cert:?}\nkey_file = {hub_key:?}\n[pull]\npoll_secs = 5\ntimeout_secs = 5\n[[peer]]\nname = \"eu\"\nurl = \"{}\"\nca_file = {peer_ca:?}\n[[peer]]\nname = \"dead\"\nurl = \"https://127.0.0.1:{}\"\nca_file = {peer_ca:?}\n",
        peer.url(),
        free_port()
    );
    std::fs::write(&file, &good).unwrap();
    let mut child = Command::new(BIN)
        .args(["hub", "--config", file.to_str().unwrap()])
        .env("RUST_LOG", "trace")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the hub");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let op = client_config(&pki, &dir, "op");
    let up = std::time::Instant::now();
    while tokio::net::TcpStream::connect(addr).await.is_err() {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("the hub exited early ({status}): {stderr}");
        }
        assert!(up.elapsed() < DEADLINE, "the hub never listened");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut answers = String::new();
    let start = std::time::Instant::now();
    loop {
        let got =
            tokio::time::timeout(Duration::from_secs(2), get(addr, &op, "/v1/clusters")).await;
        if let Ok(got) = got {
            answers = String::from_utf8_lossy(&got.body).into_owned();
            if answers.contains("\"state\":\"fresh\"") {
                break;
            }
        }
        assert!(
            start.elapsed() < DEADLINE,
            "the view never showed a fresh cluster: {answers}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    answers.push_str(&String::from_utf8_lossy(
        &get(addr, &op, "/v1/catalog").await.body,
    ));
    child.kill().unwrap();
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child.wait().unwrap();
    assert!(stderr.contains("hub ready"), "the hub logged: {stderr}");
    for secret in &secrets {
        for (what, text) in [
            ("stderr", &stderr),
            ("stdout", &stdout),
            ("the view", &answers),
        ] {
            assert!(
                !text.contains(secret.as_str()),
                "a credential reached {what}: {secret}"
            );
        }
    }
    // Failing starts: a key that holds no key, a CA that is not one, a wrong path.
    let junk = dir.join("junk.key");
    std::fs::write(&junk, "PLANTED-JUNK-SECRET\n").unwrap();
    let bad = good.replacen(&format!("{hub_key:?}"), &format!("{junk:?}"), 1);
    std::fs::write(&file, bad).unwrap();
    let (code, stdout, stderr) = run(&["check", "hub", "--config", file.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(stderr.contains("client.key_file"), "{stderr}");
    assert!(
        !stderr.contains("PLANTED-JUNK-SECRET") && !stdout.contains("PLANTED-JUNK-SECRET"),
        "the junk key leaked"
    );
    let userinfo = good.replacen(&peer.url(), "https://user:hunter2@127.0.0.1:1", 1);
    std::fs::write(&file, userinfo).unwrap();
    let (code, stdout, stderr) = run(&["check", "hub", "--config", file.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(
        !stderr.contains("hunter2") && !stdout.contains("hunter2"),
        "a URL's credentials are never echoed: {stderr}"
    );
}
