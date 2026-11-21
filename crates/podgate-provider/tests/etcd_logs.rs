//! The etcd source authenticates and never logs the password, the token or the client key.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the lines it asserts.

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::etcd::{FakeEtcd, Pki};
use common::{DEADLINE, config};
use podgate_provider::UpstreamPolicy;
use podgate_provider::etcd::EtcdSource;
use podgate_provider::source::{Source, Update, UpdateBody};
use serde_json::json;
use tokio::sync::mpsc;

const PASSWORD: &str = "s3cr3t-etcd-password-7d41f0c9";
const WRONG_PASSWORD: &str = "wr0ng-etcd-password-2b6e93aa";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn source(endpoint: &str, password_file: &Path, tls: &str) -> EtcdSource {
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "[[tenant]]\nid = \"acme\"\nhosts = [\"acme.test\", \"*.acme.test\"]\n\n[[source]]\nkind = \"etcd\"\nname = \"etcd\"\nendpoints = [{endpoint:?}]\nusername = \"podgate\"\npassword_file = {:?}\nresync_secs = 3600\n{tls}\n[[source.prefix]]\nprefix = \"podgate/acme\"\ntenant = \"acme\"\nlayout = \"podgate-json\"\n",
            password_file.display().to_string()
        ),
    );
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("a valid policy");
    EtcdSource::from_config(&config.sources[0], &policy).expect("a valid etcd source")
}

/// Runs `source` until `done` accepts an update, and returns what it said.
async fn until(source: EtcdSource, done: impl Fn(&UpdateBody) -> bool) -> Vec<UpdateBody> {
    let (tx, mut rx) = mpsc::channel::<Update>(64);
    let task = tokio::spawn(source.run(tx));
    let mut seen = Vec::new();
    let wait = async {
        while let Some(update) = rx.recv().await {
            let finished = done(&update.body);
            seen.push(update.body);
            if finished {
                break;
            }
        }
    };
    let finished = tokio::time::timeout(DEADLINE, wait).await.is_ok();
    task.abort();
    assert!(finished && !seen.is_empty(), "the source said: {seen:?}");
    seen
}

#[tokio::test]
async fn etcd_secrets_never_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = std::env::temp_dir().join(format!("pgp-etcd-logs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let good = dir.join("password");
    std::fs::write(&good, format!("{PASSWORD}\n")).expect("password file");
    let wrong = dir.join("wrong");
    std::fs::write(&wrong, WRONG_PASSWORD).expect("password file");

    // TLS with a client certificate, so the key file is in play too.
    let pki = Pki::new();
    let etcd = FakeEtcd::start_tls(&pki, true).await;
    etcd.require_auth("podgate", PASSWORD);
    etcd.put(
        "podgate/acme/apps/shop",
        &json!({
            "tls": { "mode": "acme" },
            "routers": [{ "name": "main", "match": { "host": ["shop.acme.test"] }, "service": "svc" }],
            "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": "http://10.4.0.5:8080" }] }],
            "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
        })
        .to_string(),
    );
    let (cert, key) = pki.client_files(&dir, "podgate");
    let key_pem = std::fs::read_to_string(&key).expect("key");
    let key_line = key_pem
        .lines()
        .nth(1)
        .expect("a line of key material")
        .to_owned();
    let tls = format!(
        "[source.tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
        pki.ca_file(&dir).display().to_string(),
        cert.display().to_string(),
        key.display().to_string()
    );

    // With the right password the apps arrive: etcd checks the token, so the password was sent.
    let right = source(&etcd.url(), &good, &tls);
    let shown = format!("{right:?}");
    let said = until(
        right,
        |body| matches!(body, UpdateBody::State(state) if state.apps.len() == 1),
    )
    .await;
    assert!(matches!(said.last(), Some(UpdateBody::State(_))));
    let token = etcd
        .requests()
        .into_iter()
        .find(|seen| seen.path == "/v3/kv/range")
        .and_then(|seen| seen.authorization)
        .expect("the read carries a token");

    // With another password etcd refuses; the outage names the status and not the password.
    let denied = source(&etcd.url(), &wrong, &tls);
    let shown_wrong = format!("{denied:?}");
    let said = until(denied, |body| matches!(body, UpdateBody::Outage(_))).await;
    let outage = match said.last() {
        Some(UpdateBody::Outage(why)) => why.to_string(),
        other => panic!("expected an outage, got {other:?}"),
    };
    assert!(outage.contains("authentication failed"), "{outage}");

    // And an outage of the server itself, with the token of the first run long gone from memory.
    etcd.stop();
    let down = source(&etcd.url(), &good, &tls);
    let said_down = until(down, |body| matches!(body, UpdateBody::Outage(_))).await;

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("cannot read the prefix"),
        "the source logged what went wrong: {logs}"
    );
    for (what, text) in [
        ("the log", logs.as_str()),
        ("the outage", outage.as_str()),
        ("the debug output", shown.as_str()),
        (
            "the debug output of the refused source",
            shown_wrong.as_str(),
        ),
        ("the updates", &format!("{said:?} {said_down:?}")),
    ] {
        for secret in [PASSWORD, WRONG_PASSWORD, token.as_str(), key_line.as_str()] {
            assert!(!text.contains(secret), "{what} shows a secret: {text}");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
