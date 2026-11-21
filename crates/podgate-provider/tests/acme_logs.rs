//! The ACME broker never logs a key.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the `certificate stored` line it asserts.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::broker::{
    CERT_PEM, KEY_BODY, broker_toml, issued, key_pem, requested, start, state_dir, wait_cursor,
};
use podgate_provider::Config;
use serde_json::json;

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

#[tokio::test]
async fn broker_keys_never_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = state_dir("logs");
    let mut h = start(&dir, &["a.acme.test"], "", "");
    // A certificate, then events with a key where it must not be, then a certificate whose key
    // is not a key: every error names a field and never repeats the value.
    h.admin.emit(issued(&["a.acme.test"], "real"));
    h.admin.emit(json!({ "kind": "certificate_issued", "hosts": ["a.acme.test"], "cert_pem": 7, "key_pem": key_pem("wrongtype") }));
    h.admin.emit(json!({ "kind": "certificate_issued", "hosts": ["a.acme.test"], "cert_pem": CERT_PEM, "key_pem": format!("{KEY_BODY}-notakey") }));
    let marker = h.admin.emit(requested("nobody.acme.test"));
    wait_cursor(&dir, marker).await;
    let status = h.wait_status("a push", |s| s.pushes > 0).await;
    let account_key = std::fs::read_to_string(dir.join("account.key")).expect("account key");
    let account_body = account_key.lines().nth(1).expect("key body").to_owned();
    let shown = format!("{status:?}");
    let stopped = h.stop().await;
    assert!(stopped.is_ok());

    // `print` of a configured broker shows the snapshot with every key redacted.
    let config_path =
        std::env::temp_dir().join(format!("pgp-acme-print-{}.toml", std::process::id()));
    std::fs::write(
        &config_path,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n{}",
            broker_toml(&dir, "", "")
        ),
    )
    .expect("config");
    let output = tokio::task::spawn_blocking({
        let config_path = config_path.clone();
        move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
                .args(["print", "--config"])
                .arg(config_path)
                .env("RUST_LOG", "trace")
                .output()
                .expect("run print")
        }
    })
    .await
    .expect("print ran");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("\"issuer_node\":\"n1\""), "{stdout}");
    assert!(stdout.contains("[redacted]"), "{stdout}");

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("certificate stored"),
        "the broker logged what it did: {logs}"
    );
    let offline = podgate_provider::acme::offline_view(
        Config::parse(&format!(
            "admin_socket = \"/x.sock\"\n{}",
            broker_toml(&dir, "", "")
        ))
        .expect("config")
        .acme
        .as_ref()
        .expect("acme"),
    )
    .expect("offline view");
    for (what, text) in [
        ("the log", &logs),
        ("print stdout", &stdout),
        ("print stderr", &stderr),
        ("the status", &shown),
        ("the view", &format!("{offline:?}")),
    ] {
        assert!(!text.contains(KEY_BODY), "{what} shows a key: {text}");
        assert!(
            !text.contains(&account_body),
            "{what} shows the account key: {text}"
        );
    }
    let _ = std::fs::remove_file(config_path);
    let _ = std::fs::remove_dir_all(&dir);
}
