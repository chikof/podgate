//! The Consul source sends its token and never logs it.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the report line it asserts.

mod common;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::consul::{FakeConsul, Svc};
use common::{DEADLINE, config};
use podgate_provider::consul::ConsulSource;
use podgate_provider::source::{Source, UpdateBody};
use tokio::sync::mpsc;

const TOKEN: &str = "6f1d0c57-aaaa-4bbb-8ccc-token-ok";
const WRONG: &str = "0e9b7d12-dddd-4eee-8fff-token-wrong";

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

fn token_file(name: &str, token: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pgp-consul-log-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| writeln!(file, "{token}"))
        .expect("write the token file");
    path
}

fn source_toml(url: &str, token: &Path) -> String {
    format!(
        "[[source]]\nkind = \"consul\"\nname = \"consul\"\naddress = {url:?}\ntoken_file = {:?}\nresync_secs = 3600\nwait_secs = 5\n",
        token.display().to_string()
    )
}

/// The first outage text, or the first state's report, whichever carries `needle`.
async fn first_text_with(source: ConsulSource, needle: &str) -> String {
    let (tx, mut rx) = mpsc::channel(64);
    let task = tokio::spawn(source.run(tx));
    let found = tokio::time::timeout(DEADLINE, async {
        loop {
            let update = rx.recv().await.expect("the source keeps running");
            if let UpdateBody::Outage(why) = update.body
                && why.contains(needle)
            {
                return why.to_string();
            }
        }
    })
    .await;
    task.abort();
    found.unwrap_or_else(|_| panic!("no outage naming {needle}"))
}

#[tokio::test]
async fn consul_token_sent_not_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let consul = FakeConsul::start().await;
    consul.require_token(TOKEN);
    consul.register(
        Svc::new("web-1", "web", "10.4.0.1", 8080)
            .tags(&["podgate.enable=true", "podgate.host=web.acme.test"]),
    );
    // A service the source rejects, so that it logs a report.
    consul.register(Svc::new("bad-1", "bad", "10.4.0.2", 8080).tags(&[
        "podgate.enable=true",
        "podgate.host=bad.acme.test",
        "podgate.hostz=1",
    ]));
    let good_file = token_file("good", TOKEN);
    let wrong_file = token_file("wrong", WRONG);
    let load = |file: &Path| {
        let config = config(
            Path::new("/nonexistent/admin.sock"),
            &source_toml(&consul.url(), file),
        );
        ConsulSource::from_config(&config.sources[0]).expect("a valid consul source")
    };

    // The right token reads the catalog; the report of the bad service is logged and sent.
    let good = load(&good_file);
    let shown = format!("{good:?}");
    let report = first_text_with(good, "unknown label podgate.hostz").await;
    assert!(
        !report.contains(TOKEN),
        "the report shows the token: {report}"
    );
    assert!(!shown.contains(TOKEN), "Debug shows the token: {shown}");
    let requests = consul.requests();
    assert!(!requests.is_empty());
    assert!(
        requests
            .iter()
            .all(|request| request.token.as_deref() == Some(TOKEN)),
        "every request carries the token in X-Consul-Token: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.raw_query.contains(TOKEN)),
        "and never in the URL"
    );

    // A wrong token is refused, and Consul echoes it in the 403: the report must not.
    let wrong = load(&wrong_file);
    let refused = first_text_with(wrong, "Permission denied").await;
    assert!(
        !refused.contains(WRONG),
        "the outage shows the token: {refused}"
    );
    assert!(refused.contains("[redacted]"), "{refused}");

    // The program itself: its logs and its output.
    let config_path =
        std::env::temp_dir().join(format!("pgp-consul-print-{}.toml", std::process::id()));
    std::fs::write(
        &config_path,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n{}",
            source_toml(&consul.url(), &good_file)
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
    assert!(stdout.contains("consul-web"), "{stdout}");

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("unknown label podgate.hostz"),
        "the source logged what it left out: {logs}"
    );
    for (what, text) in [
        ("the log", &logs),
        ("print stdout", &stdout),
        ("print stderr", &stderr),
    ] {
        assert!(!text.contains(TOKEN), "{what} shows the token: {text}");
        assert!(
            !text.contains(WRONG),
            "{what} shows the wrong token: {text}"
        );
    }
    let requests = consul.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.token.as_deref() == Some(WRONG)),
        "the wrong token was sent"
    );
    for path in [good_file, wrong_file, config_path] {
        let _ = std::fs::remove_file(path);
    }
}
