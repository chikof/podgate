//! The Nomad source sends its ACL token and never logs it.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the lines it asserts.

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use common::nomad::{FakeNomad, Reg};
use common::{DEADLINE, config};
use podgate_provider::nomad::NomadSource;
use podgate_provider::source::{Source, Update, UpdateBody};
use tokio::sync::mpsc;

const TOKEN: &str = "s3cr3t-nomad-acl-token-0f9c2d71";
const WRONG_TOKEN: &str = "wr0ng-nomad-acl-token-5be8a43c";

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

fn source(address: &str, token_file: &Path) -> NomadSource {
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "[[source]]\nkind = \"nomad\"\nname = \"nomad\"\naddress = {address:?}\ntoken_file = {:?}\nresync_secs = 3600\n",
            token_file.display().to_string()
        ),
    );
    NomadSource::from_config(&config.sources[0]).expect("a valid nomad source")
}

/// Runs `source` until `done` accepts an update, and returns what it said.
async fn until(source: NomadSource, done: impl Fn(&UpdateBody) -> bool) -> Vec<UpdateBody> {
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
async fn nomad_token_sent_not_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = std::env::temp_dir().join(format!("pgp-nomad-logs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let good = dir.join("token");
    std::fs::write(&good, format!("{TOKEN}\n")).expect("token file");
    let wrong = dir.join("wrong");
    std::fs::write(&wrong, WRONG_TOKEN).expect("token file");

    let nomad = FakeNomad::start().await;
    nomad.require_token(TOKEN);
    nomad.add(
        Reg::new("default", "shop", "10.4.0.5", 8080)
            .tag("podgate.enable=true")
            .tag("podgate.host=shop.acme.test"),
    );

    // With the token, the registrations arrive: Nomad checks the header, so it was sent.
    let right = source(&nomad.address(), &good);
    let shown = format!("{right:?}");
    let said = until(
        right,
        |body| matches!(body, UpdateBody::State(state) if state.apps.len() == 1),
    )
    .await;
    assert!(matches!(said.last(), Some(UpdateBody::State(_))));
    let requests = nomad.requests();
    assert!(
        !requests.is_empty()
            && requests
                .iter()
                .all(|request| request.token.as_deref() == Some(TOKEN)),
        "every request carries the token: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.path() == "/v1/services" && request.param("index").is_some()),
        "including the blocking queries"
    );

    // With another token, Nomad refuses; the outage names the status and not the token.
    let denied = source(&nomad.address(), &wrong);
    let shown_wrong = format!("{denied:?}");
    let said = until(denied, |body| matches!(body, UpdateBody::Outage(_))).await;
    let outage = match said.last() {
        Some(UpdateBody::Outage(why)) => why.to_string(),
        other => panic!("expected an outage, got {other:?}"),
    };
    assert!(outage.contains("403"), "{outage}");

    // And an outage of the server itself.
    nomad.stop();
    let right = source(&nomad.address(), &good);
    let said = until(right, |body| matches!(body, UpdateBody::Outage(_))).await;

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("403") || logs.contains("blocking query failed"),
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
        ("the updates", &format!("{said:?}")),
    ] {
        assert!(!text.contains(TOKEN), "{what} shows the token: {text}");
        assert!(
            !text.contains(WRONG_TOKEN),
            "{what} shows the token: {text}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
