//! The HTTP source never logs a header secret, a token in the URL, the client key or what a
//! Traefik document's file reference points at.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the lines it asserts.

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::etcd::Pki;
use common::http_endpoint::{FakeHttp, Reply};
use common::{DEADLINE, config};
use podgate_provider::UpstreamPolicy;
use podgate_provider::http::HttpSource;
use podgate_provider::source::{Source, Update, UpdateBody};
use serde_json::json;
use tokio::sync::mpsc;

const TOKEN: &str = "s3cr3t-header-token-7d41f0c9";
const QUERY_SECRET: &str = "q-s3cr3t-3b9a61";
const MARKER: &str = "MARKER-9c2e-never-read";
const INSIDE: &str = "http://10.4.0.5:8080";

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

fn source(url: &str, keys: &str, tables: &str) -> HttpSource {
    let config = config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "[[tenant]]\nid = \"acme\"\nhosts = [\"acme.test\", \"*.acme.test\"]\n\n[[source]]\nkind = \"http\"\nname = \"web\"\nurl = {url:?}\ntenant = \"acme\"\nallow_local = true\n{keys}\n{tables}\n"
        ),
    );
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("a valid policy");
    HttpSource::from_config(&config.sources[0], &policy)
        .expect("a valid HTTP source")
        .with_timing(Duration::from_millis(50), Duration::from_millis(200))
}

/// Runs `source` until `done` accepts an update, and returns what it said.
async fn until(source: HttpSource, done: impl Fn(&UpdateBody) -> bool) -> Vec<UpdateBody> {
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

fn app(id: &str, host: &str) -> serde_json::Value {
    json!({
        "id": id,
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": { "host": [host] }, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": INSIDE }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    })
}

#[tokio::test]
async fn http_secrets_never_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = std::env::temp_dir().join(format!("pgp-http-logs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let token = dir.join("token");
    std::fs::write(&token, format!("Bearer {TOKEN}\n")).expect("token file");

    // TLS with a client certificate, a header secret from a file and a token in the URL query.
    let pki = Pki::new();
    let endpoint = FakeHttp::start_tls(&pki, true).await;
    let query = format!("/?access={QUERY_SECRET}");
    endpoint.set(
        &query,
        Reply::json(json!({ "apps": [app("shop", "shop.acme.test")] }).to_string()),
    );
    let (cert, key) = pki.client_files(&dir, "podgate");
    let key_pem = std::fs::read_to_string(&key).expect("key");
    let key_line = key_pem
        .lines()
        .nth(1)
        .expect("a line of key material")
        .to_owned();
    let tables = format!(
        "[source.headers]\nAuthorization = \"file:{}\"\n\n[source.tls]\nca_file = {:?}\ncert_file = {:?}\nkey_file = {:?}\n",
        token.display(),
        pki.ca_file(&dir).display().to_string(),
        cert.display().to_string(),
        key.display().to_string()
    );
    let good = source(&endpoint.url(&query), "", &tables);
    let shown = format!("{good:?}");
    let said = until(
        good,
        |body| matches!(body, UpdateBody::State(state) if state.apps.len() == 1),
    )
    .await;
    // The server saw the secret (so it was sent), and nothing below shows it.
    let sent = endpoint.requests().remove(0);
    assert_eq!(
        sent.headers.get("authorization").map(String::as_str),
        Some(format!("Bearer {TOKEN}").as_str())
    );

    // Failures of every kind: an error status, a dropped connection, a refused redirect.
    let mut outages = String::new();
    for reply in [
        Reply::status(500),
        Reply::dropped(),
        Reply::redirect(
            302,
            &format!("http://elsewhere.test/?access={QUERY_SECRET}"),
        ),
        Reply::json("{ \"apps\": [oops").content_type("application/json"),
    ] {
        endpoint.set(&query, reply);
        let failing = source(&endpoint.url(&query), "", &tables);
        let said = until(failing, |body| matches!(body, UpdateBody::Outage(_))).await;
        outages.push_str(&format!("{said:?}"));
    }

    // A Traefik document that names a file: the refusal is logged, the file's content and path are not.
    let marker = dir.join("marker.key");
    std::fs::write(&marker, MARKER).expect("marker file");
    let traefik = FakeHttp::start().await;
    traefik.set(
        "/",
        Reply::json(
            json!({
                "http": {
                    "routers": { "shop": { "rule": "Host(`shop.acme.test`)", "service": "web" } },
                    "services": { "web": { "loadBalancer": { "servers": [{ "url": INSIDE }] } } },
                },
                "tls": { "certificates": [{ "certFile": marker, "keyFile": marker }] },
            })
            .to_string(),
        ),
    );
    let reading = source(&traefik.url("/"), "format = \"traefik\"", "");
    let said_traefik = until(
        reading,
        |body| matches!(body, UpdateBody::Outage(why) if why.contains("file_reference_not_allowed")),
    )
    .await;

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("poll failed") && logs.contains("file_reference_not_allowed"),
        "the source logged what went wrong: {logs}"
    );
    for (what, text) in [
        ("the log", logs.as_str()),
        ("the debug output", shown.as_str()),
        ("the updates", &format!("{said:?} {said_traefik:?}")),
        ("the outages", outages.as_str()),
    ] {
        for secret in [
            TOKEN,
            QUERY_SECRET,
            key_line.as_str(),
            MARKER,
            marker.display().to_string().as_str(),
        ] {
            assert!(!text.contains(secret), "{what} shows {secret}: {text}");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
