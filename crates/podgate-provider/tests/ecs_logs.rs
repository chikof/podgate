//! The ECS source signs with credentials from the chain and never logs them, shows them in an
//! error, or prints them.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the lines it asserts.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::ecs::{
    ACCESS_KEY, CONTAINER_AUTH_TOKEN, FakeAws, IMDS_TOKEN, ROLE_ARN, SECRET_KEY, SESSION_TOKEN,
    Task, WEB_IDENTITY_TOKEN,
};
use common::{DEADLINE, config};
use podgate_provider::ecs::EcsSource;
use podgate_provider::source::{Source, Update, UpdateBody};
use tokio::sync::mpsc;

const WRONG_SECRET: &str = "wr0ng-secret-access-key-3d90e1";
const WRONG_CONTAINER_TOKEN: &str = "wr0ng-container-token-8a17";

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

fn pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn source(address: &str, env: Vec<(String, String)>) -> EcsSource {
    let config = config(
        std::path::Path::new("/nonexistent/admin.sock"),
        &format!(
            "[[source]]\nkind = \"ecs\"\nname = \"ecs\"\nregion = \"eu-west-1\"\nendpoint = {address:?}\nclusters = [\"prod\"]\nrefresh_secs = 5\n"
        ),
    );
    EcsSource::from_config_with_env(&config.sources[0], env).expect("a valid ecs source")
}

/// Runs `source` until `done` accepts an update, and returns what it said.
async fn until(source: EcsSource, done: impl Fn(&UpdateBody) -> bool) -> Vec<UpdateBody> {
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

fn outage(said: &[UpdateBody]) -> String {
    match said.last() {
        Some(UpdateBody::Outage(why)) => why.to_string(),
        other => panic!("expected an outage, got {other:?}"),
    }
}

#[tokio::test]
async fn ecs_secrets_never_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = std::env::temp_dir().join(format!("pgp-ecs-logs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let token_file = dir.join("web-identity");
    std::fs::write(&token_file, WEB_IDENTITY_TOKEN).expect("token file");

    let fake = FakeAws::start().await;
    fake.add(Task::web("prod", "shop", "10.4.0.5", "shop.acme.test"));
    let address = fake.address();
    let good = || {
        pairs(&[
            ("AWS_ACCESS_KEY_ID", ACCESS_KEY),
            ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
            ("AWS_SESSION_TOKEN", SESSION_TOKEN),
        ])
    };
    let mut shown: Vec<(&str, String)> = Vec::new();

    // Good credentials: the app arrives, and the fake checked the signature.
    let source_good = source(&address, good());
    shown.push(("the debug output of the source", format!("{source_good:?}")));
    let said = until(
        source_good,
        |body| matches!(body, UpdateBody::State(state) if state.apps.len() == 1),
    )
    .await;
    shown.push(("the updates", format!("{said:?}")));
    assert!(
        fake.requests().iter().all(|r| r.signed == Some(true)),
        "every request was signed"
    );

    // A wrong secret: AWS answers 403 and quotes the canonical request, token included.
    let mut wrong = good();
    wrong[1].1 = WRONG_SECRET.to_owned();
    let said = until(source(&address, wrong), |body| {
        matches!(body, UpdateBody::Outage(_))
    })
    .await;
    let denied = outage(&said);
    assert!(denied.contains("403"), "{denied}");
    shown.push(("the outage of a wrong secret", denied));

    // A task role endpoint that refuses the authorization token.
    fake.require_container_token(CONTAINER_AUTH_TOKEN);
    let said = until(
        source(
            &address,
            pairs(&[
                (
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    &format!("{address}/creds"),
                ),
                ("AWS_CONTAINER_AUTHORIZATION_TOKEN", WRONG_CONTAINER_TOKEN),
            ]),
        ),
        |body| matches!(body, UpdateBody::Outage(_)),
    )
    .await;
    shown.push(("the outage of a refused container token", outage(&said)));

    // The same endpoint with the right token, then instance metadata and a web identity: the
    // credentials arrive and are used.
    for (what, env) in [
        (
            "the container credentials",
            pairs(&[
                (
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    &format!("{address}/creds"),
                ),
                ("AWS_CONTAINER_AUTHORIZATION_TOKEN", CONTAINER_AUTH_TOKEN),
            ]),
        ),
        (
            "the instance profile",
            pairs(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", &address)]),
        ),
        (
            "the web identity",
            pairs(&[
                (
                    "AWS_WEB_IDENTITY_TOKEN_FILE",
                    &token_file.display().to_string(),
                ),
                ("AWS_ROLE_ARN", ROLE_ARN),
                ("AWS_ENDPOINT_URL_STS", &address),
            ]),
        ),
    ] {
        let source = source(&address, env);
        shown.push((what, format!("{source:?}")));
        let said = until(
            source,
            |body| matches!(body, UpdateBody::State(state) if state.apps.len() == 1),
        )
        .await;
        shown.push((what, format!("{said:?}")));
    }

    // ECS refuses the call, and then it is gone altogether.
    fake.deny(true);
    let said = until(source(&address, good()), |body| {
        matches!(body, UpdateBody::Outage(_))
    })
    .await;
    shown.push(("the outage of a denied call", outage(&said)));
    fake.deny(false);
    fake.stop();
    let said = until(source(&address, good()), |body| {
        matches!(body, UpdateBody::Outage(_))
    })
    .await;
    shown.push(("the outage of a dead server", outage(&said)));

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("the ECS poll failed"),
        "the source logged what went wrong: {logs}"
    );
    shown.push(("the log", logs));
    for (what, text) in &shown {
        for secret in [
            SECRET_KEY,
            SESSION_TOKEN,
            WRONG_SECRET,
            CONTAINER_AUTH_TOKEN,
            WRONG_CONTAINER_TOKEN,
            WEB_IDENTITY_TOKEN,
            IMDS_TOKEN,
        ] {
            assert!(!text.contains(secret), "{what} shows {secret}: {text}");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}
