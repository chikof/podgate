//! The DNS-01 solvers never log, print or return a secret.
//!
//! This test has its own binary: it captures logs with a thread-local subscriber, and `tracing`
//! caches a callsite as disabled for the whole process when another test thread reaches it first
//! with no subscriber, which would drop the lines it asserts (see `acme_logs.rs`).

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex};

use common::dns_server::{
    Answer, DnsServer, SECRET, TOKEN, WebhookServer, acme_claims, b64, challenge, config, file,
    rfc2136_zone, scratch, timing, tsig_server, webhook_zone, within,
};
use podgate_provider::acme::dns::DnsSolver;
use podgate_provider::acme::events::Solver;

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
async fn dns_secrets_never_logged() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish(),
    );
    let dir = scratch("logs");
    let name = "_acme-challenge.acme.test";
    let mut shown = Vec::new();

    // RFC 2136: a good key, then a server that knows another key.
    let good = tsig_server("acme.test", SECRET).await;
    let bad = tsig_server("acme.test", b"another-key-entirely").await;
    let tsig_file = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    for server in [&good, &bad] {
        let config = config(
            &dir,
            &rfc2136_zone("acme.test", server, &tsig_file, &[server]),
        );
        let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
        shown.push(format!("{solver:?} {:?}", config.acme));
        let outcome = within(
            "present",
            solver.present(challenge(name, "v1"), acme_claims()),
        )
        .await;
        shown.push(format!("{outcome:?}"));
        within("cleanup", solver.cleanup(challenge(name, "v1"))).await;
    }

    // A webhook that fails twice, echoing the request it got (headers included), then works.
    let dns = Arc::new(DnsServer::start("acme.test", None).await);
    let operator = Arc::clone(&dns);
    let hook = WebhookServer::start(move |_, number| match number {
        0 | 1 => Answer::Echo(500),
        2 => {
            operator.set_txt(name, "v2");
            Answer::Status(200)
        }
        _ => Answer::Echo(401),
    })
    .await;
    let token_file = file(&dir, "token", TOKEN, 0o600);
    let config = config(
        &dir,
        &webhook_zone("acme.test", &hook, &token_file, &[&dns]),
    );
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    shown.push(format!("{solver:?} {:?}", config.acme));
    let outcome = within(
        "present",
        solver.present(challenge(name, "v2"), acme_claims()),
    )
    .await;
    assert!(outcome.is_ok(), "{outcome:?}");
    // The cleanup call is answered with an echo of the request, too.
    within("cleanup", solver.cleanup(challenge(name, "v2"))).await;
    assert!(
        hook.requests().iter().all(|request| request
            .headers
            .get("authorization")
            .is_some_and(|value| value.ends_with(TOKEN))),
        "the webhook did receive the token it must not leak"
    );

    let logs = String::from_utf8_lossy(&capture.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("DNS-01 record published"),
        "the solver logged what it did: {logs}"
    );
    assert!(logs.contains("refused the update"), "{logs}");
    assert!(logs.contains("DNS-01 record not published yet"), "{logs}");
    let tsig_text = String::from_utf8_lossy(SECRET).into_owned();
    for (what, text) in std::iter::once(("the log", &logs))
        .chain(shown.iter().map(|text| ("a Debug or error text", text)))
    {
        for secret in [tsig_text.as_str(), &b64(SECRET), TOKEN] {
            assert!(
                !text.contains(secret),
                "{what} shows a secret ({secret}): {text}"
            );
        }
    }
}
