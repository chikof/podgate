//! No private key of the internal CA reaches a log, a `Debug` string, the `print` output or the
//! `ca` command's output.
//!
//! This test has its own binary, like `acme_logs.rs`: it captures logs with a thread-local
//! subscriber, and `tracing` caches a callsite as disabled for the whole process when another
//! test thread reaches it first with no subscriber, which would drop the lines it asserts.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::{Arc, Mutex};

use common::app;
use common::ca::{internal, key_lines, pki, want, wants};
use podgate_provider::ca::cli;
use podgate_provider::ca::issue::Signer;
use podgate_provider::ca::{CaView, Secret, unix_now};
use podgate_provider::source::State;
use podgate_provider::{Merger, UpstreamPolicy};

const UP: &str = "http://10.0.0.5:8080";
const DAY: i64 = 86_400;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

#[test]
fn ca_keys_never_logged() {
    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let p = pki("logs", &["internal"]);
    let root_key = std::fs::read_to_string(&p.root_key).expect("root key");
    let mut ca = p.ca("");
    let now = unix_now();
    let w = wants(vec![
        want("a", "default", &["a.internal"]),
        want("bad", "default", &["a.example.com"]),
    ]);
    ca.reconcile(&w, now).expect("issue");
    ca.reconcile(&w, now + 3 * DAY).expect("renew");
    let _ = ca.issue(&["a.example.com"], now, 14);
    let view = ca.view(now + 3 * DAY);
    let key = view.certificates()[0].key_pem.clone();
    let mut secrets = key_lines(&key);
    secrets.extend(key_lines(&root_key));
    secrets.extend(key_lines(
        &std::fs::read_to_string(p.dir.join("intermediate.key.pem")).expect("key"),
    ));

    // Debug output of everything that holds a key.
    let leaf = ca.issue(&["b.internal"], now, 14).expect("leaf");
    secrets.extend(key_lines(leaf.key.expose()));
    let signer_key =
        Secret::new(std::fs::read_to_string(p.dir.join("intermediate.key.pem")).expect("key"));
    let signer = Signer::from_pem(&p.made.intermediate_cert, &signer_key).expect("signer");
    let shown = format!(
        "{ca:?} {leaf:?} {signer:?} {view:?} {:?} {signer_key:?}",
        CaView::off()
    );
    // The `print` output: what the merge shows an operator.
    let merger = Merger::new(&p.config(""), UpstreamPolicy::builtin());
    let mut states = BTreeMap::new();
    states.insert(
        Box::<str>::from("local"),
        State {
            apps: vec![internal(app("local", "a", &["a.internal"], UP))],
            certificates: Vec::new(),
        },
    );
    let merged = merger.merge_all(
        &states,
        &BTreeSet::new(),
        &podgate_provider::acme::BrokerView::off(),
        &view,
    );
    assert_eq!(
        merged.snapshot().certificates.len(),
        1,
        "the leaf is in the merge"
    );
    let printed = merged.redacted_body(0);
    assert!(printed.contains("[redacted]"), "{printed}");
    let debug_merged = format!("{merged:?}");
    // The commands' output.
    let config_file = p.work.join("provider.toml");
    std::fs::write(
        &config_file,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n{}",
            p.toml_full("")
        ),
    )
    .ok();
    let mut cli_out = Vec::new();
    let mut cli_err = Vec::new();
    for command in [vec!["status"], vec!["export-root"]] {
        let mut args: Vec<String> = command.iter().map(|s| (*s).to_owned()).collect();
        args.extend(["--config".to_owned(), config_file.display().to_string()]);
        let code = cli::run(&args, &mut cli_out, &mut cli_err);
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&cli_err));
    }

    let logs = String::from_utf8_lossy(&sink.0.lock().expect("lock")).into_owned();
    assert!(
        logs.contains("internal certificate issued"),
        "the logs saw the issuance: {logs}"
    );
    let everything = [
        ("the logs", logs),
        ("Debug", shown),
        ("print", printed),
        ("Debug of the merge", debug_merged),
        (
            "the ca command",
            String::from_utf8_lossy(&cli_out).into_owned() + &String::from_utf8_lossy(&cli_err),
        ),
    ];
    for (what, text) in &everything {
        assert!(
            !text.contains("PRIVATE KEY"),
            "{what} shows a private key header"
        );
        for line in &secrets {
            assert!(!text.contains(line.as_str()), "{what} shows key material");
        }
    }
}
