//! The two files: every bad value stops startup naming its field, and the crate depends on no
//! podgate crate.

#![allow(
    clippy::unwrap_used,
    reason = "an unwrap that fails is the test failing, and the message is the line"
)]

mod common;

use common::{Dir, Pki};
use podgate_federation::config::{ExportFile, PeersFile};

struct Files {
    dir: Dir,
    pki: Pki,
}

impl Files {
    fn new() -> Self {
        Self {
            dir: Dir::new(),
            pki: Pki::new(),
        }
    }

    /// A good peers file with `peers` peers and `pull` as the content of `[pull]`.
    fn hub(&self, peers: usize, pull: &str) -> String {
        let (hub_cert, hub_key) = self.pki.client_files(&self.dir.0, "hub");
        let (view_cert, view_key) = self.pki.server_files(&self.dir.0, "view");
        let ops = self.pki.ca_file(&self.dir.0, "ops");
        let ca = self.pki.ca_file(&self.dir.0, "peer-ca");
        let mut text = format!(
            "[view]\naddr = \"127.0.0.1:9444\"\ncert_file = {view_cert:?}\nkey_file = {view_key:?}\nclient_ca_file = {ops:?}\n\n[client]\ncert_file = {hub_cert:?}\nkey_file = {hub_key:?}\n\n[pull]\n{pull}\n"
        );
        for n in 0..peers {
            text.push_str(&format!("\n[[peer]]\nname = \"c{n}\"\nurl = \"https://c{n}.internal:9443\"\nca_file = {ca:?}\n"));
        }
        text
    }

    fn export(&self, top: &str, serve: &str) -> String {
        let (cert, key) = self.pki.server_files(&self.dir.0, "exp");
        let ca = self.pki.ca_file(&self.dir.0, "hub-ca");
        format!(
            "read_socket = \"/run/podgate-read/read.sock\"\n{top}\n[serve]\naddr = \"127.0.0.1:9443\"\ncert_file = {cert:?}\nkey_file = {key:?}\nclient_ca_file = {ca:?}\n{serve}\n"
        )
    }
}

fn refused(text: &str, field: &str) {
    let err = PeersFile::from_text(text).expect_err(&format!("{field} must be refused"));
    let message = err.to_string();
    assert!(
        message.contains(field),
        "the error names {field}: {message}"
    );
}

#[test]
fn federation_bad_peers_file() {
    let files = Files::new();
    PeersFile::from_text(&files.hub(2, "")).expect("the base file is good");
    let good = files.hub(1, "");
    let replace = |from: &str, to: &str| {
        assert!(good.contains(from), "{from}");
        good.replacen(from, to, 1)
    };
    refused(&files.hub(1, "bogus = 1"), "bogus");
    refused(&files.hub(1, "poll_secs = 1"), "pull.poll_secs");
    refused(&files.hub(1, "poll_secs = 4000"), "pull.poll_secs");
    refused(&files.hub(1, "timeout_secs = 0"), "pull.timeout_secs");
    refused(&files.hub(1, "timeout_secs = 121"), "pull.timeout_secs");
    refused(
        &files.hub(
            1,
            "poll_secs = 30\ntimeout_secs = 20\nstale_after_secs = 49",
        ),
        "pull.stale_after_secs",
    );
    refused(&files.hub(1, "max_bytes = 10"), "pull.max_bytes");
    refused(&files.hub(1, "max_entries = 0"), "pull.max_entries");
    refused(&files.hub(0, ""), "peer");
    refused(&files.hub(33, ""), "peer");
    refused(&replace("name = \"c0\"", "name = \"C 0\""), "peer[0].name");
    refused(&replace("name = \"c0\"", "name = \"a/b\""), "peer[0].name");
    refused(&replace("name = \"c0\"", "name = \"\""), "peer[0].name");
    refused(
        &replace("https://c0.internal:9443", "http://c0.internal:9443"),
        "peer[0].url",
    );
    refused(
        &replace("https://c0.internal:9443", "https://c0.internal:9443/path"),
        "peer[0].url",
    );
    refused(
        &replace("https://c0.internal:9443", "https://c0.internal:9443/?x=1"),
        "peer[0].url",
    );
    refused(
        &replace(
            "https://c0.internal:9443",
            "https://user:pw@c0.internal:9443",
        ),
        "peer[0].url",
    );
    refused(
        &replace("https://c0.internal:9443", "not a url"),
        "peer[0].url",
    );
    refused(
        &replace("addr = \"127.0.0.1:9444\"", "addr = \"nope\""),
        "view.addr",
    );
    refused(&replace("[client]", "max_x = 1\n[client]"), "max_x");
    refused(
        &format!(
            "{}\n[[peer]]\nname = \"c0\"\nurl = \"https://x:1\"\nca_file = \"/nonexistent\"\n",
            files.hub(1, "")
        ),
        "peer[1]",
    );
    let two_same = format!(
        "{}\n[[peer]]\nname = \"c0\"\nurl = \"https://x:1\"\nca_file = {:?}\n",
        files.hub(1, ""),
        files.dir.join("peer-ca.pem")
    );
    refused(&two_same, "peer[1].name");
    // Missing files and files without the right content name the setting.
    refused(
        &replace(
            &format!("{:?}", files.dir.join("peer-ca.pem")),
            "\"/nonexistent/ca.pem\"",
        ),
        "peer[0].ca_file",
    );
    let empty = files.dir.join("empty.pem");
    std::fs::write(&empty, "nothing here").unwrap();
    refused(
        &replace(
            &format!("{:?}", files.dir.join("peer-ca.pem")),
            &format!("{empty:?}"),
        ),
        "peer[0].ca_file",
    );
    refused(
        &replace(
            &format!("{:?}", files.dir.join("hub.key")),
            &format!("{empty:?}"),
        ),
        "client.key_file",
    );
    refused(
        &replace(
            &format!("{:?}", files.dir.join("hub.pem")),
            &format!("{empty:?}"),
        ),
        "client.cert_file",
    );
    refused(
        &replace(
            &format!("{:?}", files.dir.join("view.key")),
            &format!("{empty:?}"),
        ),
        "view.key_file",
    );
    // A key that is not the certificate's.
    let (_, other_key) = files.pki.client_files(&files.dir.0, "other");
    refused(
        &replace(
            &format!("{:?}", files.dir.join("hub.key")),
            &format!("{other_key:?}"),
        ),
        "peer[0]",
    );
    refused("[view]\naddr = \"127.0.0.1:1\"\n", "cert_file");
    let syntax = PeersFile::from_text("[view\nsecret = \"hunter2\"\n")
        .unwrap_err()
        .to_string();
    assert!(syntax.contains("line 1"), "{syntax}");
    assert!(
        !syntax.contains("hunter2"),
        "a syntax error never quotes the file: {syntax}"
    );
}

#[test]
fn federation_bad_export_file() {
    let files = Files::new();
    ExportFile::from_text(&files.export("", "")).expect("the base file is good");
    let bad = |text: String, field: &str| {
        let message = ExportFile::from_text(&text).expect_err(field).to_string();
        assert!(message.contains(field), "{field}: {message}");
    };
    bad(files.export("admin_slots = 0", ""), "admin_slots");
    bad(files.export("admin_slots = 5", ""), "admin_slots");
    bad(files.export("bogus = 1", ""), "bogus");
    bad(
        files.export("", "max_connections = 0"),
        "serve.max_connections",
    );
    bad(
        files.export("", "max_connections = 65"),
        "serve.max_connections",
    );
    bad(files.export("", "other = 1"), "other");
    bad(
        files.export("", "").replace("127.0.0.1:9443", "9443"),
        "serve.addr",
    );
    bad(
        files.export("", "").replace(
            "read_socket = \"/run/podgate-read/read.sock\"",
            "read_socket = \"\"",
        ),
        "read_socket",
    );
    bad(
        files.export("", "").replace(
            &format!("{:?}", files.dir.join("exp.key")),
            "\"/nonexistent\"",
        ),
        "serve.key_file",
    );
    bad(
        files.export("", "").replace(
            &format!("{:?}", files.dir.join("hub-ca.pem")),
            "\"/nonexistent\"",
        ),
        "serve.client_ca_file",
    );
    bad(
        files
            .export("", "")
            .replace("read_socket = \"/run/podgate-read/read.sock\"\n", ""),
        "read_socket",
    );
}

#[test]
fn federation_crate_depends_on_no_podgate_crate() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let own = std::fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
    for line in own.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        let name = line.split(['=', ' ']).next().unwrap_or_default();
        assert!(
            !(name.starts_with("podgate") && name != "podgate-federation"),
            "the crate depends on {name}"
        );
    }
    let root = std::fs::read_to_string(manifest.join("../../Cargo.toml")).unwrap();
    assert!(
        !root.contains("podgate-federation"),
        "the daemon does not depend on the crate"
    );
    let lock = std::fs::read_to_string(manifest.join("../../Cargo.lock")).unwrap();
    let block = lock
        .split("[[package]]")
        .find(|block| block.contains("name = \"podgate-federation\""))
        .expect("the crate is in the lock");
    assert!(
        !block
            .split("dependencies = [")
            .nth(1)
            .unwrap_or_default()
            .contains("\"podgate"),
        "no podgate package among its dependencies: {block}"
    );
    for package in lock
        .split("[[package]]")
        .filter(|b| b.contains("name = \"podgate\"\n"))
    {
        assert!(!package.contains("podgate-federation"));
    }
}
