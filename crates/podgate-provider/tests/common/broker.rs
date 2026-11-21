//! Builders for the ACME broker tests (`acme_broker.rs`, `acme_logs.rs`): the provider
//! configuration with an `[acme]` section, podgate events, and the state directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{AppExt, Harness, app};

pub const UP: &str = "http://10.0.0.5:8080";
pub const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
pub const KEY_BODY: &str = "KEYMATERIAL-9f3c1b7a";

/// A PKCS#8-shaped PEM carrying `KEY_BODY`: the broker checks the armor, never the content.
pub fn key_pem(tag: &str) -> String {
    let armor = |edge: &str| format!("-----{edge} {} KEY-----", "PRIVATE");
    format!("{}\n{KEY_BODY}-{tag}\n{}\n", armor("BEGIN"), armor("END"))
}

/// A fresh state directory path under the temp dir (not created).
pub fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgp-acme-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

pub const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// Provider configuration after the `admin_socket` line: quick debounce, the tenants, and an
/// `[acme]` section for `dir`. `acme_extra` goes inside the section.
pub fn broker_toml(dir: &Path, acme_extra: &str, on_demand: &str) -> String {
    format!(
        r#"debounce_ms = 20
max_delay_ms = 100
resync_secs = 60
{TENANTS}
[acme]
enabled = true
state_dir = {dir:?}
directory_url = "https://ca.test/dir"
issuer_node = "n1"
contact = ["mailto:ops@acme.test"]
{acme_extra}
[acme.on_demand]
{on_demand}
"#
    )
}

pub fn issued(hosts: &[&str], tag: &str) -> Value {
    json!({ "kind": "certificate_issued", "hosts": hosts, "cert_pem": CERT_PEM, "key_pem": key_pem(tag) })
}

pub fn http_challenge(token: &str) -> Value {
    json!({ "kind": "acme_challenge", "type": "http-01", "token": token, "key_authorization": format!("{token}.thumb") })
}

pub fn requested(host: &str) -> Value {
    json!({ "kind": "certificate_requested", "host": host })
}

/// Starts a broker over a fake admin socket with the `local` source serving `hosts` of `acme`.
pub fn start(dir: &Path, hosts: &[&str], acme_extra: &str, on_demand: &str) -> Harness {
    let h = Harness::start(&broker_toml(dir, acme_extra, on_demand), &["local"]);
    h.source("local").apps(
        hosts
            .iter()
            .enumerate()
            .map(|(at, host)| app("local", &format!("app{at}"), &[*host], UP).mapped("acme"))
            .collect(),
    );
    h
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read")).expect("JSON")
}

pub fn read_json_opt(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub async fn wait_cursor(dir: &Path, after: u64) {
    let start = Instant::now();
    while read_json_opt(&dir.join("cursor.json")).is_none_or(|c| c["after"].as_u64() < Some(after))
    {
        assert!(
            start.elapsed() < super::DEADLINE,
            "the cursor did not reach {after}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
