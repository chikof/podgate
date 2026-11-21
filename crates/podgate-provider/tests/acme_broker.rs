//! The ACME broker: podgate's event feed in, certificates and challenge answers in the
//! snapshot out.
//!
//! Most tests play podgate with the fake admin socket of `common`, which serves a real event feed
//! (long poll, `410`, `boot_id`). `broker_http01_end_to_end` and `broker_survives_restarts` run
//! the real daemon against `pebble`: nothing is skipped, a missing `pebble` or daemon binary
//! fails them. Every wait has a deadline.

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{AppExt, FakeAdmin, Harness, app, daemon, free_ports, pebble};
use podgate_provider::acme::approve::{Approver, Decision, Refusal};
use podgate_provider::acme::settings::OnDemandLimits;
use podgate_provider::acme::{ClaimedApp, Claims};
use podgate_provider::trust::{HostPattern, Trust};
use podgate_provider::{Config, UpstreamPolicy};
use serde_json::{Value, json};

const UP: &str = "http://10.0.0.5:8080";
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
const KEY_BODY: &str = "KEYMATERIAL-9f3c1b7a";

/// A PKCS#8-shaped PEM carrying `KEY_BODY`: the broker checks the armor, never the content.
fn key_pem(tag: &str) -> String {
    let armor = |edge: &str| format!("-----{edge} {} KEY-----", "PRIVATE");
    format!("{}\n{KEY_BODY}-{tag}\n{}\n", armor("BEGIN"), armor("END"))
}

/// A fresh state directory path under the temp dir (not created).
fn state_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgp-acme-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
"#;

/// Provider configuration after the `admin_socket` line: quick debounce, the tenants, and an
/// `[acme]` section for `dir`. `acme_extra` goes inside the section.
fn broker_toml(dir: &Path, acme_extra: &str, on_demand: &str) -> String {
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

fn issued(hosts: &[&str], tag: &str) -> Value {
    json!({ "kind": "certificate_issued", "hosts": hosts, "cert_pem": CERT_PEM, "key_pem": key_pem(tag) })
}

fn http_challenge(token: &str) -> Value {
    json!({ "kind": "acme_challenge", "type": "http-01", "token": token, "key_authorization": format!("{token}.thumb") })
}

fn requested(host: &str) -> Value {
    json!({ "kind": "certificate_requested", "host": host })
}

fn acme_of(put: &common::Put) -> &Value {
    &put.body["acme"]
}

fn challenge_tokens(put: &common::Put) -> Vec<String> {
    let mut tokens: Vec<String> = acme_of(put)["challenges"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|c| c["token"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    tokens.sort();
    tokens
}

fn requested_hosts(put: &common::Put) -> Vec<String> {
    let mut hosts: Vec<String> = acme_of(put)["requested_hosts"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|h| h.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    hosts.sort();
    hosts
}

fn cert_hosts(put: &common::Put) -> Vec<Vec<String>> {
    put.body["certificates"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|cert| {
                    cert["hosts"]
                        .as_array()
                        .map(|hosts| {
                            hosts
                                .iter()
                                .filter_map(|h| h.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

/// Starts a broker over a fake admin socket with the `local` source serving `hosts` of `acme`.
fn start(dir: &Path, hosts: &[&str], acme_extra: &str, on_demand: &str) -> Harness {
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read")).expect("JSON")
}

// ---- the broker over the fake admin socket ---------------------------------------------------

#[tokio::test]
async fn broker_persists_before_push() {
    let dir = state_dir("persist");
    let admin = FakeAdmin::start();
    // The fake runs this on every snapshot it sees, before it answers: a certificate in the
    // snapshot must already be on disk, key included.
    let violations = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = Arc::new(AtomicBool::new(false));
    {
        let (dir, violations, seen) = (dir.clone(), Arc::clone(&violations), Arc::clone(&seen));
        admin.reject_when(move |body| {
            for cert in body["certificates"].as_array().into_iter().flatten() {
                seen.store(true, Ordering::SeqCst);
                let key = cert["key_pem"].as_str().unwrap_or_default();
                let on_disk = std::fs::read_dir(dir.join("certs"))
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|file| std::fs::read_to_string(file.path()).is_ok_and(|text| text == key));
                if !on_disk {
                    violations.lock().expect("lock").push(format!(
                        "a pushed certificate for {} was not on disk",
                        cert["hosts"]
                    ));
                }
            }
            Vec::new()
        });
    }
    let h = Harness::start_with(admin, &broker_toml(&dir, "", ""), &["local"]);
    h.source("local")
        .apps(vec![app("local", "a", &["a.acme.test"], UP).mapped("acme")]);
    let first = h.admin.wait_puts("the first push", |p| !p.is_empty()).await;
    assert_eq!(first[0].body["acme"]["issuer_node"], "n1");
    assert!(
        first[0].body["certificates"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    let account_key = first[0].body["acme"]["account_key_pem"]
        .as_str()
        .expect("the broker made an account key");
    assert!(account_key.contains("PRIVATE KEY"), "a PKCS#8 PEM");

    h.admin.emit(issued(&["a.acme.test"], "1"));
    let puts = h
        .admin
        .wait_puts("a push with the certificate", |p| {
            p.iter().any(|p| !cert_hosts(p).is_empty())
        })
        .await;
    assert!(seen.load(Ordering::SeqCst));
    assert_eq!(
        violations.lock().expect("lock").as_slice(),
        Vec::<String>::new()
    );
    let pushed = puts
        .iter()
        .find(|p| !cert_hosts(p).is_empty())
        .expect("push");
    assert_eq!(cert_hosts(pushed), [["a.acme.test"]]);

    // What the broker made is private to it.
    assert_eq!(mode_of(&dir), 0o700);
    assert_eq!(mode_of(&dir.join("certs")), 0o700);
    for file in [
        "index.json",
        "cursor.json",
        "account.key",
        "certs/1.cert.pem",
        "certs/1.key.pem",
    ] {
        assert_eq!(mode_of(&dir.join(file)), 0o600, "{file}");
    }
    assert_eq!(read_json(&dir.join("cursor.json"))["after"], 1);
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_store_failure_keeps_last_state() {
    let dir = state_dir("failure");
    let mut h = start(&dir, &["a.acme.test", "b.acme.test", "c.acme.test"], "", "");
    h.admin.emit(issued(&["a.acme.test"], "a"));
    h.admin
        .wait_puts("certificate A pushed", |p| {
            p.iter().any(|p| cert_hosts(p) == [["a.acme.test"]])
        })
        .await;

    // The store becomes unwritable: `certs` turns into a file, which no uid can write through.
    std::fs::remove_dir_all(dir.join("certs")).expect("remove certs");
    std::fs::write(dir.join("certs"), "not a directory").expect("sabotage");
    let before = h.admin.puts().len();
    let failing = h.admin.emit(issued(&["b.acme.test"], "b"));
    let status = h
        .wait_status("the broker stops with an error", |s| s.acme_error.is_some())
        .await;
    let why = status.acme_error.expect("error");
    assert!(why.contains("state directory"), "{why}");
    assert!(!why.contains(KEY_BODY), "{why}");
    assert_ne!(
        read_json(&dir.join("cursor.json"))["after"],
        failing,
        "the cursor does not move past an event that was not persisted"
    );

    // The sources still work, and what was pushed stays: A, never B.
    h.source("local").apps(
        ["a", "b", "c"]
            .iter()
            .map(|n| app("local", n, &[format!("{n}.acme.test").as_str()], UP).mapped("acme"))
            .chain([app("local", "d", &["d.acme.test"], UP).mapped("acme")])
            .collect(),
    );
    let puts = h
        .admin
        .wait_puts("a push after the failure", |p| {
            p.len() > before
                && p.last()
                    .is_some_and(|p| p.body["apps"].as_array().is_some_and(|a| a.len() == 4))
        })
        .await;
    for put in &puts[before..] {
        assert_eq!(
            cert_hosts(put),
            [["a.acme.test"]],
            "last pushed state kept, B never pushed"
        );
    }
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_event_resume() {
    let dir = state_dir("resume");
    let toml = broker_toml(&dir, "", "");
    let h = Harness::start(&toml, &["local"]);
    h.source("local")
        .apps(vec![app("local", "a", &["a.acme.test"], UP).mapped("acme")]);
    h.admin.emit(http_challenge("t1"));
    h.admin
        .wait_puts("t1 pushed", |p| {
            p.iter().any(|p| challenge_tokens(p) == ["t1"])
        })
        .await;
    let admin = h.stop_keep_admin().await;
    assert_eq!(read_json(&dir.join("cursor.json"))["after"], 1);
    let polled = admin.polls().len();

    // An event arrives while the provider is down; a new provider continues after the stored
    // sequence number: it neither misses it nor reads the first one again.
    admin.emit(http_challenge("t2"));
    let h = Harness::start_with(admin, &toml, &["local"]);
    h.source("local")
        .apps(vec![app("local", "a", &["a.acme.test"], UP).mapped("acme")]);
    let puts = h
        .admin
        .wait_puts("both challenges pushed once", |p| {
            p.last()
                .is_some_and(|p| challenge_tokens(p) == ["t1", "t2"])
        })
        .await;
    let polls = h.admin.polls();
    assert_eq!(
        polls[polled], 1,
        "the first poll of the new provider resumes after 1: {polls:?}"
    );
    assert!(polls[polled..].iter().all(|after| *after >= 1), "{polls:?}");
    assert_eq!(
        acme_of(puts.last().expect("push"))["challenges"]
            .as_array()
            .map(Vec::len),
        Some(2),
        "no duplicates"
    );
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_resync_on_410_and_boot_id() {
    let dir = state_dir("resync");
    let h = start(&dir, &["a.acme.test"], "", "");
    h.admin.emit(issued(&["a.acme.test"], "a"));
    h.admin.emit(http_challenge("stale"));
    h.admin
        .wait_puts("certificate and challenge pushed", |p| {
            p.iter()
                .any(|p| !cert_hosts(p).is_empty() && challenge_tokens(p) == ["stale"])
        })
        .await;
    let pushed = h.admin.puts().len();

    // podgate restarts: no snapshot, no feed, a new boot id. The provider notices through the
    // feed within a poll, not at the next 60 second resync, drops the challenge of the dead
    // order, polls from the start and pushes everything it holds again.
    h.admin.restart();
    let puts = h
        .admin
        .wait_puts("the whole snapshot again after the restart", |p| {
            p.len() > pushed
        })
        .await;
    let again = &puts[pushed];
    assert_eq!(again.version, 1, "a fresh podgate starts at version 1");
    assert_eq!(
        cert_hosts(again),
        [["a.acme.test"]],
        "the certificate is pushed before use"
    );
    assert!(
        challenge_tokens(again).is_empty(),
        "the stale answer went: {:?}",
        acme_of(again)
    );
    let polls = h.admin.polls();
    assert_eq!(
        polls.last().copied(),
        Some(0),
        "polling starts over: {polls:?}"
    );

    // The feed forgets what the provider has not read: `410`. It continues from what the feed
    // still holds, and reads what comes next.
    h.admin.emit(http_challenge("before-gap"));
    h.admin
        .wait_puts("before-gap pushed", |p| {
            p.last()
                .is_some_and(|p| challenge_tokens(p) == ["before-gap"])
        })
        .await;
    h.admin.forget_events_before(20);
    h.admin.emit(http_challenge("after-gap"));
    let puts = h
        .admin
        .wait_puts("after-gap pushed", |p| {
            p.last()
                .is_some_and(|p| challenge_tokens(p).contains(&"after-gap".to_owned()))
        })
        .await;
    let polls = h.admin.polls();
    assert!(polls.contains(&19), "continues from oldest - 1: {polls:?}");
    assert_eq!(
        challenge_tokens(puts.last().expect("push")),
        ["after-gap", "before-gap"]
    );
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_replaces_a_renewed_certificate() {
    let dir = state_dir("renew");
    let h = start(&dir, &["a.acme.test", "b.acme.test"], "", "");
    h.admin.emit(issued(&["a.acme.test"], "old"));
    h.admin
        .wait_puts("first certificate", |p| {
            p.iter().any(|p| !cert_hosts(p).is_empty())
        })
        .await;
    h.admin.emit(issued(&["a.acme.test"], "new"));
    let puts = h
        .admin
        .wait_puts("the renewal", |p| {
            p.last().is_some_and(|p| {
                p.body["certificates"][0]["key_pem"]
                    .as_str()
                    .is_some_and(|k| k.contains("-new"))
            })
        })
        .await;
    assert_eq!(
        puts.last().expect("push").body["certificates"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn certificates_of_unclaimed_hosts_are_not_pushed() {
    let dir = state_dir("unclaimed");
    let h = start(&dir, &["a.acme.test"], "", "");
    h.admin.emit(issued(&["gone.acme.test"], "gone"));
    h.admin.emit(issued(&["a.acme.test"], "a"));
    let puts = h
        .admin
        .wait_puts("the claimed certificate", |p| {
            p.iter().any(|p| !cert_hosts(p).is_empty())
        })
        .await;
    for put in &puts {
        assert!(
            cert_hosts(put)
                .iter()
                .all(|hosts| hosts != &["gone.acme.test"]),
            "{:?}",
            cert_hosts(put)
        );
    }
    // It is kept for the day an app claims the host again.
    assert!(std::fs::read_dir(dir.join("certs")).expect("certs").count() >= 4);
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn broker_answers_tls_alpn_and_clears_on_issue() {
    let dir = state_dir("alpn");
    let h = start(&dir, &["a.acme.test"], "", "");
    h.admin.emit(json!({
        "kind": "acme_challenge", "type": "tls-alpn-01", "name": "a.acme.test", "key_authorization": "ka"
    }));
    let puts = h
        .admin
        .wait_puts("the tls-alpn-01 answer", |p| {
            p.iter()
                .any(|p| acme_of(p)["challenges"][0]["name"] == "a.acme.test")
        })
        .await;
    let answer = puts
        .iter()
        .map(acme_of)
        .find(|a| a["challenges"][0]["name"] == "a.acme.test")
        .expect("push");
    assert_eq!(answer["challenges"][0]["key_authorization"], "ka");
    assert!(answer["challenges"][0]["token"].is_null());
    h.admin.emit(issued(&["a.acme.test"], "a"));
    h.admin
        .wait_puts("the answer is gone with the certificate", |p| {
            p.last().is_some_and(|p| {
                !cert_hosts(p).is_empty()
                    && acme_of(p)["challenges"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
            })
        })
        .await;
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- on-demand approval ----------------------------------------------------------------------

fn on_demand_harness(dir: &Path, limits: &str) -> Harness {
    let h = Harness::start(&broker_toml(dir, "", limits), &["local"]);
    h.source("local").apps(vec![
        app("local", "shop", &["*.acme.test"], UP)
            .mapped("acme")
            .on_demand(),
        app("local", "gshop", &["*.globex.test"], UP)
            .mapped("globex")
            .on_demand(),
    ]);
    h
}

async fn wait_cursor(dir: &Path, after: u64) {
    let start = Instant::now();
    while read_json_opt(&dir.join("cursor.json")).is_none_or(|c| c["after"].as_u64() < Some(after))
    {
        assert!(
            start.elapsed() < common::DEADLINE,
            "the cursor did not reach {after}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn read_json_opt(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[tokio::test]
async fn on_demand_approved_for_owning_tenant() {
    let dir = state_dir("od-ok");
    let h = on_demand_harness(&dir, "");
    h.admin.emit(requested("x.acme.test"));
    let puts = h
        .admin
        .wait_puts("the host is listed", |p| {
            p.iter().any(|p| requested_hosts(p) == ["x.acme.test"])
        })
        .await;
    assert!(puts.iter().any(|p| requested_hosts(p) == ["x.acme.test"]));

    // The approval is kept: it survives a restart of the provider and shows in the next push.
    let admin = h.stop_keep_admin().await;
    let h = Harness::start_with(admin, &broker_toml(&dir, "", ""), &["local"]);
    h.source("local").apps(vec![
        app("local", "shop", &["*.acme.test"], UP)
            .mapped("acme")
            .on_demand(),
        app("local", "gshop", &["*.globex.test"], UP)
            .mapped("globex")
            .on_demand(),
    ]);
    h.admin
        .wait_puts("still listed after a restart", |p| {
            p.last()
                .is_some_and(|p| requested_hosts(p) == ["x.acme.test"])
        })
        .await;

    // Once the certificate exists the host is no longer listed.
    h.admin.emit(issued(&["x.acme.test"], "x"));
    h.admin
        .wait_puts("delisted with the certificate", |p| {
            p.last().is_some_and(|p| {
                requested_hosts(p).is_empty() && cert_hosts(p) == [["x.acme.test"]]
            })
        })
        .await;
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn on_demand_refused_for_foreign_host() {
    let dir = state_dir("od-refuse");
    let h = on_demand_harness(&dir, "");
    // A host of no app, a host two labels below the wildcard, a name that is not a host, an
    // address. Then one good host, as the marker.
    let bad = [
        "evil.test",
        "a.b.acme.test",
        "*.acme.test",
        "10.1.2.3",
        "under_score.example.org",
    ];
    for host in bad {
        h.admin.emit(requested(host));
    }
    let marker = h.admin.emit(requested("ok.acme.test"));
    wait_cursor(&dir, marker).await;
    let puts = h
        .admin
        .wait_puts("the marker is listed", |p| {
            p.iter().any(|p| requested_hosts(p) == ["ok.acme.test"])
        })
        .await;
    for put in &puts {
        let listed = requested_hosts(put);
        assert!(
            listed.is_empty() || listed == ["ok.acme.test"],
            "{listed:?}"
        );
    }
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn on_demand_rate_limited() {
    let dir = state_dir("od-rate");
    let h = on_demand_harness(&dir, "max_per_tenant_per_hour = 2\nmax_pending = 3");
    for host in [
        "a1.acme.test",
        "a2.acme.test",
        "a3.acme.test",
        "g1.globex.test",
        "g2.globex.test",
    ] {
        h.admin.emit(requested(host));
    }
    let last = h.admin.emit(requested("g3.globex.test"));
    wait_cursor(&dir, last).await;
    // acme: two approvals an hour, the third is refused. globex is a tenant of its own and gets
    // one, but three hosts wait for certificates already, so the next ones are refused too.
    let puts = h
        .admin
        .wait_puts("three hosts listed", |p| {
            p.last().is_some_and(|p| {
                requested_hosts(p) == ["a1.acme.test", "a2.acme.test", "g1.globex.test"]
            })
        })
        .await;
    for put in &puts {
        let listed = requested_hosts(put);
        assert!(
            !listed.contains(&"a3.acme.test".to_owned())
                && !listed.contains(&"g2.globex.test".to_owned())
                && !listed.contains(&"g3.globex.test".to_owned()),
            "{listed:?}"
        );
    }
    h.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

fn trust_of(extra: &str) -> Trust {
    let config =
        Config::parse(&format!("admin_socket = \"/x.sock\"\n{TENANTS}{extra}")).expect("config");
    Trust::new(&config)
}

fn claim(app: &str, tenant: &str, on_demand: bool, hosts: &[&str]) -> ClaimedApp {
    ClaimedApp {
        app: app.into(),
        tenant: tenant.into(),
        on_demand,
        hosts: hosts
            .iter()
            .map(|h| HostPattern::parse(h).expect("host"))
            .collect(),
    }
}

#[test]
fn on_demand_trust_rule_and_rate_window() {
    let limits = OnDemandLimits {
        max_per_tenant_per_hour: 2,
        max_pending: 10,
    };
    let mut approver = Approver::new(limits, trust_of(""), Vec::new());
    let claims = Claims {
        apps: vec![
            claim("shop", "acme", true, &["*.acme.test"]),
            // Defense in depth: an app that declares a host outside its tenant's patterns would
            // be dropped by the merge; if one ever got here the host is refused.
            claim("squat", "acme", true, &["*.globex.test"]),
        ],
    };
    let hour = 3_600_000;
    assert!(matches!(
        approver.decide("x.acme.test", &claims, 0),
        Decision::Approved { .. }
    ));
    assert_eq!(
        approver.decide("y.globex.test", &claims, 1),
        Decision::Refused(Refusal::ForeignHost {
            tenant: "acme".into()
        })
    );
    assert!(matches!(
        approver.decide("y.acme.test", &claims, 2),
        Decision::Approved { .. }
    ));
    assert_eq!(
        approver.decide("z.acme.test", &claims, 3),
        Decision::Refused(Refusal::TenantRateLimited {
            tenant: "acme".into()
        })
    );
    // An approved host asked about again is the same approval, not a new one.
    assert!(matches!(
        approver.decide("x.acme.test", &claims, 4),
        Decision::Approved { .. }
    ));
    // A certificate arrived: it is no longer listed but still counts in the hour.
    approver.release("x.acme.test");
    let expected: Box<str> = "y.acme.test".into();
    assert_eq!(approver.open_hosts(), [expected]);
    assert!(matches!(
        approver.decide("z.acme.test", &claims, hour - 1),
        Decision::Refused(Refusal::TenantRateLimited { .. })
    ));
    // An hour later the window has slid.
    assert!(matches!(
        approver.decide("z.acme.test", &claims, hour + 1),
        Decision::Approved { .. }
    ));
}

// ---- keys and logs --------------------------------------------------------------------------

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

// ---- follower --------------------------------------------------------------------------------

#[tokio::test]
async fn follower_serves_shared_store() {
    let dir = state_dir("follower");
    let broker = start(&dir, &["a.acme.test"], "", "");
    broker.admin.emit(issued(&["a.acme.test"], "shared"));
    broker.admin.emit(http_challenge("tok"));
    broker
        .admin
        .wait_puts("the broker pushes both", |p| {
            p.last()
                .is_some_and(|p| !cert_hosts(p).is_empty() && challenge_tokens(p) == ["tok"])
        })
        .await;

    // Another node's provider reads the same directory and pushes the same certificate and
    // answer to its own podgate. It reads no event feed, and the account key stays with the
    // broker.
    let follower_toml = broker_toml(&dir, "mode = \"follower\"", "");
    let follower = Harness::start(&follower_toml, &["local"]);
    follower
        .source("local")
        .apps(vec![app("local", "a", &["a.acme.test"], UP).mapped("acme")]);
    let puts = follower
        .admin
        .wait_puts("the follower pushes the shared certificate", |p| {
            p.last()
                .is_some_and(|p| !cert_hosts(p).is_empty() && challenge_tokens(p) == ["tok"])
        })
        .await;
    let theirs = puts.last().expect("push");
    let ours = broker.admin.puts().pop().expect("broker push");
    assert_eq!(theirs.body["certificates"], ours.body["certificates"]);
    assert_eq!(acme_of(theirs)["issuer_node"], "n1");
    assert!(
        acme_of(theirs)["account_key_pem"].is_null(),
        "{}",
        acme_of(theirs)
    );
    assert!(acme_of(&ours)["account_key_pem"].is_string());
    assert!(
        follower.admin.polls().is_empty(),
        "a follower does not read the event feed"
    );

    // A certificate the broker stores later reaches the follower within a poll of the directory.
    broker
        .admin
        .emit(issued(&["a.acme.test", "b.acme.test"], "second"));
    follower
        .admin
        .wait_puts("the next certificate", |p| {
            p.last()
                .is_some_and(|p| cert_hosts(p) == [["a.acme.test", "b.acme.test"]])
        })
        .await;
    follower.stop().await.expect("clean stop");
    broker.stop().await.expect("clean stop");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- configuration ---------------------------------------------------------------------------

fn field_of(text: &str) -> String {
    match Config::parse(text) {
        Err(podgate_provider::ConfigError::Invalid { field, .. }) => field.to_string(),
        other => panic!("expected an invalid field, got {other:?}"),
    }
}

#[test]
fn acme_config_names_the_bad_field() {
    let head = "admin_socket = \"/x.sock\"\n[acme]\nenabled = true\n";
    let good =
        "state_dir = \"/s\"\ndirectory_url = \"https://ca.test/dir\"\nissuer_node = \"n1\"\n";
    assert!(
        Config::parse(&format!("{head}{good}"))
            .expect("valid")
            .acme
            .is_some()
    );
    assert!(
        Config::parse("admin_socket = \"/x.sock\"\n[acme]\nenabled = false\n")
            .expect("off")
            .acme
            .is_none()
    );
    assert_eq!(
        field_of(&format!(
            "{head}directory_url = \"https://x\"\nissuer_node = \"n\"\n"
        )),
        "acme.state_dir"
    );
    assert_eq!(
        field_of(&format!(
            "{head}state_dir = \"/s\"\ndirectory_url = \"http://x\"\nissuer_node = \"n\"\n"
        )),
        "acme.directory_url"
    );
    assert_eq!(
        field_of(&format!(
            "{head}state_dir = \"/s\"\ndirectory_url = \"https://x\"\n"
        )),
        "acme.issuer_node"
    );
    assert_eq!(
        field_of(&format!(
            "{head}{good}account_key_file = \"/k\"\n[acme.eab]\nkey_id = \"k\"\nhmac_key_file = \"/h\"\n"
        )),
        "acme.eab"
    );
    assert_eq!(
        field_of(&format!("{head}{good}[acme.on_demand]\nmax_pending = 0\n")),
        "acme.on_demand.max_pending"
    );
    // A key is a path, never a value.
    assert!(Config::parse(&format!("{head}{good}account_key = \"-----BEGIN\"\n")).is_err());
}

#[test]
fn snapshot_acme_is_not_a_snapshot_key() {
    // ACME is configured in [acme], which runs the broker. A snapshot-level acme object would
    // order certificates nobody answers, so the section does not take one.
    let text = "admin_socket = \"/x.sock\"\n[snapshot.acme]\nissuer_node = \"n1\"\ndirectory_url = \"https://ca.test/dir\"\n";
    let err = Config::parse(text).expect_err("not a key of [snapshot]");
    assert!(err.to_string().contains("acme"), "{err}");
    assert!(
        Config::parse("admin_socket = \"/x.sock\"\n[snapshot]\nrevert_window_secs = 60\n").is_ok(),
        "the rest of [snapshot] loads"
    );
}

// ---- the real daemon against pebble ----------------------------------------------------------

/// The pieces of an end-to-end run: pebble, the daemon it validates against, and the backend.
struct Setup {
    dir: PathBuf,
    pebble: pebble::Pebble,
    daemon: daemon::Daemon,
    policy: PathBuf,
    alpn: bool,
    backend: Backend,
}

struct Backend {
    addr: std::net::SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

async fn setup(name: &str, alpn: bool) -> Setup {
    let dir = state_dir(name);
    std::fs::create_dir_all(&dir).expect("dir");
    let policy = dir.join("upstream-policy.json");
    std::fs::write(&policy, daemon::LOOPBACK_POLICY).expect("policy");
    let ports = free_ports(2);
    let pki = pebble::Pki::new(&dir);
    let pebble = pebble::Pebble::start(
        pki,
        pebble::Validation {
            http: Some(ports[0]),
            tls: alpn.then_some(ports[1]),
        },
    )
    .await;
    let ca_file = pebble.pki.ca_pem.display().to_string();
    let daemon = daemon::Daemon::start(
        &policy,
        (ports[0], ports[1]),
        &[("NODE_NAME", "n1"), ("ACME_CA_FILE", &ca_file)],
    )
    .await;
    let (addr, task) = daemon::backend("from-the-backend").await;
    Setup {
        dir,
        pebble,
        daemon,
        policy,
        alpn,
        backend: Backend { addr, _task: task },
    }
}

/// A provider process-in-a-task against the real daemon.
struct Provider {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    run: Option<tokio::task::JoinHandle<Result<(), podgate_provider::RunError>>>,
    status: tokio::sync::watch::Receiver<podgate_provider::Status>,
}

impl Provider {
    fn start(setup: &Setup, state: &Path) -> Self {
        let extra = format!(
            "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n[acme]\nenabled = true\nstate_dir = {state:?}\ndirectory_url = {:?}\nissuer_node = \"n1\"\ncontact = [\"mailto:ops@example.test\"]\n",
            setup.policy.display().to_string(),
            setup.pebble.directory,
        );
        let config = common::config(
            &setup.daemon.admin,
            &format!("{extra}[[source]]\nkind = \"fake\"\nname = \"local\"\n"),
        );
        let mut engine = podgate_provider::Engine::new(
            config,
            UpstreamPolicy::load(&setup.policy).expect("policy"),
        )
        .with_tuning(common::fast_tuning());
        let (source, handle) = common::scripted("local");
        engine.add_source(source).expect("source");
        let mut shop = app(
            "local",
            "shop",
            &["a.test"],
            &format!("http://{}", setup.backend.addr),
        );
        if setup.alpn {
            shop.app.tls.challenge = podgate_model::ChallengeKind::TlsAlpn01;
        }
        handle.apps(vec![shop]);
        let status = engine.status();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let run = tokio::spawn(async move {
            engine
                .run(async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            stop: Some(stop),
            run: Some(run),
            status,
        }
    }

    async fn stop(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let run = self.run.take().expect("running");
        tokio::time::timeout(Duration::from_secs(20), run)
            .await
            .expect("the provider stops")
            .expect("no panic")
            .expect("clean stop");
    }
}

/// A TLS client that trusts only pebble's root: `GET /` for `host` on the daemon's TLS listener.
async fn https_get(
    setup: &Setup,
    root: &rustls_pki_types::CertificateDer<'static>,
    host: &str,
) -> Result<(u16, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).map_err(|e| e.to_string())?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(setup.daemon.tls)
        .await
        .map_err(|e| e.to_string())?;
    let name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let mut tls = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| "handshake timed out".to_owned())?
    .map_err(|e| e.to_string())?;
    tls.write_all(
        format!("GET / HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    // The server may close without a close_notify: what was read is the whole answer.
    let _ = tls.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// Retries `https_get` until it answers `200`, for up to `within`.
async fn serves_over_tls(
    setup: &Setup,
    root: &rustls_pki_types::CertificateDer<'static>,
    within: Duration,
) -> String {
    let start = Instant::now();
    loop {
        match https_get(setup, root, "a.test").await {
            Ok((200, body)) => return body,
            other => assert!(
                start.elapsed() < within,
                "a.test is not served over TLS after {within:?}: {other:?}\n--- pebble.log\n{}",
                setup.pebble.pki.read("pebble.log")
            ),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn count_events(events: &[Value], kind: &str) -> usize {
    events.iter().filter(|event| event["kind"] == kind).count()
}

#[tokio::test]
async fn broker_http01_end_to_end() {
    let work = tokio::time::timeout(Duration::from_secs(240), async {
        let setup = setup("e2e", false).await;
        let state = setup.dir.join("state");
        let provider = Provider::start(&setup, &state);
        let root = setup.pebble.root().await;

        // No human step: the daemon orders, the provider answers its challenge and stores the
        // certificate it is sent, and the next snapshot carries it.
        let body = serves_over_tls(&setup, &root, Duration::from_secs(120)).await;
        assert_eq!(body, "from-the-backend");

        // What pebble created is what the provider answered: one challenge per authorization
        // (pebble reuses one now and then, and an order that reuses has none to answer).
        let created = common::pebble_authorizations_created(&setup.pebble.pki.read("pebble.log"));
        let events = setup.daemon.events().await;
        assert_eq!(
            count_events(&events, "acme_challenge"),
            created,
            "{events:?}"
        );
        assert_eq!(
            count_events(&events, "certificate_issued"),
            1,
            "one order, one certificate"
        );
        let kept = read_json(&state.join("challenges.json"));
        assert_eq!(kept.as_array().map(Vec::len), Some(created), "{kept}");
        let index = read_json(&state.join("index.json"));
        assert_eq!(index["certs"][0]["hosts"], json!(["a.test"]));
        assert_eq!(mode_of(&state), 0o700);
        assert_eq!(mode_of(&state.join("certs/1.key.pem")), 0o600);
        assert!(
            provider.status.borrow().pushes >= 2,
            "{:?}",
            provider.status.borrow()
        );
        provider.stop().await;
    });
    work.await.expect("the end-to-end test finished in time");
}

/// The same round trip proved over TLS-ALPN-01: the answer goes into `acme.challenges` as
/// `{name, key_authorization}`, and every TLS handshake of the CA is answered by the daemon.
#[tokio::test]
async fn broker_tls_alpn01_end_to_end() {
    let work = tokio::time::timeout(Duration::from_secs(240), async {
        let setup = setup("e2e-alpn", true).await;
        let state = setup.dir.join("state");
        let provider = Provider::start(&setup, &state);
        let root = setup.pebble.root().await;
        let body = serves_over_tls(&setup, &root, Duration::from_secs(120)).await;
        assert_eq!(body, "from-the-backend");
        let created = common::pebble_authorizations_created(&setup.pebble.pki.read("pebble.log"));
        let events = setup.daemon.events().await;
        let answered = events
            .iter()
            .filter(|event| event["kind"] == "acme_challenge" && event["type"] == "tls-alpn-01")
            .count();
        assert_eq!(answered, created, "{events:?}");
        assert_eq!(count_events(&events, "certificate_issued"), 1);
        provider.stop().await;
    });
    work.await.expect("the tls-alpn-01 test finished in time");
}

#[tokio::test]
async fn broker_survives_restarts() {
    let work = tokio::time::timeout(Duration::from_secs(360), async {
        let mut setup = setup("restarts", false).await;
        let state = setup.dir.join("state");
        let root = setup.pebble.root().await;
        let provider = Provider::start(&setup, &state);
        serves_over_tls(&setup, &root, Duration::from_secs(120)).await;
        let created = common::pebble_authorizations_created(&setup.pebble.pki.read("pebble.log"));
        provider.stop().await;

        // The provider restarts: the certificate comes from disk, nothing is ordered again.
        let provider = Provider::start(&setup, &state);
        let pushes = provider.status.borrow().pushes;
        let start = Instant::now();
        while provider.status.borrow().pushes == pushes {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no push after the provider restart"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            serves_over_tls(&setup, &root, Duration::from_secs(10)).await,
            "from-the-backend"
        );

        // podgate restarts: it has no snapshot and no certificate. The running provider sees the
        // new boot id on the feed and pushes the whole snapshot, certificate included, before
        // podgate could have ordered anything.
        setup.daemon.restart().await;
        assert_eq!(
            serves_over_tls(&setup, &root, Duration::from_secs(60)).await,
            "from-the-backend"
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        let events = setup.daemon.events().await;
        assert_eq!(
            count_events(&events, "certificate_issued"),
            0,
            "the restarted podgate ordered again: {events:?}"
        );
        assert_eq!(
            common::pebble_authorizations_created(&setup.pebble.pki.read("pebble.log")),
            created,
            "no new authorization after either restart"
        );
        provider.stop().await;
    });
    work.await.expect("the restart test finished in time");
}
