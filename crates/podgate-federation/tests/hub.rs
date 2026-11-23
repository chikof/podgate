//! The hub against fake peers: the combined view, staleness, hostile peers, read-only requests
//! and the view listener.

#![allow(
    clippy::unwrap_used,
    reason = "an unwrap that fails is the test failing, and the message is the line"
)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    Answer, DEADLINE, Dir, FakePeer, Pki, Script, Seen, anonymous_client, catalog_script,
    client_config, eventually, get, item, request,
};
use podgate_federation::config::{PeersFile, Pull};
use podgate_federation::failure::ErrorClass;
use podgate_federation::hub::Hub;
use podgate_federation::pull::{Limits, pull};
use serde_json::{Value, json};

const MIB: usize = 1024 * 1024;

struct Opts {
    poll_ms: u64,
    timeout_ms: u64,
    stale_ms: u64,
    max_bytes: usize,
    max_entries: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            poll_ms: 100,
            timeout_ms: 5000,
            stale_ms: 3000,
            max_bytes: 8 * MIB,
            max_entries: 20_000,
        }
    }
}

struct Rig {
    dir: Dir,
    pki: Pki,
    hub: Hub,
    op: Arc<rustls::ClientConfig>,
}

fn hub_text(dir: &Dir, pki: &Pki, peers: &[(&str, String)]) -> String {
    let (hub_cert, hub_key) = pki.client_files(&dir.0, "hub");
    let (view_cert, view_key) = pki.server_files(&dir.0, "view");
    let ops_ca = pki.ca_file(&dir.0, "ops-ca");
    let peer_ca = pki.ca_file(&dir.0, "peer-ca");
    let mut text = format!(
        "[view]\naddr = \"127.0.0.1:0\"\ncert_file = {view_cert:?}\nkey_file = {view_key:?}\nclient_ca_file = {ops_ca:?}\n\n[client]\ncert_file = {hub_cert:?}\nkey_file = {hub_key:?}\n"
    );
    for (name, url) in peers {
        text.push_str(&format!(
            "\n[[peer]]\nname = {name:?}\nurl = {url:?}\nca_file = {peer_ca:?}\n"
        ));
    }
    text
}

impl Rig {
    async fn start(pki: Pki, peers: &[(&str, String)], opts: Opts) -> Self {
        let dir = Dir::new();
        let mut file = PeersFile::from_text(&hub_text(&dir, &pki, peers)).expect("peers file");
        file.pull = Pull {
            poll: Duration::from_millis(opts.poll_ms),
            timeout: Duration::from_millis(opts.timeout_ms),
            stale_after: Duration::from_millis(opts.stale_ms),
            max_bytes: opts.max_bytes,
            max_entries: opts.max_entries,
        };
        let hub = Hub::start(file).await.expect("hub starts");
        let op = client_config(&pki, &dir, "op");
        Self { dir, pki, hub, op }
    }

    async fn get(&self, target: &str) -> common::Got {
        get(self.hub.view_addr(), &self.op, target).await
    }

    async fn clusters(&self) -> Value {
        self.get("/v1/clusters").await.json()
    }

    async fn row(&self, name: &str) -> Value {
        let doc = self.clusters().await;
        doc["items"]
            .as_array()
            .expect("items")
            .iter()
            .find(|row| row["name"] == name)
            .unwrap_or_else(|| panic!("no cluster {name}"))
            .clone()
    }

    async fn wait_state(&self, name: &str, state: &str) -> Value {
        let mut last = Value::Null;
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            last = self.row(name).await;
            if last["state"] == state {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("cluster {name} never became {state}: {last}");
    }

    /// Waits for the first pull to fail, which is when a cluster has an error to show.
    async fn wait_error(&self, name: &str) -> Value {
        let mut last = Value::Null;
        let start = Instant::now();
        while start.elapsed() < DEADLINE {
            last = self.row(name).await;
            if !last["error"].is_null() {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("cluster {name} never failed: {last}");
    }

    async fn catalog(&self, query: &str) -> Value {
        self.get(&format!("/v1/catalog?{query}")).await.json()
    }
}

fn items(tenant: &str, ids: &[&str]) -> Vec<Value> {
    ids.iter()
        .map(|id| item(tenant, id, "1", "stable"))
        .collect()
}

async fn peer(pki: &Pki, script: Script) -> FakePeer {
    FakePeer::start(pki, pki, script).await
}

fn json_answer(value: &Value) -> Answer {
    Answer::Json(value.to_string().into_bytes())
}

#[tokio::test]
async fn federation_combined_view() {
    let pki = Pki::new();
    let eu = peer(&pki, catalog_script(items("acme", &["pets", "users"]), 3)).await;
    let us = peer(&pki, catalog_script(items("acme", &["pets"]), 9)).await;
    let ap = peer(
        &pki,
        catalog_script(vec![item("zed", "billing", "2", "deprecated")], 1),
    )
    .await;
    let rig = Rig::start(
        pki,
        &[("eu-1", eu.url()), ("us-2", us.url()), ("ap-3", ap.url())],
        Opts::default(),
    )
    .await;
    for name in ["eu-1", "us-2", "ap-3"] {
        rig.wait_state(name, "fresh").await;
    }
    let catalog = rig.catalog("limit=100").await;
    assert_eq!(catalog["total"], 4);
    let rows: Vec<(String, String, String)> = catalog["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|e| {
            (
                e["cluster"].as_str().unwrap().to_owned(),
                e["tenant"].as_str().unwrap().to_owned(),
                e["id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expect = |c: &str, t: &str, i: &str| (c.to_owned(), t.to_owned(), i.to_owned());
    assert_eq!(
        rows,
        [
            expect("ap-3", "zed", "billing"),
            expect("eu-1", "acme", "pets"),
            expect("eu-1", "acme", "users"),
            expect("us-2", "acme", "pets"),
        ],
        "the same tenant in two clusters is two rows, labelled by the operator's name"
    );
    assert_eq!(catalog["stale_clusters"], json!([]));
    let clusters = rig.clusters().await;
    let by_name = |name: &str| {
        clusters["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()
            .clone()
    };
    let eu_row = by_name("eu-1");
    assert_eq!(eu_row["snapshot_version"], 3);
    assert_eq!(eu_row["entries"], 2);
    assert_eq!(eu_row["counts"]["servers"]["healthy"], 5);
    assert_eq!(eu_row["writer"], "podgate-provider");
    assert_eq!(by_name("us-2")["snapshot_version"], 9);
    assert!(eu_row["last_success"].is_u64() && eu_row["error"].is_null());
    assert_eq!(clusters["items"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn federation_filters() {
    let pki = Pki::new();
    let mut eu_items = items("acme", &["a", "b", "c"]);
    eu_items.push(item("acme", "old", "1", "deprecated"));
    eu_items.push(item("zed", "z", "1", "retired"));
    let eu = peer(&pki, catalog_script(eu_items, 1)).await;
    let us = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url()), ("us", us.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    rig.wait_state("us", "fresh").await;
    assert_eq!(rig.catalog("cluster=us").await["total"], 1);
    assert_eq!(rig.catalog("cluster=eu").await["total"], 5);
    assert_eq!(rig.catalog("tenant=zed").await["total"], 1);
    assert_eq!(rig.catalog("tenant=acme").await["total"], 5);
    assert_eq!(rig.catalog("lifecycle=deprecated").await["total"], 1);
    assert_eq!(
        rig.catalog("cluster=eu&tenant=acme&lifecycle=stable").await["total"],
        3
    );
    assert_eq!(rig.catalog("cluster=nowhere").await["total"], 0);
    assert_eq!(rig.get("/v1/catalog?lifecycle=sideways").await.status, 400);
    assert_eq!(rig.get("/v1/catalog?limit=0").await.status, 400);
    assert_eq!(rig.get("/v1/catalog?after=broken").await.status, 400);
    let mut seen = Vec::new();
    let mut query = "limit=2".to_owned();
    loop {
        let page = rig.catalog(&query).await;
        for entry in page["items"].as_array().unwrap() {
            seen.push(format!(
                "{}/{}/{}",
                entry["cluster"].as_str().unwrap(),
                entry["tenant"].as_str().unwrap(),
                entry["id"].as_str().unwrap()
            ));
        }
        if page["truncated"] != json!(true) {
            break;
        }
        let next = page["next"].as_str().expect("next");
        query = format!(
            "limit=2&after={}",
            podgate_federation::wire::percent_encode(next)
        );
    }
    assert_eq!(
        seen,
        [
            "eu/acme/a",
            "eu/acme/b",
            "eu/acme/c",
            "eu/acme/old",
            "eu/zed/z",
            "us/acme/a"
        ],
        "paging crosses the cluster boundary without repeating or skipping"
    );
}

#[tokio::test]
async fn federation_peer_down_is_stale() {
    let pki = Pki::new();
    let good = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let flaky = peer(&pki, catalog_script(items("acme", &["f"]), 1)).await;
    let dead = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://127.0.0.1:{}", probe.local_addr().unwrap().port());
        drop(probe);
        url
    };
    flaky.set(Arc::new(|_: &Seen| {
        Answer::Status(500, Vec::new(), b"{}".to_vec())
    }));
    let rig = Rig::start(
        pki,
        &[("good", good.url()), ("flaky", flaky.url()), ("dead", dead)],
        Opts::default(),
    )
    .await;
    rig.wait_state("good", "fresh").await;
    let dead_row = rig.wait_error("dead").await;
    assert_eq!(dead_row["error"]["class"], "connect");
    assert!(dead_row["last_success"].is_null(), "never reached");
    assert_eq!(dead_row["entries"], 0);
    let flaky_row = rig.wait_error("flaky").await;
    assert_eq!(
        flaky_row["error"],
        json!({"class": "status", "status": 500})
    );
    assert_eq!(
        rig.row("good").await["state"],
        "fresh",
        "the others stay current"
    );
    flaky.set(catalog_script(items("acme", &["f"]), 2));
    let recovered = rig.wait_state("flaky", "fresh").await;
    assert!(recovered["error"].is_null() && recovered["last_success"].is_u64());
    assert_eq!(rig.catalog("cluster=flaky").await["total"], 1);
}

#[tokio::test]
async fn federation_peer_slow_bounded() {
    let pki = Pki::new();
    let trickle = peer(
        &pki,
        Arc::new(|seen: &Seen| {
            if seen.path.ends_with("status") {
                Answer::Trickle
            } else {
                Answer::Hang
            }
        }),
    )
    .await;
    let hang = peer(&pki, Arc::new(|_: &Seen| Answer::Hang)).await;
    let ok = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    // The pull itself ends within its deadline, whatever the peer does.
    let dir = Dir::new();
    let file = PeersFile::from_text(&hub_text(
        &dir,
        &pki,
        &[("slow", trickle.url()), ("hang", hang.url())],
    ))
    .expect("file");
    let limits = Limits {
        timeout: Duration::from_millis(800),
        max_bytes: 8 * MIB,
        max_entries: 100,
    };
    for peer in &file.peers {
        let start = Instant::now();
        let result = pull(peer, &limits).await;
        let took = start.elapsed();
        assert_eq!(
            result.unwrap_err().class,
            ErrorClass::Timeout,
            "{}",
            peer.name
        );
        assert!(
            took < Duration::from_millis(1500),
            "{} took {took:?}",
            peer.name
        );
    }
    let rig = Rig::start(
        pki,
        &[
            ("slow", trickle.url()),
            ("hang", hang.url()),
            ("ok", ok.url()),
        ],
        Opts {
            timeout_ms: 500,
            ..Opts::default()
        },
    )
    .await;
    let slow = rig.wait_error("slow").await;
    assert_eq!(slow["error"]["class"], "timeout");
    assert_eq!(rig.wait_error("hang").await["error"]["class"], "timeout");
    rig.wait_state("ok", "fresh").await;
    let before = rig.row("ok").await["last_attempt"].as_u64().unwrap();
    eventually(
        "the fresh peer keeps being pulled while two peers hang",
        || async { rig.row("ok").await["last_attempt"].as_u64().unwrap() > before },
    )
    .await;
    assert_eq!(rig.row("ok").await["state"], "fresh");
}

fn with_format(version: i64, items_: Vec<Value>) -> Script {
    let good = catalog_script(items_, 4);
    Arc::new(move |seen: &Seen| match good(seen) {
        Answer::Json(body) => {
            let mut doc: Value = serde_json::from_slice(&body).unwrap();
            doc["format_version"] = json!(version);
            Answer::Json(doc.to_string().into_bytes())
        }
        other => other,
    })
}

#[tokio::test]
async fn federation_old_format_degrades() {
    let pki = Pki::new();
    let peer_ = peer(&pki, with_format(1, items("acme", &["a"]))).await;
    let other = peer(&pki, catalog_script(items("zed", &["z"]), 1)).await;
    let rig = Rig::start(
        pki,
        &[("eu", peer_.url()), ("us", other.url())],
        Opts::default(),
    )
    .await;
    rig.wait_state("eu", "fresh").await;
    let good_success = rig.row("eu").await["last_success"].as_u64().unwrap();
    for version in [2, 0] {
        peer_.set(with_format(version, items("acme", &["a"])));
        let row = {
            let start = Instant::now();
            loop {
                let row = rig.row("eu").await;
                if row["state"] == "stale" || start.elapsed() > DEADLINE {
                    break row;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        };
        assert_eq!(
            row["error"]["class"], "unsupported_format",
            "format {version}"
        );
        assert_eq!(row["peer_format_version"], version);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let later = rig.row("eu").await;
        assert_eq!(
            later["last_success"], row["last_success"],
            "the last success is kept, not renewed"
        );
        assert!(row["last_success"].as_u64().unwrap() >= good_success);
        assert_eq!(
            row["entries"], 1,
            "the last good entries stay, flagged stale"
        );
        let catalog = rig.catalog("cluster=eu").await;
        assert_eq!(catalog["items"][0]["stale"], true);
        assert_eq!(
            rig.row("us").await["state"],
            "fresh",
            "the other cluster is unaffected"
        );
        peer_.set(with_format(1, items("acme", &["a"])));
        rig.wait_state("eu", "fresh").await;
    }
}

#[tokio::test]
async fn federation_peer_error_status() {
    let pki = Pki::new();
    let internal = peer(
        &pki,
        Arc::new(|_: &Seen| Answer::Status(500, Vec::new(), b"{}".to_vec())),
    )
    .await;
    let redirect = peer(
        &pki,
        Arc::new(|_: &Seen| {
            Answer::Status(
                302,
                vec![("location".into(), "https://169.254.169.254/".into())],
                Vec::new(),
            )
        }),
    )
    .await;
    let not_modified = peer(
        &pki,
        Arc::new(|_: &Seen| Answer::Status(304, Vec::new(), Vec::new())),
    )
    .await;
    let html = peer(
        &pki,
        Arc::new(|_: &Seen| {
            Answer::Status(
                200,
                vec![("content-type".into(), "text/html".into())],
                b"<p>hi</p>".to_vec(),
            )
        }),
    )
    .await;
    let rig = Rig::start(
        pki,
        &[
            ("a-500", internal.url()),
            ("b-302", redirect.url()),
            ("c-304", not_modified.url()),
            ("d-html", html.url()),
        ],
        Opts::default(),
    )
    .await;
    assert_eq!(
        rig.wait_error("a-500").await["error"],
        json!({"class": "status", "status": 500})
    );
    assert_eq!(
        rig.wait_error("b-302").await["error"],
        json!({"class": "status", "status": 302})
    );
    assert_eq!(
        rig.wait_error("c-304").await["error"],
        json!({"class": "status", "status": 304})
    );
    assert_eq!(
        rig.wait_error("d-html").await["error"]["class"],
        "malformed"
    );
    assert_eq!(
        redirect
            .seen()
            .iter()
            .filter(|s| s.path.starts_with("/federation/v1/"))
            .count(),
        redirect.seen().len(),
        "the redirect target is never requested"
    );
}

async fn switch_to(rig: &Rig, name: &str, peer: &FakePeer, script: Script, class: &str) -> Value {
    peer.set(script);
    let start = Instant::now();
    loop {
        let row = rig.row(name).await;
        if row["error"]["class"] == class {
            return row;
        }
        assert!(
            start.elapsed() < DEADLINE,
            "{name} never failed with {class}: {row}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn status_doc(version: u64) -> Value {
    json!({"format_version": 1, "snapshot_version": version, "applied_at": 1, "boot_id": "b"})
}

fn custom(status: Value, catalog: impl Fn(&Seen) -> Answer + Send + Sync + 'static) -> Script {
    Arc::new(move |seen: &Seen| {
        if seen.path.ends_with("/status") {
            json_answer(&status)
        } else {
            catalog(seen)
        }
    })
}

#[tokio::test]
async fn federation_hostile_peer_oversized() {
    let pki = Pki::new();
    let victim = peer(&pki, catalog_script(items("acme", &["a", "b"]), 1)).await;
    let rig = Rig::start(
        pki,
        &[("victim", victim.url())],
        Opts {
            max_bytes: 2 * MIB,
            max_entries: 3,
            ..Opts::default()
        },
    )
    .await;
    rig.wait_state("victim", "fresh").await;
    let huge = format!(
        r#"{{"format_version":1,"snapshot_version":1,"total":1,"items":[],"pad":"{}"}}"#,
        "x".repeat(6 * MIB)
    );
    let row = switch_to(
        &rig,
        "victim",
        &victim,
        custom(status_doc(1), move |_| {
            Answer::Json(huge.clone().into_bytes())
        }),
        "too_large",
    )
    .await;
    assert_eq!(row["state"], "stale");
    assert_eq!(row["entries"], 2, "the previous list is kept");
    // A total over the entry cap, and a run of pages over the byte budget.
    let many: Vec<Value> = (0..10)
        .map(|n| item("acme", &format!("id{n:02}"), "1", "stable"))
        .collect();
    switch_to(
        &rig,
        "victim",
        &victim,
        catalog_script(many, 1),
        "too_large",
    )
    .await;
    let big_items: Vec<Value> = (0..3)
        .map(|n| {
            let mut e = item("acme", &format!("id{n}"), "1", "stable");
            e["description"] = json!("d".repeat(2000));
            e
        })
        .collect();
    victim.set(catalog_script(big_items, 1));
    rig.wait_state("victim", "fresh").await;
    assert!(rig.row("victim").await["entries"] == 3);
}

#[tokio::test]
async fn federation_hostile_peer_malformed_json() {
    let pki = Pki::new();
    let bad = peer(
        &pki,
        Arc::new(|_: &Seen| Answer::Json(b"{\"format_version\": 1, \"items\": [".to_vec())),
    )
    .await;
    let rig = Rig::start(pki, &[("bad", bad.url())], Opts::default()).await;
    assert_eq!(rig.wait_error("bad").await["error"]["class"], "malformed");
    for body in [&b"[]"[..], b"null", b"{\"format_version\":1}", b"\xff\xfe"] {
        bad.set(Arc::new({
            let body = body.to_vec();
            move |_: &Seen| Answer::Json(body.clone())
        }));
        let row = switch_to(
            &rig,
            "bad",
            &bad,
            Arc::new({
                let body = body.to_vec();
                move |_: &Seen| Answer::Json(body.clone())
            }),
            "malformed",
        )
        .await;
        assert_eq!(row["state"], "stale");
    }
}

#[tokio::test]
async fn federation_hostile_peer_unordered_pages() {
    let pki = Pki::new();
    let unordered = peer(&pki, custom(status_doc(1), |_| {
        json_answer(&json!({"format_version": 1, "snapshot_version": 1, "total": 2,
            "items": [item("acme", "b", "1", "stable"), item("acme", "a", "1", "stable")], "truncated": false}))
    }))
    .await;
    let rig = Rig::start(pki, &[("unordered", unordered.url())], Opts::default()).await;
    assert_eq!(
        rig.wait_error("unordered").await["error"]["class"],
        "malformed"
    );
}

#[tokio::test]
async fn federation_hostile_peer_duplicate_keys() {
    let pki = Pki::new();
    let dup = peer(&pki, custom(status_doc(1), |_| {
        json_answer(&json!({"format_version": 1, "snapshot_version": 1, "total": 2,
            "items": [item("acme", "a", "1", "stable"), item("acme", "a", "1", "deprecated")], "truncated": false}))
    }))
    .await;
    let across = peer(
        &pki,
        custom(status_doc(1), |seen| {
            // The second page starts at the cursor's own key: a repeat across pages.
            let after = seen.query.get("after").cloned();
            let items = [item("acme", "a", "1", "stable")];
            json_answer(
                &json!({"format_version": 1, "snapshot_version": 1, "total": 2, "items": items,
            "truncated": true, "next": "acme/a/1", "after": after}),
            )
        }),
    )
    .await;
    let rig = Rig::start(
        pki,
        &[("dup", dup.url()), ("across", across.url())],
        Opts::default(),
    )
    .await;
    assert_eq!(rig.wait_error("dup").await["error"]["class"], "malformed");
    assert_eq!(
        rig.wait_error("across").await["error"]["class"],
        "malformed"
    );
}

#[tokio::test]
async fn federation_hostile_peer_no_progress() {
    let pki = Pki::new();
    let empty = peer(&pki, custom(status_doc(1), |_| {
        json_answer(&json!({"format_version": 1, "snapshot_version": 1, "total": 5, "items": [], "truncated": true, "next": "acme/a/1"}))
    }))
    .await;
    let rig = Rig::start(pki, &[("empty", empty.url())], Opts::default()).await;
    assert_eq!(rig.wait_error("empty").await["error"]["class"], "malformed");
    let catalog_requests = empty
        .seen()
        .iter()
        .filter(|s| s.path.ends_with("catalog"))
        .count();
    assert!(
        catalog_requests <= 4 * 3,
        "the hub gives up at once, not after a thousand pages"
    );
}

#[tokio::test]
async fn federation_hostile_peer_lies_about_next() {
    let pki = Pki::new();
    let liar = peer(
        &pki,
        custom(status_doc(1), |_| {
            json_answer(
                &json!({"format_version": 1, "snapshot_version": 1, "total": 3,
            "items": [item("acme", "a", "1", "stable")], "truncated": true,
            "next": "../../etc/passwd?x=1&after=zzz"}),
            )
        }),
    )
    .await;
    let rig = Rig::start(pki, &[("liar", liar.url())], Opts::default()).await;
    assert_eq!(rig.wait_error("liar").await["error"]["class"], "malformed");
    for seen in liar.seen() {
        assert!(
            seen.path.starts_with("/federation/v1/")
                && !seen.target.contains("passwd")
                && !seen.target.contains("zzz"),
            "the hub never repeats the peer's cursor: {}",
            seen.target
        );
    }
}

#[tokio::test]
async fn federation_hostile_peer_cannot_rename() {
    let pki = Pki::new();
    let b_items = items("b-tenant", &["real"]);
    let b = peer(&pki, catalog_script(b_items, 1)).await;
    let a_script: Script = {
        let good = catalog_script(vec![], 1);
        Arc::new(move |seen: &Seen| {
            if seen.path.ends_with("/status") {
                let Answer::Json(body) = good(seen) else {
                    unreachable!()
                };
                let mut doc: Value = serde_json::from_slice(&body).unwrap();
                doc["cluster"] = json!("b");
                return Answer::Status(
                    200,
                    vec![
                        ("content-type".into(), "application/json".into()),
                        ("x-cluster".into(), "b".into()),
                    ],
                    doc.to_string().into_bytes(),
                );
            }
            let mut entry = item("b-tenant", "real", "1", "retired");
            entry["cluster"] = json!("b");
            entry["stale"] = json!(false);
            entry["total"] = json!(99);
            Answer::Status(200, vec![("content-type".into(), "application/json".into()), ("x-cluster".into(), "b".into())],
                json!({"format_version": 1, "snapshot_version": 1, "total": 1, "cluster": "b", "items": [entry], "truncated": false}).to_string().into_bytes())
        })
    };
    let a = peer(&pki, a_script).await;
    let rig = Rig::start(pki, &[("a", a.url()), ("b", b.url())], Opts::default()).await;
    rig.wait_state("a", "fresh").await;
    rig.wait_state("b", "fresh").await;
    let b_only = rig.catalog("cluster=b").await;
    assert_eq!(b_only["total"], 1);
    assert_eq!(
        b_only["items"][0]["lifecycle"], "stable",
        "b's entry is b's, not what a claimed"
    );
    let a_only = rig.catalog("cluster=a").await;
    assert_eq!(
        a_only["items"][0]["cluster"], "a",
        "a's rows carry a's name from the file"
    );
    assert_eq!(a_only["items"][0]["stale"], false);
    let all = rig.catalog("limit=10").await;
    assert_eq!(all["total"], 2);
    let text = all.to_string();
    assert_eq!(text.matches("\"cluster\":\"b\"").count(), 1, "{text}");
}

#[tokio::test]
async fn federation_peer_text_as_text() {
    let pki = Pki::new();
    let mut entry = item("acme", "xss", "1", "stable");
    entry["title"] = json!("<script>alert(1)</script>");
    entry["description"] = json!("<img src=x onerror=alert(1)>\n\"quoted\"");
    let evil = peer(&pki, catalog_script(vec![entry], 1)).await;
    let rig = Rig::start(pki, &[("evil", evil.url())], Opts::default()).await;
    rig.wait_state("evil", "fresh").await;
    let got = rig.get("/v1/catalog").await;
    assert_eq!(got.status, 200);
    assert_eq!(
        got.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        got.header("x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(
        got.header("content-security-policy").as_deref(),
        Some("default-src 'none'; sandbox")
    );
    let doc = got.json();
    assert_eq!(doc["items"][0]["title"], "<script>alert(1)</script>");
    assert_eq!(
        doc["items"][0]["description"],
        "<img src=x onerror=alert(1)>\n\"quoted\""
    );
    assert!(!got.head.to_lowercase().contains("text/html"));
}

#[tokio::test]
async fn federation_peer_version_flip_is_unstable() {
    let pki = Pki::new();
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
    let flip = peer(
        &pki,
        custom(status_doc(1), move |_| {
            let version = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            json_answer(
                &json!({"format_version": 1, "snapshot_version": version, "total": 2,
            "items": [item("acme", &format!("a{version}"), "1", "stable")], "truncated": true,
            "next": format!("acme/a{version}/1")}),
            )
        }),
    )
    .await;
    let rig = Rig::start(pki, &[("flip", flip.url())], Opts::default()).await;
    assert_eq!(rig.wait_error("flip").await["error"]["class"], "unstable");
}

#[tokio::test]
async fn federation_only_gets() {
    let pki = Pki::new();
    let many: Vec<Value> = (0..250)
        .map(|n| item("acme", &format!("id{n:03}"), "1", "stable"))
        .collect();
    let eu = peer(&pki, catalog_script(many, 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    assert_eq!(rig.catalog("limit=1").await["total"], 250);
    let seen = eu.seen();
    assert!(seen.len() >= 4, "status and three catalog pages at least");
    for request in &seen {
        assert_eq!(request.method, "GET", "{}", request.target);
        let allowed = request.target == "/federation/v1/status"
            || request
                .target
                .starts_with("/federation/v1/catalog?limit=100");
        assert!(allowed, "an unexpected target {}", request.target);
        let params: Vec<&String> = request.query.keys().collect();
        assert!(
            params
                .iter()
                .all(|k| matches!(k.as_str(), "limit" | "after")),
            "{params:?}"
        );
    }
    // Filters of a reader of the view never reach a peer.
    let before = eu.seen().len();
    rig.catalog("tenant=zzz&cluster=eu&lifecycle=retired").await;
    assert!(
        eu.seen()
            .iter()
            .skip(before)
            .all(|s| s.query.keys().all(|k| k == "limit" || k == "after"))
    );
}

#[tokio::test]
async fn federation_view_requires_client_cert() {
    let pki = Pki::new();
    let rogue = Pki::new();
    let eu = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    let addr = rig.hub.view_addr();
    let anon = anonymous_client(&rig.pki, &rig.dir);
    assert!(
        request(addr, anon, "GET", "/v1/clusters", "")
            .await
            .is_err(),
        "no certificate"
    );
    let wrong = client_config(&rogue, &rig.dir, "rogue");
    // The server's CA is not the rogue's, so the client also refuses the server; trust ours.
    let rogue_with_ours = {
        let (cert, key) = rogue.client_files(&rig.dir.0, "rogue2");
        let ca = rig.pki.ca_file(&rig.dir.0, "trust-ours");
        podgate_federation::tls::Identity::load("t", &cert, &key)
            .unwrap()
            .client_config("t", podgate_federation::tls::roots("t", &ca).unwrap())
            .unwrap()
    };
    let _ = wrong;
    assert!(
        request(addr, rogue_with_ours, "GET", "/v1/clusters", "")
            .await
            .is_err(),
        "a certificate of another CA"
    );
    assert_eq!(
        rig.get("/v1/clusters").await.status,
        200,
        "the right certificate works"
    );
}

#[tokio::test]
async fn federation_view_methods_405() {
    let pki = Pki::new();
    let eu = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    let addr = rig.hub.view_addr();
    for path in ["/v1/catalog", "/v1/clusters"] {
        for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let got = request(addr, rig.op.clone(), method, path, "")
                .await
                .unwrap();
            assert_eq!(got.status, 405, "{method} {path}");
            assert_eq!(got.header("allow").as_deref(), Some("GET"));
        }
    }
    for path in [
        "/",
        "/v1",
        "/v1/snapshot",
        "/v1/events",
        "/healthz",
        "/v1/catalog/",
        "/federation/v1/status",
    ] {
        for method in ["GET", "POST"] {
            let got = request(addr, rig.op.clone(), method, path, "")
                .await
                .unwrap();
            assert_eq!(got.status, 404, "{method} {path}");
            assert_eq!(got.json(), json!({"error": "not found"}));
        }
    }
    let with_body = request(
        addr,
        rig.op.clone(),
        "GET",
        "/v1/clusters",
        "Content-Length: 4\r\n",
    )
    .await
    .unwrap();
    assert_eq!(with_body.status, 400);
    assert!(
        eu.seen().iter().all(|s| s.method == "GET"),
        "a reader's POST never reaches a peer"
    );
}

#[tokio::test]
async fn federation_view_headers() {
    let pki = Pki::new();
    let eu = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    let addr = rig.hub.view_addr();
    let mut answers = vec![
        rig.get("/v1/catalog").await,
        rig.get("/v1/clusters").await,
        rig.get("/v1/catalog?limit=0").await,
        rig.get("/nowhere").await,
    ];
    answers.push(
        request(addr, rig.op.clone(), "POST", "/v1/catalog", "")
            .await
            .unwrap(),
    );
    let statuses: Vec<u16> = answers.iter().map(|a| a.status).collect();
    assert_eq!(statuses, [200, 200, 400, 404, 405]);
    for got in answers {
        assert_eq!(
            got.header("content-type").as_deref(),
            Some("application/json"),
            "{}",
            got.status
        );
        assert_eq!(
            got.header("x-content-type-options").as_deref(),
            Some("nosniff")
        );
        assert_eq!(
            got.header("content-security-policy").as_deref(),
            Some("default-src 'none'; sandbox")
        );
        assert_eq!(
            got.header("referrer-policy").as_deref(),
            Some("no-referrer")
        );
        assert_eq!(got.header("cache-control").as_deref(), Some("no-store"));
    }
}

#[tokio::test]
async fn federation_hostile_peer_long_strings() {
    let pki = Pki::new();
    let mut long_title = item("acme", "a", "1", "stable");
    long_title["title"] = json!("t".repeat(100_000));
    long_title["description"] = json!("d".repeat(100_000));
    long_title["hosts"] = json!((0..500).map(|n| format!("h{n}.test")).collect::<Vec<_>>());
    let mut long_key = item("acme", "b", "1", "stable");
    long_key["id"] = json!("i".repeat(10_000));
    let mut control = item("acme", "c", "1", "stable");
    control["title"] = json!("\u{1b}[2Jgotcha");
    let mut long_tenant = item("zz", "d", "1", "stable");
    long_tenant["tenant"] = json!("z".repeat(500));
    let mut fine = item("acme", "e", "1", "stable");
    fine["lifecycle"] = json!("from-the-future");
    let hostile = peer(
        &pki,
        catalog_script(vec![long_title, long_key, control, long_tenant, fine], 1),
    )
    .await;
    let rig = Rig::start(pki, &[("hostile", hostile.url())], Opts::default()).await;
    let row = rig.wait_state("hostile", "fresh").await;
    assert_eq!(row["entries"], 2, "only the two that break no rule: {row}");
    assert_eq!(row["dropped"], 3);
    let catalog = rig.catalog("limit=10").await;
    let title = catalog["items"][0]["title"].as_str().unwrap();
    assert_eq!(title.len(), 256, "display text is cut");
    assert!(catalog["items"][0]["description"].as_str().unwrap().len() <= 2048);
    assert_eq!(catalog["items"][0]["hosts"].as_array().unwrap().len(), 64);
    assert_eq!(
        catalog["items"][1]["lifecycle"], "unknown",
        "a stage the hub does not know"
    );
    assert_eq!(rig.catalog("lifecycle=unknown").await["total"], 1);
}

#[tokio::test]
async fn federation_files_are_read_once() {
    let pki = Pki::new();
    let eu = peer(&pki, catalog_script(items("acme", &["a"]), 1)).await;
    let rig = Rig::start(pki, &[("eu", eu.url())], Opts::default()).await;
    rig.wait_state("eu", "fresh").await;
    for entry in std::fs::read_dir(&rig.dir.0).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() && path.extension().is_none_or(|e| e != "sock") {
            std::fs::remove_file(path).unwrap();
        }
    }
    let before = rig.row("eu").await["last_attempt"].as_u64().unwrap();
    eventually("pulls continue without the files", || async {
        rig.row("eu").await["last_attempt"].as_u64().unwrap() > before
    })
    .await;
    assert_eq!(rig.row("eu").await["state"], "fresh");
    assert_eq!(
        rig.get("/v1/clusters").await.status,
        200,
        "the view keeps its certificate"
    );
}
