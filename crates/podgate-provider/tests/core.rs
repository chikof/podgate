//! Black-box tests of the provider core: merge, trust, upstream policy, push, quarantine and the
//! real daemon. Everything that waits has a deadline (see `common`).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{
    AppExt, FakeAdmin, Harness, Reply, app, app_ids, app_with, certificate, config, conflict,
    socket_path, unattributed,
};
use podgate_provider::push::{Backoff, Debounce};
use podgate_provider::quarantine::{self, BisectError, Validate, Verdict, bisect_bound};
use podgate_provider::source::{ObjectKind, ObjectRef, State};
use podgate_provider::{Merged, Merger, RunError, SourceApp, UpstreamPolicy};
use serde_json::{Value, json};

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
weight = 4
hosts = ["acme.test", "*.acme.test"]
label_sources = ["local"]

[[tenant]]
id = "globex"
hosts = ["globex.test"]

[[source]]
kind = "docker"
name = "local"

[[source]]
kind = "kubernetes"
name = "k8s"
"#;

fn merger(extra: &str) -> Merger {
    merger_with(extra, UpstreamPolicy::builtin())
}

fn merger_with(extra: &str, policy: UpstreamPolicy) -> Merger {
    Merger::new(&config(Path::new("/nonexistent/admin.sock"), extra), policy)
}

fn states(entries: Vec<(&str, Vec<SourceApp>)>) -> BTreeMap<Box<str>, State> {
    entries
        .into_iter()
        .map(|(source, apps)| {
            (
                Box::from(source),
                State {
                    apps,
                    certificates: Vec::new(),
                },
            )
        })
        .collect()
}

fn merge(merger: &Merger, entries: Vec<(&str, Vec<SourceApp>)>) -> Merged {
    merger.merge(&states(entries), &BTreeSet::new())
}

fn ids(merged: &Merged) -> Vec<String> {
    merged
        .snapshot()
        .apps
        .iter()
        .map(|app| app.id.to_string())
        .collect()
}

fn findings(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn tenant_of<'a>(merged: &'a Merged, id: &str) -> &'a str {
    merged
        .snapshot()
        .apps
        .iter()
        .find(|app| &*app.id == id)
        .map(|app| &*app.tenant)
        .unwrap_or_else(|| panic!("app {id} is not in the snapshot: {:?}", ids(merged)))
}

const UP: &str = "http://10.0.0.5:8080";

// ---- merge -----------------------------------------------------------------------------------

#[test]
fn merge_is_deterministic() {
    let merger = merger(TENANTS);
    let web = || app("local", "web", &["x.acme.test"], UP).mapped("acme");
    let api = || app("local", "api", &["api.acme.test"], UP).mapped("acme");
    let free = || app("k8s", "web", &["free.test"], UP);

    let first = merge(
        &merger,
        vec![("local", vec![web(), api()]), ("k8s", vec![free()])],
    );
    let second = merge(
        &merger,
        vec![("k8s", vec![free()]), ("local", vec![api(), web()])],
    );
    assert_eq!(first.body(3), second.body(3));
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(first.findings(), second.findings());
    assert_eq!(first.snapshot().version, 0, "the push owns the version");
    assert_eq!(ids(&first), ["k8s-web", "local-api", "local-web"]);

    let body = first.body(3);
    assert!(body.contains("\"version\":3"), "{body}");
    assert!(
        body.find("\"apps\"") < body.find("\"tenants\""),
        "top-level keys are sorted: {body}"
    );
    assert!(
        body.find("\"declared_by\"") < body.find("\"id\""),
        "keys of every object are sorted: {body}"
    );

    let changed = merge(&merger, vec![("local", vec![web()]), ("k8s", vec![free()])]);
    assert_ne!(first.fingerprint(), changed.fingerprint());
}

#[test]
fn merge_sets_declared_by() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![
            (
                "local",
                vec![app("local", "web-1", &["x.acme.test"], UP).mapped("acme")],
            ),
            ("k8s", vec![app("k8s", "shop/web", &["free.test"], UP)]),
        ],
    );
    let by_id: BTreeMap<&str, &str> = merged
        .snapshot()
        .apps
        .iter()
        .map(|app| (&*app.id, &*app.declared_by))
        .collect();
    assert_eq!(by_id["local-web-1"], "docker/local:web-1");
    assert_eq!(by_id["k8s-shop-web"], "kubernetes/k8s:shop/web");
    let included: Vec<&str> = merged
        .included()
        .iter()
        .map(|included| &*included.declared_by)
        .collect();
    assert_eq!(included.len(), 2);
    assert!(included.contains(&"docker/local:web-1"));
}

#[test]
fn app_id_collision_prefixed() {
    let merger = merger(TENANTS);
    // The same local id in two sources never collides: the source name prefixes it.
    let merged = merge(
        &merger,
        vec![
            ("local", vec![app("local", "web", &["a.test"], UP)]),
            ("k8s", vec![app("k8s", "web", &["b.test"], UP)]),
        ],
    );
    assert_eq!(ids(&merged), ["k8s-web", "local-web"]);
    assert!(merged.findings().is_empty());

    // Different (source, id) pairs can still spell one id: the older object keeps it.
    let two = format!(
        "{TENANTS}\n[[source]]\nkind = \"file\"\nname = \"a\"\n[[source]]\nkind = \"file\"\nname = \"a-b\"\n"
    );
    let merger = self::merger(&two);
    let merged = merge(
        &merger,
        vec![
            ("a", vec![app("a", "b-c", &["old.test"], UP).first_seen(5)]),
            (
                "a-b",
                vec![app("a-b", "c", &["new.test"], UP).first_seen(9)],
            ),
        ],
    );
    assert_eq!(ids(&merged), ["a-b-c"]);
    assert_eq!(merged.snapshot().apps[0].declared_by.as_ref(), "file/a:b-c");
    assert_eq!(findings(&merged), [("app_id_collision", "c".to_owned())]);
    let swapped = merge(
        &merger,
        vec![
            ("a", vec![app("a", "b-c", &["old.test"], UP).first_seen(9)]),
            (
                "a-b",
                vec![app("a-b", "c", &["new.test"], UP).first_seen(5)],
            ),
        ],
    );
    assert_eq!(
        swapped.snapshot().apps[0].declared_by.as_ref(),
        "file/a-b:c",
        "the older object wins whichever source sent it"
    );
}

#[test]
fn unknown_tenant_rejected() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![(
            "local",
            vec![
                app("local", "typo", &["free.test"], UP).mapped("acmee"),
                app("local", "labelled", &["free2.test"], UP).labelled("nobody"),
                app("local", "fine", &["free3.test"], UP),
            ],
        )],
    );
    assert_eq!(
        ids(&merged),
        ["local-fine"],
        "a typo must not default to another tenant"
    );
    assert_eq!(
        findings(&merged),
        [
            ("unknown_tenant", "labelled".to_owned()),
            ("unknown_tenant", "typo".to_owned())
        ]
    );
    assert!(merged.findings().iter().all(|finding| finding.dropped));
}

#[test]
fn default_tenant_budget_from_config() {
    let merger = merger(&format!(
        "[default_tenant]\nweight = 3\nbudget = {{ max_inflight = 10, max_buffer_bytes = 2048 }}\n{TENANTS}"
    ));
    let merged = merge(&merger, vec![("local", vec![])]);
    let tenants: BTreeMap<&str, (u32, u32, u64)> = merged
        .snapshot()
        .tenants
        .iter()
        .map(|t| {
            (
                &*t.id,
                (t.weight, t.budget.max_inflight, t.budget.max_buffer_bytes),
            )
        })
        .collect();
    assert_eq!(tenants["default"], (3, 10, 2048));
    assert_eq!(
        tenants["acme"],
        (4, 256, 64 * 1024 * 1024),
        "defaults for what the config leaves out"
    );
    assert_eq!(tenants["globex"].0, 1);
    assert_eq!(tenants.len(), 3);
}

// ---- trust -----------------------------------------------------------------------------------

#[test]
fn tenant_cannot_claim_foreign_host() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![(
            "local",
            vec![
                app("local", "own", &["acme.test", "shop.acme.test"], UP).mapped("acme"),
                app("local", "foreign", &["globex.test"], UP).mapped("acme"),
                app("local", "mixed", &["shop.acme.test", "globex.test"], UP).mapped("acme"),
                app("local", "wild", &["*.globex.test"], UP).mapped("acme"),
                app("local", "deep", &["a.b.acme.test"], UP).mapped("acme"),
                app_with(
                    "local",
                    "nested",
                    json!({ "all": [{ "any": [{ "host": "globex.test" }, { "host": "acme.test" }] }, { "path_prefix": "/" }] }),
                    UP,
                )
                .mapped("acme"),
            ],
        )],
    );
    assert_eq!(ids(&merged), ["local-own"]);
    let dropped: Vec<_> = findings(&merged);
    for object in ["foreign", "mixed", "wild", "deep", "nested"] {
        assert!(
            dropped.contains(&("foreign_host_claim", object.to_owned())),
            "{object} must be dropped: {dropped:?}"
        );
    }
    let message = merged
        .findings()
        .iter()
        .find(|finding| &*finding.object == "foreign")
        .map(|finding| finding.message.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("globex.test") && message.contains("acme"),
        "{message}"
    );
}

#[test]
fn default_tenant_cannot_claim_other_tenants_hosts() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![(
            "k8s",
            vec![
                app("k8s", "exact", &["globex.test"], UP),
                app("k8s", "under", &["shop.acme.test"], UP),
                app("k8s", "wild", &["*.acme.test"], UP),
                app("k8s", "apex", &["acme.test"], UP),
            ],
        )],
    );
    assert_eq!(
        ids(&merged),
        Vec::<String>::new(),
        "{:?}",
        findings(&merged)
    );
    assert_eq!(merged.findings().len(), 4);
    assert!(
        merged
            .findings()
            .iter()
            .all(|f| f.code == "foreign_host_claim")
    );
}

#[test]
fn default_tenant_can_claim_unclaimed_host() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![(
            "k8s",
            vec![app("k8s", "free", &["free.test", "*.free.test"], UP)],
        )],
    );
    assert_eq!(ids(&merged), ["k8s-free"]);
    assert_eq!(tenant_of(&merged, "k8s-free"), "default");
    assert!(merged.findings().is_empty());
}

#[test]
fn label_tenant_requires_label_sources() {
    let merger = merger(TENANTS);
    // `local` is listed in acme's label_sources, `k8s` is not.
    let merged = merge(
        &merger,
        vec![
            (
                "local",
                vec![app("local", "trusted", &["shop.acme.test"], UP).labelled("acme")],
            ),
            (
                "k8s",
                vec![app("k8s", "spoof", &["shop2.acme.test"], UP).labelled("acme")],
            ),
        ],
    );
    assert_eq!(ids(&merged), ["local-trusted"]);
    assert_eq!(tenant_of(&merged, "local-trusted"), "acme");
    assert_eq!(
        findings(&merged),
        [
            ("label_ignored", "spoof".to_owned()),
            ("foreign_host_claim", "spoof".to_owned())
        ],
        "the label is ignored, so the object is the default tenant's and its host is foreign"
    );

    // An ignored label leaves the source's own mapping in force, and a host of its own works.
    let merged = merge(
        &merger,
        vec![(
            "k8s",
            vec![
                app("k8s", "mapped", &["globex.test"], UP)
                    .mapped("globex")
                    .labelled("acme"),
                app("k8s", "free", &["free.test"], UP).labelled("acme"),
            ],
        )],
    );
    assert_eq!(tenant_of(&merged, "k8s-mapped"), "globex");
    assert_eq!(tenant_of(&merged, "k8s-free"), "default");
    assert_eq!(
        merged
            .findings()
            .iter()
            .filter(|f| f.code == "label_ignored")
            .count(),
        2
    );

    // A source that may label for acme still cannot label for globex, which does not list it.
    let merged = merge(
        &merger,
        vec![(
            "local",
            vec![app("local", "x", &["globex.test"], UP).labelled("globex")],
        )],
    );
    assert!(ids(&merged).is_empty());
}

#[test]
fn label_spoofing_cannot_claim_other_tenants_host() {
    let merger = merger(TENANTS);
    // A user-set label on an object of an untrusted source, aimed at every tenant's hosts.
    let merged = merge(
        &merger,
        vec![(
            "k8s",
            vec![
                app("k8s", "a", &["acme.test"], UP).labelled("acme"),
                app("k8s", "b", &["globex.test"], UP).labelled("globex"),
                app("k8s", "c", &["globex.test"], UP).labelled("acme"),
                app("k8s", "d", &["*.acme.test"], UP).labelled("default"),
            ],
        )],
    );
    assert!(ids(&merged).is_empty(), "{:?}", findings(&merged));
}

#[test]
fn certificate_hosts_follow_the_trust_rule() {
    let merger = merger(TENANTS);
    let state = State {
        apps: Vec::new(),
        certificates: vec![
            {
                let mut own = certificate("local", "own", &["shop.acme.test"]);
                own.tenant = podgate_provider::TenantClaim::mapped("acme");
                own
            },
            certificate("local", "foreign", &["acme.test"]),
            certificate("local", "free", &["free.test"]),
        ],
    };
    let mut by_source = BTreeMap::new();
    by_source.insert(Box::from("local"), state);
    let merged = merger.merge(&by_source, &BTreeSet::new());
    let hosts: Vec<String> = merged
        .snapshot()
        .certificates
        .iter()
        .map(|cert| cert.hosts.join(","))
        .collect();
    assert_eq!(hosts, ["free.test", "shop.acme.test"]);
    assert_eq!(
        findings(&merged),
        [("foreign_host_claim", "foreign".to_owned())]
    );
}

#[test]
fn catch_all_needs_an_exclusive_entry_point_or_the_operator() {
    let extra = format!(
        "[[tenant]]\nid = \"wide\"\nhosts = [\"wide.test\"]\ncatch_all = true\n\n[[tenant]]\nid = \"alone\"\nhosts = [\"alone.test\"]\nexclusive_entry_points = [\"private\"]\n\n{TENANTS}"
    );
    let merger = merger(&extra);
    let regexp = || json!({ "host_regexp": "^.*\\.example$" });
    let narrowed = json!({ "all": [{ "host": "alone.test" }, { "host_regexp": "^x" }] });
    let mut on_private = app_with("local", "private", regexp(), UP).mapped("alone");
    on_private.app.routers[0].entry_points = Some(vec!["private".into()]);
    let mut on_mixed = app_with("local", "mixed", regexp(), UP).mapped("alone");
    on_mixed.app.routers[0].entry_points = Some(vec!["private".into(), "web".into()]);
    let merged = merge(
        &merger,
        vec![(
            "local",
            vec![
                app_with("local", "regexp", regexp(), UP).mapped("acme"),
                app_with("local", "hostless", json!({ "path_prefix": "/" }), UP).mapped("acme"),
                app_with(
                    "local",
                    "negated",
                    json!({ "not": { "host": "x.test" } }),
                    UP,
                )
                .mapped("acme"),
                app_with("local", "narrowed", narrowed, UP).mapped("alone"),
                app_with("local", "wide", regexp(), UP).mapped("wide"),
                on_private,
                on_mixed,
            ],
        )],
    );
    assert_eq!(
        ids(&merged),
        ["local-narrowed", "local-private", "local-wide"]
    );
    for object in ["regexp", "hostless", "negated", "mixed"] {
        assert!(
            findings(&merged).contains(&("catch_all_not_allowed", object.to_owned())),
            "{object}: {:?}",
            findings(&merged)
        );
    }
    let snapshot = merged.snapshot();
    let policy = snapshot
        .entry_points
        .iter()
        .find(|entry| &*entry.name == "private")
        .expect("the exclusive entry point reaches the snapshot");
    assert_eq!(policy.tenants.as_deref(), Some(&["alone".into()][..]));
}

#[test]
fn invalid_matchers_are_dropped_not_guessed() {
    let merger = merger(TENANTS);
    let merged = merge(
        &merger,
        vec![(
            "k8s",
            vec![
                app_with(
                    "k8s",
                    "two-keys",
                    json!({ "host": "a.test", "path": "/" }),
                    UP,
                ),
                app_with("k8s", "unknown", json!({ "hostname": "a.test" }), UP),
                app_with("k8s", "bad-host", json!({ "host": "not a host" }), UP),
                app_with("k8s", "empty-all", json!({ "all": [] }), UP),
            ],
        )],
    );
    assert!(ids(&merged).is_empty());
    assert_eq!(
        findings(&merged)
            .iter()
            .map(|(code, _)| *code)
            .collect::<Vec<_>>(),
        [
            "invalid_host",
            "invalid_matcher",
            "invalid_matcher",
            "invalid_matcher"
        ]
    );
}

// ---- upstream policy -------------------------------------------------------------------------

#[test]
fn upstream_outside_allowlist_rejected() {
    let policy = UpstreamPolicy::parse(r#"{"tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#)
        .expect("policy");
    let merger = merger_with(TENANTS, policy);
    let mut in_revision =
        app("local", "revision", &["r.acme.test"], "http://10.4.0.9:80").mapped("acme");
    in_revision.app.revisions[0].services = serde_json::from_value(json!([
        { "name": "svc", "type": "loadbalancer", "servers": [{ "url": "http://10.5.0.9:80" }] }
    ]))
    .expect("services");
    let merged = merge(
        &merger,
        vec![(
            "local",
            vec![
                app("local", "ok", &["ok.acme.test"], "http://10.4.0.1:80").mapped("acme"),
                app("local", "outside", &["out.acme.test"], "http://10.5.0.1:80").mapped("acme"),
                app(
                    "local",
                    "loopback",
                    &["lo.acme.test"],
                    "http://127.0.0.1:80",
                )
                .mapped("acme"),
                app(
                    "local",
                    "metadata",
                    &["md.acme.test"],
                    "http://[::ffff:169.254.169.254]:80",
                )
                .mapped("acme"),
                app(
                    "local",
                    "named",
                    &["named.acme.test"],
                    "http://backend.internal:80",
                )
                .mapped("acme"),
                in_revision,
                app(
                    "local",
                    "default-tenant",
                    &["free.test"],
                    "http://10.5.0.1:80",
                ),
            ],
        )],
    );
    assert_eq!(
        ids(&merged),
        ["local-default-tenant", "local-named", "local-ok"]
    );
    let forbidden: Vec<String> = findings(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "upstream_forbidden")
        .map(|(_, object)| object)
        .collect();
    assert_eq!(forbidden, ["loopback", "metadata", "outside", "revision"]);
    let message = merged
        .findings()
        .iter()
        .find(|finding| &*finding.object == "outside")
        .map(|finding| finding.message.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("10.5.0.1") && message.contains("tenant acme"),
        "{message}"
    );
}

#[test]
fn policy_shared_vectors() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/upstream_policy_cases.json"))
        .expect("the fixture is JSON");
    let mut checked = 0;
    for case in fixture["cases"].as_array().expect("cases") {
        let name = case["name"].as_str().unwrap_or("?");
        let policy = if case["policy"].is_null() {
            UpstreamPolicy::builtin()
        } else {
            UpstreamPolicy::parse(&case["policy"].to_string())
                .unwrap_or_else(|err| panic!("{name}: {err}"))
        };
        let tenant = case["tenant"].as_str().expect("tenant");
        let list = |key: &str| -> Vec<&str> {
            case[key]
                .as_array()
                .map(|list| list.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default()
        };
        for address in list("allowed") {
            let ip = address.parse().expect("address");
            assert!(
                policy.evaluate(tenant, ip).is_ok(),
                "{name}: {address} must be allowed"
            );
            checked += 1;
        }
        for address in list("refused") {
            let ip = address.parse().expect("address");
            let refused = policy
                .evaluate(tenant, ip)
                .expect_err(&format!("{name}: {address} must be refused"));
            if let Some(rule) = case["rules"][address].as_str() {
                assert_eq!(refused.rule(), rule, "{name}: {address}");
            }
            checked += 1;
        }
    }
    assert!(checked > 60, "the vectors ran: {checked}");
    for invalid in fixture["invalid_files"].as_array().expect("invalid_files") {
        let json = invalid["json"].as_str().expect("json");
        let err = UpstreamPolicy::parse(json).expect_err(json);
        assert_eq!(
            &*err.entry,
            invalid["entry"].as_str().expect("entry"),
            "{json}: {err}"
        );
    }
}

// ---- debounce and backoff on a fake clock ----------------------------------------------------

#[test]
fn updates_within_window_coalesce() {
    let mut debounce = Debounce::new(100, 1000);
    assert_eq!(debounce.deadline(), None);
    assert!(!debounce.due(5000), "nothing pending, nothing due");

    // Five updates, 30 ms apart: one push, 100 ms after the last.
    let mut fired = Vec::new();
    for now in 0..=400u64 {
        if now % 30 == 0 && now <= 120 {
            debounce.note(now);
        }
        if debounce.due(now) {
            fired.push(now);
        }
    }
    assert_eq!(
        fired,
        [220],
        "one push, a window after the last update (at 120)"
    );

    // An update inside the window moves the deadline; an update after the push starts a new burst.
    debounce.note(1000);
    assert!(!debounce.due(1099));
    debounce.note(1099);
    assert!(!debounce.due(1100));
    assert!(debounce.due(1199));
    assert!(!debounce.due(1400), "the burst is over");
}

#[test]
fn max_delay_bounds_debounce() {
    let mut debounce = Debounce::new(100, 300);
    let mut fired = Vec::new();
    for now in 0..=1000u64 {
        // A steady stream: an update every 50 ms, never quiet for the 100 ms window.
        if now % 50 == 0 {
            debounce.note(now);
        }
        if debounce.due(now) {
            fired.push(now);
        }
    }
    assert_eq!(
        fired,
        [300, 650, 1000],
        "a push is never later than max_delay after the first update of its burst"
    );
    // With max_delay below the window the window is the bound.
    let mut tight = Debounce::new(100, 10);
    tight.note(0);
    assert_eq!(tight.deadline(), Some(100));
}

#[test]
fn backoff_runs_from_one_to_thirty_seconds() {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    let delays: Vec<u64> = (0..8).map(|_| backoff.next_delay().as_secs()).collect();
    assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
}

// ---- push ------------------------------------------------------------------------------------

const FAST: &str = "debounce_ms = 20\nmax_delay_ms = 200\n";

#[tokio::test]
async fn versions_strictly_increase() {
    let admin = FakeAdmin::start();
    admin.someone_else_pushed(41);
    let mut h = Harness::start_with(admin, FAST, &["one", "two"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    // The live snapshot is not replaced until every source has spoken.
    h.source("two").apps(vec![app("two", "b", &["b.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("first push", |puts| !puts.is_empty())
        .await;
    assert_eq!(
        puts[0].version, 42,
        "the live version plus one, across all sources"
    );
    assert_eq!(puts[0].writer.as_deref(), Some("podgate-provider"));
    assert_eq!(app_ids(&puts[0].body), ["one-a", "two-b"]);

    h.source("two")
        .apps(vec![app("two", "b", &["b2.test"], UP)]);
    h.source("one").apps(vec![
        app("one", "a", &["a.test"], UP),
        app("one", "c", &["c.test"], UP),
    ]);
    let puts = h
        .admin
        .wait_puts("second push", |puts| puts.len() >= 2)
        .await;
    h.source("two").apps(vec![]);
    let puts_after = h
        .admin
        .wait_puts("third push", |puts| puts.len() >= 3)
        .await;
    let versions: Vec<u64> = puts_after.iter().map(|put| put.version).collect();
    assert_eq!(versions, [42, 43, 44]);
    assert!(puts.len() >= 2);
    let status = h
        .wait_status("three pushes", |status| status.pushes == 3)
        .await;
    assert_eq!(status.pushed_version, Some(44));
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn unchanged_snapshot_not_pushed() {
    let h = Harness::start(FAST, &["one"]);
    let state = || vec![app("one", "a", &["a.test"], UP)];
    h.source("one").apps(state());
    h.admin
        .wait_puts("first push", |puts| puts.len() == 1)
        .await;
    // The same state again, and an outage report, change nothing.
    h.source("one").apps(state());
    h.source("one").outage("flaky");
    h.source("one").apps(state());
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        h.admin.puts().len(),
        1,
        "an unchanged snapshot is not pushed"
    );
    assert_eq!(h.admin.attempts().len(), 1);

    h.source("one")
        .apps(vec![app("one", "a", &["a.test", "a2.test"], UP)]);
    h.admin
        .wait_puts("changed state", |puts| puts.len() == 2)
        .await;
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn engine_coalesces_updates_into_one_push() {
    let h = Harness::start("debounce_ms = 300\nmax_delay_ms = 5000\n", &["one"]);
    for round in 0..5 {
        h.source("one")
            .apps(vec![app("one", "a", &[&format!("h{round}.test")], UP)]);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let puts = h.admin.wait_puts("one push", |puts| !puts.is_empty()).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let all = h.admin.puts();
    assert_eq!(
        all.len(),
        1,
        "five updates in the window are one push: {puts:?}"
    );
    assert!(
        all[0].body.to_string().contains("h4.test"),
        "the push carries the last update"
    );
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn engine_pushes_within_max_delay_under_a_steady_stream() {
    let h = Harness::start("debounce_ms = 200\nmax_delay_ms = 600\n", &["one"]);
    let handle = h.source("one").clone();
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let started = Instant::now();
    let stream = tokio::spawn(async move {
        for round in 0..60 {
            handle.apps(vec![app("one", "a", &[&format!("s{round}.test")], UP)]);
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    });
    let puts = h
        .admin
        .wait_puts("a push during the stream", |puts| !puts.is_empty())
        .await;
    let waited = puts[0].at.duration_since(started);
    assert!(
        waited >= Duration::from_millis(450),
        "the window held it back: {waited:?}"
    );
    assert!(
        waited <= Duration::from_millis(1400),
        "max_delay bounded it: {waited:?}"
    );
    assert!(
        sent.load(Ordering::SeqCst) < 60,
        "the stream was still running"
    );
    stream.abort();
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn push_retries_when_socket_missing() {
    // Reserve a path, start the engine, and only then create the socket.
    let path = socket_path();
    let mut h = Harness::start_unbound(path, FAST, &["one"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let status = h
        .wait_status("a connect error", |status| {
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("cannot connect"))
        })
        .await;
    assert_eq!(status.pushes, 0);
    tokio::time::sleep(Duration::from_millis(250)).await;
    h.admin.listen();
    let puts = h
        .admin
        .wait_puts("the push after the socket appears", |puts| !puts.is_empty())
        .await;
    assert_eq!(puts[0].version, 1);
    h.wait_status("error cleared", |status| {
        status.error.is_none() && status.pushes == 1
    })
    .await;
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn push_retries_on_5xx_and_dropped_connections() {
    let h = Harness::start(FAST, &["one"]);
    h.admin.script([
        Reply::Status(503, json!({ "error": "busy" })),
        Reply::Drop,
        Reply::Status(500, json!({ "error": "internal" })),
    ]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("the push after three failures", |puts| !puts.is_empty())
        .await;
    assert_eq!(puts[0].version, 1);
    assert_eq!(
        h.admin.attempts().len(),
        4,
        "three failures and the success"
    );
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn push_409_stale_resyncs() {
    let h = Harness::start(FAST, &["one"]);
    // Someone moved the live version between our read and our push.
    h.admin.script([Reply::Stale(9)]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("the push after the stale answer", |puts| !puts.is_empty())
        .await;
    assert_eq!(
        puts[0].version, 10,
        "the version is read again: live 9 plus one"
    );
    let versions: Vec<u64> = h
        .admin
        .attempts()
        .iter()
        .map(|body| body["version"].as_u64().unwrap_or(0))
        .collect();
    assert_eq!(versions, [1, 10]);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn push_writer_conflict_stops() {
    let mut h = Harness::start(FAST, &["one"]);
    h.admin.pin_writer("podkit-agent");
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let ended = h.finished().await;
    let err = ended.expect_err("the engine stops with an error");
    assert_eq!(
        err,
        RunError::WriterConflict {
            writer: Some("podkit-agent".into())
        }
    );
    assert!(err.to_string().contains("podkit-agent"), "{err}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.admin.attempts().len(), 1, "no retry loop and no takeover");
    assert!(h.admin.puts().is_empty());
}

#[tokio::test]
async fn repush_after_podgate_restart() {
    let h = Harness::start(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 1\n",
        &["one"],
    );
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    h.admin
        .wait_puts("first push", |puts| puts.len() == 1)
        .await;
    h.admin.restart();
    let puts = h
        .admin
        .wait_puts("the push after the restart", |puts| puts.len() == 2)
        .await;
    assert_eq!(
        puts[1].version, 1,
        "the sequence starts again from the new live version"
    );
    assert_eq!(
        puts[0].body["apps"], puts[1].body["apps"],
        "the whole snapshot, unchanged"
    );
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn restart_push_survives_a_transient_failure() {
    let h = Harness::start(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\n",
        &["one"],
    );
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    h.admin
        .wait_puts("first push", |puts| puts.len() == 1)
        .await;
    let restarted = Instant::now();
    h.admin.restart();
    // The push after the restart fails once. It is retried with backoff, not at the next resync.
    h.admin
        .script([Reply::Status(503, json!({ "error": "starting" }))]);
    let puts = h
        .admin
        .wait_puts("the push after the restart", |puts| puts.len() == 2)
        .await;
    let waited = puts[1].at.duration_since(restarted);
    assert!(
        waited < Duration::from_millis(3000),
        "retried within the backoff, not at the second resync tick: {waited:?}"
    );
    assert_eq!(puts[1].version, 1);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn resync_does_not_repush_an_unchanged_snapshot() {
    let h = Harness::start(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 1\n",
        &["one"],
    );
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    h.admin
        .wait_puts("first push", |puts| puts.len() == 1)
        .await;
    // Two resync ticks pass. A push resets canaries, so an unchanged snapshot stays put.
    tokio::time::sleep(Duration::from_millis(2300)).await;
    assert_eq!(h.admin.attempts().len(), 1);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn startup_waits_for_every_source_when_podgate_is_serving() {
    let admin = FakeAdmin::start();
    admin.someone_else_pushed(5);
    let mut h = Harness::start_with(admin, FAST, &["one", "two"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    h.wait_status("waiting for the other source", |status| {
        status
            .error
            .as_deref()
            .is_some_and(|error| error.contains("waiting for every source"))
    })
    .await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        h.admin.attempts().is_empty(),
        "a half-known state must not replace the live one"
    );
    h.source("two").apps(vec![app("two", "b", &["b.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("push with both sources", |puts| !puts.is_empty())
        .await;
    assert_eq!(puts[0].version, 6);
    assert_eq!(app_ids(&puts[0].body), ["one-a", "two-b"]);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn fresh_node_gets_what_is_known_without_waiting() {
    let h = Harness::start(FAST, &["one", "two"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("first push", |puts| !puts.is_empty())
        .await;
    assert_eq!(app_ids(&puts[0].body), ["one-a"]);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn source_outage_keeps_last_state() {
    let mut h = Harness::start(FAST, &["one", "two"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    h.source("two").apps(vec![app("two", "b", &["b.test"], UP)]);
    h.admin
        .wait_puts("first push", |puts| puts.len() == 1)
        .await;

    h.source("one").outage("docker: connection refused");
    let status = h
        .wait_status("the outage is reported", |status| {
            status.outages.contains_key("one")
        })
        .await;
    assert_eq!(status.outages["one"].as_ref(), "docker: connection refused");
    // Another source changes: the snapshot still holds the unreachable source's routes.
    h.source("two")
        .apps(vec![app("two", "b", &["b2.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("push after the outage", |puts| puts.len() == 2)
        .await;
    assert_eq!(
        app_ids(&puts[1].body),
        ["one-a", "two-b"],
        "an outage must not delete routes"
    );

    h.source("one").apps(vec![]);
    let status = h
        .wait_status("recovered", |status| status.outages.is_empty())
        .await;
    assert!(status.outages.is_empty());
    let puts = h
        .admin
        .wait_puts("push after recovery", |puts| puts.len() == 3)
        .await;
    assert_eq!(app_ids(&puts[2].body), ["two-b"]);
    h.stop().await.expect("clean stop");
}

// ---- quarantine ------------------------------------------------------------------------------

#[tokio::test]
async fn quarantine_by_declared_by() {
    let mut h = Harness::start(FAST, &["local"]);
    // A conflict between two objects names both; the older one stays whatever the order.
    h.admin.reject_when(|snapshot| {
        if app_ids(snapshot).contains(&"local-bad".to_owned()) {
            vec![conflict(
                "host_conflict",
                &["fake/local:bad", "fake/local:ok"],
            )]
        } else {
            Vec::new()
        }
    });
    h.source("local").apps(vec![
        app("local", "ok", &["ok.test"], UP).first_seen(1),
        app("local", "bad", &["ok.test"], UP).first_seen(2),
        app("local", "third", &["third.test"], UP).first_seen(3),
    ]);
    let puts = h
        .admin
        .wait_puts("push without the newer conflicting object", |puts| {
            !puts.is_empty()
        })
        .await;
    assert_eq!(app_ids(&puts[0].body), ["local-ok", "local-third"]);
    assert_eq!(
        h.admin.attempts().len(),
        2,
        "the rejected try and the accepted one"
    );
    assert!(
        h.admin.validations().is_empty(),
        "the conflict named the object: no bisection"
    );
    let status = h
        .wait_status("quarantine reported", |status| {
            !status.quarantined.is_empty()
        })
        .await;
    assert_eq!(status.quarantined.len(), 1);
    assert_eq!(status.quarantined[0].declared_by.as_ref(), "fake/local:bad");
    assert!(status.quarantined[0].reason.contains("host_conflict"));
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn quarantine_by_declared_by_single_object_and_reversed_order() {
    let h = Harness::start(FAST, &["local"]);
    h.admin.reject_when(|snapshot| {
        let ids = app_ids(snapshot);
        let mut found = Vec::new();
        if ids.contains(&"local-new".to_owned()) {
            // The newer object is listed first.
            found.push(conflict(
                "host_conflict",
                &["fake/local:new", "fake/local:old"],
            ));
        }
        if ids.contains(&"local-broken".to_owned()) {
            found.push(conflict("upstream_forbidden", &["fake/local:broken"]));
        }
        found
    });
    h.source("local").apps(vec![
        app("local", "old", &["x.test"], UP).first_seen(1),
        app("local", "new", &["x.test"], UP).first_seen(2),
        app("local", "broken", &["y.test"], UP).first_seen(3),
        app("local", "fine", &["z.test"], UP).first_seen(4),
    ]);
    let puts = h.admin.wait_puts("push", |puts| !puts.is_empty()).await;
    assert_eq!(app_ids(&puts[0].body), ["local-fine", "local-old"]);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn quarantine_by_bisect() {
    let mut h = Harness::start(FAST, &["local"]);
    // The rejection names nobody: the compiler found something wrong with the snapshot.
    h.admin.reject_when(|snapshot| {
        let ids = app_ids(snapshot);
        if ["local-a05", "local-a21"]
            .iter()
            .any(|bad| ids.iter().any(|id| id == bad))
        {
            vec![unattributed()]
        } else {
            Vec::new()
        }
    });
    let apps: Vec<SourceApp> = (0..32)
        .map(|n| app("local", &format!("a{n:02}"), &[&format!("h{n}.test")], UP).first_seen(n))
        .collect();
    h.source("local").apps(apps);
    let puts = h
        .admin
        .wait_puts("push without the culprits", |puts| !puts.is_empty())
        .await;
    let ids = app_ids(&puts[0].body);
    assert_eq!(ids.len(), 30);
    assert!(!ids.contains(&"local-a05".to_owned()) && !ids.contains(&"local-a21".to_owned()));
    let validations = h.admin.validations().len();
    assert!(
        validations <= bisect_bound(32, 2),
        "{validations} validations for 2 culprits among 32 objects, bound {}",
        bisect_bound(32, 2)
    );
    let status = h
        .wait_status("both reported", |status| status.quarantined.len() == 2)
        .await;
    let held: Vec<&str> = status.quarantined.iter().map(|q| &*q.declared_by).collect();
    assert_eq!(held, ["fake/local:a05", "fake/local:a21"]);
    h.stop().await.expect("clean stop");
}
/// A validator that applies a rule to every candidate and counts the questions.
struct RuleValidator<F> {
    rule: F,
    calls: usize,
}

impl<F: Fn(&Merged) -> Verdict + Send + Sync> Validate for RuleValidator<F> {
    async fn validate(&mut self, candidate: &Merged) -> Result<Verdict, Box<str>> {
        self.calls += 1;
        Ok((self.rule)(candidate))
    }
}

#[tokio::test]
async fn bisect_is_bounded_and_finds_the_culprits() {
    // Without the network: 256 changed objects, 3 culprits, the validations counted.
    let merger = merger(TENANTS);
    let apps: Vec<SourceApp> = (0..256)
        .map(|n| app("local", &format!("o{n:03}"), &[&format!("h{n}.test")], UP).first_seen(n))
        .collect();
    let by_source = states(vec![("local", apps)]);
    let full = merger.merge(&by_source, &BTreeSet::new());
    let build = |excluded: &BTreeSet<ObjectRef>| merger.merge(&by_source, excluded);
    let culprits = ["local-o017", "local-o100", "local-o254"];
    let mut validator = RuleValidator {
        rule: |candidate: &Merged| {
            let bad = candidate
                .snapshot()
                .apps
                .iter()
                .any(|app| culprits.contains(&&*app.id));
            if bad {
                Verdict::Rejected(vec![unattributed()])
            } else {
                Verdict::Valid
            }
        },
        calls: 0,
    };
    let found = quarantine::bisect(full.included(), build, &mut validator)
        .await
        .expect("bisection");
    let names: Vec<&str> = found.culprits.iter().map(|c| &*c.object.object).collect();
    assert_eq!(names, ["o017", "o100", "o254"]);
    assert_eq!(found.calls, validator.calls);
    assert!(
        found.calls <= bisect_bound(256, 3),
        "{} validations, bound {}",
        found.calls,
        bisect_bound(256, 3)
    );
    assert!(
        found.calls < 256 / 4,
        "far fewer than one validation per object"
    );

    // A rejection that the changed objects do not explain is an error, not a guess.
    let build = |excluded: &BTreeSet<ObjectRef>| merger.merge(&by_source, excluded);
    let mut always = RuleValidator {
        rule: |_: &Merged| Verdict::Rejected(vec![unattributed()]),
        calls: 0,
    };
    let err = quarantine::bisect(full.included(), build, &mut always)
        .await
        .expect_err("base rejected");
    assert!(matches!(err, BisectError::BaseRejected(_)), "{err:?}");
    assert_eq!(always.calls, 1, "it stops at the base");
    let build = |excluded: &BTreeSet<ObjectRef>| merger.merge(&by_source, excluded);
    let mut never = RuleValidator {
        rule: |_: &Merged| Verdict::Valid,
        calls: 0,
    };
    let none = quarantine::bisect(&[], build, &mut never)
        .await
        .expect_err("nothing changed");
    assert_eq!(none, BisectError::NothingChanged);
    assert_eq!(never.calls, 0);
    assert_eq!(bisect_bound(1, 1), 2);
    assert_eq!(bisect_bound(32, 2), 13);
}

#[tokio::test]
async fn quarantine_gives_up_on_a_rejection_it_cannot_attribute() {
    let broken = Arc::new(AtomicBool::new(false));
    let mut h = Harness::start(FAST, &["local"]);
    let flag = Arc::clone(&broken);
    h.admin.reject_when(move |_| {
        if flag.load(Ordering::SeqCst) {
            vec![unattributed()]
        } else {
            Vec::new()
        }
    });
    h.source("local")
        .apps(vec![app("local", "a", &["a.test"], UP)]);
    h.admin
        .wait_puts("the first push", |puts| puts.len() == 1)
        .await;

    // From now on the compiler refuses everything, whatever is in it.
    broken.store(true, Ordering::SeqCst);
    h.source("local").apps(vec![
        app("local", "a", &["a.test"], UP),
        app("local", "b", &["b.test"], UP),
    ]);
    let status = h
        .wait_status("the refusal is reported", |status| {
            status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("no object can be blamed"))
        })
        .await;
    assert!(
        status.quarantined.is_empty(),
        "nothing was blamed: {:?}",
        status.quarantined
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        h.admin.attempts().len(),
        2,
        "one rejected push, and no loop"
    );
    assert_eq!(
        h.admin.validations().len(),
        1,
        "one validation of the base, and no more"
    );
    assert_eq!(
        h.admin.puts().len(),
        1,
        "the last accepted snapshot stays live"
    );

    // The next change by a source is tried again.
    broken.store(false, Ordering::SeqCst);
    h.source("local").apps(vec![
        app("local", "a", &["a.test"], UP),
        app("local", "b", &["b2.test"], UP),
    ]);
    let puts = h.admin.wait_puts("recovery", |puts| puts.len() == 2).await;
    assert_eq!(app_ids(&puts[1].body), ["local-a", "local-b"]);
    h.stop().await.expect("clean stop");
}

fn host_of(snapshot: &Value, id: &str) -> Option<String> {
    snapshot["apps"]
        .as_array()?
        .iter()
        .find(|app| app["id"] == id)?["routers"][0]["match"]["host"][0]
        .as_str()
        .map(str::to_owned)
}

#[tokio::test]
async fn quarantine_released_on_change() {
    let mut h = Harness::start(FAST, &["local"]);
    h.admin.reject_when(|snapshot| {
        if host_of(snapshot, "local-bad").as_deref() == Some("bad.test") {
            vec![conflict("upstream_forbidden", &["fake/local:bad"])]
        } else {
            Vec::new()
        }
    });
    h.source("local").apps(vec![
        app("local", "good", &["good.test"], UP),
        app("local", "bad", &["bad.test"], UP),
    ]);
    let puts = h
        .admin
        .wait_puts("push without the bad object", |puts| !puts.is_empty())
        .await;
    assert_eq!(app_ids(&puts[0].body), ["local-good"]);
    h.wait_status("quarantined", |status| status.quarantined.len() == 1)
        .await;

    // The same state again does not release it.
    h.source("local").apps(vec![
        app("local", "good", &["good.test"], UP),
        app("local", "bad", &["bad.test"], UP),
    ]);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.admin.puts().len(), 1);

    // The source changes the object: it gets another try, and now it passes.
    h.source("local").apps(vec![
        app("local", "good", &["good.test"], UP),
        app("local", "bad", &["fixed.test"], UP),
    ]);
    let puts = h
        .admin
        .wait_puts("push with the fixed object", |puts| puts.len() == 2)
        .await;
    assert_eq!(app_ids(&puts[1].body), ["local-bad", "local-good"]);
    let status = h
        .wait_status("released", |status| status.quarantined.is_empty())
        .await;
    assert!(status.quarantined.is_empty());
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn quarantine_released_after_resync() {
    let h = Harness::start(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 1\n",
        &["local"],
    );
    let broken = Arc::new(AtomicBool::new(true));
    let flag = Arc::clone(&broken);
    h.admin.reject_when(move |snapshot| {
        if flag.load(Ordering::SeqCst) && app_ids(snapshot).contains(&"local-bad".to_owned()) {
            vec![conflict("upstream_forbidden", &["fake/local:bad"])]
        } else {
            Vec::new()
        }
    });
    h.source("local").apps(vec![
        app("local", "good", &["good.test"], UP),
        app("local", "bad", &["bad.test"], UP),
    ]);
    h.admin
        .wait_puts("push without the bad object", |puts| puts.len() == 1)
        .await;
    // The daemon changed its mind (say, its policy file was fixed); nothing changed in the source.
    broken.store(false, Ordering::SeqCst);
    let puts = h
        .admin
        .wait_puts("the retry after the resync interval", |puts| {
            puts.len() == 2
        })
        .await;
    assert_eq!(app_ids(&puts[1].body), ["local-bad", "local-good"]);
    h.stop().await.expect("clean stop");
}

#[tokio::test]
async fn validate_busy_is_waited_out() {
    let h = Harness::start(FAST, &["local"]);
    h.admin.busy_validations(2);
    h.admin.reject_when(|snapshot| {
        if app_ids(snapshot).contains(&"local-a1".to_owned()) {
            vec![unattributed()]
        } else {
            Vec::new()
        }
    });
    h.source("local").apps(vec![
        app("local", "a0", &["a0.test"], UP).first_seen(0),
        app("local", "a1", &["a1.test"], UP).first_seen(1),
    ]);
    let puts = h.admin.wait_puts("push", |puts| !puts.is_empty()).await;
    assert_eq!(app_ids(&puts[0].body), ["local-a0"]);
    assert!(
        h.admin.validations().len() >= 3,
        "two busy answers, then real ones"
    );
    h.stop().await.expect("clean stop");
}

// ---- the real daemon -------------------------------------------------------------------------

mod daemon {
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UnixStream};

    /// A `podgate` process, killed on drop.
    pub(crate) struct Daemon {
        child: Child,
        pub(crate) dir: PathBuf,
        pub(crate) admin: PathBuf,
        pub(crate) proxy: std::net::SocketAddr,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// The daemon binary: `PODGATE_BIN`, else `target/debug/podgate` of the workspace, which the
    /// workspace build of the test run produces. This never runs cargo: a test must not build
    /// under the shared build lock. `None` means skip, which is allowed only outside the gate
    /// (`VJ_GATE_LOCKED` is set by `scripts/check.sh`); under the gate a missing binary fails.
    pub(crate) fn binary() -> Option<PathBuf> {
        let path = std::env::var("PODGATE_BIN").map_or_else(
            |_| {
                let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
                let target = std::env::var("CARGO_TARGET_DIR")
                    .map_or_else(|_| workspace.join("target"), PathBuf::from);
                target.join("debug/podgate")
            },
            PathBuf::from,
        );
        if path.exists() {
            return Some(path);
        }
        assert!(
            std::env::var_os("VJ_GATE_LOCKED").is_none(),
            "end_to_end_against_daemon needs the podgate binary at {}: run `cargo nextest run --workspace` (its build produces it) or set PODGATE_BIN",
            path.display()
        );
        None
    }

    fn free_ports(count: usize) -> Vec<u16> {
        let probes: Vec<std::net::TcpListener> = (0..count)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("a free port"))
            .collect();
        probes
            .iter()
            .map(|probe| probe.local_addr().expect("address").port())
            .collect()
    }

    pub(crate) const LOOPBACK_POLICY: &str =
        r#"{"deny": ["0.0.0.0/8", "169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8"]}"#;

    async fn http(
        stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
        request: &str,
    ) -> (u16, String) {
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut raw = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
            .await
            .expect("answer in time")
            .expect("read answer");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default();
        (status, body)
    }

    impl Daemon {
        /// Starts the daemon with `policy` as its upstream policy file and waits for it.
        pub(crate) async fn start(binary: &Path, policy: &Path) -> Self {
            for attempt in 0..5 {
                let ports = free_ports(2);
                let dir = std::env::temp_dir().join(format!(
                    "pgp-daemon-{}-{}",
                    std::process::id(),
                    super::socket_path()
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("x")
                ));
                std::fs::create_dir_all(&dir).expect("temp dir");
                let admin = dir.join("admin.sock");
                let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], ports[0]));
                let child = Command::new(binary)
                    .env("PROXY_ADDR", proxy.to_string())
                    .env("PROXY_TLS_ADDR", format!("127.0.0.1:{}", ports[1]))
                    .env("ADMIN_SOCKET", &admin)
                    .env("UPSTREAM_POLICY_FILE", policy)
                    .env("RUST_LOG", "warn")
                    .stdin(Stdio::null())
                    .spawn()
                    .expect("spawn the daemon");
                let mut daemon = Self {
                    child,
                    dir,
                    admin,
                    proxy,
                };
                if daemon.wait_ready().await {
                    return daemon;
                }
                assert!(attempt < 4, "the daemon did not start in 5 tries");
            }
            unreachable!("the loop returns or asserts");
        }

        async fn wait_ready(&mut self) -> bool {
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline {
                if matches!(self.child.try_wait(), Ok(Some(_))) {
                    return false;
                }
                if let Ok(mut stream) = UnixStream::connect(&self.admin).await {
                    let (status, _) = http(
                        &mut stream,
                        "GET /readyz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                    if status == 200 {
                        return true;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            false
        }

        pub(crate) async fn admin_get(&self, path: &str) -> (u16, Value) {
            let mut stream = UnixStream::connect(&self.admin)
                .await
                .expect("admin socket");
            let (status, body) = http(
                &mut stream,
                &format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n"),
            )
            .await;
            (status, serde_json::from_str(&body).unwrap_or(Value::Null))
        }

        pub(crate) async fn get(&self, host: &str) -> (u16, String) {
            let mut stream = TcpStream::connect(self.proxy).await.expect("proxy");
            http(
                &mut stream,
                &format!("GET / HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n"),
            )
            .await
        }
    }

    /// A backend answering every request with `body`, on a loopback port.
    pub(crate) async fn backend(
        body: &'static str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("backend");
        let addr = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer).await;
                    let answer = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                });
            }
        });
        (addr, task)
    }
}

#[tokio::test]
async fn end_to_end_against_daemon() {
    let work = tokio::time::timeout(Duration::from_secs(1500), async {
        let Some(binary) = daemon::binary() else {
            eprintln!(
                "skipped: no podgate binary (set PODGATE_BIN, or build the workspace so that target/debug/podgate exists)"
            );
            return;
        };
        let dir = std::env::temp_dir().join(format!("pgp-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let policy_file = dir.join("upstream-policy.json");
        std::fs::write(&policy_file, daemon::LOOPBACK_POLICY).expect("policy file");

        let (addr_a, _backend_a) = daemon::backend("from-docker").await;
        let (addr_b, _backend_b) = daemon::backend("from-k8s").await;
        let (addr_c, _backend_c) = daemon::backend("from-docker-two").await;
        let daemon = daemon::Daemon::start(&binary, &policy_file).await;

        let socket = daemon.admin.clone();
        let extra = format!(
            "debounce_ms = 20\nmax_delay_ms = 200\nupstream_policy_file = {:?}\n{TENANTS}",
            policy_file.display().to_string()
        );
        let mut engine = podgate_provider::Engine::new(
            config(&socket, &extra),
            UpstreamPolicy::load(&policy_file).expect("the shared policy file"),
        )
        .with_tuning(common::fast_tuning());
        let (docker, docker_handle) = common::scripted("local");
        let (k8s, k8s_handle) = common::scripted("k8s");
        engine.add_source(docker).expect("source");
        engine.add_source(k8s).expect("source");
        let status = engine.status();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let run = tokio::spawn(async move {
            engine
                .run(async {
                    let _ = stopped.await;
                })
                .await
        });

        let on = |source: &str, local: &str, host: &str, addr: std::net::SocketAddr| {
            app(source, local, &[host], &format!("http://{addr}"))
        };
        docker_handle.apps(vec![
            on("local", "web", "a.acme.test", addr_a)
                .mapped("acme")
                .first_seen(1),
            on("local", "free", "free.test", addr_c).first_seen(2),
        ]);
        k8s_handle.apps(vec![
            on("k8s", "shop", "b.test", addr_b).first_seen(3),
            // The same host as docker's `a.acme.test`, from a source that may not claim it.
            on("k8s", "squat", "a.acme.test", addr_b).first_seen(4),
            // Fine for the provider, a conflict only the daemon sees: two objects, one host.
            on("k8s", "twin", "free.test", addr_b).first_seen(5),
        ]);

        let started = Instant::now();
        loop {
            let (a, a_body) = daemon.get("a.acme.test").await;
            let (b, b_body) = daemon.get("b.test").await;
            let (f, f_body) = daemon.get("free.test").await;
            if (a, b, f) == (200, 200, 200) {
                assert_eq!(a_body, "from-docker");
                assert_eq!(b_body, "from-k8s");
                assert_eq!(
                    f_body, "from-docker-two",
                    "the older of two conflicting objects serves"
                );
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the merged snapshot is not serving: {a} {b} {f}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let (code, version) = daemon.admin_get("/v1/snapshot/version").await;
        assert_eq!(code, 200);
        assert_eq!(version["writer"], "podgate-provider");
        let (code, explain) = daemon
            .admin_get("/v1/explain?url=http://a.acme.test/")
            .await;
        assert_eq!(code, 200, "{explain}");
        assert_eq!(explain["declared_by"], "docker/local:web");
        assert_eq!(explain["tenant"], "acme");

        let report = status.borrow().clone();
        let quarantined: Vec<&str> = report.quarantined.iter().map(|q| &*q.declared_by).collect();
        assert_eq!(
            quarantined,
            ["kubernetes/k8s:twin"],
            "the daemon's conflict, attributed by declared_by"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.code == "foreign_host_claim" && &*f.object == "squat"),
            "{:?}",
            report.findings
        );

        let _ = stop.send(());
        run.await.expect("task").expect("clean stop");
        let _ = std::fs::remove_dir_all(&dir);
    });
    work.await.expect("the end-to-end test finished in time");
}

#[test]
fn object_refs_order_by_source_then_kind() {
    let a = ObjectRef {
        source: "a".into(),
        kind: ObjectKind::Certificate,
        object: "x".into(),
    };
    let b = ObjectRef {
        source: "b".into(),
        kind: ObjectKind::App,
        object: "x".into(),
    };
    assert!(a < b);
}

// ---- the program -----------------------------------------------------------------------------

fn write_config(name: &str, text: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("pgp-{}-{name}.toml", std::process::id()));
    std::fs::write(&path, text).expect("write the config");
    path
}

/// Runs `podgate-provider <command> --config <path>` off the runtime's thread, so the fake admin
/// socket in this process keeps answering.
async fn provider(command: &'static str, config: std::path::PathBuf) -> std::process::Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
            .args([command, "--config"])
            .arg(config)
            .env("RUST_LOG", "error")
            .output()
            .expect("run podgate-provider")
    })
    .await
    .expect("the provider process ran")
}

#[test]
fn config_example_parses() {
    let config = podgate_provider::Config::parse(include_str!(
        "../../../deploy/podgate-provider.example.toml"
    ))
    .expect("the example configuration is valid");
    assert_eq!(config.tenants.len(), 2);
    assert_eq!(&*config.sources[0].name, "docker-prod");
    assert_eq!(&*config.tenants[0].label_sources[0], "docker-prod");
}

#[tokio::test]
async fn print_outputs_the_canonical_snapshot() {
    let path = write_config("print", "admin_socket = \"/nonexistent/admin.sock\"\n");
    let output = provider("print", path.clone()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: Value = serde_json::from_slice(&output.stdout).expect("the snapshot is JSON");
    assert_eq!(printed["version"], 0);
    assert_eq!(printed["tenants"][0]["id"], "default");
    assert_eq!(printed["apps"], json!([]));
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn check_asks_podgate_to_validate() {
    let admin = FakeAdmin::start();
    let text = format!("admin_socket = {:?}\n", admin.path.display().to_string());
    let path = write_config("check", &text);

    let output = provider("check", path.clone()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("valid"));
    assert_eq!(admin.validations().len(), 1);
    assert!(admin.attempts().is_empty(), "check pushes nothing");

    admin.reject_when(|_| vec![conflict("host_conflict", &["a", "b"])]);
    let output = provider("check", path.clone()).await;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("host_conflict"));
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn a_source_kind_that_is_not_built_is_an_error() {
    let text = "admin_socket = \"/nonexistent/admin.sock\"\n[[source]]\nkind = \"consul\"\nname = \"local\"\n";
    let path = write_config("unbuilt", text);
    let output = provider("print", path.clone()).await;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not built into this binary"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = std::fs::remove_file(path);
}

// ---- the operator's snapshot section ---------------------------------------------------------

const SECRET: &str = "0123456789abcdef-skew-secret";

fn operator_toml(secret_file: &Path) -> String {
    format!(
        "debounce_ms = 20\nmax_delay_ms = 200\n\n[snapshot]\nrevert_window_secs = 90\nskew_secret_file = {:?}\n[snapshot.observability]\naccess_log = true\n",
        secret_file.display().to_string()
    )
}

#[tokio::test]
async fn operator_section_reaches_snapshot() {
    let secret_file = std::env::temp_dir().join(format!("pgp-{}-skew.key", std::process::id()));
    std::fs::write(&secret_file, format!("{SECRET}\n")).expect("write the key file");
    let extra = operator_toml(&secret_file);

    // `print` shows the fields, with the secret redacted.
    let text = format!("admin_socket = \"/nonexistent/admin.sock\"\n{extra}");
    let path = write_config("operator", &text);
    let output = provider("print", path.clone()).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(SECRET),
        "the key must not be printed: {stdout}"
    );
    let printed: Value = serde_json::from_str(&stdout).expect("the snapshot is JSON");
    assert_eq!(printed["skew_secret"], "[redacted]");
    assert_eq!(printed["revert_window_secs"], 90);
    assert_eq!(printed["observability"]["access_log"], true);

    // The pushed body carries the real key.
    let h = Harness::start(&extra, &["one"]);
    h.source("one").apps(vec![app("one", "a", &["a.test"], UP)]);
    let puts = h
        .admin
        .wait_puts("first push", |puts| !puts.is_empty())
        .await;
    assert_eq!(puts[0].body["skew_secret"], SECRET);
    assert_eq!(puts[0].body["revert_window_secs"], 90);
    assert_eq!(puts[0].body["observability"]["access_log"], true);
    h.stop().await.expect("clean stop");

    // Unset means absent.
    let bare = merge(&merger(TENANTS), vec![("local", vec![])]);
    let body: Value = serde_json::from_str(&bare.body(1)).expect("JSON");
    assert!(body["skew_secret"].is_null() && body["acme"].is_null());
    assert!(body["revert_window_secs"].is_null() && body["observability"].is_null());
    let _ = std::fs::remove_file(secret_file);
    let _ = std::fs::remove_file(path);
}

#[test]
fn skew_secret_file_unreadable_fails_config() {
    let field_of = |text: &str| match podgate_provider::Config::parse(text) {
        Err(podgate_provider::ConfigError::Invalid { field, .. }) => field.to_string(),
        other => panic!("expected an invalid field, got {other:?}"),
    };
    let head = "admin_socket = \"/x.sock\"\n[snapshot]\n";
    assert_eq!(
        field_of(&format!(
            "{head}skew_secret_file = \"/nonexistent/skew.key\"\n"
        )),
        "snapshot.skew_secret_file"
    );
    let short = std::env::temp_dir().join(format!("pgp-{}-short.key", std::process::id()));
    std::fs::write(&short, "too short\n").expect("write");
    assert_eq!(
        field_of(&format!(
            "{head}skew_secret_file = {:?}\n",
            short.display().to_string()
        )),
        "snapshot.skew_secret_file"
    );
    let _ = std::fs::remove_file(short);
    // The key is a file path only: an inline key is an unknown field.
    assert!(
        podgate_provider::Config::parse(&format!("{head}skew_secret = \"0123456789abcdef\"\n"))
            .is_err()
    );
}
