//! The shared key-value layer without any store: layouts to apps, the tenant mapping, the
//! allowlist requirement, the limits, and what the merge makes of the result (hosts, catch-all routers
//! and server addresses are judged exactly as for every other source).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use common::config;
use podgate_provider::kv::{
    Built, ConfigError, Layout, MAX_APPS_PER_PREFIX, MAX_DOCUMENT_BYTES, Mapping, RawPrefix,
};
use podgate_provider::source::{SourceApp, State};
use podgate_provider::traefik::translate;
use podgate_provider::{Merged, Merger, UpstreamPolicy};
use serde_json::{Value, json};

const POLICY: &str = r#"{"tenants": {
    "acme": {"allow": ["10.4.0.0/16"]},
    "globex": {"allow": ["10.5.0.0/16"]}
}}"#;

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
catch_all = true

[[source]]
kind = "etcd"
name = "kv"
"#;

fn policy() -> UpstreamPolicy {
    UpstreamPolicy::parse(POLICY).expect("a valid policy")
}

fn raw(prefix: &str, tenant: &str, layout: Layout) -> RawPrefix {
    RawPrefix {
        prefix: prefix.to_owned(),
        tenant: tenant.to_owned(),
        layout,
        app: None,
    }
}

fn mapping(prefixes: Vec<RawPrefix>) -> Mapping {
    Mapping::new(prefixes, &policy()).expect("a valid mapping")
}

fn acme_json() -> Mapping {
    mapping(vec![raw("podgate/acme", "acme", Layout::PodgateJson)])
}

/// An app document in the file source's shape, without a tenant.
fn document(host: &str, upstream: &str) -> Value {
    json!({
        "tls": { "mode": "acme" },
        "routers": [{ "name": "main", "match": { "host": [host] }, "service": "svc" }],
        "services": [{ "name": "svc", "type": "loadbalancer", "servers": [{ "url": upstream }] }],
        "revisions": [{ "id": "r1", "state": "serving", "weight": 1 }],
    })
}

fn pairs(entries: &[(&str, &Value)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries
        .iter()
        .map(|(key, value)| (key.as_bytes().to_vec(), value.to_string().into_bytes()))
        .collect()
}

fn text_pairs(entries: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    entries
        .iter()
        .map(|(key, value)| (key.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect()
}

fn ids(built: &Built) -> Vec<String> {
    built
        .apps
        .iter()
        .map(|app| app.app.id.to_string())
        .collect()
}

fn reports(built: &Built) -> String {
    built.reports.join("\n")
}

fn merge(extra: &str, built: Built) -> Merged {
    let config = config(Path::new("/nonexistent/admin.sock"), extra);
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("kv".into(), built.into_state())]);
    Merger::new(&config, policy()).merge(&states, &BTreeSet::new())
}

fn findings(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn app_json(app: &SourceApp) -> Value {
    serde_json::to_value(&app.app).expect("an app serializes")
}

// ---- layouts -------------------------------------------------------------------------------

#[test]
fn kv_json_layout_builds_apps_for_the_mapped_tenant() {
    let site = document("shop.acme.test", "http://10.4.0.5:8080");
    let api = document("api.acme.test", "http://10.4.0.6:8080");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/site", &site),
            ("podgate/acme/apps/api", &api),
        ]),
    );
    assert_eq!(ids(&built), ["api", "site"], "key order, not arrival order");
    assert!(built.reports.is_empty(), "{:?}", built.reports);
    for app in &built.apps {
        assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
        assert_eq!(app.tenant.label, None);
        assert_eq!(app.app.tenant.as_ref(), "acme");
        assert_eq!(&*app.origin.source, "kv");
        assert_eq!(&*app.origin.object, &*app.app.id);
        assert_eq!(app.origin.first_seen, 0, "etcd has no creation time");
    }
}

#[test]
fn kv_traefik_tree_to_app() {
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build(
        "kv",
        text_pairs(&[
            ("traefik/http/routers/site/rule", "Host(`shop.acme.test`)"),
            ("traefik/http/routers/site/service", "web"),
            ("traefik/http/routers/site/entrypoints/0", "web"),
            ("traefik/http/routers/site/entrypoints/1", "websecure"),
            (
                "traefik/http/services/web/loadbalancer/servers/0/url",
                "http://10.4.0.5:8080",
            ),
            (
                "traefik/http/services/web/loadbalancer/servers/1/url",
                "http://10.4.0.6:8080",
            ),
        ]),
    );
    assert!(built.reports.is_empty(), "{:?}", built.reports);
    assert_eq!(ids(&built), ["acme"], "the app is named like its tenant");
    let app = app_json(&built.apps[0]);
    assert_eq!(app["tenant"], "acme");
    assert_eq!(
        app["routers"][0]["entry_points"],
        json!(["web", "websecure"]),
        "an indexed list is one comma separated label"
    );
    assert_eq!(
        app["revisions"][0]["services"][0]["servers"],
        json!([{ "url": "http://10.4.0.5:8080" }, { "url": "http://10.4.0.6:8080" }])
    );
}

#[test]
fn kv_traefik_tree_matches_label_translation() {
    let tree = text_pairs(&[
        (
            "traefik/http/routers/site/rule",
            "Host(`shop.acme.test`) && PathPrefix(`/v1`)",
        ),
        ("traefik/http/routers/site/service", "web"),
        ("traefik/http/routers/site/middlewares/0", "strip"),
        (
            "traefik/http/middlewares/strip/stripprefix/prefixes/0",
            "/v1",
        ),
        (
            "traefik/http/services/web/loadbalancer/servers/0/url",
            "https://10.4.0.5:8443",
        ),
        (
            "traefik/http/services/web/loadbalancer/passhostheader",
            "false",
        ),
    ]);
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build("kv", tree);
    assert!(built.reports.is_empty(), "{:?}", built.reports);
    let app = app_json(&built.apps[0]);

    // The same labels as a container would carry them, minus the server URL, through the
    // translator the Docker source uses.
    let translated = translate([
        (
            "traefik.http.routers.site.rule",
            "Host(`shop.acme.test`) && PathPrefix(`/v1`)",
        ),
        ("traefik.http.routers.site.service", "web"),
        ("traefik.http.routers.site.middlewares", "strip"),
        ("traefik.http.middlewares.strip.stripprefix.prefixes", "/v1"),
        (
            "traefik.http.services.web.loadbalancer.passhostheader",
            "false",
        ),
    ]);
    assert!(translated.problems.is_empty(), "{:?}", translated.problems);
    assert_eq!(
        app["routers"],
        serde_json::to_value(&translated.routers).expect("routers")
    );
    assert_eq!(
        app["middlewares"],
        serde_json::to_value(&translated.middlewares).expect("middlewares")
    );
    let mut service = serde_json::to_value(&translated.services[0]).expect("service");
    service["servers"] = json!([{ "url": "https://10.4.0.5:8443" }]);
    assert_eq!(app["revisions"][0]["services"], json!([service]));
    assert_eq!(app["revisions"][0]["id"], "default");
}

#[test]
fn kv_traefik_tree_leaves_out_what_it_cannot_serve() {
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build(
        "kv",
        text_pairs(&[
            ("traefik/http/routers/good/rule", "Host(`a.acme.test`)"),
            ("traefik/http/routers/good/service", "web"),
            ("traefik/http/routers/nowhere/rule", "Host(`b.acme.test`)"),
            ("traefik/http/routers/nowhere/service", "empty"),
            (
                "traefik/http/services/web/loadbalancer/servers/0/url",
                "http://10.4.0.5:8080",
            ),
            (
                "traefik/http/services/empty/loadbalancer/passhostheader",
                "true",
            ),
            (
                "traefik/http/services/odd/loadbalancer/servers/0/url",
                "ftp://10.4.0.5:21",
            ),
            (
                "traefik/http/services/odd/loadbalancer/servers/0/weight",
                "3",
            ),
        ]),
    );
    let app = app_json(&built.apps[0]);
    let names: Vec<&str> = app["routers"]
        .as_array()
        .expect("routers")
        .iter()
        .filter_map(|router| router["name"].as_str())
        .collect();
    assert_eq!(
        names,
        ["good"],
        "a router whose service has no servers is left out"
    );
    let text = reports(&built);
    assert!(text.contains("service empty"), "{text}");
    assert!(
        text.contains("the scheme must be http, https or h2c"),
        "{text}"
    );
    assert!(
        text.contains("only the url of a server is translated"),
        "{text}"
    );
}

#[test]
fn kv_traefik_dotted_key_segments_are_ignored() {
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build(
        "kv",
        text_pairs(&[
            ("traefik/http/routers/site/rule", "Host(`a.acme.test`)"),
            ("traefik/http/routers/site/service", "web"),
            ("traefik/http/routers/a.b/rule", "Host(`c.acme.test`)"),
            (
                "traefik/http/services/web/loadbalancer/servers/0/url",
                "http://10.4.0.5:8080",
            ),
        ]),
    );
    assert_eq!(ids(&built), ["acme"]);
    assert!(reports(&built).contains("a.b"), "{}", reports(&built));
}

// ---- tenants and keys ----------------------------------------------------------------------

#[test]
fn kv_tenant_only_from_prefix() {
    let mut naming = document("shop.acme.test", "http://10.4.0.5:8080");
    naming["tenant"] = json!("globex");
    let mut naming_own = document("api.acme.test", "http://10.4.0.5:8080");
    naming_own["tenant"] = json!("acme");
    let fine = document("www.acme.test", "http://10.4.0.5:8080");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/naming", &naming),
            ("podgate/acme/apps/naming-own", &naming_own),
            ("podgate/acme/apps/fine", &fine),
        ]),
    );
    assert_eq!(
        ids(&built),
        ["fine"],
        "a document that names a tenant is ignored, even its own"
    );
    let text = reports(&built);
    assert!(text.contains("podgate/acme/apps/naming"), "{text}");
    assert!(
        text.contains("the tenant comes only from the prefix mapping"),
        "{text}"
    );
    assert_eq!(built.apps[0].tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(built.apps[0].tenant.label, None);

    // A certificate document too.
    let certificate =
        json!({ "hosts": ["a.acme.test"], "cert_pem": "x", "key_pem": "y", "tenant": "globex" });
    let built = acme_json().build(
        "kv",
        pairs(&[("podgate/acme/certificates/a", &certificate)]),
    );
    assert!(built.certificates.is_empty());
    assert!(
        reports(&built).contains("names a tenant"),
        "{}",
        reports(&built)
    );
}

#[test]
fn kv_key_outside_prefix_ignored() {
    let doc = document("shop.acme.test", "http://10.4.0.5:8080");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/site", &doc),
            ("podgate/acme2/apps/other", &doc),
            ("podgate/globex/apps/site", &doc),
            ("podgate/acme", &doc),
            ("podgate/acme/junk", &doc),
            ("podgate/acme/apps/site/extra", &doc),
            ("podgate/acme/apps/bad name", &doc),
        ]),
    );
    assert_eq!(ids(&built), ["site"]);
    let text = reports(&built);
    for key in [
        "podgate/acme2/apps/other",
        "podgate/globex/apps/site",
        "\"podgate/acme\"",
        "podgate/acme/junk",
        "podgate/acme/apps/site/extra",
        "podgate/acme/apps/bad name",
    ] {
        assert!(text.contains(key), "{key} is reported: {text}");
    }
    assert!(text.contains("outside every configured prefix"), "{text}");
}

#[test]
fn kv_prefixes_may_not_overlap() {
    for (first, second) in [
        ("podgate/acme", "podgate/acme/sub"),
        ("podgate/acme/", "podgate/acme"),
        ("podgate", "podgate/globex"),
    ] {
        let err = Mapping::new(
            vec![
                raw(first, "acme", Layout::PodgateJson),
                raw(second, "globex", Layout::PodgateJson),
            ],
            &policy(),
        )
        .expect_err("overlapping prefixes");
        assert!(
            err.to_string().contains("overlaps"),
            "{first} {second}: {err}"
        );
    }
    // `acme` and `acme2` are different prefixes: the slash is part of the match.
    Mapping::new(
        vec![
            raw("podgate/acme", "acme", Layout::PodgateJson),
            raw("podgate/acme2", "globex", Layout::PodgateJson),
        ],
        &policy(),
    )
    .expect("prefixes that only share letters");
    let err = Mapping::new(vec![raw("/", "acme", Layout::PodgateJson)], &policy())
        .expect_err("the whole store");
    assert!(err.to_string().contains("not the whole store"), "{err}");
}

// ---- the allowlist requirement ---------------------------------------------------------------

#[test]
fn kv_source_requires_tenant_allowlist() {
    // `initech` has no allow list; neither does the `default` entry help it.
    let policy = UpstreamPolicy::parse(
        r#"{"default": {"allow": ["10.0.0.0/8"]}, "tenants": {"acme": {"allow": ["10.4.0.0/16"]}}}"#,
    )
    .expect("a valid policy");
    let err = Mapping::new(
        vec![
            raw("podgate/acme", "acme", Layout::PodgateJson),
            raw("podgate/initech", "initech", Layout::PodgateJson),
        ],
        &policy,
    )
    .expect_err("a tenant without an allow list");
    assert_eq!(
        err,
        ConfigError::NoAllowlist {
            tenant: "initech".into()
        }
    );
    assert_eq!(err.code(), "kv_source_requires_tenant_allowlist");
    assert!(err.to_string().contains("tenants.initech.allow"), "{err}");

    // With no policy file at all, no tenant has one.
    let err = Mapping::new(
        vec![raw("podgate/acme", "acme", Layout::PodgateJson)],
        &UpstreamPolicy::builtin(),
    )
    .expect_err("no policy file");
    assert_eq!(err.code(), "kv_source_requires_tenant_allowlist");

    Mapping::new(
        vec![raw("podgate/acme", "acme", Layout::PodgateJson)],
        &policy,
    )
    .expect("a tenant with an allow list starts");
}

#[test]
fn upstream_outside_allowlist_rejected_kv() {
    let inside = document("shop.acme.test", "http://10.4.0.5:8080");
    let outside = document("api.acme.test", "http://10.9.0.5:8080");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/inside", &inside),
            ("podgate/acme/apps/outside", &outside),
        ]),
    );
    let merged = merge(TENANTS, built);
    assert_eq!(
        findings(&merged),
        [("upstream_forbidden", "outside".to_owned())]
    );
    let ids: Vec<&str> = merged.snapshot().apps.iter().map(|app| &*app.id).collect();
    assert_eq!(ids, ["kv-inside"]);

    // The same for the Traefik tree: its explicit server URLs are checked.
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build(
        "kv",
        text_pairs(&[
            ("traefik/http/routers/site/rule", "Host(`shop.acme.test`)"),
            ("traefik/http/routers/site/service", "web"),
            (
                "traefik/http/services/web/loadbalancer/servers/0/url",
                "http://10.9.0.5:8080",
            ),
        ]),
    );
    let merged = merge(TENANTS, built);
    assert_eq!(
        findings(&merged),
        [("upstream_forbidden", "acme".to_owned())]
    );
    assert!(merged.snapshot().apps.is_empty());
}

#[test]
fn kv_foreign_container_address_rejected() {
    // 10.5.0.0/16 is globex's range: acme may not point a server at its containers.
    let theirs = document("shop.acme.test", "http://10.5.0.7:8080");
    let built = acme_json().build("kv", pairs(&[("podgate/acme/apps/site", &theirs)]));
    let merged = merge(TENANTS, built);
    assert_eq!(
        findings(&merged),
        [("upstream_forbidden", "site".to_owned())]
    );
    let message = merged.findings()[0].message.to_string();
    assert!(message.contains("10.5.0.7"), "{message}");
    assert!(message.contains("tenant acme"), "{message}");
    assert!(merged.snapshot().apps.is_empty());
}

// ---- hosts and catch-all routers ----------------------------------------------------------------------

#[test]
fn kv_foreign_host_rejected() {
    let mine = document("shop.acme.test", "http://10.4.0.5:8080");
    let theirs = document("globex.test", "http://10.4.0.6:8080");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/mine", &mine),
            ("podgate/acme/apps/theirs", &theirs),
        ]),
    );
    let merged = merge(TENANTS, built);
    assert_eq!(
        findings(&merged),
        [("foreign_host_claim", "theirs".to_owned())]
    );
    let ids: Vec<&str> = merged.snapshot().apps.iter().map(|app| &*app.id).collect();
    assert_eq!(ids, ["kv-mine"]);
}

#[test]
fn kv_catch_all_needs_allowance() {
    let mut hostless = document("unused.test", "http://10.4.0.5:8080");
    hostless["routers"][0]["match"] = json!({ "path_prefix": "/" });
    let acme = acme_json().build("kv", pairs(&[("podgate/acme/apps/any", &hostless)]));
    let merged = merge(TENANTS, acme);
    assert_eq!(
        findings(&merged),
        [("catch_all_not_allowed", "any".to_owned())]
    );

    // globex has `catch_all = true` in the configuration.
    let mut hostless = document("unused.test", "http://10.5.0.5:8080");
    hostless["routers"][0]["match"] = json!({ "path_prefix": "/" });
    let globex = mapping(vec![raw("podgate/globex", "globex", Layout::PodgateJson)])
        .build("kv", pairs(&[("podgate/globex/apps/any", &hostless)]));
    let merged = merge(TENANTS, globex);
    assert!(findings(&merged).is_empty(), "{:?}", findings(&merged));
    assert_eq!(merged.snapshot().apps.len(), 1);
}

// ---- limits ------------------------------------------------------------------------------------

#[test]
fn kv_document_limits() {
    let fine = document("shop.acme.test", "http://10.4.0.5:8080");
    let mut padded = document("api.acme.test", "http://10.4.0.5:8080");
    padded["pad"] = json!("x".repeat(MAX_DOCUMENT_BYTES));
    let mut entries = pairs(&[
        ("podgate/acme/apps/fine", &fine),
        ("podgate/acme/apps/huge", &padded),
    ]);
    entries.push((b"podgate/acme/apps/empty".to_vec(), b"  ".to_vec()));
    entries.push((b"podgate/acme/apps/array".to_vec(), b"[1]".to_vec()));
    entries.push((b"podgate/acme/apps/garbage".to_vec(), b"{not json".to_vec()));
    let built = acme_json().build("kv", entries);
    assert_eq!(
        ids(&built),
        ["fine"],
        "each bad document is left out on its own"
    );
    let text = reports(&built);
    assert!(text.contains("the limit is 1048576"), "{text}");
    assert!(text.contains("the document is empty"), "{text}");
    assert!(text.contains("must be a JSON object"), "{text}");
    assert!(text.contains("is not JSON"), "{text}");

    // Too many apps: the ones past the limit, in key order, are left out and reported.
    let many: Vec<(Vec<u8>, Vec<u8>)> = (0..MAX_APPS_PER_PREFIX + 3)
        .map(|n| {
            (
                format!("podgate/acme/apps/app{n:04}").into_bytes(),
                fine.to_string().into_bytes(),
            )
        })
        .collect();
    let built = acme_json().build("kv", many);
    assert_eq!(built.apps.len(), MAX_APPS_PER_PREFIX);
    assert_eq!(built.reports.len(), 3);
    assert!(built.reports[0].contains("app0256"), "{:?}", built.reports);
    assert!(
        built.reports[0].contains("more than 256 apps"),
        "{:?}",
        built.reports
    );

    // A tree over the limit is one document and is left out whole.
    let big = "x".repeat(MAX_DOCUMENT_BYTES);
    let built = mapping(vec![raw("traefik", "acme", Layout::TraefikKv)]).build(
        "kv",
        text_pairs(&[("traefik/http/routers/site/rule", &big)]),
    );
    assert!(built.apps.is_empty());
    assert!(
        reports(&built).contains("the tree is"),
        "{}",
        reports(&built)
    );
}

#[test]
fn kv_unknown_field_rejected() {
    let fine = document("shop.acme.test", "http://10.4.0.5:8080");
    let mut top = document("a.acme.test", "http://10.4.0.5:8080");
    top["bogus"] = json!(1);
    // A typo that would silently turn client authentication off.
    let mut nested = document("b.acme.test", "http://10.4.0.5:8080");
    nested["tls"]["client_ca"] = json!("-----BEGIN CERTIFICATE-----");
    let mut in_router = document("c.acme.test", "http://10.4.0.5:8080");
    in_router["routers"][0]["serv"] = json!("svc");
    // Free-form parts stay free-form: the middleware and service bodies belong to their kinds.
    let mut free = document("d.acme.test", "http://10.4.0.5:8080");
    free["services"][0]["anything_the_kind_knows"] = json!({ "deep": [1, 2] });
    free["tls"]["pass_client_cert"] = json!(false);
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/fine", &fine),
            ("podgate/acme/apps/top", &top),
            ("podgate/acme/apps/nested", &nested),
            ("podgate/acme/apps/in-router", &in_router),
            ("podgate/acme/apps/free", &free),
        ]),
    );
    assert_eq!(ids(&built), ["fine", "free"]);
    let text = reports(&built);
    assert!(text.contains("unknown field bogus"), "{text}");
    assert!(text.contains("unknown field tls.client_ca"), "{text}");
    assert!(text.contains("unknown field routers[0].serv"), "{text}");
    assert!(
        !text.contains("BEGIN CERTIFICATE"),
        "a report never quotes a value: {text}"
    );

    let certificate =
        json!({ "hosts": ["a.acme.test"], "cert_pem": "x", "key_pem": "SECRET-KEY", "typo": true });
    let built = acme_json().build(
        "kv",
        pairs(&[("podgate/acme/certificates/a", &certificate)]),
    );
    assert!(built.certificates.is_empty());
    assert!(
        reports(&built).contains("unknown field typo"),
        "{}",
        reports(&built)
    );
    assert!(!reports(&built).contains("SECRET-KEY"));
}

#[test]
fn kv_document_errors_never_quote_values() {
    // `hosts` must be a list: serde would quote the string it found.
    let certificate =
        json!({ "hosts": "-----BEGIN PRIVATE KEY-----", "cert_pem": "x", "key_pem": "y" });
    let built = acme_json().build(
        "kv",
        pairs(&[("podgate/acme/certificates/a", &certificate)]),
    );
    assert!(built.certificates.is_empty());
    let text = reports(&built);
    assert!(text.contains("invalid type"), "{text}");
    assert!(!text.contains("PRIVATE KEY"), "{text}");
}

#[test]
fn kv_id_must_match_its_key() {
    let mut other = document("shop.acme.test", "http://10.4.0.5:8080");
    other["id"] = json!("elsewhere");
    let mut same = document("api.acme.test", "http://10.4.0.5:8080");
    same["id"] = json!("same");
    let built = acme_json().build(
        "kv",
        pairs(&[
            ("podgate/acme/apps/other", &other),
            ("podgate/acme/apps/same", &same),
        ]),
    );
    assert_eq!(ids(&built), ["same"]);
    assert!(
        reports(&built).contains("`id` must be the key's name"),
        "{}",
        reports(&built)
    );
}
