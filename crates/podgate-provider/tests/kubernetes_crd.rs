//! Black-box tests of the podgate custom resources: the translation of `PodgateRoute` and
//! `PodgateMiddleware` against a fake API server (`common/k8s.rs`), the generated CRD manifests
//! (`deploy/crd/`) against the schema fixture and against the rules of the API server's
//! structural schemas, and one run through the real daemon. Never a real cluster; everything
//! that waits has a deadline.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::k8s::{self, FakeApi};
use common::k8s_crd::{
    Dir, Run, app, backend, config, ids, middleware, route, servers, stripped, web,
};
use podgate_provider::kubernetes::crd::schema;
use serde_json::{Value, json};

// ---- the translation -------------------------------------------------------------------------

#[tokio::test]
async fn crd_route_to_app() {
    let api = FakeApi::start().await;
    let dir = Dir::new("route");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.2", true, false), ("10.0.0.1", true, false)],
    );
    api.put(
        "podgateroutes",
        route(
            "team-a",
            "shop",
            web(
                "shop.acme.test",
                json!({
                    "default_chain": ["strip"],
                    "middlewares": [{ "name": "strip", "type": "strip_prefix", "prefixes": ["/api"] }],
                }),
            ),
        ),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.shop"]).await;

    let shop = app(&state, "route_team-a.shop");
    assert_eq!(&*shop.origin.object, "route/team-a/shop");
    assert_eq!(&*shop.origin.source, "k8s");
    assert_eq!(
        shop.origin.first_seen, 1_795_176_000,
        "the creation timestamp, in unix seconds"
    );
    assert_eq!(shop.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(
        &*shop.app.declared_by,
        "kubernetes/k8s:podgateroute/team-a/shop"
    );
    assert_eq!(
        stripped(&shop.app.routers),
        json!([{
            "name": "web",
            "match": { "all": [{ "host": "shop.acme.test" }, { "path_prefix": "/" }] },
            "service": "web",
            "chain": [],
        }])
    );
    assert_eq!(
        stripped(&shop.app.services),
        json!([{ "name": "web", "type": "loadbalancer",
                 "servers": [{ "url": "http://10.0.0.1:8080" }, { "url": "http://10.0.0.2:8080" }] }])
    );
    assert_eq!(
        stripped(&shop.app.middlewares),
        json!([{ "name": "strip", "type": "strip_prefix", "prefixes": ["/api"] }])
    );
    assert_eq!(stripped(&shop.app.default_chain), json!(["strip"]));
    assert_eq!(
        stripped(&shop.app.tls)["mode"],
        "on_demand",
        "no tls means on_demand, as for an Ingress"
    );
    assert_eq!(
        stripped(&shop.app.revisions),
        json!([{ "id": "k8s", "state": "serving", "weight": 1, "services": [] }])
    );
    assert!(run.outage.is_none(), "{:?}", run.outage);

    // `tls` is the model's policy.
    let mut tls = web("shop.acme.test", json!({ "tls": { "mode": "acme" } }));
    tls["routers"][0]["name"] = json!("tls");
    api.put("podgateroutes", route("team-a", "secure", tls));
    let state = run
        .wait_ids(&["route_team-a.secure", "route_team-a.shop"])
        .await;
    assert_eq!(
        stripped(&app(&state, "route_team-a.secure").app.tls)["mode"],
        "acme"
    );
}

#[tokio::test]
async fn crd_service_ref_to_endpoints() {
    let api = FakeApi::start().await;
    let dir = Dir::new("serviceref");
    api.put(
        "services",
        k8s::service(
            "team-a",
            "web",
            &[(Some("http"), 80), (Some("metrics"), 9090)],
        ),
    );
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(Some("http"), 8080), (Some("metrics"), 9091)],
            &[
                ("10.0.0.1", true, false),
                ("10.0.0.2", false, false),
                ("10.0.0.3", true, true),
            ],
        ),
    );
    let mut spec = web("shop.acme.test", json!({}));
    spec["services"] = json!([
        { "name": "web", "type": "loadbalancer", "serviceRef": { "name": "web", "port": 80 } },
        { "name": "named", "type": "loadbalancer", "serviceRef": { "name": "web", "port": "http" } },
        { "name": "metrics", "type": "loadbalancer", "serviceRef": { "name": "web", "port": "metrics" } },
    ]);
    api.put("podgateroutes", route("team-a", "shop", spec));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.shop"]).await;

    let id = "route_team-a.shop";
    assert_eq!(servers(&state, id, "web"), ["http://10.0.0.1:8080"]);
    assert_eq!(
        servers(&state, id, "named"),
        ["http://10.0.0.1:8080"],
        "a port by number or by name is the same Service port"
    );
    assert_eq!(
        servers(&state, id, "metrics"),
        ["http://10.0.0.1:9091"],
        "the container port of that Service port"
    );

    // Pods come and go: the state follows the slices, with no change to the route.
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(Some("http"), 8080), (Some("metrics"), 9091)],
            &[("10.0.0.1", true, false), ("10.0.0.4", true, false)],
        ),
    );
    let state = run
        .wait("the new pod to appear", |state| {
            servers(state, id, "web") == ["http://10.0.0.1:8080", "http://10.0.0.4:8080"]
        })
        .await;
    assert_eq!(
        servers(&state, id, "metrics"),
        ["http://10.0.0.1:9091", "http://10.0.0.4:9091"]
    );

    // A Service that does not exist rejects the route, and says which.
    api.remove("services", "team-a", "web");
    let why = run.wait_outage("team-a/shop").await;
    assert!(
        why.contains("PodgateRoute team-a/shop rejected")
            && why.contains("Service team-a/web does not exist"),
        "{why}"
    );
}

#[tokio::test]
async fn crd_address_servers_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("servers");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut addressed = web("a.acme.test", json!({}));
    addressed["services"] = json!([{
        "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://10.0.0.9:80" }],
    }]);
    let mut both = web("b.acme.test", json!({}));
    both["services"][0]["servers"] = json!([{ "url": "http://10.0.0.9:80" }]);
    let mut host = web("c.acme.test", json!({}));
    host["services"][0]["serviceRef"]["name"] = json!("10.0.0.9");
    api.put(
        "podgateroutes",
        route("team-a", "addressed", addressed.clone()),
    );
    api.put("podgateroutes", route("team-a", "both", both.clone()));
    api.put("podgateroutes", route("team-a", "host", host));
    api.put(
        "podgateroutes",
        route("team-a", "good", web("d.acme.test", json!({}))),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.good"]).await;
    let why = run.wait_outage("team-a/host").await;
    for name in ["addressed", "both"] {
        assert!(
            why.contains(&format!("PodgateRoute team-a/{name} rejected"))
                && why.contains("`servers` are addresses"),
            "{why}"
        );
    }
    assert!(why.contains("a Service is named plainly"), "{why}");
    assert_eq!(
        servers(&state, "route_team-a.good", "web"),
        ["http://10.0.0.1:8080"],
        "the good route is served meanwhile"
    );

    // The schema refuses the same manifests before they reach the cluster.
    let routes = crd("podgateroutes.yaml");
    let validator = spec_validator(&routes);
    assert!(validator.is_valid(&web("d.acme.test", json!({}))));
    assert!(
        !validator.is_valid(&addressed),
        "servers in place of serviceRef"
    );
    assert!(!validator.is_valid(&both), "servers next to serviceRef");
}

#[tokio::test]
async fn crd_middleware_copied_into_app() {
    let api = FakeApi::start().await;
    let dir = Dir::new("copied");
    for namespace in ["team-a", "team-b"] {
        backend(
            &api,
            namespace,
            "web",
            80,
            8080,
            &[("10.0.0.1", true, false)],
        );
    }
    let auth = |namespace, prefix| {
        middleware(
            namespace,
            "auth",
            "strip_prefix",
            json!({ "prefixes": [prefix] }),
        )
    };
    api.put("podgatemiddlewares", auth("team-a", "/v1"));
    api.put("podgatemiddlewares", auth("team-b", "/b"));
    api.put(
        "podgatemiddlewares",
        middleware(
            "team-a",
            "unused",
            "strip_prefix",
            json!({ "prefixes": ["/x"] }),
        ),
    );
    let mut in_router = web("a.acme.test", json!({}));
    in_router["routers"][0]["chain"] = json!(["auth"]);
    api.put("podgateroutes", route("team-a", "a", in_router));
    api.put(
        "podgateroutes",
        route(
            "team-a",
            "b",
            web("b.acme.test", json!({ "default_chain": ["team-a/auth"] })),
        ),
    );
    api.put(
        "podgateroutes",
        route("team-a", "c", web("c.acme.test", json!({}))),
    );
    let mut other = web("globex.test", json!({}));
    other["routers"][0]["chain"] = json!(["auth"]);
    api.put("podgateroutes", route("team-b", "d", other));

    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run
        .wait_ids(&[
            "route_team-a.a",
            "route_team-a.b",
            "route_team-a.c",
            "route_team-b.d",
        ])
        .await;
    let strip =
        |prefix: &str| json!([{ "name": "auth", "type": "strip_prefix", "prefixes": [prefix] }]);
    let middlewares = |id: &str| stripped(&app(&state, id).app.middlewares);
    assert_eq!(middlewares("route_team-a.a"), strip("/v1"));
    assert_eq!(middlewares("route_team-a.b"), strip("/v1"));
    assert_eq!(
        middlewares("route_team-a.c"),
        json!([]),
        "a copy only where it is named"
    );
    assert_eq!(
        middlewares("route_team-b.d"),
        strip("/b"),
        "the namespace's own middleware, not the other one of the same name"
    );
    assert_eq!(
        stripped(&app(&state, "route_team-a.b").app.default_chain),
        json!(["auth"]),
        "namespace/name is the same object, named plainly in the app"
    );

    // Invariant 3: no object refers outside its own app.
    for source_app in &state.apps {
        let declared: Vec<&str> = source_app
            .app
            .middlewares
            .iter()
            .map(|declared| &*declared.name)
            .collect();
        let names = source_app.app.default_chain.iter().chain(
            source_app
                .app
                .routers
                .iter()
                .flat_map(|router| &router.chain),
        );
        for name in names {
            assert!(
                declared.contains(&&**name),
                "app {} names {name}, which it does not declare",
                source_app.app.id
            );
        }
    }

    // Changing the shared object changes every copy.
    api.put("podgatemiddlewares", auth("team-a", "/v2"));
    let state = run
        .wait("both copies to change", |state| {
            ["route_team-a.a", "route_team-a.b"]
                .iter()
                .all(|id| stripped(&app(state, id).app.middlewares) == strip("/v2"))
        })
        .await;
    assert_eq!(
        stripped(&app(&state, "route_team-b.d").app.middlewares),
        strip("/b")
    );
}

#[tokio::test]
async fn crd_missing_middleware_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("missing");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    let mut spec = web("a.acme.test", json!({}));
    spec["routers"][0]["chain"] = json!(["ghost"]);
    api.put("podgateroutes", route("team-a", "a", spec));
    api.put(
        "podgateroutes",
        route("team-a", "ok", web("ok.acme.test", json!({}))),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.ok"]).await;
    let why = run.wait_outage("team-a/a").await;
    assert!(
        why.contains("PodgateRoute team-a/a rejected")
            && why.contains("router web: chain")
            && why.contains("no PodgateMiddleware team-a/ghost"),
        "{why}"
    );
    assert_eq!(ids(&state), ["route_team-a.ok"]);

    // An object that cannot be read is named, and a route that uses it is refused.
    api.put(
        "podgatemiddlewares",
        middleware(
            "team-a",
            "ghost",
            "strip_prefix",
            json!({ "name": "other", "prefixes": ["/"] }),
        ),
    );
    let why = run.wait_outage("cannot be used").await;
    assert!(
        why.contains("PodgateMiddleware team-a/ghost rejected")
            && why.contains("spec.config holds `name` or `type`"),
        "{why}"
    );

    // Created properly, it is found, and the outage ends.
    api.put(
        "podgatemiddlewares",
        middleware(
            "team-a",
            "ghost",
            "strip_prefix",
            json!({ "prefixes": ["/"] }),
        ),
    );
    let state = run.wait_ids(&["route_team-a.a", "route_team-a.ok"]).await;
    assert_eq!(
        stripped(&app(&state, "route_team-a.a").app.middlewares),
        json!([{ "name": "ghost", "type": "strip_prefix", "prefixes": ["/"] }])
    );
    assert!(run.outage.is_none(), "{:?}", run.outage);
}

#[tokio::test]
async fn crd_cross_namespace_ref_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("cross");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    // Everything the routes of team-a reach for lives in team-b.
    backend(
        &api,
        "team-b",
        "only-b",
        80,
        8080,
        &[("10.0.0.2", true, false)],
    );
    api.put(
        "podgatemiddlewares",
        middleware(
            "team-b",
            "auth",
            "strip_prefix",
            json!({ "prefixes": ["/b"] }),
        ),
    );
    let mut qualified = web("q.acme.test", json!({}));
    qualified["routers"][0]["chain"] = json!(["team-b/auth"]);
    let mut plain = web("p.acme.test", json!({}));
    plain["routers"][0]["chain"] = json!(["auth"]);
    let mut service = web("s.acme.test", json!({}));
    service["services"][0]["serviceRef"]["name"] = json!("only-b");
    let mut dotted = web("d.acme.test", json!({}));
    dotted["services"][0]["serviceRef"]["name"] = json!("only-b.team-b");
    for (name, spec) in [
        ("qualified", qualified),
        ("plain", plain),
        ("service", service),
        ("dotted", dotted),
    ] {
        api.put("podgateroutes", route("team-a", name, spec));
    }
    api.put(
        "podgateroutes",
        route("team-a", "ok", web("ok.acme.test", json!({}))),
    );
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.ok"]).await;
    let why = run.wait_outage("team-a/dotted").await;
    assert!(
        why.contains("PodgateRoute team-a/qualified rejected")
            && why.contains("uses only the middlewares of its own namespace"),
        "{why}"
    );
    assert!(
        why.contains("PodgateRoute team-a/plain rejected")
            && why.contains("no PodgateMiddleware team-a/auth"),
        "a plain name never falls through to another namespace: {why}"
    );
    assert!(
        why.contains("PodgateRoute team-a/service rejected")
            && why.contains("Service team-a/only-b does not exist"),
        "a Service is looked up in the route's own namespace: {why}"
    );
    assert!(
        why.contains("PodgateRoute team-a/dotted rejected")
            && why.contains("a Service is named plainly"),
        "{why}"
    );
    assert_eq!(ids(&state), ["route_team-a.ok"]);
}

#[tokio::test]
async fn crd_foreign_host_rejected() {
    let api = FakeApi::start().await;
    let dir = Dir::new("foreign");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put(
        "podgateroutes",
        route("team-a", "shop", web("shop.acme.test", json!({}))),
    );
    api.put(
        "podgateroutes",
        route("team-a", "stolen", web("globex.test", json!({}))),
    );
    api.put(
        "podgateroutes",
        route("team-a", "elsewhere", web("anything.example", json!({}))),
    );
    // The host claim hides in the matcher tree: it is still a claim.
    let mut nested = web("shop.acme.test", json!({}));
    nested["routers"][0]["match"] =
        json!({ "any": [{ "host": "shop.acme.test" }, { "host": "globex.test" }] });
    api.put("podgateroutes", route("team-a", "nested", nested));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.shop"]).await;
    let why = run.wait_outage("team-a/nested").await;
    for name in ["stolen", "elsewhere", "nested"] {
        assert!(
            why.contains(&format!("PodgateRoute team-a/{name} rejected"))
                && why.contains("foreign_host_claim"),
            "{name}: {why}"
        );
    }
    assert_eq!(ids(&state), ["route_team-a.shop"]);
}

#[tokio::test]
async fn crd_tenant_from_namespace() {
    let api = FakeApi::start().await;
    let dir = Dir::new("tenant");
    for namespace in ["team-a", "team-b", "team-c"] {
        backend(
            &api,
            namespace,
            "web",
            80,
            8080,
            &[("10.0.0.1", true, false)],
        );
    }
    api.put(
        "podgateroutes",
        route("team-a", "a", web("a.acme.test", json!({}))),
    );
    api.put(
        "podgateroutes",
        route("team-b", "b", web("globex.test", json!({}))),
    );
    // `spec.tenant` is a label claim on top of the namespace's mapping; the core decides on it.
    api.put(
        "podgateroutes",
        route(
            "team-a",
            "claim",
            web("claim.acme.test", json!({ "tenant": "globex" })),
        ),
    );
    // team-c is mapped to nobody: the core gives it the provider's default tenant.
    api.put(
        "podgateroutes",
        route("team-c", "c", web("c.example", json!({}))),
    );
    // globex may not have a catch-all router: that router goes, the route stays.
    let mut catch_all = web("globex.test", json!({}));
    catch_all["routers"] = json!([
        { "name": "host", "match": { "all": [{ "host": "globex.test" }, { "path_prefix": "/" }] }, "service": "web" },
        { "name": "everything", "match": { "path_prefix": "/" }, "service": "web", "priority": -1 },
    ]);
    api.put("podgateroutes", route("team-b", "site", catch_all));

    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run
        .wait("every route", |state| {
            ids(state).len() >= 4 && ids(state).contains(&"route_team-b.site".to_owned())
        })
        .await;
    assert_eq!(
        app(&state, "route_team-a.a").tenant.mapped.as_deref(),
        Some("acme")
    );
    assert_eq!(
        app(&state, "route_team-b.b").tenant.mapped.as_deref(),
        Some("globex")
    );
    let claim = app(&state, "route_team-a.claim");
    assert_eq!(claim.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(claim.tenant.label.as_deref(), Some("globex"));

    let site = app(&state, "route_team-b.site");
    let names: Vec<&str> = site
        .app
        .routers
        .iter()
        .map(|router| &*router.name)
        .collect();
    assert_eq!(names, ["host"], "the catch-all router is left out");
    let why = run.wait_outage("catch_all_not_allowed").await;
    assert!(
        why.contains("PodgateRoute team-b/site") && why.contains("router everything"),
        "{why}"
    );
}

#[tokio::test]
async fn crd_transport_client_cert_from_secret() {
    let api = FakeApi::start().await;
    let dir = Dir::new("transport");
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put(
        "secrets",
        k8s::secret(
            "team-a",
            "mtls",
            "kubernetes.io/tls",
            "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
        ),
    );
    let mut good = web("good.acme.test", json!({}));
    good["transports"] =
        json!([{ "name": "t", "type": "servers_transport", "clientCertSecret": "mtls" }]);
    let mut inline = web("inline.acme.test", json!({}));
    inline["transports"] = json!([{
        "name": "t", "type": "servers_transport",
        "client_cert": { "cert_pem": "c", "key_pem": "k" },
    }]);
    let mut missing = web("missing.acme.test", json!({}));
    missing["transports"] =
        json!([{ "name": "t", "type": "servers_transport", "clientCertSecret": "nope" }]);
    api.put("podgateroutes", route("team-a", "good", good));
    api.put("podgateroutes", route("team-a", "inline", inline));
    api.put("podgateroutes", route("team-a", "missing", missing));
    let mut run = Run::start(&config(&api, &dir, ""));
    let state = run.wait_ids(&["route_team-a.good"]).await;
    let transports = stripped(&app(&state, "route_team-a.good").app.transports);
    assert_eq!(
        transports[0]["client_cert"],
        json!({
            "cert_pem": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
            "key_pem": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
        })
    );
    let why = run.wait_outage("team-a/missing").await;
    assert!(
        why.contains("PodgateRoute team-a/inline rejected")
            && why.contains("would put a private key in the manifest"),
        "{why}"
    );
    assert!(
        why.contains("no Secret team-a/nope of type kubernetes.io/tls"),
        "{why}"
    );
    assert!(
        !why.contains("PRIVATE-KEY-BODY"),
        "no key material in a message: {why}"
    );
}

#[tokio::test]
async fn crd_disabled_by_default() {
    // Without `crds = true` the source never asks for the kinds, so a cluster without the CRDs
    // works as before.
    let api = FakeApi::start().await;
    let dir = Dir::new("disabled");
    api.put(
        "podgateroutes",
        route("team-a", "a", web("a.acme.test", json!({}))),
    );
    backend(
        &api,
        "team-a",
        "web",
        80,
        8080,
        &[("10.0.0.1", true, false)],
    );
    api.put(
        "ingresses",
        k8s::ingress(
            "team-a",
            "shop",
            "podgate",
            json!([k8s::rule(
                Some("shop.acme.test"),
                &[("/", "Prefix", "web", json!(80))]
            )]),
        ),
    );
    let mut disabled = config(&api, &dir, "");
    disabled.sources[0].settings.remove("crds");
    let mut run = Run::start(&disabled);
    let state = run.wait_ids(&["team-a.shop"]).await;
    assert_eq!(ids(&state), ["team-a.shop"]);
    assert_eq!(api.count("podgateroutes", false), 0);
    assert_eq!(api.count("podgatemiddlewares", false), 0);
}

// ---- through the daemon ----------------------------------------------------------------------

async fn get(addr: std::net::SocketAddr, host: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("proxy");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write");
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut raw),
    )
    .await;
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

#[tokio::test]
async fn crd_route_through_the_daemon() {
    // The app a route becomes is one the daemon compiles and serves: a matcher tree, a service
    // resolved from EndpointSlices, and a middleware copied from a PodgateMiddleware.
    let api = FakeApi::start().await;
    let dir = Dir::new("daemon");
    let ports = common::free_ports(2);
    let policy = dir.0.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = common::daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let (upstream, _task) = common::daemon::backend("from-the-backend").await;
    backend(
        &api,
        "team-a",
        "web",
        80,
        upstream.port(),
        &[("127.0.0.1", true, false)],
    );
    api.put(
        "podgatemiddlewares",
        middleware(
            "team-a",
            "strip",
            "strip_prefix",
            json!({ "prefixes": ["/api"] }),
        ),
    );
    let mut spec = web("shop.acme.test", json!({}));
    spec["routers"][0]["match"] =
        json!({ "all": [{ "host": "shop.acme.test" }, { "path_prefix": "/api" }] });
    spec["routers"][0]["chain"] = json!(["strip"]);
    api.put("podgateroutes", route("team-a", "shop", spec));

    let extra = format!(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n",
        policy.display().to_string()
    );
    let kubeconfig = api.kubeconfig(&dir.0, "test-token");
    let config = common::config(
        &daemon.admin,
        &format!(
            "{extra}{}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\ncrds = true\nnamespace_tenants = {{ team-a = \"acme\" }}\n",
            common::k8s_crd::TENANTS,
            kubeconfig.display().to_string()
        ),
    );
    let mut engine = podgate_provider::Engine::new(
        config.clone(),
        podgate_provider::UpstreamPolicy::load(&policy).expect("policy"),
    )
    .with_tuning(common::fast_tuning());
    engine
        .add_source(common::k8s_crd::source(&config))
        .expect("source");
    let status_rx = engine.status();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let _ = engine
            .run(async {
                let _ = stopped.await;
            })
            .await;
    });

    let started = std::time::Instant::now();
    loop {
        let (status, body) = get(daemon.proxy, "shop.acme.test", "/api/x").await;
        if status == 200 {
            assert_eq!(body, "from-the-backend");
            break;
        }
        assert!(
            started.elapsed() < common::DEADLINE,
            "the route never went live; provider status: {:?}",
            *status_rx.borrow()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        get(daemon.proxy, "shop.acme.test", "/other").await.0,
        404,
        "the router's matcher is the manifest's"
    );
    let _ = stop.send(());
    let _ = run.await;
}

// ---- the manifests ---------------------------------------------------------------------------

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture() -> Value {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/snapshot-schema.json"),
    )
    .expect("the schema fixture");
    serde_json::from_str(&text).expect("the fixture is JSON")
}

/// The committed manifest `file`, parsed.
fn crd(file: &str) -> Value {
    let text = fs::read_to_string(root().join("deploy/crd").join(file))
        .unwrap_or_else(|err| panic!("deploy/crd/{file}: {err}"));
    serde_yaml_ng::from_str(&text).unwrap_or_else(|err| panic!("deploy/crd/{file}: {err}"))
}

fn spec_schema(crd: &Value) -> &Value {
    &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
}

/// Adds what the API server's strict field validation does: an object with declared properties
/// refuses any other key. Only the structural part is walked, never a `oneOf` branch.
fn strict(node: &mut Value) {
    let Some(object) = node.as_object_mut() else {
        return;
    };
    let opaque = object.get("x-kubernetes-preserve-unknown-fields") == Some(&json!(true));
    let has_properties = object.contains_key("properties");
    if let Some(Value::Object(properties)) = object.get_mut("properties") {
        properties.values_mut().for_each(strict);
    }
    if let Some(items) = object.get_mut("items") {
        strict(items);
    }
    if let Some(additional @ Value::Object(_)) = object.get_mut("additionalProperties") {
        strict(additional);
    }
    if has_properties && !opaque {
        object.insert("additionalProperties".to_owned(), json!(false));
    }
}

/// A validator of the `spec` of `crd` that also refuses unknown fields.
fn spec_validator(crd: &Value) -> jsonschema::Validator {
    let mut schema = spec_schema(crd).clone();
    strict(&mut schema);
    jsonschema::validator_for(&schema).expect("the spec schema compiles")
}

fn errors(validator: &jsonschema::Validator, instance: &Value) -> Vec<String> {
    validator
        .iter_errors(instance)
        .map(|err| format!("{err} at {}", err.instance_path()))
        .collect()
}

/// The rules of the API server for a structural schema (`apiextensions-apiserver`,
/// `pkg/apiserver/schema`: `validateStructuralInvariants`, `validateStructuralCompleteness` and
/// the nested-context checks), as far as the generator can break them.
fn structural_errors(crd: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let root = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
    if root["type"] != "object" {
        errors.push("root: type must be object".to_owned());
    }
    if root.get("additionalProperties").is_some() {
        errors.push("root: additionalProperties must not be used at the root".to_owned());
    }
    for field in ["apiVersion", "kind", "metadata"] {
        if root["properties"].get(field).is_some() {
            errors.push(format!("root: {field} is implicit, never declared"));
        }
    }
    structural(root, "root", &mut errors);
    errors
}

const FORBIDDEN: [&str; 9] = [
    "$ref",
    "$defs",
    "const",
    "default",
    "format",
    "pattern",
    "uniqueItems",
    "exclusiveMinimum",
    "exclusiveMaximum",
];

fn structural(node: &Value, at: &str, errors: &mut Vec<String>) {
    let Some(object) = node.as_object() else {
        errors.push(format!("{at}: not a schema object"));
        return;
    };
    for key in FORBIDDEN {
        if object.contains_key(key) {
            errors.push(format!("{at}: {key} is not allowed"));
        }
    }
    if object.get("additionalProperties") == Some(&json!(false)) {
        errors.push(format!("{at}: additionalProperties: false is not allowed"));
    }
    if object.contains_key("additionalProperties") && object.contains_key("properties") {
        errors.push(format!(
            "{at}: additionalProperties and properties are mutually exclusive"
        ));
    }
    let kind = object.get("type").and_then(Value::as_str);
    let preserve = object.get("x-kubernetes-preserve-unknown-fields") == Some(&json!(true));
    let int_or_string = object.get("x-kubernetes-int-or-string") == Some(&json!(true));
    if kind.is_none() && !preserve && !int_or_string {
        errors.push(format!("{at}: type must not be empty"));
    }
    if preserve && int_or_string {
        errors.push(format!("{at}: preserve-unknown-fields and int-or-string"));
    }
    if kind == Some("array") && !object.contains_key("items") {
        errors.push(format!("{at}: an array needs items"));
    }
    for junctor in ["oneOf", "anyOf", "allOf"] {
        let Some(Value::Array(branches)) = object.get(junctor) else {
            continue;
        };
        // The integer-or-string pattern is the one junctor allowed to carry types.
        if junctor == "anyOf" && int_or_string {
            continue;
        }
        for (index, branch) in branches.iter().enumerate() {
            nested(branch, node, &format!("{at}.{junctor}[{index}]"), errors);
        }
    }
    if let Some(Value::Object(properties)) = object.get("properties") {
        for (name, property) in properties {
            structural(property, &format!("{at}.{name}"), errors);
        }
    }
    if let Some(items) = object.get("items") {
        structural(items, &format!("{at}[]"), errors);
    }
    if let Some(additional @ Value::Object(_)) = object.get("additionalProperties") {
        structural(additional, &format!("{at}{{}}"), errors);
    }
}

/// A `oneOf` branch `value`, which may only restrict what `structure` already declares.
fn nested(value: &Value, structure: &Value, at: &str, errors: &mut Vec<String>) {
    let Some(object) = value.as_object() else {
        errors.push(format!("{at}: not a schema object"));
        return;
    };
    for key in [
        "type",
        "additionalProperties",
        "default",
        "title",
        "description",
        "nullable",
        "x-kubernetes-preserve-unknown-fields",
        "x-kubernetes-int-or-string",
        "x-kubernetes-validations",
    ] {
        if object.contains_key(key) {
            errors.push(format!("{at}: {key} must be undefined in a junctor"));
        }
    }
    for junctor in ["oneOf", "anyOf", "allOf"] {
        if let Some(Value::Array(branches)) = object.get(junctor) {
            for (index, branch) in branches.iter().enumerate() {
                nested(
                    branch,
                    structure,
                    &format!("{at}.{junctor}[{index}]"),
                    errors,
                );
            }
        }
    }
    if let Some(Value::Object(properties)) = object.get("properties") {
        for (name, property) in properties {
            match structure
                .get("properties")
                .and_then(|known| known.get(name))
            {
                None => errors.push(format!(
                    "{at}.{name}: defined in a junctor but not in the structural part"
                )),
                Some(known) => nested(property, known, &format!("{at}.{name}"), errors),
            }
        }
    }
    if let Some(items) = object.get("items") {
        match structure.get("items") {
            None => errors.push(format!("{at}[]: items only in a junctor")),
            Some(known) => nested(items, known, &format!("{at}[]"), errors),
        }
    }
}

/// `word` with its second letter missing: a typo made on purpose (the spelling checker of the gate
/// would flag it written out).
fn typo(word: &str) -> String {
    word.chars()
        .enumerate()
        .filter(|(index, _)| *index != 1)
        .map(|(_, letter)| letter)
        .collect()
}

/// A route spec that uses most of what the schema describes.
fn rich_route() -> Value {
    json!({
        "tenant": "acme",
        "tls": { "mode": "acme", "client_ca_pem": "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", "min_version": "1.2" },
        "default_chain": ["security", "team-a/shared"],
        "routers": [
            {
                "name": "api",
                "entry_points": ["websecure"],
                "match": { "all": [
                    { "host": ["shop.acme.test", "www.acme.test"] },
                    { "path_prefix": "/api" },
                    { "any": [{ "method": ["GET", "HEAD"] }, { "not": { "header": { "name": "x-debug", "value": "1" } } }] },
                ] },
                "priority": 10,
                "chain": ["strip"],
                "service": "web",
            },
            { "name": "site", "match": { "host": "shop.acme.test" }, "service": "canary" },
        ],
        "services": [
            { "name": "web", "type": "loadbalancer", "algorithm": "round_robin", "pass_host_header": true,
              "serviceRef": { "name": "web", "port": "http" } },
            { "name": "canary", "type": "loadbalancer", "algorithm": { "type": "header_hash", "header": "x-user" },
              "transport": "mtls", "serviceRef": { "name": "canary", "port": 8080 } },
        ],
        "transports": [
            { "name": "mtls", "type": "servers_transport", "dial_timeout_secs": 5, "clientCertSecret": "mtls" },
        ],
        "middlewares": [
            { "name": "strip", "type": "strip_prefix", "prefixes": ["/api"] },
            { "name": "security", "type": "headers", "response": { "set": { "x-frame-options": "DENY" } } },
        ],
    })
}

#[test]
fn crd_schema_validates_samples() {
    let routes = crd("podgateroutes.yaml");
    let middlewares = crd("podgatemiddlewares.yaml");
    let route_validator = spec_validator(&routes);
    let middleware_validator = spec_validator(&middlewares);

    let rich = rich_route();
    let found = errors(&route_validator, &rich);
    assert!(found.is_empty(), "the rich route is valid: {found:?}");
    let minimal = web("a.acme.test", json!({}));
    assert!(route_validator.is_valid(&minimal));
    // A matcher nested deeper than the schema unrolls is free-form there, and still accepted.
    let mut deep = minimal.clone();
    deep["routers"][0]["match"] =
        json!({ "all": [{ "all": [{ "all": [{ "all": [{ "all": [{ "host": "a" }] }] }] }] }] });
    let found = errors(&route_validator, &deep);
    assert!(found.is_empty(), "{found:?}");

    for (spec, why) in [
        (
            json!({ "type": "strip_prefix", "config": { "prefixes": ["/api"] } }),
            "a middleware",
        ),
        (
            json!({ "type": "basic_auth", "config": { "users": ["alice:$2y$05$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012"], "realm": "x" } }),
            "needs only its own fields",
        ),
    ] {
        let found = errors(&middleware_validator, &spec);
        assert!(found.is_empty(), "{why}: {found:?}");
    }

    // The samples of the reference are valid too, so the page cannot teach a manifest the
    // schema refuses.
    let page = fs::read_to_string(root().join("docs/ref/provider-crd.md")).expect("the reference");
    let mut checked = 0;
    for block in page.split("```yaml\n").skip(1) {
        let text = block.split("```").next().unwrap_or("");
        for document in text.split("\n---\n") {
            let object: Value = serde_yaml_ng::from_str(document).expect("a YAML sample");
            let validator = match object["kind"].as_str() {
                Some("PodgateRoute") => &route_validator,
                Some("PodgateMiddleware") => &middleware_validator,
                _ => continue,
            };
            let found = errors(validator, &object["spec"]);
            assert!(found.is_empty(), "{document}\n{found:?}");
            checked += 1;
        }
    }
    assert!(checked >= 2, "the reference has samples of both kinds");
}

#[test]
fn crd_schema_rejects_unknown_fields() {
    let routes = crd("podgateroutes.yaml");
    let middlewares = crd("podgatemiddlewares.yaml");
    let route_validator = spec_validator(&routes);
    let middleware_validator = spec_validator(&middlewares);
    assert!(route_validator.is_valid(&rich_route()));

    let broken = |edit: &dyn Fn(&mut Value)| {
        let mut spec = rich_route();
        edit(&mut spec);
        spec
    };
    let route_cases: Vec<(&str, Value)> = vec![
        (
            "a typo in the spec",
            broken(&|spec| {
                spec["routres"] = json!([]);
            }),
        ),
        (
            "a missing required field",
            broken(&|spec| {
                spec.as_object_mut().map(|spec| spec.remove("routers"));
            }),
        ),
        (
            "a typo in a router",
            broken(&|spec| {
                spec["routers"][0][typo("service").as_str()] = json!("web");
            }),
        ),
        (
            "provenance in a router",
            broken(&|spec| {
                spec["routers"][0]["declared_by"] = json!("someone");
            }),
        ),
        (
            "a typo in a service",
            broken(&|spec| {
                spec["services"][0][typo("algorithm").as_str()] = json!("random");
            }),
        ),
        (
            "a typo in a serviceRef",
            broken(&|spec| {
                spec["services"][0]["serviceRef"]["prot"] = json!(80);
            }),
        ),
        (
            "a serviceRef without a port",
            broken(&|spec| {
                spec["services"][0]["serviceRef"]
                    .as_object_mut()
                    .map(|r| r.remove("port"));
            }),
        ),
        (
            "a loadbalancer without serviceRef",
            broken(&|spec| {
                spec["services"][0]
                    .as_object_mut()
                    .map(|s| s.remove("serviceRef"));
            }),
        ),
        (
            "addresses in a loadbalancer",
            broken(&|spec| {
                spec["services"][0]["servers"] = json!([{ "url": "http://10.0.0.1:80" }]);
            }),
        ),
        (
            "an unknown service type",
            broken(&|spec| {
                spec["services"][0]["type"] = json!("teleport");
            }),
        ),
        (
            "a typo in an inline middleware",
            broken(&|spec| {
                spec["middlewares"][0]["prefixs"] = json!(["/x"]);
            }),
        ),
        (
            "an inline middleware without its required field",
            broken(&|spec| {
                spec["middlewares"][0]
                    .as_object_mut()
                    .map(|m| m.remove("prefixes"));
            }),
        ),
        (
            "an unknown middleware type",
            broken(&|spec| {
                spec["middlewares"][0]["type"] = json!("teleport");
            }),
        ),
        (
            "a private key in a transport",
            broken(&|spec| {
                spec["transports"][0]["client_cert"] = json!({ "cert_pem": "c", "key_pem": "k" });
            }),
        ),
        (
            "a typo in a transport",
            broken(&|spec| {
                spec["transports"][0]["dial_timeout"] = json!(5);
            }),
        ),
        (
            "a typo in tls",
            broken(&|spec| {
                spec["tls"][typo("mode").as_str()] = json!("acme");
            }),
        ),
        (
            "an unknown tls mode",
            broken(&|spec| {
                spec["tls"]["mode"] = json!("sometimes");
            }),
        ),
        (
            "a typo in a matcher",
            broken(&|spec| {
                spec["routers"][1]["match"] = json!({ "hostt": "a.test" });
            }),
        ),
        (
            "two keys in one matcher",
            broken(&|spec| {
                spec["routers"][1]["match"] = json!({ "host": "a.test", "path": "/" });
            }),
        ),
        (
            "a typo in a nested matcher",
            broken(&|spec| {
                spec["routers"][0]["match"]["all"][0] = json!({ "hots": "a.test" });
            }),
        ),
        (
            "a wrong type",
            broken(&|spec| {
                spec["routers"][0]["priority"] = json!("high");
            }),
        ),
    ];
    for (why, spec) in route_cases {
        assert!(!route_validator.is_valid(&spec), "must be refused: {why}");
    }

    let middleware_cases: Vec<(&str, Value)> = vec![
        (
            "a typo in the spec",
            json!({ "type": "strip_prefix", "config_": {} }),
        ),
        (
            "a typo in the config",
            json!({ "type": "strip_prefix", "config": { "prefixs": ["/x"] } }),
        ),
        (
            "a missing required field",
            json!({ "type": "strip_prefix", "config": {} }),
        ),
        ("a missing config", json!({ "type": "basic_auth" })),
        (
            "an unknown type",
            json!({ "type": "teleport", "config": {} }),
        ),
        ("no type", json!({ "config": { "prefixes": ["/x"] } })),
    ];
    for (why, spec) in middleware_cases {
        assert!(
            !middleware_validator.is_valid(&spec),
            "must be refused: {why}"
        );
    }
}

#[test]
fn crd_manifests_are_structural() {
    for file in ["podgateroutes.yaml", "podgatemiddlewares.yaml"] {
        let manifest = crd(file);
        let found = structural_errors(&manifest);
        assert!(
            found.is_empty(),
            "{file} is not a structural schema:\n{}",
            found.join("\n")
        );
        let compact = serde_json::to_string(&manifest).expect("serializes").len();
        assert!(
            compact < 240_000,
            "{file} is {compact} bytes as JSON: close to the 262144 of kubectl's last-applied annotation"
        );
        assert_eq!(manifest["spec"]["group"], "podgate.io");
        assert_eq!(manifest["spec"]["scope"], "Namespaced");
        assert_eq!(manifest["spec"]["versions"][0]["name"], "v1alpha1");
    }
}

#[test]
fn crd_manifests_not_stale() {
    let fresh = schema::manifests(&fixture()).expect("the fixture generates");
    for manifest in &fresh {
        let committed = fs::read_to_string(root().join("deploy/crd").join(manifest.file))
            .unwrap_or_else(|err| panic!("deploy/crd/{}: {err}", manifest.file));
        assert!(
            committed == manifest.yaml,
            "deploy/crd/{} is stale: regenerate it with `podgate-provider print-crd --schema crates/podgate-provider/tests/fixtures/snapshot-schema.json --out deploy/crd` (docs/ref/provider-crd.md)",
            manifest.file
        );
    }
}

#[tokio::test]
async fn crd_manifests_match_the_daemon() {
    // The fixture is the daemon's own document: a middleware that lands changes the daemon's
    // schema, and this fails until the fixture and the manifests are regenerated with it.
    let dir = Dir::new("print");
    let ports = common::free_ports(2);
    let policy = dir.0.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = common::daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let (status, mut live) = daemon.admin_get("/v1/schema").await;
    assert_eq!(status, 200);
    live.as_object_mut()
        .map(|live| live.remove("podgate_version"));
    assert!(
        live == fixture(),
        "tests/fixtures/snapshot-schema.json is not the daemon's schema: regenerate it with `podgate-provider print-crd --socket <admin socket> --save-schema crates/podgate-provider/tests/fixtures/snapshot-schema.json --out deploy/crd`"
    );

    // The command itself, from the socket, writes what is committed.
    let out = dir.0.join("out");
    fs::create_dir_all(&out).expect("out dir");
    let output = Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
        .arg("print-crd")
        .arg("--socket")
        .arg(&daemon.admin)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run print-crd");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for file in ["podgateroutes.yaml", "podgatemiddlewares.yaml"] {
        let written = fs::read_to_string(out.join(file)).expect("a written manifest");
        let committed =
            fs::read_to_string(root().join("deploy/crd").join(file)).expect("committed");
        assert!(
            written == committed,
            "deploy/crd/{file} differs from print-crd's output"
        );
    }

    // Without --out, one YAML stream on stdout; a missing source is a usage error.
    let stream = Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
        .args(["print-crd", "--schema"])
        .arg(root().join("crates/podgate-provider/tests/fixtures/snapshot-schema.json"))
        .output()
        .expect("run print-crd");
    let text = String::from_utf8_lossy(&stream.stdout);
    assert!(
        text.contains("kind: CustomResourceDefinition") && text.contains("\n---\n"),
        "{text}"
    );
    let usage = Command::new(env!("CARGO_BIN_EXE_podgate-provider"))
        .arg("print-crd")
        .output()
        .expect("run print-crd");
    assert_eq!(usage.status.code(), Some(2));
}
