#![allow(
    clippy::needless_pass_by_value,
    reason = "the object builders take the JSON they embed, so a call site reads like the manifest"
)]

//! Tests of the Gateway API half of the Kubernetes source.
//!
//! Most tests feed objects straight into [`gateway::translate`] (no network, no timing), the
//! rest run the source against the fake API server (`common/k8s.rs`) and one runs a snapshot
//! through the real daemon. Everything that waits has a deadline.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use common::k8s::{self, FakeApi};
use common::{DEADLINE, config as base_config};
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::client::Event;
use podgate_provider::kubernetes::endpoints::{EndpointSlice, Secret, Service, ServiceIndex};
use podgate_provider::kubernetes::gateway::types::CONTROLLER;
use podgate_provider::kubernetes::gateway::{Cache, Change, Options, Translation};
use podgate_provider::kubernetes::ingress::Cluster;
use podgate_provider::kubernetes::tenancy::Tenancy;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, UpstreamPolicy};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
catch_all = true

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]

[[tenant]]
id = "zeta"
hosts = ["zeta.test"]
exclusive_entry_points = ["zeta"]
"#;

const GROUP: &str = "gateway.networking.k8s.io";

fn config() -> Config {
    base_config(
        &std::env::temp_dir().join("pgp-gw-unused.sock"),
        &format!("{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\n"),
    )
}

// ---- builders ---------------------------------------------------------------------------------

fn class(name: &str, controller: &str) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "GatewayClass",
            "metadata": { "name": name }, "spec": { "controllerName": controller } })
}

fn namespace(name: &str, labels: Value) -> Value {
    json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": name, "labels": labels } })
}

fn listener(name: &str, port: u16, protocol: &str, hostname: Option<&str>) -> Value {
    let mut listener = json!({ "name": name, "port": port, "protocol": protocol });
    if let Some(hostname) = hostname {
        listener["hostname"] = json!(hostname);
    }
    listener
}

fn with(mut value: Value, key: &str, extra: Value) -> Value {
    value[key] = extra;
    value
}

fn gateway(namespace: &str, name: &str, class: &str, listeners: Value) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "Gateway",
            "metadata": { "namespace": namespace, "name": name, "creationTimestamp": "2026-11-01T00:00:00Z" },
            "spec": { "gatewayClassName": class, "listeners": listeners } })
}

fn all_namespaces() -> Value {
    json!({ "namespaces": { "from": "All" } })
}

/// The usual Gateway: one HTTP listener on 80 that accepts routes of every namespace.
fn open_gateway(namespace: &str, name: &str) -> Value {
    gateway(
        namespace,
        name,
        "podgate",
        json!([with(
            listener("http", 80, "HTTP", None),
            "allowedRoutes",
            all_namespaces()
        )]),
    )
}

fn parent(namespace: &str, gateway: &str, section: Option<&str>) -> Value {
    let mut parent = json!({ "namespace": namespace, "name": gateway });
    if let Some(section) = section {
        parent["sectionName"] = json!(section);
    }
    parent
}

fn route(
    kind: &str,
    namespace: &str,
    name: &str,
    created: &str,
    parents: Value,
    hostnames: &[&str],
    rules: Value,
) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": kind,
            "metadata": { "namespace": namespace, "name": name, "creationTimestamp": created },
            "spec": { "parentRefs": parents, "hostnames": hostnames, "rules": rules } })
}

fn http_route(namespace: &str, name: &str, hostnames: &[&str], rules: Value) -> Value {
    route(
        "HTTPRoute",
        namespace,
        name,
        "2026-11-10T00:00:00Z",
        json!([parent("team-a", "gw", None)]),
        hostnames,
        rules,
    )
}

fn backend(name: &str, port: u16) -> Value {
    json!({ "name": name, "port": port })
}

fn weighted(name: &str, port: u16, weight: u32) -> Value {
    json!({ "name": name, "port": port, "weight": weight })
}

fn rule(matches: Value, backends: Value) -> Value {
    json!({ "matches": matches, "backendRefs": backends })
}

// ---- the world -------------------------------------------------------------------------------

/// Objects of the cluster, by plural, fed to the translation as a source would hold them.
struct World {
    objects: BTreeMap<&'static str, Vec<Value>>,
}

fn parse<T: DeserializeOwned>(objects: &[Value]) -> Vec<T> {
    objects
        .iter()
        .map(|object| serde_json::from_value(object.clone()).expect("a valid object"))
        .collect()
}

impl World {
    /// Namespaces `team-a`, `team-a2` (both `acme`), `team-b` (`globex`) and `team-z` (`zeta`), the
    /// served class, an open Gateway `team-a/gw`, and a Service `web` in `team-a`.
    fn new() -> Self {
        let mut world = Self {
            objects: BTreeMap::new(),
        };
        world.put("gatewayclasses", class("podgate", CONTROLLER));
        for name in ["team-a", "team-a2", "team-b", "team-z"] {
            world.put("namespaces", namespace(name, json!({ "tenant": name })));
        }
        world.put("gateways", open_gateway("team-a", "gw"));
        world.service("team-a", "web", 80, 8080, &["10.0.0.1"]);
        world
    }

    fn put(&mut self, plural: &'static str, object: Value) {
        self.objects.entry(plural).or_default().push(object);
    }

    fn service(&mut self, namespace: &str, name: &str, port: u16, container: u16, ips: &[&str]) {
        self.put("services", k8s::service(namespace, name, &[(None, port)]));
        let endpoints: Vec<(&str, bool, bool)> = ips.iter().map(|ip| (*ip, true, false)).collect();
        self.put(
            "endpointslices",
            k8s::slice(namespace, name, 0, &[(None, container)], &endpoints),
        );
    }

    fn list(&self, plural: &str) -> &[Value] {
        self.objects.get(plural).map_or(&[], Vec::as_slice)
    }

    fn translate(&self) -> Translation {
        self.translate_with(None)
    }

    fn translate_with(&self, entry_points: Option<BTreeMap<String, String>>) -> Translation {
        let config = config();
        let mut cache = Cache::new(1);
        let mut outages = BTreeMap::new();
        cache.apply(
            &mut outages,
            0,
            Change::Class(Event::Reset(parse(self.list("gatewayclasses")))),
        );
        cache.apply(
            &mut outages,
            0,
            Change::Namespace(Event::Reset(parse(self.list("namespaces")))),
        );
        cache.apply(
            &mut outages,
            0,
            Change::Gateway(Event::Reset(parse(self.list("gateways")))),
        );
        cache.apply(
            &mut outages,
            0,
            Change::Http(Event::Reset(parse(self.list("httproutes")))),
        );
        cache.apply(
            &mut outages,
            0,
            Change::Grpc(Event::Reset(parse(self.list("grpcroutes")))),
        );
        cache.apply(
            &mut outages,
            0,
            Change::Grant(Event::Reset(parse(self.list("referencegrants")))),
        );
        let services: Vec<Service> = parse(self.list("services"));
        let slices: Vec<EndpointSlice> = parse(self.list("endpointslices"));
        let secrets: Vec<Secret> = parse(self.list("secrets"));
        let index = ServiceIndex::new(services.iter(), slices.iter(), false);
        let secret = |namespace: &str, name: &str| {
            secrets.iter().find(|secret| {
                secret.metadata.namespace() == namespace && secret.metadata.name == name
            })
        };
        let tenancy = Tenancy::new(
            "k8s",
            &config,
            BTreeMap::from([
                ("team-a".into(), "acme".into()),
                ("team-a2".into(), "acme".into()),
                ("team-b".into(), "globex".into()),
                ("team-z".into(), "zeta".into()),
            ]),
            None,
        )
        .expect("tenancy");
        let cluster = Cluster {
            source: "k8s",
            tenancy: &tenancy,
            services: &index,
            secret: &secret,
        };
        let options = Options::new(None, entry_points).expect("options");
        podgate_provider::kubernetes::gateway::translate(&cache, &options, &cluster)
    }
}

fn app<'a>(translation: &'a Translation, id: &str) -> &'a podgate_provider::SourceApp {
    translation
        .apps
        .iter()
        .find(|app| &*app.app.id == id)
        .unwrap_or_else(|| {
            panic!(
                "no app {id}: apps {:?}; notes {:?}",
                translation
                    .apps
                    .iter()
                    .map(|app| app.app.id.to_string())
                    .collect::<Vec<_>>(),
                translation.notes
            )
        })
}

/// The JSON of `value` without the fields that are absent (the model serializes them as null).
fn strip(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, strip(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(strip).collect()),
        other => other,
    }
}

fn routers(translation: &Translation, id: &str) -> Value {
    strip(serde_json::to_value(&app(translation, id).app.routers).expect("routers"))
}

fn services(translation: &Translation, id: &str) -> Value {
    strip(serde_json::to_value(&app(translation, id).app.services).expect("services"))
}

fn middlewares(translation: &Translation, id: &str) -> Value {
    strip(serde_json::to_value(&app(translation, id).app.middlewares).expect("middlewares"))
}

/// The one rejection the route `key` got, as `(reason, message)`.
fn rejection(translation: &Translation, key: &str) -> (&'static str, String) {
    let report = translation
        .routes
        .iter()
        .find(|report| report.key == key)
        .unwrap_or_else(|| panic!("no report for {key}: {:?}", translation.routes));
    let rejected = report
        .rejected
        .as_ref()
        .unwrap_or_else(|| panic!("{key} was accepted: {:?}", translation.apps));
    (rejected.reason, rejected.message.clone())
}

fn accepted(translation: &Translation, key: &str) -> bool {
    translation
        .routes
        .iter()
        .find(|report| report.key == key)
        .is_some_and(|report| report.rejected.is_none())
}

// ---- routes become routers -------------------------------------------------------------------

#[test]
fn httproute_matches_to_routers() {
    let mut world = World::new();
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            &["shop.acme.test"],
            json!([rule(
                json!([
                    { "path": { "type": "PathPrefix", "value": "/api" },
                      "headers": [{ "name": "X-Env", "value": "canary" }],
                      "queryParams": [{ "name": "v", "value": "2" }],
                      "method": "GET" },
                    { "path": { "type": "Exact", "value": "/health" } },
                    { "path": { "type": "RegularExpression", "value": "/v[0-9]+/.*" },
                      "headers": [{ "type": "RegularExpression", "name": "x-id", "value": "[0-9]+" },
                                  { "name": "X-ID", "value": "ignored: the first of a name wins" }] },
                ]),
                json!([backend("web", 80)])
            )]),
        ),
    );
    let translation = world.translate();
    assert!(translation.notes.is_empty(), "{:?}", translation.notes);
    let shop = app(&translation, "httproute_team-a_shop");
    assert_eq!(&*shop.origin.object, "HTTPRoute/team-a/shop");
    assert_eq!(shop.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(shop.origin.first_seen, 1_794_268_800);
    assert_eq!(
        routers(&translation, "httproute_team-a_shop"),
        json!([
            { "name": "r0m0", "entry_points": ["web"], "priority": 1, "service": "team-a.web.80", "chain": [],
              "match": { "all": [
                  { "host": "shop.acme.test" },
                  { "path_prefix": "/api" },
                  { "header": { "name": "X-Env", "value": "canary" } },
                  { "query": { "name": "v", "value": "2" } },
                  { "method": "GET" } ] } },
            { "name": "r0m1", "entry_points": ["web"], "priority": 3, "service": "team-a.web.80", "chain": [],
              "match": { "all": [ { "host": "shop.acme.test" }, { "path": "/health" } ] } },
            { "name": "r0m2", "entry_points": ["web"], "priority": 2, "service": "team-a.web.80", "chain": [],
              "match": { "all": [
                  { "host": "shop.acme.test" },
                  { "path_regexp": "^(?:/v[0-9]+/.*)$" },
                  { "header_regexp": { "name": "x-id", "regex": "^(?:[0-9]+)$" } } ] } },
        ])
    );
    assert_eq!(
        services(&translation, "httproute_team-a_shop"),
        json!([{ "name": "team-a.web.80", "type": "loadbalancer", "servers": [{ "url": "http://10.0.0.1:8080" }] }])
    );
    // A match without a path is the whole site, and a rule with no match at all is too.
    let mut world = World::new();
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "site",
            &["site.acme.test"],
            json!([{ "backendRefs": [backend("web", 80)] }]),
        ),
    );
    let translation = world.translate();
    assert_eq!(
        routers(&translation, "httproute_team-a_site")[0]["match"],
        json!({ "all": [{ "host": "site.acme.test" }, { "path_prefix": "/" }] })
    );
}

#[test]
fn httproute_backend_weights_to_weighted_service() {
    let mut world = World::new();
    world.service("team-a", "web-v2", 80, 8081, &["10.0.0.2"]);
    world.service("team-a", "off", 80, 8082, &["10.0.0.3"]);
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "canary",
            &["c.acme.test"],
            json!([rule(
                json!([{ "path": { "value": "/" } }]),
                json!([
                    weighted("web", 80, 90),
                    weighted("web-v2", 80, 10),
                    weighted("off", 80, 0)
                ])
            )]),
        ),
    );
    let translation = world.translate();
    let id = "httproute_team-a_canary";
    assert_eq!(routers(&translation, id)[0]["service"], "r0-split");
    let services = services(&translation, id);
    let split = services
        .as_array()
        .and_then(|all| all.iter().find(|service| service["name"] == "r0-split"))
        .expect("the split");
    assert_eq!(
        split,
        &json!({ "name": "r0-split", "type": "weighted", "services": [
            { "service": "team-a.web.80", "weight": 90 },
            { "service": "team-a.web-v2.80", "weight": 10 } ] })
    );
    let names: Vec<&str> = services
        .as_array()
        .expect("services")
        .iter()
        .map(|service| service["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(
        names,
        ["r0-split", "team-a.web-v2.80", "team-a.web.80"],
        "a weight of 0 sends nothing, so its service is not declared"
    );

    // Only weight-0 backends: the rule has nothing to send to and answers 500, as the API says.
    let mut world = World::new();
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "dark",
            &["d.acme.test"],
            json!([rule(json!([]), json!([weighted("web", 80, 0)]))]),
        ),
    );
    let translation = world.translate();
    let id = "httproute_team-a_dark";
    assert_eq!(routers(&translation, id)[0]["service"], "none");
    assert_eq!(routers(&translation, id)[0]["chain"], json!(["r0f0"]));
    assert_eq!(
        middlewares(&translation, id),
        json!([{ "name": "r0f0", "type": "respond", "status": 500 }])
    );
}

#[test]
fn filters_translate_into_the_chain() {
    let mut world = World::new();
    world.service("team-a", "shadow", 80, 9090, &["10.0.0.9"]);
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "filters",
            &["f.acme.test"],
            json!([
                { "matches": [{ "path": { "value": "/api" } }],
                  "filters": [
                    { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                        "set": [{ "name": "X-Tenant", "value": "acme" }], "remove": ["X-Debug"] } },
                    { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "set": [{ "name": "X-Served-By", "value": "podgate" }] } },
                    { "type": "URLRewrite", "urlRewrite": { "path": {
                        "type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2" } } },
                    { "type": "RequestMirror", "requestMirror": {
                        "backendRef": backend("shadow", 80), "fraction": { "numerator": 1, "denominator": 1000 } } },
                  ],
                  "backendRefs": [backend("web", 80)] },
                { "matches": [{ "path": { "value": "/old" } }],
                  "filters": [{ "type": "RequestRedirect", "requestRedirect": {
                      "scheme": "https", "statusCode": 301 } }] },
            ]),
        ),
    );
    let translation = world.translate();
    assert!(translation.notes.is_empty(), "{:?}", translation.notes);
    let id = "httproute_team-a_filters";
    let routers = routers(&translation, id);
    assert_eq!(routers[0]["chain"], json!(["r0f0", "r0f1", "r0m0f2"]));
    assert_eq!(routers[0]["service"], "r0-mirror");
    assert_eq!(routers[1]["chain"], json!(["r1f0"]));
    assert_eq!(routers[1]["service"], "none", "a redirect needs no backend");
    assert_eq!(
        middlewares(&translation, id),
        json!([
            { "name": "r0f0", "type": "headers", "request": { "set": { "x-tenant": "acme" }, "remove": ["x-debug"] } },
            { "name": "r0f1", "type": "headers", "response": { "set": { "x-served-by": "podgate" } } },
            { "name": "r0m0f2", "type": "replace_path_regex", "regex": "^/api(?P<rest>/.*)?$", "replacement": "/v2${rest}" },
            { "name": "r1f0", "type": "redirect_scheme", "scheme": "https", "permanent": true },
        ])
    );
    let services = services(&translation, id);
    let mirror = services
        .as_array()
        .and_then(|all| all.iter().find(|service| service["name"] == "r0-mirror"))
        .expect("the mirror");
    assert_eq!(
        mirror,
        &json!({ "name": "r0-mirror", "type": "mirroring", "service": "team-a.web.80",
                 "mirrors": [{ "service": "team-a.shadow.80", "percent": 0.1 }], "mirror_body": true })
    );
}

#[test]
fn unsupported_filter_rejects_route_with_a_reason() {
    let cases = [
        (
            json!({ "filters": [{ "type": "RequestHeaderModifier", "requestHeaderModifier": {
                "add": [{ "name": "x", "value": "1" }] } }] }),
            "add is not supported",
        ),
        (
            json!({ "filters": [{ "type": "URLRewrite", "urlRewrite": { "hostname": "x.test" } }] }),
            "hostname",
        ),
        (
            json!({ "filters": [{ "type": "ExtensionRef", "extensionRef": { "group": "podgate.io", "kind": "Middleware", "name": "m" } }] }),
            "0076",
        ),
        (json!({ "timeouts": { "request": "1s" } }), "timeouts"),
        (
            json!({ "sessionPersistence": { "sessionName": "s" } }),
            "sessionPersistence",
        ),
        (
            json!({ "matches": [{ "path": { "type": "RegularExpression", "value": "(" } }] }),
            "regular expression",
        ),
        (
            json!({ "backendRefs": [{ "name": "web", "port": 80, "filters": [{ "type": "RequestMirror" }] }] }),
            "filters of its own",
        ),
    ];
    for (index, (rule, needle)) in cases.into_iter().enumerate() {
        let mut world = World::new();
        let mut rule = rule;
        if rule.get("backendRefs").is_none() {
            rule["backendRefs"] = json!([backend("web", 80)]);
        }
        world.put(
            "httproutes",
            http_route("team-a", "bad", &["bad.acme.test"], json!([rule])),
        );
        let translation = world.translate();
        let (reason, message) = rejection(&translation, "team-a/bad");
        assert_eq!(reason, "UnsupportedValue", "case {index}: {message}");
        assert!(
            message.contains(needle),
            "case {index}: {needle:?} not in {message:?}"
        );
        assert!(
            translation.apps.is_empty(),
            "case {index}: nothing is served"
        );
        assert!(
            translation
                .notes
                .iter()
                .any(|note| note.contains("HTTPRoute team-a/bad rejected")),
            "the outage report names the route: {:?}",
            translation.notes
        );
    }
}

#[test]
fn grpcroute_method_matches() {
    let mut world = World::new();
    world.service("team-a", "greeter", 50051, 50052, &["10.0.0.7"]);
    world.put(
        "grpcroutes",
        route(
            "GRPCRoute",
            "team-a",
            "rpc",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", None)]),
            &["rpc.acme.test"],
            json!([
                { "matches": [
                    { "method": { "service": "helloworld.Greeter", "method": "SayHello" } },
                    { "method": { "service": "helloworld.Greeter" },
                      "headers": [{ "name": "x-env", "value": "dev" }] },
                    { "method": { "type": "RegularExpression", "service": "echo\\..*", "method": "Echo.*" } },
                    { "method": { "method": "Ping" } },
                    {},
                  ],
                  "backendRefs": [backend("greeter", 50051)] }
            ]),
        ),
    );
    let translation = world.translate();
    assert!(translation.notes.is_empty(), "{:?}", translation.notes);
    let id = "grpcroute_team-a_rpc";
    let content_type = json!({ "header_regexp": { "name": "content-type",
        "regex": "^application/grpc(?:\\+[^;]*)?(?:;.*)?$" } });
    let routers = routers(&translation, id);
    let matchers: Vec<&Value> = routers
        .as_array()
        .expect("routers")
        .iter()
        .map(|router| &router["match"])
        .collect();
    let host = json!({ "host": "rpc.acme.test" });
    assert_eq!(
        matchers,
        [
            &json!({ "all": [host, { "path": "/helloworld.Greeter/SayHello" }, content_type] }),
            &json!({ "all": [host, { "path_prefix": "/helloworld.Greeter" }, content_type,
                             { "header": { "name": "x-env", "value": "dev" } }] }),
            &json!({ "all": [host, { "path_regexp": "^(?:/(?:echo\\..*)/(?:Echo.*))$" }, content_type] }),
            &json!({ "all": [host, { "path_regexp": "^/[^/]+/Ping$" }, content_type] }),
            &json!({ "all": [host, content_type] }),
        ]
    );
    // Service and method named exactly outrank the service alone, then a method alone, then
    // every call.
    let priority = |name: &str| {
        routers
            .as_array()
            .and_then(|all| all.iter().find(|router| router["name"] == name))
            .map(|router| router["priority"].as_i64().expect("a priority"))
            .expect("a router")
    };
    assert!(
        priority("r0m0") > priority("r0m1"),
        "service+method over service"
    );
    assert!(
        priority("r0m1") > priority("r0m3"),
        "service over method alone"
    );
    assert!(
        priority("r0m3") > priority("r0m2"),
        "a method alone over expressions"
    );
    assert!(
        priority("r0m2") > priority("r0m4"),
        "expressions over every call"
    );
    // gRPC speaks HTTP/2: plain servers become h2c.
    assert_eq!(
        services(&translation, id)[0]["servers"],
        json!([{ "url": "h2c://10.0.0.7:50052" }])
    );
}

// ---- attachment ------------------------------------------------------------------------------

#[test]
fn allowed_routes_same_namespace() {
    let mut world = World::new();
    // Listeners: the default (Same), All, a label Selector, and a kind list without GRPCRoute.
    world.objects.get_mut("gateways").expect("gateways").clear();
    world.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            "podgate",
            json!([
                listener("same", 8081, "HTTP", None),
                with(
                    listener("selected", 8082, "HTTP", None),
                    "allowedRoutes",
                    json!({ "namespaces": { "from": "Selector",
                        "selector": { "matchLabels": { "tenant": "team-b" } } } })
                ),
                with(
                    listener("everyone", 8083, "HTTP", None),
                    "allowedRoutes",
                    json!({ "namespaces": { "from": "All" }, "kinds": [{ "kind": "HTTPRoute" }] })
                ),
            ]),
        ),
    );
    world.service("team-b", "web", 80, 8080, &["10.0.1.1"]);
    let entry_points = Some(BTreeMap::from([
        ("8081".to_owned(), "same".to_owned()),
        ("8082".to_owned(), "selected".to_owned()),
        ("8083".to_owned(), "everyone".to_owned()),
    ]));
    let attach = |world: &mut World, name: &str, ns: &str, section: &str| {
        world.put(
            "httproutes",
            route(
                "HTTPRoute",
                ns,
                name,
                "2026-11-10T00:00:00Z",
                json!([parent("team-a", "gw", Some(section))]),
                &[if ns == "team-a" {
                    "a.acme.test"
                } else {
                    "b.globex.test"
                }],
                json!([rule(json!([]), json!([backend("web", 80)]))]),
            ),
        );
    };
    attach(&mut world, "own", "team-a", "same");
    attach(&mut world, "foreign", "team-b", "same");
    attach(&mut world, "labelled", "team-b", "selected");
    attach(&mut world, "unlabelled", "team-a", "selected");
    attach(&mut world, "anywhere", "team-b", "everyone");
    world.put(
        "grpcroutes",
        route(
            "GRPCRoute",
            "team-b",
            "rpc",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", Some("everyone"))]),
            &["b.globex.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    let translation = world.translate_with(entry_points);
    assert!(
        accepted(&translation, "team-a/own"),
        "{:?}",
        translation.notes
    );
    let (reason, message) = rejection(&translation, "team-b/foreign");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(message.contains("from is Same"), "{message}");
    assert!(
        accepted(&translation, "team-b/labelled"),
        "{:?}",
        translation.notes
    );
    let (_, message) = rejection(&translation, "team-a/unlabelled");
    assert!(message.contains("do not match"), "{message}");
    assert!(accepted(&translation, "team-b/anywhere"));
    let (_, message) = rejection(&translation, "team-b/rpc");
    assert!(
        message.contains("kinds does not list GRPCRoute"),
        "{message}"
    );
    // The parent report says what happened to each parent reference.
    let foreign = translation
        .routes
        .iter()
        .find(|report| report.key == "team-b/foreign")
        .expect("a report");
    assert_eq!(foreign.parents.len(), 1);
    assert!(!foreign.parents[0].accepted);
    assert_eq!(foreign.parents[0].gateway, "team-a/gw");
    assert_eq!(foreign.parents[0].section.as_deref(), Some("same"));
}

#[test]
fn listener_hostname_intersection() {
    let mut world = World::new();
    world.objects.get_mut("gateways").expect("gateways").clear();
    world.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            "podgate",
            json!([with(
                listener("wild", 80, "HTTP", Some("*.acme.test")),
                "allowedRoutes",
                all_namespaces()
            )]),
        ),
    );
    let attach = |world: &mut World, name: &str, hostnames: &[&str]| {
        world.put(
            "httproutes",
            http_route(
                "team-a",
                name,
                hostnames,
                json!([rule(json!([]), json!([backend("web", 80)]))]),
            ),
        );
    };
    // The names that fit the listener stay, the others drop out; a wildcard narrower than the
    // listener's wins over it, and an exact name inside the wildcard is kept as it is.
    attach(
        &mut world,
        "mixed",
        &["shop.acme.test", "other.test", "*.eu.acme.test"],
    );
    attach(&mut world, "inherits", &[]);
    attach(&mut world, "outside", &["x.other.test"]);
    let translation = world.translate();
    assert_eq!(
        routers(&translation, "httproute_team-a_mixed")[0]["match"],
        json!({ "all": [{ "host": ["shop.acme.test", "*.eu.acme.test"] }, { "path_prefix": "/" }] })
    );
    assert_eq!(
        routers(&translation, "httproute_team-a_inherits")[0]["match"],
        json!({ "all": [{ "host": "*.acme.test" }, { "path_prefix": "/" }] }),
        "a route with no host names inherits the listener's"
    );
    let (reason, message) = rejection(&translation, "team-a/outside");
    assert_eq!(reason, "NoMatchingListenerHostname");
    assert!(message.contains("*.acme.test"), "{message}");
}

#[test]
fn listener_port_maps_to_entry_point() {
    let mut world = World::new();
    world.objects.get_mut("gateways").expect("gateways").clear();
    world.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            "podgate",
            json!([
                with(
                    listener("http", 80, "HTTP", None),
                    "allowedRoutes",
                    all_namespaces()
                ),
                with(
                    with(
                        listener("https", 443, "HTTPS", None),
                        "allowedRoutes",
                        all_namespaces()
                    ),
                    "tls",
                    json!({ "mode": "Terminate" })
                ),
                with(
                    listener("odd", 8080, "HTTP", None),
                    "allowedRoutes",
                    all_namespaces()
                ),
                with(
                    listener("tcp", 5432, "TCP", None),
                    "allowedRoutes",
                    all_namespaces()
                ),
            ]),
        ),
    );
    let attach = |world: &mut World, name: &str, sections: &[&str]| {
        let parents: Vec<Value> = sections
            .iter()
            .map(|section| parent("team-a", "gw", Some(section)))
            .collect();
        world.put(
            "httproutes",
            route(
                "HTTPRoute",
                "team-a",
                name,
                "2026-11-10T00:00:00Z",
                json!(parents),
                &["p.acme.test"],
                json!([rule(json!([]), json!([backend("web", 80)]))]),
            ),
        );
    };
    attach(&mut world, "plain", &["http"]);
    attach(&mut world, "secure", &["https"]);
    attach(&mut world, "both", &["http", "https"]);
    attach(&mut world, "odd", &["odd"]);
    attach(&mut world, "tcp", &["tcp"]);
    let translation = world.translate();
    let entry_points = |id: &str| routers(&translation, id)[0]["entry_points"].clone();
    assert_eq!(entry_points("httproute_team-a_plain"), json!(["web"]));
    assert_eq!(
        entry_points("httproute_team-a_secure"),
        json!(["websecure"])
    );
    assert_eq!(
        entry_points("httproute_team-a_both"),
        json!(["web", "websecure"]),
        "one router listens on the entry points of both listeners"
    );
    let (reason, message) = rejection(&translation, "team-a/odd");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(
        message.contains("port 8080 has no entry point")
            && message.contains("listener_entry_points"),
        "{message}"
    );
    let (_, message) = rejection(&translation, "team-a/tcp");
    assert!(message.contains("carries no HTTP route"), "{message}");

    // The map is the operator's: 8080 can be given an entry point.
    let mapped = world.translate_with(Some(BTreeMap::from([
        ("80".to_owned(), "web".to_owned()),
        ("8080".to_owned(), "alt".to_owned()),
    ])));
    assert_eq!(
        routers(&mapped, "httproute_team-a_odd")[0]["entry_points"],
        json!(["alt"])
    );
}

#[test]
fn other_gateway_class_ignored() {
    let mut world = World::new();
    world.put(
        "gateways",
        gateway(
            "team-a",
            "foreign",
            "someone-else",
            json!([listener("http", 80, "HTTP", None)]),
        ),
    );
    world.put(
        "httproutes",
        route(
            "HTTPRoute",
            "team-a",
            "theirs",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "foreign", None)]),
            &["t.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    let translation = world.translate();
    assert!(translation.apps.is_empty());
    assert!(translation.routes.is_empty(), "not our route: no report");
    assert!(translation.notes.is_empty(), "{:?}", translation.notes);

    // Our class name with a controller that is not ours: nothing is served either.
    let mut world = World::new();
    world
        .objects
        .get_mut("gatewayclasses")
        .expect("classes")
        .clear();
    world.put(
        "gatewayclasses",
        class("podgate", "example.com/other-controller"),
    );
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "mine",
            &["m.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    let translation = world.translate();
    assert!(translation.apps.is_empty());
    assert!(translation.routes.is_empty());
}

// ---- precedence ------------------------------------------------------------------------------

#[test]
fn gateway_precedence_applies_to_routers_of_a_tenant() {
    let mut world = World::new();
    let one = |world: &mut World, name: &str, created: &str, path: Value| {
        world.put(
            "httproutes",
            route(
                "HTTPRoute",
                "team-a",
                name,
                created,
                json!([parent("team-a", "gw", None)]),
                &["p.acme.test"],
                json!([rule(json!([{ "path": path }]), json!([backend("web", 80)]))]),
            ),
        );
    };
    one(
        &mut world,
        "young-exact",
        "2026-11-12T00:00:00Z",
        json!({ "type": "Exact", "value": "/x" }),
    );
    one(
        &mut world,
        "old-exact",
        "2026-11-01T00:00:00Z",
        json!({ "type": "Exact", "value": "/x" }),
    );
    one(
        &mut world,
        "prefix",
        "2026-10-01T00:00:00Z",
        json!({ "value": "/" }),
    );
    let translation = world.translate();
    let priority = |id: &str| {
        routers(&translation, id)[0]["priority"]
            .as_i64()
            .expect("priority")
    };
    assert_eq!(
        priority("httproute_team-a_old-exact"),
        3,
        "the oldest of two equal matches"
    );
    assert_eq!(priority("httproute_team-a_young-exact"), 2);
    assert_eq!(
        priority("httproute_team-a_prefix"),
        1,
        "a prefix never outranks an exact path"
    );
}

#[test]
fn precedence_never_crosses_tenants_in_the_output() {
    let mut world = World::new();
    // Tenant acme has three routers, tenant globex one. Globex's number does not depend on
    // acme's routers, so no priority of one tenant is above another's by construction.
    for (name, path) in [("a1", "/one"), ("a2", "/two"), ("a3", "/three")] {
        world.put(
            "httproutes",
            http_route(
                "team-a",
                name,
                &["p.acme.test"],
                json!([rule(
                    json!([{ "path": { "type": "Exact", "value": path } }]),
                    json!([backend("web", 80)])
                )]),
            ),
        );
    }
    world.service("team-b", "web", 80, 8080, &["10.0.1.1"]);
    world.put(
        "httproutes",
        route(
            "HTTPRoute",
            "team-b",
            "g1",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", None)]),
            &["p.globex.test"],
            json!([rule(
                json!([{ "path": { "type": "Exact", "value": "/one" } }]),
                json!([backend("web", 80)])
            )]),
        ),
    );
    let translation = world.translate();
    let mut acme: Vec<i64> = ["a1", "a2", "a3"]
        .iter()
        .map(|name| {
            routers(&translation, &format!("httproute_team-a_{name}"))[0]["priority"]
                .as_i64()
                .expect("priority")
        })
        .collect();
    acme.sort_unstable();
    assert_eq!(acme, [1, 2, 3]);
    assert_eq!(
        routers(&translation, "httproute_team-b_g1")[0]["priority"],
        1,
        "globex's only router is 1 whatever acme has"
    );
}

// ---- tenancy ---------------------------------------------------------------------------------

#[test]
fn reference_grant_required() {
    let mut world = World::new();
    world.service("team-a2", "api", 80, 8080, &["10.0.2.1"]);
    let cross = |name: &str| {
        http_route(
            "team-a",
            name,
            &["x.acme.test"],
            json!([rule(
                json!([]),
                json!([{ "name": "api", "namespace": "team-a2", "port": 80 }])
            )]),
        )
    };
    world.put("httproutes", cross("cross"));
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/cross");
    assert_eq!(reason, "RefNotPermitted");
    assert!(
        message.contains("no ReferenceGrant in team-a2"),
        "{message}"
    );

    // A grant for another kind of referrer, or another namespace, or another Service, is no grant.
    let grant = |from_kind: &str, from_ns: &str, to_name: Option<&str>| {
        let mut to = json!({ "group": "", "kind": "Service" });
        if let Some(name) = to_name {
            to["name"] = json!(name);
        }
        json!({ "apiVersion": format!("{GROUP}/v1beta1"), "kind": "ReferenceGrant",
                "metadata": { "namespace": "team-a2", "name": "g" },
                "spec": { "from": [{ "group": GROUP, "kind": from_kind, "namespace": from_ns }], "to": [to] } })
    };
    for (kind, ns, name) in [
        ("GRPCRoute", "team-a", None),
        ("HTTPRoute", "team-b", None),
        ("HTTPRoute", "team-a", Some("other")),
    ] {
        let mut world = World::new();
        world.service("team-a2", "api", 80, 8080, &["10.0.2.1"]);
        world.put("httproutes", cross("cross"));
        world.put("referencegrants", grant(kind, ns, name));
        let translation = world.translate();
        assert_eq!(
            rejection(&translation, "team-a/cross").0,
            "RefNotPermitted",
            "{kind} {ns} {name:?}"
        );
    }

    // The right grant (any Service, or this one by name) lets it through, inside one tenant.
    for name in [None, Some("api")] {
        let mut world = World::new();
        world.service("team-a2", "api", 80, 8080, &["10.0.2.1"]);
        world.put("httproutes", cross("cross"));
        world.put("referencegrants", grant("HTTPRoute", "team-a", name));
        let translation = world.translate();
        assert!(
            accepted(&translation, "team-a/cross"),
            "{:?}",
            translation.notes
        );
        assert_eq!(
            routers(&translation, "httproute_team-a_cross")[0]["service"],
            "team-a2.api.80"
        );
    }
}

#[test]
fn reference_grant_to_other_tenant_refused() {
    let mut world = World::new();
    world.service("team-b", "api", 80, 8080, &["10.0.1.1"]);
    world.put(
        "referencegrants",
        json!({ "apiVersion": format!("{GROUP}/v1beta1"), "kind": "ReferenceGrant",
                "metadata": { "namespace": "team-b", "name": "open" },
                "spec": { "from": [{ "group": GROUP, "kind": "HTTPRoute", "namespace": "team-a" }],
                          "to": [{ "group": "", "kind": "Service" }] } }),
    );
    world.put(
        "httproutes",
        http_route(
            "team-a",
            "steal",
            &["s.acme.test"],
            json!([rule(
                json!([]),
                json!([{ "name": "api", "namespace": "team-b", "port": 80 }])
            )]),
        ),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/steal");
    assert_eq!(reason, "RefNotPermitted");
    assert!(
        message.contains("another tenant") && message.contains("with a ReferenceGrant or without"),
        "{message}"
    );
    assert!(translation.apps.is_empty());
}

#[test]
fn route_on_forbidden_entry_point_rejected() {
    let mut world = World::new();
    world.objects.get_mut("gateways").expect("gateways").clear();
    world.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            "podgate",
            json!([with(
                listener("private", 9443, "HTTP", None),
                "allowedRoutes",
                all_namespaces()
            )]),
        ),
    );
    world.service("team-z", "web", 80, 8080, &["10.0.9.1"]);
    for (ns, name, host) in [
        ("team-a", "intruder", "i.acme.test"),
        ("team-z", "owner", "zeta.test"),
    ] {
        world.put(
            "httproutes",
            route(
                "HTTPRoute",
                ns,
                name,
                "2026-11-10T00:00:00Z",
                json!([parent("team-a", "gw", None)]),
                &[host],
                json!([rule(json!([]), json!([backend("web", 80)]))]),
            ),
        );
    }
    let translation = world.translate_with(Some(BTreeMap::from([(
        "9443".to_owned(),
        "zeta".to_owned(),
    )])));
    let (reason, message) = rejection(&translation, "team-a/intruder");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(
        message.contains("entry_point_forbidden") && message.contains("exclusive to tenant zeta"),
        "{message}"
    );
    assert!(
        accepted(&translation, "team-z/owner"),
        "{:?}",
        translation.notes
    );
}

#[test]
fn gateway_route_foreign_host_rejected() {
    let mut world = World::new();
    world.service("team-b", "web", 80, 8080, &["10.0.1.1"]);
    world.put(
        "httproutes",
        route(
            "HTTPRoute",
            "team-b",
            "grab",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", None)]),
            &["shop.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    let translation = world.translate();
    let (_, message) = rejection(&translation, "team-b/grab");
    assert!(
        message.contains("foreign_host_claim") && message.contains("globex"),
        "{message}"
    );
    assert!(translation.apps.is_empty());
}

#[test]
fn gateway_hostless_route_needs_catch_all_allowance() {
    let mut world = World::new();
    world.service("team-b", "web", 80, 8080, &["10.0.1.1"]);
    let hostless = |ns: &str, name: &str| {
        route(
            "HTTPRoute",
            ns,
            name,
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", None)]),
            &[],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        )
    };
    // acme has `catch_all = true`; globex does not.
    world.put("httproutes", hostless("team-a", "anything"));
    world.put("httproutes", hostless("team-b", "anything"));
    let translation = world.translate();
    assert_eq!(
        routers(&translation, "httproute_team-a_anything")[0]["match"],
        json!({ "path_prefix": "/" }),
        "no host leaf: a host-less router"
    );
    let (_, message) = rejection(&translation, "team-b/anything");
    assert!(message.contains("catch_all_not_allowed"), "{message}");
    assert!(accepted(&translation, "team-a/anything"));
}

// ---- certificates ----------------------------------------------------------------------------

#[test]
fn gateway_listener_certificates_follow_the_same_rules() {
    let mut world = World::new();
    world.objects.get_mut("gateways").expect("gateways").clear();
    let tls = |name: &str, namespace: Option<&str>| {
        let mut reference = json!({ "name": name });
        if let Some(namespace) = namespace {
            reference["namespace"] = json!(namespace);
        }
        json!({ "mode": "Terminate", "certificateRefs": [reference] })
    };
    world.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            "podgate",
            json!([
                with(
                    with(
                        listener("shop", 443, "HTTPS", Some("shop.acme.test")),
                        "tls",
                        tls("shop-tls", None)
                    ),
                    "allowedRoutes",
                    all_namespaces()
                ),
                with(
                    with(
                        listener("other", 8443, "HTTPS", Some("o.acme.test")),
                        "tls",
                        tls("tls", Some("team-b"))
                    ),
                    "allowedRoutes",
                    all_namespaces()
                ),
                with(
                    with(
                        listener("shared", 9443, "HTTPS", Some("s.acme.test")),
                        "tls",
                        tls("tls", Some("team-a2"))
                    ),
                    "allowedRoutes",
                    all_namespaces()
                ),
                with(
                    with(
                        listener("any", 7443, "HTTPS", None),
                        "tls",
                        tls("any-tls", None)
                    ),
                    "allowedRoutes",
                    all_namespaces()
                ),
            ]),
        ),
    );
    world.put(
        "secrets",
        k8s::secret(
            "team-a",
            "shop-tls",
            "kubernetes.io/tls",
            "CERT-SHOP",
            "KEY-SHOP",
        ),
    );
    world.put(
        "secrets",
        k8s::secret(
            "team-a",
            "any-tls",
            "kubernetes.io/tls",
            "CERT-ANY",
            "KEY-ANY",
        ),
    );
    world.put(
        "secrets",
        k8s::secret("team-b", "tls", "kubernetes.io/tls", "C", "K"),
    );
    world.put(
        "secrets",
        k8s::secret("team-a2", "tls", "kubernetes.io/tls", "C2", "K2"),
    );
    // A route on the listener without a hostname gives the certificate its names.
    world.put(
        "httproutes",
        route(
            "HTTPRoute",
            "team-a",
            "any",
            "2026-11-10T00:00:00Z",
            json!([parent("team-a", "gw", Some("any"))]),
            &["b.acme.test", "a.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    let translation = world.translate_with(Some(BTreeMap::from([
        ("443".to_owned(), "websecure".to_owned()),
        ("8443".to_owned(), "websecure".to_owned()),
        ("9443".to_owned(), "websecure".to_owned()),
        ("7443".to_owned(), "websecure".to_owned()),
    ])));
    let certificates: Vec<(String, Value, String)> = translation
        .certificates
        .iter()
        .map(|cert| {
            let value = serde_json::to_value(&cert.certificate).expect("certificate");
            (
                cert.origin.object.to_string(),
                value["hosts"].clone(),
                value["cert_pem"].as_str().expect("pem").to_owned(),
            )
        })
        .collect();
    assert_eq!(
        certificates,
        [
            (
                "Gateway/team-a/gw#any-0".to_owned(),
                json!(["a.acme.test", "b.acme.test"]),
                "CERT-ANY".to_owned()
            ),
            (
                "Gateway/team-a/gw#shop-0".to_owned(),
                json!(["shop.acme.test"]),
                "CERT-SHOP".to_owned()
            ),
        ],
    );
    let notes = translation.notes.join("\n");
    assert!(
        notes.contains("another tenant"),
        "the other tenant's Secret is refused: {notes}"
    );
    assert!(
        notes.contains("no ReferenceGrant in team-a2"),
        "a Secret in another namespace needs a grant: {notes}"
    );
}

// ---- the source ------------------------------------------------------------------------------

fn dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pgp-gw-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create the test directory");
    path
}

fn tuning() -> podgate_provider::kubernetes::client::Tuning {
    podgate_provider::kubernetes::client::Tuning {
        watch_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        backoff_min: Duration::from_millis(20),
        backoff_max: Duration::from_millis(80),
        page_size: 2,
    }
}

fn source_config(api: &FakeApi, dir: &std::path::Path, extra: &str) -> Config {
    let kubeconfig = api.kubeconfig(dir, "test-token");
    base_config(
        &dir.join("admin.sock"),
        &format!(
            "{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\", team-b = \"globex\" }}\n{extra}\n",
            kubeconfig.display().to_string()
        ),
    )
}

fn source(config: &Config) -> KubernetesSource {
    KubernetesSource::from_config(&config.sources[0], config)
        .expect("a valid Kubernetes source")
        .with_tuning(tuning())
        .with_settle(Duration::from_millis(20))
}

async fn next_state(
    rx: &mut mpsc::Receiver<Update>,
    what: &str,
    done: impl Fn(&State) -> bool,
) -> (State, Vec<String>) {
    let mut outages = Vec::new();
    let wait = async {
        loop {
            let update = rx.recv().await.expect("the source keeps running");
            match update.body {
                UpdateBody::State(state) if done(&state) => return state,
                UpdateBody::State(_) => {}
                UpdateBody::Outage(why) => outages.push(why.to_string()),
            }
        }
    };
    let state = tokio::time::timeout(DEADLINE, wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for: {what}"));
    (state, outages)
}

fn gateway_world(api: &FakeApi) {
    api.put("gatewayclasses", class("podgate", CONTROLLER));
    api.put("namespaces", namespace("team-a", json!({})));
    api.put("namespaces", namespace("team-b", json!({})));
    api.put("gateways", open_gateway("team-a", "gw"));
    api.put("services", k8s::service("team-a", "web", &[(None, 80)]));
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, 8080)],
            &[("10.0.0.1", true, false)],
        ),
    );
}

#[tokio::test]
async fn gateway_source_follows_the_cluster() {
    let api = FakeApi::start().await;
    let dir = dir("source");
    gateway_world(&api);
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "shop",
            &["shop.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    // A route the source cannot serve is named in an outage report, the rest keeps being served.
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "broken",
            &["broken.acme.test"],
            json!([{ "timeouts": { "request": "1s" }, "backendRefs": [backend("web", 80)] }]),
        ),
    );
    let config = source_config(&api, &dir, "gateway_api = true");
    let (tx, mut rx) = mpsc::channel(64);
    let task = tokio::spawn(source(&config).run(tx));

    let (state, _) = next_state(&mut rx, "the shop route", |state| {
        state
            .apps
            .iter()
            .any(|app| &*app.app.id == "httproute_team-a_shop")
    })
    .await;
    assert_eq!(state.apps.len(), 1);
    // The report follows the state it belongs to.
    let report = tokio::time::timeout(DEADLINE, async {
        loop {
            match rx.recv().await.expect("the source keeps running").body {
                UpdateBody::Outage(why) => return why.to_string(),
                UpdateBody::State(_) => {}
            }
        }
    })
    .await
    .expect("an outage report");
    assert!(
        report.contains("HTTPRoute team-a/broken rejected") && report.contains("timeouts"),
        "{report}"
    );

    // The routes follow the cluster live: another route, then the first one gone.
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "docs",
            &["docs.acme.test"],
            json!([rule(json!([]), json!([backend("web", 80)]))]),
        ),
    );
    next_state(&mut rx, "the docs route", |state| state.apps.len() == 2).await;
    api.remove("httproutes", "team-a", "shop");
    let (state, _) = next_state(&mut rx, "the shop route gone", |state| {
        state
            .apps
            .iter()
            .all(|app| &*app.app.id != "httproute_team-a_shop")
    })
    .await;
    assert_eq!(state.apps.len(), 1);
    task.abort();
}

#[tokio::test]
async fn gateway_settings_are_checked() {
    let api = FakeApi::start().await;
    let dir = dir("settings");
    let check = |extra: &str| {
        let config = source_config(&api, &dir, extra);
        KubernetesSource::from_config(&config.sources[0], &config)
            .err()
            .map(|err| err.to_string())
    };
    let why = check("gateway_class = \"x\"").expect("an error");
    assert!(why.contains("need gateway_api = true"), "{why}");
    let why = check("gateway_api = true\n[source.listener_entry_points]\nhttp = \"web\"")
        .expect("an error");
    assert!(why.contains("is not a port"), "{why}");
    let why = check("gateway_api = true\ngateway_class = \"\"").expect("an error");
    assert!(why.contains("gateway_class: is empty"), "{why}");
    assert!(check("gateway_api = true").is_none());
    assert!(check("gateway_api = true\ngateway_class = \"other\"\n[source.listener_entry_points]\n80 = \"web\"").is_none());
}

// ---- the real daemon -------------------------------------------------------------------------

/// A raw `GET` with `Host: host`: the status line's code and the whole head.
async fn head(addr: SocketAddr, host: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("proxy");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("write");
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (code, text)
}

#[tokio::test]
async fn gateway_snapshot_is_accepted_by_the_daemon() {
    // Everything the translation emits (matchers, weights, header edits, redirects, rewrites,
    // mirrors, the 500 answer) is compiled and served by the real daemon.
    let api = FakeApi::start().await;
    let dir = dir("daemon");
    let ports = common::free_ports(2);
    let policy = dir.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = common::daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let (upstream, _task) = common::daemon::backend("from-the-backend").await;
    let (shadow, _shadow_task) = common::daemon::backend("from-the-shadow").await;
    gateway_world(&api);
    api.put("services", k8s::service("team-a", "web", &[(None, 80)]));
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "web",
            0,
            &[(None, upstream.port())],
            &[("127.0.0.1", true, false)],
        ),
    );
    api.put("services", k8s::service("team-a", "shadow", &[(None, 80)]));
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "shadow",
            0,
            &[(None, shadow.port())],
            &[("127.0.0.1", true, false)],
        ),
    );
    api.put(
        "httproutes",
        http_route(
            "team-a",
            "site",
            &["site.acme.test"],
            json!([
                { "matches": [{ "path": { "value": "/split" }, "method": "GET",
                                "headers": [{ "name": "x-env", "value": "dev" }],
                                "queryParams": [{ "name": "v", "value": "1" }] }],
                  "filters": [
                    { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                        "set": [{ "name": "x-gw", "value": "1" }], "remove": ["x-debug"] } },
                    { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "set": [{ "name": "x-served-by", "value": "gateway" }] } },
                    { "type": "URLRewrite", "urlRewrite": { "path": {
                        "type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2" } } },
                    { "type": "RequestMirror", "requestMirror": {
                        "backendRef": backend("shadow", 80), "percent": 100 } },
                  ],
                  "backendRefs": [weighted("web", 80, 3), weighted("web", 80, 1)] },
                { "matches": [{ "path": { "value": "/old" } }],
                  "filters": [{ "type": "RequestRedirect", "requestRedirect": {
                      "hostname": "new.acme.test", "path": { "type": "ReplaceFullPath", "replaceFullPath": "/moved" },
                      "statusCode": 301 } }] },
                { "matches": [{ "path": { "value": "/legacy" } }],
                  "filters": [{ "type": "RequestRedirect", "requestRedirect": {
                      "path": { "type": "ReplacePrefixMatch", "replacePrefixMatch": "/modern" } } }] },
                { "matches": [{ "path": { "value": "/plain" } }],
                  "filters": [{ "type": "RequestRedirect", "requestRedirect": { "scheme": "https" } }] },
                { "matches": [{ "path": { "value": "/none" } }] },
            ]),
        ),
    );
    let extra = format!(
        "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n",
        policy.display().to_string()
    );
    let kubeconfig = api.kubeconfig(&dir, "test-token");
    let config = base_config(
        &daemon.admin,
        &format!(
            "{extra}[[tenant]]\nid = \"acme\"\nhosts = [\"acme.test\", \"*.acme.test\"]\ncatch_all = true\n\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\" }}\ngateway_api = true\n",
            kubeconfig.display().to_string()
        ),
    );
    let mut engine = podgate_provider::Engine::new(
        config.clone(),
        UpstreamPolicy::load(&policy).expect("policy"),
    )
    .with_tuning(common::fast_tuning());
    engine.add_source(source(&config)).expect("source");
    let status_rx = engine.status();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        let _ = engine
            .run(async {
                let _ = stopped.await;
            })
            .await;
    });

    let host = "site.acme.test";
    let started = std::time::Instant::now();
    loop {
        let (code, _) = head(daemon.proxy, host, "/none").await;
        if code == 500 {
            break;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "the routes never went live; provider status: {:?}",
            *status_rx.borrow()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // No backend: the API says 500.
    assert_eq!(head(daemon.proxy, host, "/none").await.0, 500);
    // The match needs its header and its query parameter; with them the filters and the split run.
    let split = "GET /split?v=1 HTTP/1.1\r\nhost: site.acme.test\r\nx-env: dev\r\nconnection: close\r\n\r\n";
    let (code, text) = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(daemon.proxy)
            .await
            .expect("proxy");
        stream.write_all(split.as_bytes()).await.expect("write");
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw)).await;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (code, text)
    };
    assert_eq!(code, 200, "{text}");
    assert!(
        text.to_ascii_lowercase().contains("x-served-by: gateway"),
        "{text}"
    );
    assert!(text.ends_with("from-the-backend"), "{text}");
    assert_eq!(
        head(daemon.proxy, host, "/split").await.0,
        404,
        "the query is required"
    );
    // Redirects: host and full path, then prefix replacement keeping the rest and the query.
    let (code, text) = head(daemon.proxy, host, "/old?x=1").await;
    assert_eq!(code, 301, "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("location: http://new.acme.test/moved?x=1"),
        "{text}"
    );
    let (code, text) = head(daemon.proxy, host, "/legacy/a/b?q=2").await;
    assert_eq!(code, 302, "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("location: http://site.acme.test/modern/a/b?q=2"),
        "{text}"
    );
    let (code, text) = head(daemon.proxy, host, "/plain").await;
    assert_eq!(code, 302, "{text}");
    assert!(
        text.to_ascii_lowercase()
            .contains("location: https://site.acme.test/plain"),
        "{text}"
    );
    let _ = stop.send(());
    let _ = tokio::time::timeout(DEADLINE, run).await;
}
