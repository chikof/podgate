#![allow(
    clippy::needless_pass_by_value,
    reason = "the object builders take the JSON they embed, so a call site reads like the manifest"
)]

//! Tests of the experimental `TLSRoute`, `TCPRoute` and `UDPRoute` of the Gateway API half of
//! the Kubernetes source.
//!
//! Most tests feed objects straight into [`gateway::translate`]; the discovery test runs the
//! source against the fake API server, and one test runs the source, the engine and the real
//! daemon with a TCP, a TLS and a UDP entry point.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::k8s::{self, FakeApi};
use common::{DEADLINE, config as base_config};
use podgate_provider::kubernetes::KubernetesSource;
use podgate_provider::kubernetes::client::Event;
use podgate_provider::kubernetes::endpoints::{EndpointSlice, Secret, Service, ServiceIndex};
use podgate_provider::kubernetes::gateway::tcproute::TcpRoute;
use podgate_provider::kubernetes::gateway::tlsroute::TlsRoute;
use podgate_provider::kubernetes::gateway::types::CONTROLLER;
use podgate_provider::kubernetes::gateway::udproute::UdpRoute;
use podgate_provider::kubernetes::gateway::{Cache, Change, Options, Translation};
use podgate_provider::kubernetes::ingress::Cluster;
use podgate_provider::kubernetes::tenancy::Tenancy;
use podgate_provider::source::{Source, State, Update, UpdateBody};
use podgate_provider::{Config, UpstreamPolicy};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const GROUP: &str = "gateway.networking.k8s.io";

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
exclusive_entry_points = ["pg", "dns"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]
exclusive_entry_points = ["gx"]
"#;

/// The tenant of the daemon test: only entry points the daemon binds may be reserved, or it
/// refuses the whole snapshot (`unknown_entry_point`).
const DAEMON_TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]
exclusive_entry_points = ["pg", "dns"]
"#;

const PORTS: &[(&str, &str)] = &[
    ("80", "web"),
    ("443", "websecure"),
    ("5432", "pg"),
    ("5300", "dns"),
    ("8443", "edge"),
    ("8444", "term"),
    ("9000", "gx"),
    ("7000", "open"),
];

fn config() -> Config {
    base_config(
        &std::env::temp_dir().join("pgp-l4-unused.sock"),
        &format!("{TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\n"),
    )
}

// ---- builders ---------------------------------------------------------------------------------

fn class(name: &str, controller: &str) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "GatewayClass",
            "metadata": { "name": name }, "spec": { "controllerName": controller } })
}

fn namespace(name: &str) -> Value {
    json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": name, "labels": {} } })
}

fn listener(name: &str, port: u16, protocol: &str, hostname: Option<&str>, tls: Value) -> Value {
    let mut listener = json!({ "name": name, "port": port, "protocol": protocol,
                               "allowedRoutes": { "namespaces": { "from": "All" } } });
    if let Some(hostname) = hostname {
        listener["hostname"] = json!(hostname);
    }
    if !tls.is_null() {
        listener["tls"] = tls;
    }
    listener
}

fn gateway(namespace: &str, name: &str, listeners: Value) -> Value {
    json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "Gateway",
            "metadata": { "namespace": namespace, "name": name, "creationTimestamp": "2026-11-01T00:00:00Z" },
            "spec": { "gatewayClassName": "podgate", "listeners": listeners } })
}

fn passthrough() -> Value {
    json!({ "mode": "Passthrough" })
}

fn terminate() -> Value {
    json!({ "mode": "Terminate", "certificateRefs": [{ "name": "tls" }] })
}

/// The Gateway `team-a/gw`: one listener of each kind, every namespace allowed.
fn l4_gateway() -> Value {
    gateway(
        "team-a",
        "gw",
        json!([
            listener("tcp", 5432, "TCP", None, Value::Null),
            listener("dns", 5300, "UDP", None, Value::Null),
            listener("pass", 8443, "TLS", None, passthrough()),
            listener("term", 8444, "TLS", None, terminate()),
            listener("gxtcp", 9000, "TCP", None, Value::Null),
            listener("open", 7000, "TCP", None, Value::Null),
        ]),
    )
}

fn route(
    kind: &str,
    namespace: &str,
    name: &str,
    created: &str,
    section: &str,
    hostnames: &[&str],
    backends: Value,
) -> Value {
    let mut spec = json!({
        "parentRefs": [{ "namespace": "team-a", "name": "gw", "sectionName": section }],
        "rules": [{ "backendRefs": backends }],
    });
    if !hostnames.is_empty() {
        spec["hostnames"] = json!(hostnames);
    }
    let version = if kind == "TLSRoute" { "v1" } else { "v1alpha2" };
    json!({ "apiVersion": format!("{GROUP}/{version}"), "kind": kind,
            "metadata": { "namespace": namespace, "name": name, "creationTimestamp": created },
            "spec": spec })
}

fn tcp_route(namespace: &str, name: &str, created: &str, section: &str, backends: Value) -> Value {
    route("TCPRoute", namespace, name, created, section, &[], backends)
}

fn udp_route(namespace: &str, name: &str, created: &str, section: &str, backends: Value) -> Value {
    route("UDPRoute", namespace, name, created, section, &[], backends)
}

fn tls_route(namespace: &str, name: &str, section: &str, hosts: &[&str], backends: Value) -> Value {
    route(
        "TLSRoute",
        namespace,
        name,
        "2026-11-10T00:00:00Z",
        section,
        hosts,
        backends,
    )
}

fn backend(name: &str, port: u16) -> Value {
    json!({ "name": name, "port": port })
}

fn weighted(name: &str, port: u16, weight: u32) -> Value {
    json!({ "name": name, "port": port, "weight": weight })
}

fn udp_service(namespace: &str, name: &str, port: u16) -> Value {
    json!({ "apiVersion": "v1", "kind": "Service",
            "metadata": { "namespace": namespace, "name": name },
            "spec": { "type": "ClusterIP", "ports": [{ "port": port, "protocol": "UDP" }] } })
}

fn udp_slice(namespace: &str, service: &str, port: u16, ip: &str) -> Value {
    json!({
        "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": { "namespace": namespace, "name": format!("{service}-0"),
                      "labels": { k8s::SERVICE_LABEL: service,
                                  "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io" } },
        "addressType": "IPv4",
        "ports": [{ "name": "", "port": port, "protocol": "UDP" }],
        "endpoints": [{ "addresses": [ip], "conditions": { "ready": true } }],
    })
}

// ---- the world -------------------------------------------------------------------------------

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
    /// Namespaces `team-a` (acme), `team-b` (globex), the served class, the Gateway
    /// `team-a/gw`, a TCP Service `db` (10.0.0.5:5432), `web` (10.0.0.6:8080 and 10.0.0.7:8080)
    /// and a UDP Service `dns` (10.0.0.8:5353) in `team-a`, and the TLS Secret `tls`.
    fn new() -> Self {
        let mut world = Self {
            objects: BTreeMap::new(),
        };
        world.put("gatewayclasses", class("podgate", CONTROLLER));
        for name in ["team-a", "team-b"] {
            world.put("namespaces", namespace(name));
        }
        world.put("gateways", l4_gateway());
        world.service("team-a", "db", 5432, 5432, &["10.0.0.5"]);
        world.service("team-a", "web", 80, 8080, &["10.0.0.6", "10.0.0.7"]);
        world.service("team-a", "single", 80, 8080, &["10.0.0.9"]);
        world.put("services", udp_service("team-a", "dns", 53));
        world.put(
            "endpointslices",
            udp_slice("team-a", "dns", 5353, "10.0.0.8"),
        );
        world.put(
            "secrets",
            k8s::secret("team-a", "tls", "kubernetes.io/tls", "CERT", "KEY"),
        );
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
        let config = config();
        let mut cache = Cache::new(1);
        let mut outages = BTreeMap::new();
        for change in [
            Change::Class(Event::Reset(parse(self.list("gatewayclasses")))),
            Change::Namespace(Event::Reset(parse(self.list("namespaces")))),
            Change::Gateway(Event::Reset(parse(self.list("gateways")))),
            Change::Http(Event::Reset(Vec::new())),
            Change::Grpc(Event::Reset(Vec::new())),
            Change::Grant(Event::Reset(parse(self.list("referencegrants")))),
            Change::Tls(Event::Reset(parse::<TlsRoute>(self.list("tlsroutes")))),
            Change::Tcp(Event::Reset(parse::<TcpRoute>(self.list("tcproutes")))),
            Change::Udp(Event::Reset(parse::<UdpRoute>(self.list("udproutes")))),
        ] {
            cache.apply(&mut outages, 0, change);
        }
        assert!(cache.synced(), "every list of the cache was applied");
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
                ("team-b".into(), "globex".into()),
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
        let ports = PORTS
            .iter()
            .map(|(port, entry)| ((*port).to_owned(), (*entry).to_owned()))
            .collect();
        let options = Options::new(None, Some(ports)).expect("options");
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

/// The `tcp` or `udp` section of the app `id`.
fn section(translation: &Translation, id: &str, which: &str) -> Value {
    let app = strip(serde_json::to_value(&app(translation, id).app).expect("the app"));
    assert_eq!(app["routers"], json!([]), "an L4 app has no HTTP routers");
    app[which].clone()
}

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

// ---- translation -----------------------------------------------------------------------------

#[test]
fn tcproute_to_catch_all() {
    let mut world = World::new();
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "db",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let tcp = section(&translation, "tcproute_team-a_db", "tcp");
    assert_eq!(
        tcp["routers"],
        json!([{ "name": "r0", "entry_points": ["pg"], "service": "backends" }]),
        "no match and no tls: every connection of the entry point"
    );
    assert_eq!(
        tcp["services"],
        json!([{ "name": "backends", "type": "loadbalancer",
                 "servers": [{ "address": "10.0.0.5:5432" }] }])
    );
    let app = app(&translation, "tcproute_team-a_db");
    assert_eq!(&*app.origin.object, "TCPRoute/team-a/db");
    assert_eq!(
        app.origin.first_seen, 1_794_268_800,
        "the route's own creation time"
    );
    assert!(accepted(&translation, "team-a/db"));
}

#[test]
fn tcproute_backend_weights_to_server_weights() {
    let mut world = World::new();
    // 3:1 over a backend of two endpoints and one of one: each backend gets the share its weight
    // says, so the two endpoints of `web` carry 6 together and `single` 2.
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "split",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([weighted("web", 80, 3), weighted("single", 80, 1)]),
        ),
    );
    let translation = world.translate();
    let tcp = section(&translation, "tcproute_team-a_split", "tcp");
    assert_eq!(
        tcp["services"],
        json!([{ "name": "backends", "type": "loadbalancer",
                 "algorithm": "weighted_round_robin",
                 "servers": [
                     { "address": "10.0.0.6:8080", "weight": 3 },
                     { "address": "10.0.0.7:8080", "weight": 3 },
                     { "address": "10.0.0.9:8080", "weight": 2 },
                 ] }])
    );
}

#[test]
fn udproute_to_single_router() {
    let mut world = World::new();
    world.put(
        "udproutes",
        udp_route(
            "team-a",
            "resolver",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([backend("dns", 53)]),
        ),
    );
    let translation = world.translate();
    let udp = section(&translation, "udproute_team-a_resolver", "udp");
    assert_eq!(
        udp["routers"],
        json!([{ "name": "r0", "entry_points": ["dns"], "service": "backends" }])
    );
    assert_eq!(
        udp["services"],
        json!([{ "name": "backends", "type": "loadbalancer",
                "servers": [{ "address": "10.0.0.8:5353" }] }]),
        "a UDP Service port gives UDP endpoints, and the TCP port of `db` is not one"
    );
    // A UDPRoute to a TCP port is not a backend.
    world.put(
        "udproutes",
        udp_route(
            "team-a",
            "wrong",
            "2026-11-10T00:00:01Z",
            "dns",
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/wrong");
    assert_eq!(reason, "BackendNotFound");
    assert!(message.contains("is not UDP"), "{message}");
}

#[test]
fn udproute_unequal_weights_rejected() {
    let mut world = World::new();
    world.put("services", udp_service("team-a", "dns2", 53));
    world.put(
        "endpointslices",
        udp_slice("team-a", "dns2", 5353, "10.0.0.10"),
    );
    world.put(
        "udproutes",
        udp_route(
            "team-a",
            "split",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([weighted("dns", 53, 3), weighted("dns2", 53, 1)]),
        ),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/split");
    assert_eq!(reason, "UnsupportedValue");
    assert!(message.contains("no weights"), "{message}");
}

#[test]
fn tlsroute_passthrough() {
    let mut world = World::new();
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "secure",
            "pass",
            &["db.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let tcp = section(&translation, "tlsroute_team-a_secure", "tcp");
    assert_eq!(
        tcp["routers"],
        json!([{ "name": "r0", "entry_points": ["edge"], "service": "backends",
                 "match": { "sni": "db.acme.test" }, "tls": { "passthrough": true } }])
    );
    assert_eq!(
        tcp["services"][0]["servers"],
        json!([{ "address": "10.0.0.5:5432" }])
    );
    assert!(
        translation.certificates.is_empty(),
        "a passthrough listener holds no certificate"
    );
}

#[test]
fn tlsroute_terminate() {
    let mut world = World::new();
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "term",
            "term",
            &["app.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let tcp = section(&translation, "tlsroute_team-a_term", "tcp");
    assert_eq!(
        tcp["routers"],
        json!([{ "name": "r0", "entry_points": ["term"], "service": "backends",
                 "match": { "sni": "app.acme.test" }, "tls": {} }]),
        "terminating: tls is present and does not pass through"
    );
    assert_eq!(translation.certificates.len(), 1, "{:?}", translation.notes);
    let certificate =
        strip(serde_json::to_value(&translation.certificates[0].certificate).expect("certificate"));
    assert_eq!(certificate["hosts"], json!(["app.acme.test"]));
    assert_eq!(certificate["cert_pem"], "CERT");
    assert_eq!(
        &*translation.certificates[0].origin.object,
        "Gateway/team-a/gw#term-0"
    );
}

#[test]
fn tlsroute_hostnames_to_sni() {
    let mut world = World::new();
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "two",
            "pass",
            &["a.acme.test", "*.b.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    // A listener with a host name narrows the route's names to those under it, and a route
    // without names takes the listener's.
    world.put(
        "gateways",
        gateway(
            "team-a",
            "named",
            json!([listener(
                "pass",
                8443,
                "TLS",
                Some("*.acme.test"),
                passthrough()
            )]),
        ),
    );
    world.put(
        "tlsroutes",
        json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "TLSRoute",
                "metadata": { "namespace": "team-a", "name": "narrow", "creationTimestamp": "2026-11-10T00:00:00Z" },
                "spec": { "parentRefs": [{ "name": "named" }],
                          "hostnames": ["x.acme.test", "x.globex.test"],
                          "rules": [{ "backendRefs": [backend("db", 5432)] }] } }),
    );
    world.put(
        "tlsroutes",
        json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "TLSRoute",
                "metadata": { "namespace": "team-a", "name": "inherit", "creationTimestamp": "2026-11-10T00:00:00Z" },
                "spec": { "parentRefs": [{ "name": "named" }],
                          "rules": [{ "backendRefs": [backend("db", 5432)] }] } }),
    );
    let translation = world.translate();
    let sni = |id: &str| section(&translation, id, "tcp")["routers"][0]["match"].clone();
    assert_eq!(
        sni("tlsroute_team-a_two"),
        json!({ "sni": ["a.acme.test", "*.b.acme.test"] })
    );
    assert_eq!(
        sni("tlsroute_team-a_narrow"),
        json!({ "sni": "x.acme.test" })
    );
    assert_eq!(
        sni("tlsroute_team-a_inherit"),
        json!({ "sni": "*.acme.test" })
    );
}

#[test]
fn tlsroute_foreign_sni_rejected() {
    let mut world = World::new();
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "evil",
            "pass",
            &["db.globex.test"],
            json!([backend("db", 5432)]),
        ),
    );
    // Without a name the route would take every server name of a shared entry point, which no
    // tenant may do unless the operator allows it.
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "greedy",
            "pass",
            &[],
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/evil");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(message.contains("foreign_host_claim"), "{message}");
    let (_, message) = rejection(&translation, "team-a/greedy");
    assert!(message.contains("catch_all_not_allowed"), "{message}");
    assert!(translation.apps.is_empty(), "{:?}", translation.apps);
}

#[test]
fn tcproute_needs_exclusive_entry_point() {
    let mut world = World::new();
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "open",
            "2026-11-10T00:00:00Z",
            "open",
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/open");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(message.contains("catch_all_not_allowed"), "{message}");
}

#[test]
fn second_tcproute_conflicts() {
    let mut world = World::new();
    // `a-new` sorts first and is newer: the oldest route wins, not the first name.
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "a-new",
            "2026-11-12T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "z-old",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    assert!(accepted(&translation, "team-a/z-old"));
    let (reason, message) = rejection(&translation, "team-a/a-new");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(
        message.contains("route_ambiguity") && message.contains("team-a/z-old"),
        "{message}"
    );
    assert_eq!(
        translation
            .apps
            .iter()
            .map(|app| app.app.id.to_string())
            .collect::<Vec<_>>(),
        ["tcproute_team-a_z-old"],
        "only the winner is served"
    );
    let report = translation
        .routes
        .iter()
        .find(|report| report.key == "team-a/a-new")
        .expect("report");
    assert!(report.parents[0].accepted, "the parent reference attached");
}

#[test]
fn second_udproute_conflicts() {
    let mut world = World::new();
    world.put(
        "udproutes",
        udp_route(
            "team-a",
            "a-new",
            "2026-11-12T00:00:00Z",
            "dns",
            json!([backend("dns", 53)]),
        ),
    );
    world.put(
        "udproutes",
        udp_route(
            "team-a",
            "z-old",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([backend("dns", 53)]),
        ),
    );
    let translation = world.translate();
    assert!(accepted(&translation, "team-a/z-old"));
    let (_, message) = rejection(&translation, "team-a/a-new");
    assert!(
        message.contains("route_ambiguity") && message.contains("team-a/z-old"),
        "{message}"
    );
    assert_eq!(translation.apps.len(), 1);
}

#[test]
fn second_tlsroute_for_one_name_conflicts() {
    let mut world = World::new();
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "first",
            "pass",
            &["db.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    let mut second = tls_route(
        "team-a",
        "second",
        "pass",
        &["db.acme.test"],
        json!([backend("db", 5432)]),
    );
    second["metadata"]["creationTimestamp"] = json!("2026-11-11T00:00:00Z");
    world.put("tlsroutes", second);
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "other",
            "pass",
            &["other.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    assert!(accepted(&translation, "team-a/first"));
    assert!(
        accepted(&translation, "team-a/other"),
        "another name is no conflict"
    );
    let (_, message) = rejection(&translation, "team-a/second");
    assert!(message.contains("route_ambiguity"), "{message}");
}

#[test]
fn l4_route_forbidden_entry_point_rejected() {
    let mut world = World::new();
    // `pg` and `dns` are reserved to acme: globex's routes cannot attach, whatever the listener
    // says about namespaces.
    world.put(
        "tcproutes",
        tcp_route(
            "team-b",
            "steal",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    world.put(
        "udproutes",
        udp_route(
            "team-b",
            "steal",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([backend("dns", 53)]),
        ),
    );
    // A cross-tenant backend is refused before that matters: tenants never reference each other.
    let translation = world.translate();
    for key in ["team-b/steal"] {
        let reports: Vec<_> = translation
            .routes
            .iter()
            .filter(|report| report.key == key)
            .collect();
        assert_eq!(reports.len(), 2, "one report per kind");
        for report in reports {
            let rejected = report.rejected.as_ref().expect("rejected");
            assert_eq!(rejected.reason, "NotAllowedByListeners");
            assert!(
                rejected.message.contains("entry_point_forbidden")
                    && rejected.message.contains("exclusive to tenant acme"),
                "{}",
                rejected.message
            );
            assert!(!report.parents[0].accepted);
        }
    }
    assert!(translation.apps.is_empty());
}

#[test]
fn passthrough_on_shared_port_rejected_or_translated() {
    let mut world = World::new();
    // One Gateway serves HTTPS and TLS passthrough on port 443, told apart by host name, the
    // way the Gateway API allows. podgate does not share an HTTP entry point with TLS routers
    //, so the TLS listener is not used and says why.
    world.put(
        "gateways",
        gateway(
            "team-a",
            "shared",
            json!([
                listener("https", 443, "HTTPS", Some("web.acme.test"), terminate()),
                listener("pass", 443, "TLS", Some("db.acme.test"), passthrough()),
            ]),
        ),
    );
    world.put(
        "tlsroutes",
        json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "TLSRoute",
                "metadata": { "namespace": "team-a", "name": "db", "creationTimestamp": "2026-11-10T00:00:00Z" },
                "spec": { "parentRefs": [{ "name": "shared", "sectionName": "pass" }],
                          "hostnames": ["db.acme.test"],
                          "rules": [{ "backendRefs": [backend("db", 5432)] }] } }),
    );
    let translation = world.translate();
    let (reason, message) = rejection(&translation, "team-a/db");
    assert_eq!(reason, "NotAllowedByListeners");
    assert!(
        message.contains("shared with an HTTP or HTTPS listener")
            && message.contains("entry point of its own"),
        "{message}"
    );
    let gateway = translation
        .gateways
        .iter()
        .find(|gateway| gateway.key == "team-a/shared")
        .expect("the Gateway's report");
    let pass = gateway
        .listeners
        .iter()
        .find(|listener| listener.name == "pass")
        .expect("the listener");
    assert_eq!(
        pass.accepted.as_ref().expect_err("not accepted").reason,
        "PortUnavailable"
    );
    assert_eq!(pass.supported_kinds, ["TLSRoute"]);
    let https = gateway
        .listeners
        .iter()
        .find(|listener| listener.name == "https")
        .expect("the listener");
    assert!(https.accepted.is_ok(), "the HTTPS listener is unaffected");
    assert_eq!(https.supported_kinds, ["HTTPRoute", "GRPCRoute"]);
}

#[test]
fn route_kinds_attach_to_their_own_listeners_only() {
    let mut world = World::new();
    world.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "on-udp",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([backend("db", 5432)]),
        ),
    );
    world.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "on-tcp",
            "tcp",
            &["db.acme.test"],
            json!([backend("db", 5432)]),
        ),
    );
    let translation = world.translate();
    let (_, message) = rejection(&translation, "team-a/on-udp");
    assert!(message.contains("carries no TCPRoute"), "{message}");
    let (_, message) = rejection(&translation, "team-a/on-tcp");
    assert!(message.contains("carries no TLSRoute"), "{message}");
    let gateway = &translation.gateways[0];
    let kinds: BTreeMap<&str, &Vec<&'static str>> = gateway
        .listeners
        .iter()
        .map(|listener| (listener.name.as_str(), &listener.supported_kinds))
        .collect();
    assert_eq!(kinds["tcp"], &vec!["TCPRoute"]);
    assert_eq!(kinds["dns"], &vec!["UDPRoute"]);
    assert_eq!(kinds["pass"], &vec!["TLSRoute"]);
    assert_eq!(kinds["term"], &vec!["TLSRoute"]);
}

// ---- the source ------------------------------------------------------------------------------

fn dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pgp-l4-{}-{label}", std::process::id()));
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

const EXTRA: &str =
    "gateway_api = true\n[source.listener_entry_points]\n80 = \"web\"\n5432 = \"pg\"\n";

fn http_world(api: &FakeApi) {
    api.put("gatewayclasses", class("podgate", CONTROLLER));
    api.put("namespaces", namespace("team-a"));
    api.put(
        "gateways",
        gateway(
            "team-a",
            "gw",
            json!([
                listener("http", 80, "HTTP", None, Value::Null),
                listener("tcp", 5432, "TCP", None, Value::Null),
            ]),
        ),
    );
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
    api.put(
        "httproutes",
        json!({ "apiVersion": format!("{GROUP}/v1"), "kind": "HTTPRoute",
                "metadata": { "namespace": "team-a", "name": "shop", "creationTimestamp": "2026-11-10T00:00:00Z" },
                "spec": { "parentRefs": [{ "name": "gw", "sectionName": "http" }],
                          "hostnames": ["shop.acme.test"],
                          "rules": [{ "backendRefs": [backend("web", 80)] }] } }),
    );
}

#[tokio::test]
async fn missing_l4_crds_skipped() {
    // A cluster with the Gateway API's standard channel only: the L4 kinds answer 404. The
    // source is not held back by them, reports nothing about them and does not watch them.
    let api = FakeApi::start().await;
    let dir = dir("crds");
    for plural in ["tlsroutes", "tcproutes", "udproutes"] {
        api.uninstall(plural);
    }
    http_world(&api);
    let config = source_config(&api, &dir, EXTRA);
    let (tx, mut rx) = mpsc::channel(64);
    let task = tokio::spawn(source(&config).run(tx));

    let (state, outages) = next_state(&mut rx, "the shop route", |state| {
        state
            .apps
            .iter()
            .any(|app| &*app.app.id == "httproute_team-a_shop")
    })
    .await;
    assert_eq!(state.apps.len(), 1);
    assert!(
        outages.iter().all(|why| !why.contains("routes")),
        "no outage for a kind that is not installed: {outages:?}"
    );
    for plural in ["tlsroutes", "tcproutes", "udproutes"] {
        assert_eq!(api.count(plural, true), 0, "{plural} is not watched");
        assert!(api.count(plural, false) >= 1, "{plural} was probed");
    }

    // The CRD arrives later: the kind is picked up without a restart.
    api.install("tcproutes");
    api.put("services", k8s::service("team-a", "db", &[(None, 5432)]));
    api.put(
        "endpointslices",
        k8s::slice(
            "team-a",
            "db",
            0,
            &[(None, 5432)],
            &[("10.0.0.5", true, false)],
        ),
    );
    api.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "db",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    let (state, _) = next_state(&mut rx, "the TCP route after its CRD appeared", |state| {
        state
            .apps
            .iter()
            .any(|app| &*app.app.id == "tcproute_team-a_db")
    })
    .await;
    assert_eq!(state.apps.len(), 2);

    // And goes away again: its routes leave with it.
    api.uninstall("tcproutes");
    api.drop_watches();
    next_state(&mut rx, "the TCP route gone with its CRD", |state| {
        state
            .apps
            .iter()
            .all(|app| &*app.app.id != "tcproute_team-a_db")
    })
    .await;
    task.abort();
}

// ---- the real daemon -------------------------------------------------------------------------

struct Daemon {
    child: Child,
    admin: PathBuf,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The daemon with the entry points of the test: `pg` (TCP), `edge` and `term` (TCP, shared
/// between tenants) and `dns` (UDP) next to the usual two.
async fn start_daemon(
    policy: &std::path::Path,
    entry_points: &str,
    dir: &std::path::Path,
) -> Daemon {
    let admin = dir.join("daemon.sock");
    let child = Command::new(common::daemon::binary())
        .env("ENTRY_POINTS", entry_points)
        .env("ADMIN_SOCKET", &admin)
        .env("UPSTREAM_POLICY_FILE", policy)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let daemon = Daemon {
        child,
        admin,
        dir: dir.to_owned(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while tokio::net::UnixStream::connect(&daemon.admin)
        .await
        .is_err()
    {
        assert!(
            Instant::now() < deadline,
            "the daemon did not open its admin socket"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon
}

/// A TCP upstream that answers what it reads with `prefix` and the bytes it read.
async fn echo(prefix: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("upstream");
    let addr = listener.local_addr().expect("address");
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let mut answer = prefix.as_bytes().to_vec();
                answer.extend_from_slice(&buffer[..read]);
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, task)
}

/// A UDP upstream that answers every datagram with `pong:` and the datagram.
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp upstream");
    let addr = socket.local_addr().expect("address");
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            let mut answer = b"pong:".to_vec();
            answer.extend_from_slice(&buffer[..read]);
            let _ = socket.send_to(&answer, from).await;
        }
    });
    (addr, task)
}

/// Sends `payload` to `addr` until the daemon answers with something (the route may not be live
/// yet) or the deadline passes.
async fn tcp_exchange(addr: SocketAddr, hello: &[u8], context: &dyn Fn() -> String) -> Vec<u8> {
    let attempt = async {
        loop {
            if let Ok(mut stream) = TcpStream::connect(addr).await
                && stream.write_all(hello).await.is_ok()
            {
                let mut answer = Vec::new();
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer))
                        .await;
                if !answer.is_empty() {
                    return answer;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    tokio::time::timeout(DEADLINE, attempt)
        .await
        .unwrap_or_else(|_| panic!("no answer from {addr}; status: {}", context()))
}

/// The bytes of the first flight of a TLS client for `server_name`.
fn client_hello(server_name: &'static str) -> Vec<u8> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let mut connection = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from(server_name).expect("a server name"),
    )
    .expect("client connection");
    let mut hello = Vec::new();
    connection.write_tls(&mut hello).expect("the ClientHello");
    hello
}

#[tokio::test]
async fn translated_l4_routes_validate() {
    // Everything the translation emits for the four kinds is compiled and served by the real
    // daemon: the traffic goes through the routers, and the status of the routes is written.
    let api = FakeApi::start().await;
    let dir = dir("daemon");
    let policy = dir.join("policy.json");
    fs::write(&policy, common::daemon::LOOPBACK_POLICY).expect("policy");
    let ports = common::free_ports(6);
    let entry_points = format!(
        "web=127.0.0.1:{}/http,pg=127.0.0.1:{}/tcp,edge=127.0.0.1:{}/tcp,term=127.0.0.1:{}/tcp,dns=127.0.0.1:{}/udp",
        ports[0], ports[1], ports[2], ports[3], ports[4]
    );
    let daemon = start_daemon(&policy, &entry_points, &dir).await;
    let (pg, _pg_task) = echo("pong:").await;
    let (hello_upstream, _hello_task) = echo("seen:").await;
    let (term_upstream, _term_task) = echo("tls-pong:").await;
    let (dns, _dns_task) = udp_echo().await;

    let key = rcgen::KeyPair::generate().expect("key pair");
    let params = rcgen::CertificateParams::new(vec!["app.acme.test".to_owned()]).expect("params");
    let cert = params.self_signed(&key).expect("certificate");

    api.put("gatewayclasses", class("podgate", CONTROLLER));
    api.put("namespaces", namespace("team-a"));
    api.put("gateways", l4_gateway());
    let host = "127.0.0.1";
    for (name, port, upstream) in [
        ("db", 5432, pg.port()),
        ("hello", 80, hello_upstream.port()),
        ("term", 80, term_upstream.port()),
    ] {
        api.put("services", k8s::service("team-a", name, &[(None, port)]));
        api.put(
            "endpointslices",
            k8s::slice(
                "team-a",
                name,
                0,
                &[(None, upstream)],
                &[(host, true, false)],
            ),
        );
    }
    api.put("services", udp_service("team-a", "dns", 53));
    api.put(
        "endpointslices",
        udp_slice("team-a", "dns", dns.port(), host),
    );
    api.put(
        "secrets",
        k8s::secret(
            "team-a",
            "tls",
            "kubernetes.io/tls",
            &cert.pem(),
            &key.serialize_pem(),
        ),
    );
    api.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "db",
            "2026-11-10T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    api.put(
        "tcproutes",
        tcp_route(
            "team-a",
            "dup",
            "2026-11-12T00:00:00Z",
            "tcp",
            json!([backend("db", 5432)]),
        ),
    );
    api.put(
        "udproutes",
        udp_route(
            "team-a",
            "resolver",
            "2026-11-10T00:00:00Z",
            "dns",
            json!([backend("dns", 53)]),
        ),
    );
    api.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "secure",
            "pass",
            &["db.acme.test"],
            json!([backend("hello", 80)]),
        ),
    );
    api.put(
        "tlsroutes",
        tls_route(
            "team-a",
            "term",
            "term",
            &["app.acme.test"],
            json!([backend("term", 80)]),
        ),
    );

    let kubeconfig = api.kubeconfig(&dir, "test-token");
    let config = base_config(
        &daemon.admin,
        &format!(
            "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n{DAEMON_TENANTS}\n[[source]]\nkind = \"kubernetes\"\nname = \"k8s\"\nkubeconfig = {:?}\nnamespace_tenants = {{ team-a = \"acme\" }}\ngateway_api = true\n[source.listener_entry_points]\n5432 = \"pg\"\n5300 = \"dns\"\n8443 = \"edge\"\n8444 = \"term\"\n",
            policy.display().to_string(),
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
    let proxy = |index: usize| SocketAddr::from(([127, 0, 0, 1], ports[index]));

    // TCP: the catch-all router of `pg`.
    let status = || format!("{:?}", *status_rx.borrow());
    let answer = tcp_exchange(proxy(1), b"ping", &status).await;
    assert_eq!(answer, b"pong:ping", "status: {:?}", *status_rx.borrow());

    // TLS passthrough: the ClientHello reaches the upstream untouched, for the name the route
    // claims; any other name has no route and the connection is closed.
    let hello = client_hello("db.acme.test");
    let answer = tcp_exchange(proxy(2), &hello, &status).await;
    assert!(answer.starts_with(b"seen:\x16\x03"), "{answer:?}");
    assert_eq!(&answer[5..], &hello[..], "the hello arrived as it was sent");
    let mut stream = TcpStream::connect(proxy(2)).await.expect("edge");
    stream
        .write_all(&client_hello("other.acme.test"))
        .await
        .expect("hello");
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(rest.is_empty(), "a name no route claims gets nothing");

    // TLS termination: podgate answers the handshake with the Gateway's certificate and passes
    // the plain bytes on.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).expect("root");
    let client = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(client);
    let started = Instant::now();
    let answer = loop {
        let attempt = async {
            let stream = TcpStream::connect(proxy(3)).await.ok()?;
            let name = rustls::pki_types::ServerName::try_from("app.acme.test").ok()?;
            let mut stream = connector.connect(name, stream).await.ok()?;
            stream.write_all(b"hi").await.ok()?;
            let mut answer = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer)).await;
            Some(answer)
        };
        if let Some(answer) = attempt.await.filter(|answer| !answer.is_empty()) {
            break answer;
        }
        assert!(
            started.elapsed() < DEADLINE,
            "no TLS answer; status: {:?}",
            *status_rx.borrow()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(answer, b"tls-pong:hi");

    // UDP: the one router of `dns`.
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    let started = Instant::now();
    let answer = loop {
        client.send_to(b"q", proxy(4)).await.expect("send");
        let mut buffer = [0u8; 64];
        if let Ok(Ok((read, _))) =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await
        {
            break buffer[..read].to_vec();
        }
        assert!(
            started.elapsed() < DEADLINE,
            "no UDP answer; status: {:?}",
            *status_rx.borrow()
        );
    };
    assert_eq!(answer, b"pong:q");

    // The daemon took everything: nothing is quarantined, and the status of the L4 routes is
    // written by the same writer as the HTTP routes'.
    {
        let status = status_rx.borrow();
        assert!(status.quarantined.is_empty(), "{:?}", status.quarantined);
    }
    let wait_status = |plural: &'static str, name: &'static str, done: fn(&Value) -> bool| {
        let api = &api;
        async move {
            tokio::time::timeout(DEADLINE, async {
                loop {
                    if let Some(route) = api.get(plural, "team-a", name)
                        && done(&route["status"]["parents"])
                    {
                        return route;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "no status for {plural}/{name}: {:?}",
                    api.get(plural, "team-a", name)
                )
            })
        }
    };
    let holds = |parents: &Value, condition: &str, status: &str| {
        parents[0]["conditions"].as_array().is_some_and(|all| {
            all.iter()
                .any(|c| c["type"] == condition && c["status"] == status)
        })
    };
    let route = wait_status("tcproutes", "db", |parents| {
        parents[0]["conditions"].as_array().is_some_and(|all| {
            all.iter()
                .any(|c| c["type"] == "Accepted" && c["status"] == "True")
        })
    })
    .await;
    assert!(holds(&route["status"]["parents"], "ResolvedRefs", "True"));
    assert_eq!(route["status"]["parents"][0]["controllerName"], CONTROLLER);
    let loser = wait_status("tcproutes", "dup", |parents| {
        parents[0]["conditions"].as_array().is_some_and(|all| {
            all.iter()
                .any(|c| c["type"] == "Accepted" && c["status"] == "False")
        })
    })
    .await;
    let message = loser["status"]["parents"][0]["conditions"][0]["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(message.contains("route_ambiguity"), "{message}");
    wait_status("udproutes", "resolver", |parents| {
        parents[0]["conditions"].as_array().is_some_and(|all| {
            all.iter()
                .any(|c| c["type"] == "Accepted" && c["status"] == "True")
        })
    })
    .await;
    wait_status("tlsroutes", "secure", |parents| {
        parents[0]["conditions"].as_array().is_some_and(|all| {
            all.iter()
                .any(|c| c["type"] == "Accepted" && c["status"] == "True")
        })
    })
    .await;
    let gateway = tokio::time::timeout(DEADLINE, async {
        loop {
            if let Some(gateway) = api.get("gateways", "team-a", "gw")
                && gateway["status"]["listeners"]
                    .as_array()
                    .is_some_and(|listeners| listeners.len() == 6)
            {
                return gateway;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the Gateway's status");
    let kinds = |name: &str| {
        gateway["status"]["listeners"]
            .as_array()
            .and_then(|all| all.iter().find(|l| l["name"] == name))
            .map(|listener| listener["supportedKinds"].clone())
    };
    assert_eq!(
        kinds("tcp"),
        Some(json!([{ "group": GROUP, "kind": "TCPRoute" }]))
    );
    assert_eq!(
        kinds("dns"),
        Some(json!([{ "group": GROUP, "kind": "UDPRoute" }]))
    );
    assert_eq!(
        kinds("pass"),
        Some(json!([{ "group": GROUP, "kind": "TLSRoute" }]))
    );

    let _ = stop.send(());
    let _ = tokio::time::timeout(DEADLINE, run).await;
}
