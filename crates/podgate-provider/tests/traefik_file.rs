//! The Traefik file translator: a representative file converted, certificates inlined, TLS
//! options, what is reported and left out, the `convert-traefik` command, and the converted file
//! against the real daemon. Everything that waits has a deadline.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{daemon, free_ports};
use podgate_provider::push::AdminClient;
use podgate_provider::traefik::Code;
use podgate_provider::traefik_file::{Converted, Syntax, convert, convert_file};
use serde_json::{Value, json};
use tokio::net::UnixStream;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/traefik")
        .join(name)
}

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("pgp-tfile-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create the test directory");
        Self(path)
    }

    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("write a test file");
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn from_yaml(dir: &Dir, text: &str) -> Converted {
    convert("t", text, Syntax::Yaml, &dir.0).expect("the text is YAML")
}

/// `path (code)` of every problem, sorted: the order they are found in is not the contract.
fn problems(converted: &Converted) -> Vec<String> {
    let mut found: Vec<String> = converted
        .problems
        .iter()
        .map(|problem| format!("{} ({})", problem.key, problem.code.as_str()))
        .collect();
    found.sort();
    found
}

fn sorted<const N: usize>(items: [&str; N]) -> Vec<String> {
    let mut items: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();
    items.sort();
    items
}

fn names(app: &Value, field: &str) -> Vec<String> {
    app[field]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|item| item["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn named<'a>(app: &'a Value, field: &str, name: &str) -> &'a Value {
    app[field]
        .as_array()
        .and_then(|list| list.iter().find(|item| item["name"] == name))
        .unwrap_or_else(|| panic!("no {field} named {name} in {app}"))
}

fn ca_pem(host: &str) -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec![host.to_owned()]).expect("certificate");
    (cert.cert.pem(), cert.signing_key.serialize_pem())
}

#[test]
fn traefik_file_http_to_app() {
    let converted = convert_file(&fixture("shop.yml")).expect("the fixture converts");
    assert_eq!(problems(&converted), Vec::<String>::new());
    let app = &converted.app;
    assert_eq!(app["id"], "shop");
    assert_eq!(app["tls"], json!({ "mode": "acme" }));
    assert_eq!(
        app["revisions"],
        json!([{ "id": "file", "state": "serving", "weight": 1 }])
    );

    // Routers: the rule becomes the matcher, the priority is the rule's length unless given, a
    // router with TLS and no entry points listens on `websecure` only, chains keep their order.
    assert_eq!(
        app["routers"],
        json!([
            { "name": "api", "entry_points": ["web"], "priority": 39,
              "match": { "all": [{ "host": "shop.test" }, { "path_prefix": "/api" }] },
              "chain": ["strip-api", "guard"], "service": "shop" },
            { "name": "site", "entry_points": ["websecure"], "priority": 17,
              "match": { "host": "shop.test" },
              "chain": ["site-chain"], "service": "split" },
            { "name": "static", "priority": 7,
              "match": { "host": "static.shop.test" },
              "chain": ["site-chain"], "service": "pages",
              "observability": { "access_log": false } },
        ])
    );

    // Services: servers, weights, the options the label translator knows, the transport by name,
    // and the composite kinds.
    assert_eq!(
        named(app, "services", "shop"),
        &json!({
            "name": "shop", "type": "loadbalancer",
            "servers": [{ "url": "http://127.0.0.1:9001", "weight": 3 },
                        { "url": "http://127.0.0.1:9002", "weight": 1 }],
            "algorithm": "weighted_round_robin",
            "pass_host_header": true,
            "health_check": { "path": "/healthz", "interval_secs": 10, "timeout_secs": 3 },
            "sticky": { "cookie": { "name": "shop_node", "secure": true } },
        })
    );
    assert_eq!(
        named(app, "services", "secure"),
        &json!({ "name": "secure", "type": "loadbalancer",
                 "servers": [{ "url": "https://127.0.0.1:9005" }], "transport": "internal" })
    );
    assert_eq!(
        named(app, "services", "split"),
        &json!({ "name": "split", "type": "weighted",
                 "services": [{ "service": "shop", "weight": 9 }, { "service": "canary", "weight": 1 }] })
    );
    assert_eq!(
        named(app, "services", "mirrored"),
        &json!({ "name": "mirrored", "type": "mirroring", "service": "shop",
                 "mirrors": [{ "service": "canary", "percent": 10 }],
                 "mirror_body": true, "max_body_size": 65536, "forward_credentials": true })
    );
    assert_eq!(
        named(app, "services", "safe"),
        &json!({ "name": "safe", "type": "failover", "service": "shop",
                 "fallback": "canary", "fallback_hold_secs": 0 })
    );

    // Middlewares: kinds of the label translator, then the ones read here.
    assert_eq!(
        named(app, "middlewares", "strip-api"),
        &json!({ "name": "strip-api", "type": "strip_prefix", "prefixes": ["/api"] })
    );
    assert_eq!(
        named(app, "middlewares", "limit"),
        &json!({ "name": "limit", "type": "rate_limit", "average": 100, "burst": 50,
                 "source": { "ip": {} } })
    );
    assert_eq!(
        named(app, "middlewares", "compress"),
        &json!({ "name": "compress", "type": "compress", "algorithms": ["gzip", "br", "zstd"] })
    );
    assert_eq!(
        named(app, "middlewares", "sso"),
        &json!({ "name": "sso", "type": "forward_auth", "address": "http://127.0.0.1:9091/verify",
                 "trust_forward_header": true, "response_headers": ["X-User", "X-Groups"] })
    );
    assert_eq!(
        named(app, "middlewares", "cap"),
        &json!({ "name": "cap", "type": "in_flight_req", "amount": 20,
                 "source": { "header": "X-Api-Key" } })
    );
    assert_eq!(
        named(app, "middlewares", "uploads"),
        &json!({ "name": "uploads", "type": "buffering",
                 "max_request_body_bytes": 32768, "buffer_request": true,
                 "max_response_body_bytes": 1_048_576, "buffer_response": true })
    );
    assert_eq!(
        named(app, "middlewares", "error-pages"),
        &json!({ "name": "error-pages", "type": "errors", "status": ["500-599", "404"],
                 "service": "pages", "query": "/{status}.html" })
    );
    assert_eq!(
        named(app, "middlewares", "plain"),
        &json!({ "name": "plain", "type": "content_type", "auto_detect": false })
    );
    assert_eq!(
        named(app, "middlewares", "guard"),
        &json!({ "name": "guard", "type": "chain", "middlewares": ["limit", "office"] })
    );
}

#[test]
fn traefik_file_remaining_middleware_kinds() {
    let converted = convert_file(&fixture("extra.yml")).expect("the fixture converts");
    assert_eq!(problems(&converted), Vec::<String>::new());
    let app = &converted.app;
    assert_eq!(
        named(app, "middlewares", "client-cert"),
        &json!({ "name": "client-cert", "type": "pass_tls_client_cert", "pem": true,
                 "info": { "not_after": true, "subject": { "common_name": true },
                           "issuer": { "organization": true } } })
    );
    // Traefik keeps `Authorization` unless told otherwise and its realm is `traefik`.
    assert_eq!(
        named(app, "middlewares", "digest"),
        &json!({ "name": "digest", "type": "digest_auth", "realm": "traefik",
                 "remove_header": true,
                 "users": ["alice:traefik:0123456789abcdef0123456789abcdef"] })
    );
    assert_eq!(
        named(app, "middlewares", "web"),
        &json!({ "name": "web", "type": "grpc_web", "allow_origins": ["https://app.mtls.test"] })
    );
    assert_eq!(
        app["udp"],
        json!({
            "routers": [{ "name": "dns", "entry_points": ["dns"], "service": "resolvers" }],
            "services": [{ "name": "resolvers", "type": "loadbalancer",
                           "servers": [{ "address": "10.0.0.5:53" }] }],
        })
    );
}

#[test]
fn traefik_file_tcp_to_l4() {
    let converted = convert_file(&fixture("shop.yml")).expect("the fixture converts");
    assert_eq!(
        converted.app["tcp"],
        json!({
            "routers": [{
                "name": "db", "entry_points": ["edge"],
                "match": { "all": [{ "sni": "db.shop.test" }, { "alpn": "postgresql" }] },
                "tls": { "passthrough": true }, "chain": ["db-office"], "service": "pg",
            }],
            "services": [{
                "name": "pg", "type": "loadbalancer",
                "servers": [{ "address": "127.0.0.1:5432" }],
                "proxy_protocol": { "version": 2 }, "termination_delay_ms": 200,
            }],
            "middlewares": [{ "name": "db-office", "type": "ip_allow_list",
                              "source_range": ["10.0.0.0/8"] }],
        })
    );

    // `HostSNI(`*`)` is no matcher at all, a router with `tls: {}` terminates, and a TCP router
    // without entry points is refused: podgate cannot reserve "every entry point" to a tenant.
    let dir = Dir::new("l4");
    let converted = from_yaml(
        &dir,
        r"
tcp:
  routers:
    any: {rule: 'HostSNI(`*`)', entryPoints: [edge], service: s, tls: {}}
    lost: {rule: 'HostSNI(`a.test`)', service: s, tls: {}}
    ranked: {rule: 'HostSNI(`b.test`)', entryPoints: [edge], service: s, priority: 5, tls: {}}
    mixed: {rule: 'Host(`b.test`)', entryPoints: [edge], service: s}
  services:
    s: {loadBalancer: {servers: [{address: '10.0.0.1:1', tls: true}]}}
    w: {weighted: {services: [{name: s, weight: 1}]}}
",
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "tcp.routers.lost.entryPoints (invalid_label)",
            "tcp.routers.ranked.priority (unsupported_label)",
            "tcp.routers.mixed.rule (unsupported_rule)",
            "tcp.services.w.weighted (unsupported_label)",
        ])
    );
    assert_eq!(
        converted.app["tcp"]["routers"],
        json!([{ "name": "any", "entry_points": ["edge"], "service": "s", "tls": { "passthrough": false } }])
    );
    assert_eq!(
        converted.app["tcp"]["services"],
        json!([{ "name": "s", "type": "loadbalancer",
                 "servers": [{ "address": "10.0.0.1:1", "tls": true }] }])
    );
}

#[test]
fn traefik_file_transport() {
    let dir = Dir::new("transport");
    let (ca, _) = ca_pem("ca.internal");
    let (cert, key) = ca_pem("client.internal");
    dir.write("ca.pem", &ca);
    dir.write("client.crt", &cert);
    dir.write("client.key", &key);
    let converted = from_yaml(
        &dir,
        r"
http:
  serversTransports:
    full:
      serverName: backend.internal
      insecureSkipVerify: true
      disableHTTP2: true
      rootCAs: [ca.pem]
      certificates: [{certFile: client.crt, keyFile: client.key}]
      forwardingTimeouts: {dialTimeout: 5s, idleConnTimeout: 1m30s}
    pooled: {maxIdleConnsPerHost: 5}
    slow: {forwardingTimeouts: {responseHeaderTimeout: 10s}}
    two: {certificates: [{certFile: client.crt, keyFile: client.key}, {certFile: client.crt, keyFile: client.key}]}
    spiffe: {spiffe: {ids: [spiffe://x/y]}}
tcp:
  serversTransports:
    db: {dialTimeout: 3s, tls: {serverName: db.internal}}
    keepalive: {dialKeepAlive: 10s}
",
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "http.serversTransports.pooled.maxIdleConnsPerHost (unsupported_label)",
            "http.serversTransports.slow.forwardingTimeouts.responseHeaderTimeout (unsupported_label)",
            "http.serversTransports.spiffe.spiffe (unsupported_label)",
            "http.serversTransports.two.certificates (unsupported_label)",
            "tcp.serversTransports.keepalive.dialKeepAlive (unsupported_label)",
        ])
    );
    assert_eq!(names(&converted.app, "transports"), ["full", "db"]);
    assert_eq!(
        named(&converted.app, "transports", "full"),
        &json!({
            "name": "full", "type": "servers_transport",
            "server_name": "backend.internal", "insecure_skip_verify": true, "http2": false,
            "ca_pem": ca, "client_cert": { "cert_pem": cert, "key_pem": key },
            "dial_timeout_secs": 5, "idle_timeout_secs": 90,
        })
    );
    assert_eq!(
        named(&converted.app, "transports", "db"),
        &json!({ "name": "db", "type": "servers_transport",
                 "dial_timeout_secs": 3, "server_name": "db.internal" })
    );
    let mut watched: Vec<String> = converted
        .files
        .iter()
        .filter_map(|file| file.file_name()?.to_str().map(str::to_owned))
        .collect();
    watched.sort();
    watched.dedup();
    assert_eq!(watched, ["ca.pem", "client.crt", "client.key"]);
}

#[test]
fn traefik_file_certificates_inlined() {
    let dir = Dir::new("certs");
    let cert =
        rcgen::generate_simple_self_signed(vec!["Shop.Test".to_owned(), "*.shop.test".to_owned()])
            .expect("certificate");
    let (cert_pem, key_pem) = (cert.cert.pem(), cert.signing_key.serialize_pem());
    let (fallback_cert, fallback_key) = ca_pem("fallback.test");
    dir.write("shop.crt", &cert_pem);
    let key_path = dir.write("shop.key", &key_pem);
    dir.write("fallback.crt", &fallback_cert);
    dir.write("fallback.key", &fallback_key);
    dir.write("notes.txt", "this is not a certificate\n");
    let converted = from_yaml(
        &dir,
        &format!(
            r"
tls:
  certificates:
    - certFile: shop.crt
      keyFile: {}
    - certFile: notes.txt
      keyFile: shop.key
    - certFile: shop.crt
      keyFile: shop.key
      stores: [other]
  stores:
    default:
      defaultCertificate: {{certFile: fallback.crt, keyFile: fallback.key}}
    other: {{}}
",
            key_path.display()
        ),
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "tls.certificates[1].certFile (invalid_label)",
            "tls.certificates[2].stores (unsupported_label)",
            "tls.stores.other (unsupported_label)",
        ])
    );
    let certificates = serde_json::to_value(&converted.certificates).expect("JSON");
    assert_eq!(
        certificates,
        json!([
            { "hosts": ["shop.test", "*.shop.test"], "cert_pem": cert_pem, "key_pem": key_pem },
            { "hosts": ["fallback.test"], "cert_pem": fallback_cert, "key_pem": fallback_key,
              "default": true },
        ])
    );
    // The reason names the file but never what is in it.
    let reason = &converted.problems[0].reason;
    assert!(reason.contains("holds no PEM block"), "{reason}");
    assert!(!reason.contains("not a certificate"), "{reason}");
}

#[test]
fn traefik_file_tls_options() {
    let dir = Dir::new("options");
    let (ca, _) = ca_pem("clients.test");
    dir.write("clients.pem", &ca);
    let converted = from_yaml(
        &dir,
        r"
http:
  routers:
    a: {rule: 'Host(`a.test`)', service: s, tls: {}}
    b: {rule: 'Host(`b.test`)', service: s, tls: {options: default}}
    c: {rule: 'Host(`c.test`)', service: s, tls: {options: lax}}
    d: {rule: 'Host(`d.test`)', service: s, tls: {options: nope}}
    e: {rule: 'Host(`e.test`)', service: s, tls: {options: capped}}
    plain: {rule: 'Host(`f.test`)', service: s}
  services:
    s: {loadBalancer: {servers: [{url: 'http://127.0.0.1:1'}]}}
tls:
  options:
    default:
      minVersion: VersionTLS13
      sniStrict: true
      alpnProtocols: [h2, http/1.1]
      cipherSuites: [TLS_AES_128_GCM_SHA256]
      clientAuth: {caFiles: [clients.pem], clientAuthType: RequireAndVerifyClientCert}
    lax: {minVersion: VersionTLS12}
    capped: {maxVersion: VersionTLS12, curvePreferences: [CurveP256]}
",
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "tls.options.capped.maxVersion (unsupported_label)",
            "tls.options.capped.curvePreferences (unsupported_label)",
            "http.routers.c.tls.options (unsupported_label)",
            "http.routers.d.tls.options (invalid_label)",
            "http.routers.e.tls.options (unsupported_label)",
        ])
    );
    assert_eq!(
        converted.app["tls"],
        json!({
            "mode": "acme", "min_version": "1.3", "sni_strict": true,
            "alpn": ["h2", "http/1.1"], "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
            "client_auth": "require_and_verify", "client_ca_pem": ca,
        })
    );
    // `a` and `b` get `default`, `plain` takes no TLS, and the others would be served under
    // options they did not ask for.
    assert_eq!(names(&converted.app, "routers"), ["a", "b", "plain"]);
}

#[test]
fn traefik_file_unsupported_reported() {
    let dir = Dir::new("unsupported");
    let converted = from_yaml(
        &dir,
        r"
http:
  routers:
    ok: {rule: 'Host(`a.test`)', service: s}
    via-plugin: {rule: 'Host(`b.test`)', service: s, middlewares: [p]}
    old-syntax: {rule: 'HostHeader(`c.test`)', service: s}
    on-bad-service: {rule: 'Host(`d.test`)', service: flush}
    typo: {rule: 'Host(`e.test`)', service: s, entrypoints: [web], bogus: 1}
    dotted.name: {rule: 'Host(`f.test`)', service: s}
  services:
    s: {loadBalancer: {servers: [{url: 'http://127.0.0.1:1'}]}}
    flush:
      loadBalancer:
        servers: [{url: 'http://127.0.0.1:2'}]
        responseForwarding: {flushInterval: 1s}
    pathy: {loadBalancer: {servers: [{url: 'http://127.0.0.1:3/base'}]}}
    p2c: {loadBalancer: {strategy: p2c, servers: [{url: 'http://127.0.0.1:4'}]}}
  middlewares:
    p: {plugin: {demo: {x: 1}}}
    typo: {stripPrefix: {prefixes: [/a], forceSlash: false, bogus: 1}}
    fine: {stripPrefix: {prefixes: [/b]}}
    two: {stripPrefix: {prefixes: [/c]}, addPrefix: {prefix: /d}}
    old: {ipWhiteList: {sourceRange: [10.0.0.0/8]}}
    comma: {basicAuth: {users: ['a:$argon2id$v=19$m=65536,t=3,p=4$x$y']}}
    mem: {buffering: {maxRequestBodyBytes: 100, memRequestBodyBytes: 50}}
    page: {errors: {status: ['500-599'], service: s}}
    on: {contentType: {autoDetect: true}}
extra: {}
",
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "http.services.flush.loadBalancer.responseForwarding (unsupported_label)",
            "http.services.p2c.loadBalancer.strategy (unsupported_label)",
            "http.services.pathy.loadBalancer.servers[0].url (invalid_label)",
            "http.middlewares.comma.basicAuth.users (unsupported_label)",
            "http.middlewares.mem.buffering.memRequestBodyBytes (unsupported_label)",
            "http.middlewares.old.ipWhiteList (unsupported_label)",
            "http.middlewares.on.contentType.autoDetect (unsupported_label)",
            "http.middlewares.p.plugin (unsupported_label)",
            "http.middlewares.page.errors.query (invalid_label)",
            "http.middlewares.two (invalid_label)",
            "http.middlewares.typo.stripPrefix.forceSlash (unsupported_label)",
            "http.middlewares.typo.stripPrefix.bogus (unsupported_label)",
            "http.routers.dotted.name (invalid_label)",
            "http.routers.on-bad-service.service (unsupported_label)",
            "http.routers.old-syntax.rule (unsupported_rule)",
            "http.routers.typo.bogus (unsupported_label)",
            "http.routers.via-plugin.middlewares[0] (unsupported_label)",
            "extra (unsupported_label)",
        ]),
        "{:#?}",
        converted.problems
    );
    // Only the objects with a problem are gone, and nothing that names them survives.
    assert_eq!(names(&converted.app, "routers"), ["ok"]);
    assert_eq!(names(&converted.app, "middlewares"), ["fine"]);
    assert_eq!(names(&converted.app, "services"), ["s"]);
    assert!(
        converted
            .problems
            .iter()
            .all(|problem| !problem.reason.is_empty())
    );
}

#[test]
fn traefik_file_cross_provider_ref_rejected() {
    let dir = Dir::new("foreign");
    let converted = from_yaml(
        &dir,
        r"
http:
  routers:
    own: {rule: 'Host(`a.test`)', service: ok@file, middlewares: [m@file]}
    docker: {rule: 'Host(`b.test`)', service: api@docker}
    shared: {rule: 'Host(`c.test`)', service: s, middlewares: [auth@kubernetescrd]}
    internal: {rule: 'Host(`d.test`)', service: api@internal}
  services:
    s: {loadBalancer: {servers: [{url: 'http://127.0.0.1:1'}], serversTransport: t@consul}}
    ok: {loadBalancer: {servers: [{url: 'http://127.0.0.1:2'}], serversTransport: t@file}}
    w: {weighted: {services: [{name: ok@file, weight: 1}, {name: other@consul, weight: 1}]}}
  middlewares:
    m: {stripPrefix: {prefixes: [/a]}}
    chained: {chain: {middlewares: [m@file, x@docker]}}
  serversTransports:
    t: {serverName: x.internal}
",
    );
    assert_eq!(
        problems(&converted),
        sorted([
            "http.services.s.loadBalancer.serversTransport (foreign_reference)",
            "http.services.w.weighted.services[1].name (foreign_reference)",
            "http.middlewares.chained.chain.middlewares[1] (foreign_reference)",
            "http.routers.docker.service (foreign_reference)",
            "http.routers.internal.service (foreign_reference)",
            "http.routers.shared.middlewares[0] (foreign_reference)",
            "http.routers.shared.service (unsupported_label)",
        ])
    );
    assert!(
        converted
            .problems
            .iter()
            .filter(|problem| problem.code == Code::ForeignReference)
            .count()
            == 6
    );
    // The `@file` spelling is this file: the router, its middleware and `ok` survive.
    assert_eq!(names(&converted.app, "routers"), ["own"]);
    assert_eq!(names(&converted.app, "services"), ["ok"]);
    assert_eq!(
        converted.app["routers"][0]["chain"],
        json!(["m"]),
        "the `@file` suffix is not kept"
    );
}

fn provider() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_podgate-provider"));
    command.stdin(Stdio::null());
    command
}

#[test]
fn convert_traefik_exit_codes() {
    let dir = Dir::new("exit");
    let broken = dir.write(
        "broken.yml",
        "http:\n  middlewares:\n    p: {plugin: {x: 1}}\n  routers:\n    r: {rule: 'Host(`a.test`)', service: s}\n  services:\n    s: {loadBalancer: {servers: [{url: 'http://127.0.0.1:1'}]}}\n",
    );
    let shop = fixture("shop.yml");

    let clean = provider()
        .arg("convert-traefik")
        .arg(&shop)
        .output()
        .expect("runs");
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    let snapshot: Value = serde_json::from_slice(&clean.stdout).expect("stdout is the snapshot");
    assert_eq!(snapshot["apps"][0]["id"], "shop");
    assert!(
        snapshot["apps"][0].get("tenant").is_none(),
        "the tenant is the source's to set"
    );
    assert!(clean.stderr.is_empty());

    let rejected = provider()
        .arg("convert-traefik")
        .arg(&broken)
        .output()
        .expect("runs");
    assert_eq!(rejected.status.code(), Some(1));
    let report = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        report.contains("broken.yml: http.middlewares.p.plugin:"),
        "{report}"
    );
    let partial: Value = serde_json::from_slice(&rejected.stdout).expect("a partial snapshot");
    assert_eq!(partial["apps"][0]["routers"][0]["name"], "r");

    let lenient = provider()
        .args(["convert-traefik", "--lenient"])
        .arg(&broken)
        .output()
        .expect("runs");
    assert_eq!(lenient.status.code(), Some(0));
    assert_eq!(
        lenient.stdout, rejected.stdout,
        "--lenient only changes the exit status"
    );
    assert_eq!(
        lenient.stderr, rejected.stderr,
        "and the report is the same"
    );

    let many = provider()
        .arg("convert-traefik")
        .arg(&shop)
        .arg(fixture("extra.yml"))
        .output()
        .expect("runs");
    assert_eq!(many.status.code(), Some(0));
    let many: Value = serde_json::from_slice(&many.stdout).expect("JSON");
    assert_eq!(many["apps"].as_array().map(Vec::len), Some(2));

    let missing = provider()
        .arg("convert-traefik")
        .arg(dir.0.join("absent.yml"))
        .output()
        .expect("runs");
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
    let none = provider().arg("convert-traefik").output().expect("runs");
    assert_eq!(none.status.code(), Some(2));
    let unknown = provider()
        .args(["convert-traefik", "--strict"])
        .arg(&shop)
        .output()
        .expect("runs");
    assert_eq!(unknown.status.code(), Some(2));
    let text = dir.write("bad.txt", "x");
    let extension = provider()
        .arg("convert-traefik")
        .arg(&text)
        .output()
        .expect("runs");
    assert_eq!(extension.status.code(), Some(2));
}

#[test]
fn traefik_file_toml_is_the_same_tree() {
    let dir = Dir::new("toml");
    let converted = convert(
        "t",
        r#"
[http.routers.r]
  rule = "Host(`a.test`)"
  service = "s"
  [http.routers.r.tls]
[http.services.s.loadBalancer]
  [[http.services.s.loadBalancer.servers]]
    url = "http://127.0.0.1:1"
[http.middlewares.c.compress]
"#,
        Syntax::Toml,
        &dir.0,
    )
    .expect("TOML");
    assert_eq!(problems(&converted), Vec::<String>::new());
    assert_eq!(
        converted.app["routers"][0]["entry_points"],
        json!(["websecure"])
    );
    assert_eq!(names(&converted.app, "middlewares"), ["c"]);
}

/// A daemon with a TCP entry point next to the usual two, the only difference to the harness'.
struct Daemon {
    child: std::process::Child,
    admin: PathBuf,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start_daemon() -> Daemon {
    let dir = std::env::temp_dir().join(format!("pgp-tfile-daemon-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let policy = dir.join("upstream-policy.json");
    std::fs::write(&policy, daemon::LOOPBACK_POLICY).expect("policy file");
    let admin = dir.join("admin.sock");
    let ports = free_ports(3);
    let child = Command::new(daemon::binary())
        .env(
            "ENTRY_POINTS",
            format!(
                "web=127.0.0.1:{}/http,websecure=127.0.0.1:{}/https,edge=127.0.0.1:{}/tcp",
                ports[0], ports[1], ports[2]
            ),
        )
        .env("ADMIN_SOCKET", &admin)
        .env("UPSTREAM_POLICY_FILE", &policy)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn the daemon");
    let daemon = Daemon { child, admin, dir };
    let deadline = Instant::now() + Duration::from_secs(30);
    while UnixStream::connect(&daemon.admin).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "the daemon did not open its admin socket"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    daemon
}

/// What the daemon says about the snapshot of `files`, converted and given a tenant.
async fn daemon_validates(files: &[&str]) -> (u16, Value) {
    let mut apps = Vec::new();
    let mut certificates = Vec::new();
    for file in files {
        let converted = convert_file(&fixture(file)).expect("the fixture converts");
        assert_eq!(problems(&converted), Vec::<String>::new());
        let mut app = converted.app;
        app["tenant"] = json!("acme");
        app["declared_by"] = json!("file/traefik");
        apps.push(app);
        certificates.extend(converted.certificates);
    }
    let mut snapshot = json!({
        "version": 1,
        "tenants": [{ "id": "acme", "weight": 1,
                      "budget": { "max_inflight": 100, "max_buffer_bytes": 33_554_432 } }],
        "apps": apps,
        "certificates": certificates,
        "entry_points": [{ "name": "edge", "tenants": ["acme"] }],
    });
    snapshot["skew_secret"] = json!("0123456789abcdef0123456789abcdef");
    let daemon = start_daemon().await;
    let client = AdminClient::new(&daemon.admin, Duration::from_secs(30));
    let answer = client
        .validate(&snapshot.to_string())
        .await
        .expect("validate answers");
    (answer.status, answer.json().unwrap_or(Value::Null))
}

#[tokio::test]
async fn converted_fixture_validates() {
    let (status, answer) = daemon_validates(&["shop.yml"]).await;
    assert_eq!(status, 200, "{answer}");
}

/// The file source with `format = "traefik"`: a Traefik file is an app of the source's tenant
/// with `first_seen` 0, and renewing a certificate on disk is a change of the app.
#[tokio::test]
async fn traefik_file_source_follows_files_it_reads() {
    use podgate_provider::file::FileSource;
    use podgate_provider::source::Source;
    use tokio::sync::mpsc;

    let dir = Dir::new("source");
    let (cert, key) = ca_pem("web.test");
    dir.write("web.crt", &cert);
    dir.write("web.key", &key);
    dir.write(
        "web.yml",
        "http:\n  routers:\n    r: {rule: 'Host(`web.test`)', service: s}\n  services:\n    s: {loadBalancer: {servers: [{url: 'http://127.0.0.1:1'}]}}\ntls:\n  certificates: [{certFile: web.crt, keyFile: web.key}]\n",
    );
    let config = common::config(
        &dir.0.join("admin.sock"),
        &format!(
            "[[source]]\nkind = \"file\"\nname = \"files\"\npath = {:?}\nformat = \"traefik\"\npoll_ms = 20\ntenant = \"acme\"\n",
            dir.0.display().to_string()
        ),
    );
    let source = FileSource::from_config(&config.sources[0]).expect("a valid file source");
    let (tx, mut rx) = mpsc::channel(16);
    let task = tokio::spawn(source.run(tx));
    let state = next_state(&mut rx, None).await;
    assert_eq!(state.apps.len(), 1);
    let app = &state.apps[0];
    assert_eq!(&*app.app.id, "web");
    assert_eq!(app.tenant.mapped.as_deref(), Some("acme"));
    assert_eq!(app.origin.first_seen, 0);
    assert_eq!(&*app.app.routers[0].name, "r");
    assert_eq!(&*state.certificates[0].certificate.hosts[0], "web.test");

    let (renewed, renewed_key) = ca_pem("web.test");
    dir.write("web.key", &renewed_key);
    dir.write("web.crt", &renewed);
    let state = next_state(&mut rx, Some(&renewed)).await;
    assert_eq!(state.certificates[0].certificate.cert_pem, renewed);
    task.abort();
}

/// The next state the source sends, with the certificate `wanted` when one is named.
async fn next_state(
    rx: &mut tokio::sync::mpsc::Receiver<podgate_provider::source::Update>,
    wanted: Option<&str>,
) -> podgate_provider::source::State {
    use podgate_provider::source::UpdateBody;
    let wait = async {
        loop {
            let update = rx.recv().await.expect("the source keeps running");
            if let UpdateBody::State(state) = update.body
                && wanted.is_none_or(|pem| {
                    state
                        .certificates
                        .iter()
                        .any(|found| found.certificate.cert_pem == pem)
                })
            {
                return state;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(20), wait)
        .await
        .expect("the state arrives in time")
}
