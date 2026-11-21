//! The Traefik rule grammar and the `traefik.*` labels: the fixture table of rules, what is
//! refused and why, priorities (against the real `traefik` binary), podkit's own labels, the
//! middleware options, and the translated apps against the Docker source, the merge and the real
//! daemon. Everything that waits has a deadline.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::docker::{Ctr, FakeDocker};
use common::{DEADLINE, config, daemon, free_ports};
use podgate_provider::docker::DockerSource;
use podgate_provider::docker::labels::{self, Member};
use podgate_provider::push::AdminClient;
use podgate_provider::source::{Origin, Source, SourceApp, State, TenantClaim, Update, UpdateBody};
use podgate_provider::traefik::{Code, Translation, translate};
use podgate_provider::{Config, Merged, Merger, UpstreamPolicy};
use podgate_rule::{Dialect, parse};
use serde_json::{Value, json};
use tokio::sync::mpsc;

const FIXTURE: &str = include_str!("fixtures/traefik_rules.json");

/// The rows of `fixtures/traefik_rules.json`: a rule, the matcher it becomes, its length, and
/// whether Traefik 3.7 itself accepts it (it refuses several arguments to `Host`, `Path*` and
/// `Method`, which podgate reads as any-of).
struct Row {
    rule: String,
    matcher: Value,
    priority: i32,
    traefik: bool,
}

fn rows() -> Vec<Row> {
    let table: Vec<Value> = serde_json::from_str(FIXTURE).expect("the fixture is JSON");
    table
        .into_iter()
        .map(|row| Row {
            rule: row["rule"].as_str().expect("rule").to_owned(),
            matcher: row["matcher"].clone(),
            priority: i32::try_from(row["priority"].as_i64().expect("priority")).expect("i32"),
            traefik: row.get("traefik").and_then(Value::as_bool).unwrap_or(true),
        })
        .collect()
}

fn http(rule: &str) -> Result<Value, String> {
    parse(rule, Dialect::Http)
        .map(|rule| rule.matcher.expect("an HTTP rule always has a matcher"))
        .map_err(|err| err.to_string())
}

/// Translates the labels of one router `r` with `rule`, plus `extra`.
fn router_labels(rule: &str, extra: &[(&str, &str)]) -> Translation {
    let mut pairs = vec![
        ("traefik.http.routers.r.rule", rule),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ];
    pairs.extend_from_slice(extra);
    translate(pairs)
}

// ---- the grammar -----------------------------------------------------------------------------

#[test]
fn traefik_rule_table() {
    let rows = rows();
    assert!(rows.len() > 30, "the table is the evidence: {}", rows.len());
    for row in &rows {
        assert_eq!(
            http(&row.rule).as_ref(),
            Ok(&row.matcher),
            "rule {:?}",
            row.rule
        );
        let translated = router_labels(&row.rule, &[]);
        assert_eq!(translated.problems, [], "rule {:?}", row.rule);
        let router = &translated.routers[0];
        assert_eq!(router.matcher, row.matcher, "rule {:?}", row.rule);
        assert_eq!(router.priority, Some(row.priority), "rule {:?}", row.rule);
    }
}

#[test]
fn traefik_rule_nesting() {
    assert_eq!(
        http("Host(`a.test`) && (Path(`/a`) || (Path(`/b`) && Method(`GET`))) && !(Path(`/c`))"),
        Ok(json!({ "all": [
            { "host": "a.test" },
            { "any": [{ "path": "/a" }, { "all": [{ "path": "/b" }, { "method": "GET" }] }] },
            { "not": { "path": "/c" } },
        ] }))
    );
    assert_eq!(
        http("Path(`/a`) && Path(`/b`) && Path(`/c`) && Path(`/d`) && Path(`/e`)"),
        Ok(json!({ "all": [
            { "path": "/a" }, { "path": "/b" }, { "path": "/c" }, { "path": "/d" }, { "path": "/e" },
        ] }))
    );
    assert_eq!(
        http("Host(`a.test`) || Host(`b.test`) || Path(`/x`) || Host(`c.test`)"),
        Ok(json!({ "any": [{ "host": ["a.test", "b.test", "c.test"] }, { "path": "/x" }] })),
        "hosts of an || merge into the first host leaf"
    );
    let deep =
        |levels: usize| format!("{}Host(`a.test`){}", "(".repeat(levels), ")".repeat(levels));
    assert_eq!(http(&deep(60)), Ok(json!({ "host": "a.test" })));
    let err = http(&deep(500)).expect_err("a hostile nesting is refused");
    assert!(err.contains("nests too deeply"), "{err}");
    let long = format!("Host(`{}`)", "a".repeat(20_000));
    assert!(http(&long).expect_err("too long").contains("longer than"));
}

#[test]
fn traefik_rule_negation() {
    assert_eq!(
        http("!Host(`a.test`) && Path(`/x`)"),
        Ok(json!({ "all": [{ "not": { "host": "a.test" } }, { "path": "/x" }] })),
        "! binds tighter than &&"
    );
    assert_eq!(
        http("!(Host(`a.test`) && Path(`/x`))"),
        Ok(json!({ "not": { "all": [{ "host": "a.test" }, { "path": "/x" }] } }))
    );
    assert_eq!(
        http("!!Host(`a.test`)"),
        Ok(json!({ "not": { "not": { "host": "a.test" } } }))
    );
    assert_eq!(
        http("Host(`a.test`) || !Host(`b.test`)"),
        Ok(json!({ "any": [{ "host": "a.test" }, { "not": { "host": "b.test" } }] })),
        "a negated host is not merged into the host list"
    );
    let tcp = |rule: &str| parse(rule, Dialect::Tcp).map_err(|err| err.to_string());
    assert!(
        tcp("!HostSNI(`*`)")
            .expect_err("matches nothing")
            .contains("matches nothing")
    );
}

#[test]
fn traefik_tcp_rules() {
    let tcp = |rule: &str| parse(rule, Dialect::Tcp).expect(rule).matcher;
    assert_eq!(
        tcp("HostSNI(`*`)"),
        None,
        "a router with no match takes every connection"
    );
    assert_eq!(
        tcp("HostSNI(`*`) && ClientIP(`10.0.0.0/8`)"),
        Some(json!({ "client_ip": ["10.0.0.0/8"] }))
    );
    assert_eq!(
        tcp("HostSNI(`a.test`, `*`)"),
        None,
        "any-of with `*` is every name"
    );
    assert_eq!(
        tcp("HostSNI(`a.test`) && ALPN(`h2`)"),
        Some(json!({ "all": [{ "sni": "a.test" }, { "alpn": "h2" }] }))
    );
    assert_eq!(
        tcp("HostSNIRegexp(`^a\\.`)"),
        Some(json!({ "sni_regexp": "^a\\." }))
    );
    for rule in ["Host(`a.test`)", "PathPrefix(`/`)"] {
        let err = parse(rule, Dialect::Tcp).expect_err(rule);
        assert!(err.to_string().contains("HTTP rule function"), "{err}");
    }
    let err = parse("HostSNI(`a.test`)", Dialect::Http).expect_err("TCP in HTTP");
    assert!(err.to_string().contains("TCP rule function"), "{err}");
}

// ---- what is refused -------------------------------------------------------------------------

#[test]
fn traefik_v2_syntax_unsupported() {
    for rule in [
        "Headers(`X-Env`, `canary`)",
        "HeadersRegexp(`X-Env`, `c.*`)",
        "HostHeader(`a.test`)",
        "PathPrefixStrip(`/api`)",
        "PathStrip(`/api`)",
        "PathPrefixStripRegex(`/api`)",
        "HostRegexp(`{subdomain:[a-z]+}.a.test`)",
        "Host(`a.test`) && HostRegexp(`api-{env:.*}.a.test`)",
    ] {
        let err = parse(rule, Dialect::Http).expect_err(rule);
        assert_eq!(err.code(), "unsupported_rule", "{rule}");
        assert!(err.to_string().contains("v2"), "{rule}: {err}");
    }
    // A repetition is not a named group.
    assert!(http("HostRegexp(`^a{2,3}\\.test$`)").is_ok());

    // Only the router that says so is left out, with the label named.
    let translated = translate([
        ("traefik.http.routers.old.rule", "Headers(`X`, `y`)"),
        ("traefik.http.routers.new.rule", "Host(`a.test`)"),
        ("traefik.http.routers.syntax.rule", "Host(`b.test`)"),
        ("traefik.http.routers.syntax.rulesyntax", "v2"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ]);
    assert_eq!(
        translated
            .routers
            .iter()
            .map(|router| &*router.name)
            .collect::<Vec<_>>(),
        ["new"]
    );
    let mut codes: Vec<(&str, &str)> = translated
        .problems
        .iter()
        .map(|problem| (problem.code.as_str(), &*problem.key))
        .collect();
    codes.sort_unstable();
    assert_eq!(
        codes,
        [
            ("unsupported_rule", "traefik.http.routers.old.rule"),
            ("unsupported_rule", "traefik.http.routers.syntax.rulesyntax"),
        ]
    );
}

#[test]
fn traefik_unknown_function_unsupported() {
    for rule in [
        "Foo(`a`)",
        "Host",
        "Host(`a.test`) Path(`/x`)",
        "Host(`a.test`) &",
        "Host(`a.test`) &&",
        "Host(`a.test`) != Path(`/x`)",
        "Host(`a.test`",
        "Host()",
        "Host(a.test)",
        "Host(`a.test`, )",
        "Host(`a.*.test`)",
        "Host(`é.test`)",
        "Header(`X`)",
        "Query(`flag`)",
        "Path(`x`)",
        "PathPrefix(`api`)",
        "HostRegexp(`a`, `b`)",
        "ClientIP(`10.0.0.0/33`)",
        "ClientIP(`example.com`)",
        "Method(`GE T`)",
        "Host(`a.test`) && !",
        "Host(`unclosed)",
        "",
    ] {
        let err = parse(rule, Dialect::Http).expect_err(rule);
        assert_eq!(err.code(), "unsupported_rule", "{rule:?}");
    }
    let err = parse("Wibble(`a`)", Dialect::Http).expect_err("unknown");
    assert!(err.to_string().contains("unknown function Wibble"), "{err}");
}

#[test]
fn traefik_bad_regexp_rejected() {
    for rule in [
        "HostRegexp(`(`)",
        "HostRegexp(`^(?=a)`)",
        "PathRegexp(`^(a)\\1$`)",
        "HeaderRegexp(`X`, `[`)",
        "QueryRegexp(`q`, `*`)",
    ] {
        let err = parse(rule, Dialect::Http).expect_err(rule);
        assert_eq!(err.code(), "unsupported_rule", "{rule}");
        assert!(
            err.to_string().contains("regular expression"),
            "{rule}: {err}"
        );
    }
    let ok = parse(
        "Host(`a.test`) && PathRegexp(`^/a`) && HostRegexp(`b`)",
        Dialect::Http,
    )
    .expect("good regexps");
    assert_eq!(
        ok.regexes.iter().map(|re| &**re).collect::<Vec<_>>(),
        ["^/a", "b"],
        "the crate returns the regexps it checked"
    );

    // One bad regexp leaves out one router.
    let translated = translate([
        ("traefik.http.routers.bad.rule", "HostRegexp(`(`)"),
        ("traefik.http.routers.good.rule", "Host(`a.test`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ]);
    assert_eq!(translated.routers.len(), 1);
    assert_eq!(translated.problems.len(), 1);
    assert_eq!(translated.problems[0].code, Code::UnsupportedRule);
}

// ---- HostRegexp and the catch-all rule -------------------------------------------------------

const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test", "example.com", "*.example.com"]

[[tenant]]
id = "alone"
hosts = ["alone.test"]
exclusive_entry_points = ["private"]

[[tenant]]
id = "wide"
hosts = ["wide.test"]
catch_all = true

[[source]]
kind = "docker"
name = "docker"
"#;

/// One tenant and no entry point policies: what the real daemon takes without more setup.
const PLAIN_TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test", "example.com", "*.example.com"]

[[source]]
kind = "docker"
name = "docker"
"#;

/// The app the Docker source builds from one container carrying `pairs`.
fn app_of(pairs: &[(&str, &str)], object: &str, tenant: &str) -> SourceApp {
    let parsed = labels::parse(pairs.iter().copied()).expect("labels");
    let claim = TenantClaim::mapped(tenant);
    let member = Member {
        name: "web-1",
        labels: &parsed,
        server: SocketAddr::from(([10, 4, 0, 5], parsed.port.expect("a port"))),
        claim: &claim,
        created: 1,
    };
    let assembled = labels::assemble(object, &[member]).expect("assembled");
    assert_eq!(assembled.rejected, []);
    SourceApp {
        origin: Origin {
            source: "docker".into(),
            object: object.into(),
            first_seen: 1,
        },
        tenant: assembled.claim,
        app: assembled.app,
    }
}

fn merge_in(tenants: &str, apps: Vec<SourceApp>) -> Merged {
    let state = State {
        apps,
        certificates: Vec::new(),
    };
    let states: BTreeMap<Box<str>, State> = BTreeMap::from([("docker".into(), state)]);
    let merger = Merger::new(
        &config(Path::new("/nonexistent/admin.sock"), tenants),
        UpstreamPolicy::builtin(),
    );
    merger.merge(&states, &BTreeSet::new())
}

fn merge(apps: Vec<SourceApp>) -> Merged {
    merge_in(TENANTS, apps)
}

fn finding_codes(merged: &Merged) -> Vec<(&'static str, String)> {
    merged
        .findings()
        .iter()
        .map(|finding| (finding.code, finding.object.to_string()))
        .collect()
}

fn ids(merged: &Merged) -> Vec<String> {
    merged
        .snapshot()
        .apps
        .iter()
        .map(|app| app.id.to_string())
        .collect()
}

#[test]
fn traefik_hostregexp_with_literal_host_becomes_all() {
    assert_eq!(
        http("Host(`a.acme.test`) && HostRegexp(`^x`)"),
        Ok(json!({ "all": [{ "host": "a.acme.test" }, { "host_regexp": "^x" }] }))
    );
    assert_eq!(
        http("HostRegexp(`^x`) && Host(`*.acme.test`)"),
        Ok(json!({ "all": [{ "host_regexp": "^x" }, { "host": "*.acme.test" }] })),
        "the order of the rule is kept; the claim is the literal host either way"
    );
    let merged = merge(vec![app_of(
        &[
            (
                "traefik.http.routers.r.rule",
                "Host(`shop.acme.test`) && HostRegexp(`^s`)",
            ),
            ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ],
        "narrowed",
        "acme",
    )]);
    assert_eq!(
        ids(&merged),
        ["docker-narrowed"],
        "{:?}",
        finding_codes(&merged)
    );
    assert_eq!(finding_codes(&merged), []);
}

#[test]
fn traefik_hostregexp_alone_needs_exclusive_or_allowed() {
    let bare = |entry_points: Option<&'static str>| {
        let mut pairs = vec![
            (
                "traefik.http.routers.r.rule",
                "HostRegexp(`^.*\\.example$`)",
            ),
            ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ];
        if let Some(entry_points) = entry_points {
            pairs.push(("traefik.http.routers.r.entrypoints", entry_points));
        }
        pairs
    };
    let merged = merge(vec![
        app_of(&bare(None), "open", "acme"),
        app_of(&bare(Some("web")), "on-web", "acme"),
        app_of(&bare(Some("private,web")), "mixed", "alone"),
        app_of(&bare(Some("private")), "exclusive", "alone"),
        app_of(&bare(None), "allowed", "wide"),
    ]);
    assert_eq!(
        ids(&merged),
        ["docker-allowed", "docker-exclusive"],
        "{:?}",
        finding_codes(&merged)
    );
    let mut quarantined: Vec<String> = finding_codes(&merged)
        .into_iter()
        .filter(|(code, _)| *code == "catch_all_not_allowed")
        .map(|(_, object)| object)
        .collect();
    quarantined.sort();
    assert_eq!(quarantined, ["mixed", "on-web", "open"]);
}

// ---- priority --------------------------------------------------------------------------------

#[test]
fn traefik_priority_is_rule_length() {
    let rule = "Host(`a.test`) && PathPrefix(`/api`)";
    let derived = router_labels(rule, &[]);
    assert_eq!(derived.routers[0].priority, Some(36));
    assert_eq!(
        derived.routers[0].priority,
        Some(i32::try_from(rule.len()).expect("i32"))
    );

    let explicit = router_labels(rule, &[("traefik.http.routers.r.priority", "7")]);
    assert_eq!(explicit.routers[0].priority, Some(7));
    let negative = router_labels(rule, &[("traefik.http.routers.r.priority", "-3")]);
    assert_eq!(negative.routers[0].priority, Some(-3));

    let huge = router_labels(
        rule,
        &[("traefik.http.routers.r.priority", "9223372036854775806")],
    );
    assert_eq!(huge.routers, []);
    assert_eq!(huge.problems[0].code, Code::InvalidLabel);

    // The length is the bytes of the rule as written, spaces and multi-byte characters included.
    let padded = router_labels("  Host(`a.test`)  ", &[]);
    assert_eq!(padded.routers[0].priority, Some(18));
    let wide = router_labels("PathPrefix(`/é`)", &[]);
    assert_eq!(wide.routers[0].priority, Some(17));
}

/// `traefik` from `TRAEFIK_BIN`, else the PATH. The devenv shell has it (`pkgs.traefik`); a
/// missing binary fails the test, because a skipped comparison proves nothing.
fn traefik_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("TRAEFIK_BIN") {
        return PathBuf::from(path);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join("traefik"))
        .find(|candidate| candidate.is_file())
        .expect("traefik is not on PATH: run in the devenv shell (pkgs.traefik) or set TRAEFIK_BIN")
}

struct Traefik {
    child: Child,
    dir: PathBuf,
}

impl Drop for Traefik {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `GET path` on `127.0.0.1:port`, the body of a `200`.
fn get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(2),
    )
    .ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nhost: x\r\n\r\n").as_bytes())
        .ok()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).ok()?;
    let (head, body) = raw.split_once("\r\n\r\n")?;
    head.contains(" 200 ").then(|| body.to_owned())
}

#[test]
fn priority_matches_traefik_binary() {
    let rows: Vec<Row> = rows().into_iter().filter(|row| row.traefik).collect();
    assert!(rows.len() > 25);
    let dir = std::env::temp_dir().join(format!("pgp-traefik-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let ports = free_ports(2);
    let port = ports[0];
    let routers: serde_json::Map<String, Value> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            (
                format!("r{index}"),
                json!({ "rule": row.rule, "service": "s" }),
            )
        })
        .collect();
    let dynamic = json!({ "http": {
        "routers": routers,
        "services": { "s": { "loadBalancer": { "servers": [{ "url": "http://127.0.0.1:9" }] } } },
    } });
    let dynamic_file = dir.join("dynamic.yml");
    std::fs::write(&dynamic_file, dynamic.to_string()).expect("dynamic config");
    let static_config = json!({
        "entryPoints": { "web": { "address": format!("127.0.0.1:{}", ports[1]) }, "traefik": { "address": format!("127.0.0.1:{port}") } },
        "api": { "insecure": true },
        "providers": { "file": { "filename": dynamic_file } },
        "log": { "level": "ERROR" },
    });
    let static_file = dir.join("static.yml");
    std::fs::write(&static_file, static_config.to_string()).expect("static config");
    let child = Command::new(traefik_binary())
        .arg(format!("--configFile={}", static_file.display()))
        .env("TRAEFIK_ANONYMOUS_USAGE", "false")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn traefik");
    let _traefik = Traefik { child, dir };

    let deadline = Instant::now() + DEADLINE;
    let listed = loop {
        let routers: Option<Vec<Value>> = get(port, "/api/http/routers?per_page=100")
            .and_then(|body| serde_json::from_str(&body).ok())
            .filter(|list: &Vec<Value>| {
                (0..rows.len()).all(|index| {
                    list.iter()
                        .any(|router| router["name"] == format!("r{index}@file"))
                })
            });
        if let Some(routers) = routers {
            break routers;
        }
        assert!(
            Instant::now() < deadline,
            "traefik did not list the {} routers in time",
            rows.len()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    for (index, row) in rows.iter().enumerate() {
        let name = format!("r{index}@file");
        let router = listed
            .iter()
            .find(|router| router["name"] == name)
            .expect("listed");
        assert_eq!(router["status"], "enabled", "{}: {router}", row.rule);
        let theirs = router["priority"].as_i64().expect("a priority");
        assert_eq!(
            theirs,
            i64::from(row.priority),
            "traefik's priority for {:?}",
            row.rule
        );
        let ours = router_labels(&row.rule, &[]).routers[0].priority;
        assert_eq!(ours.map(i64::from), Some(theirs), "ours for {:?}", row.rule);
    }
}

// ---- podkit's labels -------------------------------------------------------------------------

/// What `routing_labels("app-7", hosts, 3000)` and `secure_routing_labels("app-7", hosts)` of
/// `podkit/agent/src/ingress.rs` produce for two plain hosts and one secure host.
fn podkit_labels() -> Vec<(&'static str, &'static str)> {
    vec![
        ("traefik.enable", "true"),
        (
            "traefik.http.services.app-7.loadbalancer.server.port",
            "3000",
        ),
        (
            "traefik.http.routers.app-7.rule",
            "Host(`a.example.com`) || Host(`b.example.com`)",
        ),
        ("traefik.http.routers.app-7.entrypoints", "web"),
        ("traefik.http.routers.app-7.service", "app-7"),
        (
            "traefik.http.routers.app-7-secure.rule",
            "Host(`a.example.com`)",
        ),
        ("traefik.http.routers.app-7-secure.entrypoints", "websecure"),
        ("traefik.http.routers.app-7-secure.tls", "true"),
        ("traefik.http.routers.app-7-secure.tls.certresolver", "le"),
        ("traefik.http.routers.app-7-secure.service", "app-7"),
    ]
}

#[test]
fn podkit_traefik_labels_translate() {
    let translated = translate(podkit_labels());
    assert_eq!(translated.problems, []);
    assert_eq!(translated.enabled, Some(true));
    assert_eq!(translated.port, Some(3000));
    assert_eq!(translated.tls, Some(podgate_model::TlsMode::Acme));
    assert_eq!(
        serde_json::to_value(&translated.routers).expect("json"),
        json!([
            {
                "name": "app-7",
                "entry_points": ["web"],
                "match": { "host": ["a.example.com", "b.example.com"] },
                "priority": 46,
                "chain": [],
                "service": "app-7",
                "observability": null,
                "declared_by": null,
            },
            {
                "name": "app-7-secure",
                "entry_points": ["websecure"],
                "match": { "host": "a.example.com" },
                "priority": 21,
                "chain": [],
                "service": "app-7",
                "observability": null,
                "declared_by": null,
            },
        ])
    );
    assert_eq!(
        serde_json::to_value(&translated.services).expect("json"),
        json!([{ "name": "app-7", "type": "loadbalancer" }])
    );

    // As an app: the address is the container's, the scheme is http, tls is acme.
    let app = app_of(&podkit_labels(), "app-7", "acme");
    let app = serde_json::to_value(&app.app).expect("json");
    assert_eq!(app["tls"]["mode"], "acme");
    assert_eq!(
        app["revisions"][0]["services"],
        json!([{
            "name": "app-7",
            "type": "loadbalancer",
            "servers": [{ "url": "http://10.4.0.5:3000" }],
        }])
    );
    assert_eq!(app["routers"].as_array().map(Vec::len), Some(2));

    // Without a resolver the router asks for TLS on the TLS entry point, and the app's
    // certificates are the snapshot's.
    let own_certs = translate([
        ("traefik.http.routers.r.rule", "Host(`a.example.com`)"),
        ("traefik.http.routers.r.tls", "true"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ]);
    assert_eq!(own_certs.tls, None);
    assert_eq!(
        own_certs.routers[0].entry_points,
        Some(vec!["websecure".into()])
    );
}

#[test]
fn traefik_service_labels() {
    let translated = translate([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.services.api.loadbalancer.server.port", "8080"),
        (
            "traefik.http.services.api.loadbalancer.server.scheme",
            "https",
        ),
        (
            "traefik.http.services.api.loadbalancer.passhostheader",
            "false",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.path",
            "/up",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.interval",
            "10s",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.timeout",
            "2s",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.hostname",
            "api.test",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.status",
            "204",
        ),
        (
            "traefik.http.services.api.loadbalancer.healthcheck.headers.X-Probe",
            "1",
        ),
        (
            "traefik.http.services.api.loadbalancer.sticky.cookie.name",
            "srv",
        ),
        (
            "traefik.http.services.api.loadbalancer.sticky.cookie.secure",
            "true",
        ),
        (
            "traefik.http.services.api.loadbalancer.sticky.cookie.httponly",
            "true",
        ),
        (
            "traefik.http.services.api.loadbalancer.sticky.cookie.samesite",
            "Lax",
        ),
        (
            "traefik.http.services.api.loadbalancer.sticky.cookie.maxage",
            "3600",
        ),
    ]);
    assert_eq!(translated.problems, []);
    assert_eq!(translated.port, Some(8080));
    assert_eq!(translated.schemes.get("api").map(|s| &**s), Some("https"));
    assert_eq!(
        translated.routers[0].service.as_ref(),
        "api",
        "the only service"
    );
    assert_eq!(
        serde_json::to_value(&translated.services[0]).expect("json"),
        json!({
            "name": "api",
            "type": "loadbalancer",
            "pass_host_header": false,
            "health_check": {
                "path": "/up", "interval_secs": 10, "timeout_secs": 2,
                "hostname": "api.test", "expect_status": [204], "headers": { "x-probe": "1" },
            },
            "sticky": { "cookie": {
                "name": "srv", "secure": true, "http_only": true, "same_site": "lax",
                "max_age_secs": 3600,
            } },
        })
    );

    // Traefik's defaults for the two durations the daemon wants written down.
    let defaults = translate([
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ("traefik.http.services.s.loadbalancer.healthcheck.path", "/"),
    ]);
    assert_eq!(
        defaults.services[0].config["health_check"],
        json!({ "path": "/", "interval_secs": 30, "timeout_secs": 5 })
    );

    // Several services and a router that names none: not guessed.
    let ambiguous = translate([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.services.one.loadbalancer.server.port", "80"),
        ("traefik.http.services.two.loadbalancer.server.port", "80"),
    ]);
    assert_eq!(ambiguous.routers, []);
    assert!(ambiguous.problems[0].reason.contains("several services"));

    // Two ports in one container cannot both be servers of it.
    let two_ports = translate([
        ("traefik.http.services.one.loadbalancer.server.port", "80"),
        ("traefik.http.services.two.loadbalancer.server.port", "81"),
    ]);
    assert_eq!(two_ports.port, Some(80));
    assert_eq!(two_ports.services.len(), 1);
    assert_eq!(two_ports.problems[0].code, Code::InvalidLabel);
}

// ---- middlewares -----------------------------------------------------------------------------

fn middleware(name: &str, labels: &[(&str, &str)]) -> Value {
    let pairs: Vec<(String, String)> = labels
        .iter()
        .map(|(key, value)| {
            (
                format!("traefik.http.middlewares.{name}.{key}"),
                (*value).to_owned(),
            )
        })
        .collect();
    let translated = translate(
        pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );
    assert_eq!(translated.problems, [], "{name}");
    serde_json::to_value(&translated.middlewares[0]).expect("json")
}

/// A middleware type, its options and the middleware they become.
type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, Value);

#[test]
fn traefik_middleware_labels() {
    let cases: Vec<Case<'_>> = vec![
        (
            "stripprefix",
            vec![("prefixes", "/api, /v1")],
            json!({ "type": "strip_prefix", "prefixes": ["/api", "/v1"] }),
        ),
        (
            "stripprefixregex",
            vec![("regex", "^/api/[0-9]+")],
            json!({ "type": "strip_prefix_regex", "regexes": ["^/api/[0-9]+"] }),
        ),
        (
            "addprefix",
            vec![("prefix", "/svc")],
            json!({ "type": "add_prefix", "prefix": "/svc" }),
        ),
        (
            "replacepath",
            vec![("path", "/new")],
            json!({ "type": "replace_path", "path": "/new" }),
        ),
        (
            "replacepathregex",
            vec![("regex", "^/old/(.*)"), ("replacement", "/new/$1")],
            json!({ "type": "replace_path_regex", "regex": "^/old/(.*)", "replacement": "/new/$1" }),
        ),
        (
            "redirectscheme",
            vec![("scheme", "https"), ("port", "8443"), ("permanent", "true")],
            json!({ "type": "redirect_scheme", "scheme": "https", "port": 8443, "permanent": true }),
        ),
        (
            "redirectregex",
            vec![
                ("regex", "^http://(.*)"),
                ("replacement", "https://$1"),
                ("permanent", "true"),
            ],
            json!({ "type": "redirect_regex", "regex": "^http://(.*)", "replacement": "https://$1", "permanent": true }),
        ),
        (
            "headers",
            vec![
                ("customrequestheaders.X-Forwarded-Proto", "https"),
                ("customrequestheaders.X-Drop", ""),
                ("customresponseheaders.X-Served-By", "podgate"),
                ("stsseconds", "31536000"),
                ("stsincludesubdomains", "true"),
                ("contenttypenosniff", "true"),
                ("framedeny", "true"),
                ("referrerpolicy", "same-origin"),
                ("contentsecuritypolicy", "default-src 'self'"),
                (
                    "accesscontrolalloworiginlist",
                    "https://a.test, https://b.test",
                ),
                ("accesscontrolallowmethods", "GET,POST"),
                ("accesscontrolmaxage", "100"),
            ],
            json!({
                "type": "headers",
                "request": { "set": { "x-forwarded-proto": "https" }, "remove": ["x-drop"] },
                "response": {
                    "set": { "x-served-by": "podgate" },
                    "remove": [],
                    "security": {
                        "hsts": { "max_age_secs": 31_536_000, "include_subdomains": true, "preload": false },
                        "content_type_nosniff": true,
                        "frame_options": "DENY",
                        "referrer_policy": "same-origin",
                        "csp": "default-src 'self'",
                    },
                },
                "cors": {
                    "allow_origins": ["https://a.test", "https://b.test"],
                    "allow_methods": ["GET", "POST"],
                    "max_age_secs": 100,
                    "add_vary": false,
                },
            }),
        ),
        (
            "compress",
            vec![
                ("minresponsebodybytes", "2048"),
                ("excludedcontenttypes", "text/event-stream"),
            ],
            json!({
                "type": "compress",
                "algorithms": ["gzip", "br", "zstd"],
                "min_bytes": 2048,
                "exclude_content_types": ["text/event-stream"],
            }),
        ),
        (
            "compress",
            vec![("encodings", "zstd")],
            json!({ "type": "compress", "algorithms": ["zstd"] }),
        ),
        (
            "ratelimit",
            vec![
                ("average", "100"),
                ("period", "1m"),
                ("burst", "200"),
                ("sourcecriterion.ipstrategy.depth", "2"),
                (
                    "sourcecriterion.ipstrategy.excludedips",
                    "10.0.0.0/8, 192.168.0.1",
                ),
            ],
            json!({
                "type": "rate_limit",
                "average": 100, "period_secs": 60, "burst": 200,
                "source": { "ip": { "depth": 2, "excluded": ["10.0.0.0/8", "192.168.0.1"] } },
            }),
        ),
        (
            "ratelimit",
            vec![
                ("average", "5"),
                ("sourcecriterion.requestheadername", "X-Api-Key"),
            ],
            json!({ "type": "rate_limit", "average": 5, "burst": 1, "source": { "header": "X-Api-Key" } }),
        ),
        (
            "ratelimit",
            vec![("average", "5"), ("sourcecriterion.requesthost", "true")],
            json!({ "type": "rate_limit", "average": 5, "burst": 1, "source": { "host": true } }),
        ),
        (
            "ipallowlist",
            vec![("sourcerange", "10.0.0.0/8,::1"), ("ipstrategy.depth", "1")],
            json!({ "type": "ip_allow_list", "source_range": ["10.0.0.0/8", "::1"], "ip_strategy": { "depth": 1 } }),
        ),
        (
            "basicauth",
            vec![
                ("users", "test:$2y$05$abc"),
                ("realm", "private"),
                ("removeheader", "true"),
            ],
            json!({ "type": "basic_auth", "users": ["test:$2y$05$abc"], "realm": "private", "remove_header": true }),
        ),
        (
            "retry",
            vec![("attempts", "3"), ("initialinterval", "250ms")],
            json!({ "type": "retry", "attempts": 3, "initial_interval_ms": 250 }),
        ),
        (
            "circuitbreaker",
            vec![
                ("expression", "ResponseCodeRatio(500, 600, 0, 600) > 0.25"),
                ("checkperiod", "200ms"),
                ("fallbackduration", "30s"),
                ("recoveryduration", "1m"),
                ("responsecode", "502"),
            ],
            json!({
                "type": "circuit_breaker",
                "trip_when": { "response_code_ratio": {
                    "from": 500, "to": 600, "over_from": 0, "over_to": 600, "ratio": 0.25
                } },
                "check_period_ms": 200, "fallback_secs": 30, "recovery_secs": 60, "response_code": 502,
            }),
        ),
        (
            "circuitbreaker",
            vec![("expression", "NetworkErrorRatio() > 0.30")],
            json!({ "type": "circuit_breaker", "trip_when": { "network_error_ratio": 0.3 } }),
        ),
        (
            "circuitbreaker",
            vec![("expression", "LatencyAtQuantileMS(50.0) > 100")],
            json!({ "type": "circuit_breaker", "trip_when": { "latency_quantile_ms": { "quantile": 50.0, "ms": 100 } } }),
        ),
    ];
    for (kind, options, expected) in cases {
        let labels: Vec<(String, &str)> = options
            .iter()
            .map(|(key, value)| (format!("{kind}.{key}"), *value))
            .collect();
        let labels: Vec<(&str, &str)> = labels
            .iter()
            .map(|(key, value)| (key.as_str(), *value))
            .collect();
        let object = middleware("m", &labels);
        let mut expected = expected;
        expected["name"] = json!("m");
        assert_eq!(object, expected, "{kind} {options:?}");
    }

    // A router puts its middlewares in order; a name of this container's own provider works.
    let routed = translate([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.routers.r.middlewares", "strip@docker,add"),
        ("traefik.http.middlewares.strip.stripprefix.prefixes", "/a"),
        ("traefik.http.middlewares.add.addprefix.prefix", "/b"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ]);
    assert_eq!(routed.problems, []);
    assert_eq!(
        routed.routers[0]
            .chain
            .iter()
            .map(|name| &**name)
            .collect::<Vec<_>>(),
        ["strip", "add"]
    );
}

#[test]
fn traefik_unsupported_label_reported() {
    let translated = translate([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.routers.r.middlewares", "auth,ok"),
        ("traefik.http.routers.r.service", "s"),
        (
            "traefik.http.middlewares.auth.forwardauth.trustForwardHeader",
            "true",
        ),
        ("traefik.http.middlewares.ok.addprefix.prefix", "/b"),
        ("traefik.http.routers.plain.rule", "Host(`b.test`)"),
        ("traefik.http.routers.plain.service", "s"),
        ("traefik.http.routers.tlsopt.rule", "Host(`c.test`)"),
        ("traefik.http.routers.tlsopt.tls.options", "strict@file"),
        ("traefik.http.routers.typo.rule", "Host(`d.test`)"),
        ("traefik.http.routers.typo.entrypoint", "web"),
        ("traefik.http.routers.foreign.rule", "Host(`e.test`)"),
        ("traefik.http.routers.foreign.service", "other@file"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
        (
            "traefik.http.services.t.loadbalancer.serverstransport",
            "t@file",
        ),
        ("traefik.tcp.routers.db.rule", "HostSNI(`*`)"),
        ("traefik.udp.routers.dns.service", "dns"),
        ("traefik.http.middlewares.p.plugin.demo.foo", "bar"),
        ("traefik.http.middlewares.rl.ratelimit.average", "5"),
        (
            "traefik.http.middlewares.rl.ratelimit.sourcecriterion.ipstrategy.typo",
            "1",
        ),
        ("traefik.http.middlewares.h.headers.sslredirect", "true"),
        (
            "traefik.http.middlewares.b.basicauth.usersfile",
            "/etc/users",
        ),
    ]);
    let key_codes: BTreeMap<&str, &str> = translated
        .problems
        .iter()
        .map(|problem| (&*problem.key, problem.code.as_str()))
        .collect();
    for (key, code) in [
        (
            "traefik.http.middlewares.auth.forwardauth.trustForwardHeader",
            "unsupported_label",
        ),
        (
            "traefik.http.routers.tlsopt.tls.options",
            "unsupported_label",
        ),
        ("traefik.http.routers.typo.entrypoint", "unsupported_label"),
        ("traefik.http.routers.foreign.service", "foreign_reference"),
        (
            "traefik.http.services.t.loadbalancer.serverstransport",
            "unsupported_label",
        ),
        ("traefik.tcp.routers.db.rule", "unsupported_label"),
        ("traefik.udp.routers.dns.service", "unsupported_label"),
        (
            "traefik.http.middlewares.p.plugin.demo.foo",
            "unsupported_label",
        ),
        (
            "traefik.http.middlewares.rl.ratelimit.sourcecriterion.ipstrategy.typo",
            "unsupported_label",
        ),
        (
            "traefik.http.middlewares.h.headers.sslredirect",
            "unsupported_label",
        ),
        (
            "traefik.http.middlewares.b.basicauth.usersfile",
            "unsupported_label",
        ),
    ] {
        assert_eq!(key_codes.get(key), Some(&code), "{key}: {key_codes:?}");
    }
    // `r` named a middleware that did not translate, `foreign` a service of another provider:
    // neither is emitted, never without its protection.
    let routers: Vec<&str> = translated
        .routers
        .iter()
        .map(|router| &*router.name)
        .collect();
    assert_eq!(routers, ["plain"]);
    assert!(
        translated.problems.iter().any(|problem| &*problem.key
            == "traefik.http.routers.r.middlewares"
            && problem
                .reason
                .contains("left out rather than served without it")),
        "{:?}",
        translated.problems
    );
    // The middleware that did translate is kept.
    assert_eq!(
        translated
            .middlewares
            .iter()
            .map(|m| &*m.name)
            .collect::<Vec<_>>(),
        ["ok"]
    );
    for problem in &translated.problems {
        assert!(!problem.fatal, "{problem}");
    }
}

#[test]
fn traefik_server_url_rejected() {
    for (key, value) in [
        (
            "traefik.http.services.s.loadbalancer.server.url",
            "http://10.9.9.9:80",
        ),
        (
            "traefik.http.services.s.loadbalancer.servers.0.url",
            "http://10.9.9.9:80",
        ),
        ("traefik.http.routers.r.service", "10.9.9.9:80"),
        ("traefik.http.routers.r.middlewares", "http://evil"),
        ("traefik.http.routers.r.rule", "Host(`10.9.9.9`)"),
    ] {
        let mut pairs = vec![("traefik.http.services.s.loadbalancer.server.port", "80")];
        if !key.ends_with(".rule") {
            pairs.push(("traefik.http.routers.r.rule", "Host(`a.test`)"));
        }
        pairs.push((key, value));
        let translated = translate(pairs.iter().copied());
        let fatal: Vec<_> = translated.problems.iter().filter(|p| p.fatal).collect();
        assert_eq!(fatal.len(), 1, "{key}={value}: {:?}", translated.problems);
        assert_eq!(fatal[0].code, Code::AddressLabel, "{key}");
        assert_eq!(&*fatal[0].key, key);

        // The Docker source's label parser refuses the whole container, like for podgate.*.
        let rejection = labels::parse(pairs.iter().copied()).expect_err(key);
        assert_eq!(rejection.code(), "address_label", "{key}");
        assert!(rejection.to_string().contains(key), "{rejection}");
    }
}

#[test]
fn traefik_labels_combine_with_podgate_labels() {
    let parsed = labels::parse([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ("podgate.router.api.match", r#"{"path_prefix": "/api"}"#),
        ("podgate.router.api.service", "s"),
        ("unrelated.label", "x"),
    ])
    .expect("both spellings");
    let names: Vec<&str> = parsed
        .definition
        .routers
        .iter()
        .map(|router| &*router.name)
        .collect();
    assert_eq!(names, ["api", "r"]);
    assert_eq!(parsed.port, Some(80));

    let twice = labels::parse([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ("podgate.router.r.match", r#"{"host": "b.test"}"#),
    ])
    .expect_err("one name, two definitions");
    assert_eq!(twice.code(), "invalid_label");

    let port = labels::parse([
        ("traefik.http.routers.r.rule", "Host(`a.test`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
        ("podgate.port", "81"),
    ])
    .expect_err("two ports");
    assert_eq!(port.code(), "invalid_label");

    // Nothing translated: the container is reported with every reason.
    let none = labels::parse([
        ("traefik.http.routers.r.rule", "Headers(`X`, `y`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "80"),
    ])
    .expect_err("no router");
    assert_eq!(none.code(), "unsupported_rule");
    assert!(
        none.to_string().contains("traefik.http.routers.r.rule"),
        "{none}"
    );
}

// ---- through the Docker source ---------------------------------------------------------------

fn docker_config(socket: &Path, settings: &str) -> Config {
    config(
        Path::new("/nonexistent/admin.sock"),
        &format!(
            "[[source]]\nkind = \"docker\"\nname = \"docker\"\nsocket = {:?}\nresync_secs = 3600\n{settings}\n",
            socket.display().to_string()
        ),
    )
}

/// Runs the Docker source until it has sent a state whose app ids are `want` and an outage text
/// that contains every word of `reported`, and returns both.
async fn settled(config: &Config, want: &[&str], reported: &[&str]) -> (State, String) {
    let (tx, mut rx) = mpsc::channel::<Update>(64);
    let source = DockerSource::from_config(&config.sources[0]).expect("a valid docker source");
    let task = tokio::spawn(source.run(tx));
    let want: Vec<String> = want.iter().map(|id| (*id).to_owned()).collect();
    let mut state: Option<State> = None;
    let mut report = String::new();
    let done = tokio::time::timeout(DEADLINE, async {
        loop {
            let ids = state.as_ref().map(|state| {
                let mut ids: Vec<String> = state
                    .apps
                    .iter()
                    .map(|app| app.app.id.to_string())
                    .collect();
                ids.sort();
                ids
            });
            if ids.as_ref() == Some(&want) && reported.iter().all(|word| report.contains(word)) {
                return;
            }
            let update = rx.recv().await.expect("the source keeps running");
            match update.body {
                UpdateBody::State(next) => state = Some(next),
                UpdateBody::Outage(why) => report = why.to_string(),
            }
        }
    })
    .await;
    task.abort();
    assert!(
        done.is_ok(),
        "timed out waiting for {want:?} and a report with {reported:?}; got {:?}, {report:?}",
        state.map(|state| state.apps.len())
    );
    (state.expect("a state"), report)
}

#[tokio::test]
async fn traefik_labels_reach_the_docker_source() {
    let docker = FakeDocker::start();
    let mut podkit = Ctr::new("app-7-1").network("podgate", "10.4.0.7");
    for (key, value) in podkit_labels() {
        podkit = podkit.label(key, value);
    }
    docker.add(podkit);
    docker.add(
        Ctr::new("opted-out")
            .network("podgate", "10.4.0.8")
            .labels(&[
                ("traefik.enable", "false"),
                ("traefik.http.routers.r.rule", "Host(`out.test`)"),
                ("traefik.http.services.s.loadbalancer.server.port", "80"),
            ]),
    );
    docker.add(Ctr::new("half").network("podgate", "10.4.0.9").labels(&[
        ("traefik.enable", "true"),
        ("traefik.http.routers.good.rule", "Host(`good.test`)"),
        ("traefik.http.routers.bad.rule", "Headers(`X`, `y`)"),
        ("traefik.http.services.s.loadbalancer.server.port", "8080"),
    ]));
    docker.add(
        Ctr::new("nameless")
            .network("podgate", "10.4.0.10")
            .labels(&[
                ("traefik.enable", "true"),
                ("traefik.http.routers.r.rule", "Host(`n.test`)"),
                (
                    "traefik.http.services.s.loadbalancer.server.url",
                    "http://10.9.9.9:80",
                ),
                ("traefik.http.services.s.loadbalancer.server.port", "80"),
            ]),
    );
    let config = docker_config(docker.path(), "network = \"podgate\"");
    let (state, report) = settled(
        &config,
        &["app-7-1", "half"],
        &[
            "container half",
            "traefik.http.routers.bad.rule",
            "container nameless",
            "names an address",
        ],
    )
    .await;

    let app = |id: &str| {
        serde_json::to_value(
            &state
                .apps
                .iter()
                .find(|app| &*app.app.id == id)
                .expect("app")
                .app,
        )
        .expect("json")
    };
    let podkit = app("app-7-1");
    assert_eq!(podkit["routers"].as_array().map(Vec::len), Some(2));
    assert_eq!(podkit["tls"]["mode"], "acme");
    assert_eq!(
        podkit["revisions"][0]["services"][0]["servers"],
        json!([{ "url": "http://10.4.0.7:3000" }])
    );
    let half = app("half");
    assert_eq!(
        half["routers"].as_array().map(|routers| routers
            .iter()
            .map(|r| r["name"].clone())
            .collect::<Vec<_>>()),
        Some(vec![json!("good")]),
        "only the router that translated"
    );
    assert_eq!(
        half["routers"][0]["service"], "s",
        "the one service of the labels"
    );
    assert!(
        report.contains("container half") && report.contains("traefik.http.routers.bad.rule"),
        "the left-out router names its label: {report}"
    );
    assert!(
        report.contains("container nameless") && report.contains("names an address"),
        "{report}"
    );
    assert!(
        !report.contains("opted-out"),
        "traefik.enable=false is not reported: {report}"
    );
}

// ---- against the real daemon -----------------------------------------------------------------

/// The merged snapshot of `apps` as the body a provider would push, at version 1.
fn body(apps: Vec<SourceApp>) -> String {
    let merged = merge_in(PLAIN_TENANTS, apps);
    assert_eq!(finding_codes(&merged), [], "the merge accepted everything");
    let mut snapshot = serde_json::to_value(merged.snapshot()).expect("the snapshot is JSON");
    snapshot["version"] = json!(1);
    snapshot["skew_secret"] = json!("0123456789abcdef0123456789abcdef");
    snapshot.to_string()
}

async fn daemon_validates(body: &str) -> (u16, Value) {
    let dir = std::env::temp_dir().join(format!("pgp-traefik-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let policy = dir.join("upstream-policy.json");
    std::fs::write(&policy, daemon::LOOPBACK_POLICY).expect("policy file");
    let ports = free_ports(2);
    let daemon = daemon::Daemon::start(&policy, (ports[0], ports[1]), &[]).await;
    let client = AdminClient::new(&daemon.admin, Duration::from_secs(30));
    let answer = client.validate(body).await.expect("validate answers");
    let json = answer.json().unwrap_or(Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
    (answer.status, json)
}

#[tokio::test]
async fn translated_podkit_app_validates() {
    let (status, answer) =
        daemon_validates(&body(vec![app_of(&podkit_labels(), "app-7", "acme")])).await;
    assert_eq!(status, 200, "{answer}");
}

#[tokio::test]
async fn translated_middlewares_validate() {
    let mut labels = vec![
        ("traefik.enable", "true"),
        (
            "traefik.http.routers.r.rule",
            "Host(`shop.acme.test`) && PathPrefix(`/api`) && !Method(`TRACE`)",
        ),
        ("traefik.http.routers.r.service", "svc"),
        (
            "traefik.http.routers.r.middlewares",
            "sp,spr,ap,rp,rpr,rs,rr,hd,cmp,rl,ip,auth,rt,cb",
        ),
        ("traefik.http.services.svc.loadbalancer.server.port", "8080"),
        (
            "traefik.http.services.svc.loadbalancer.healthcheck.path",
            "/up",
        ),
        (
            "traefik.http.services.svc.loadbalancer.healthcheck.interval",
            "10s",
        ),
        (
            "traefik.http.services.svc.loadbalancer.sticky.cookie.name",
            "srv",
        ),
        (
            "traefik.http.services.svc.loadbalancer.sticky.cookie.secure",
            "true",
        ),
        ("traefik.http.middlewares.sp.stripprefix.prefixes", "/api"),
        (
            "traefik.http.middlewares.spr.stripprefixregex.regex",
            "^/v[0-9]+",
        ),
        ("traefik.http.middlewares.ap.addprefix.prefix", "/svc"),
        ("traefik.http.middlewares.rp.replacepath.path", "/new"),
        (
            "traefik.http.middlewares.rpr.replacepathregex.regex",
            "^/old/(.*)",
        ),
        (
            "traefik.http.middlewares.rpr.replacepathregex.replacement",
            "/new/$1",
        ),
        ("traefik.http.middlewares.rs.redirectscheme.scheme", "https"),
        (
            "traefik.http.middlewares.rr.redirectregex.regex",
            "^http://(.*)",
        ),
        (
            "traefik.http.middlewares.rr.redirectregex.replacement",
            "https://$1",
        ),
        (
            "traefik.http.middlewares.hd.headers.customrequestheaders.X-Env",
            "prod",
        ),
        (
            "traefik.http.middlewares.hd.headers.customresponseheaders.X-Env",
            "prod",
        ),
        ("traefik.http.middlewares.hd.headers.stsseconds", "31536000"),
        ("traefik.http.middlewares.hd.headers.framedeny", "true"),
        (
            "traefik.http.middlewares.hd.headers.accesscontrolalloworiginlist",
            "https://a.test",
        ),
        (
            "traefik.http.middlewares.cmp.compress.minresponsebodybytes",
            "2048",
        ),
        ("traefik.http.middlewares.rl.ratelimit.average", "100"),
        ("traefik.http.middlewares.rl.ratelimit.burst", "50"),
        ("traefik.http.middlewares.rl.ratelimit.period", "1s"),
        (
            "traefik.http.middlewares.ip.ipallowlist.sourcerange",
            "10.0.0.0/8, 192.168.0.0/16",
        ),
        (
            "traefik.http.middlewares.auth.basicauth.users",
            "test:$2y$05$abcdefghijklmnopqrstuuUBXkOK/F4S4bGQ3F2wz8wUCczvZ9u2a",
        ),
        ("traefik.http.middlewares.rt.retry.attempts", "3"),
        ("traefik.http.middlewares.rt.retry.initialinterval", "100ms"),
        (
            "traefik.http.middlewares.cb.circuitbreaker.expression",
            "NetworkErrorRatio() > 0.30",
        ),
    ];
    labels.retain(|(key, _)| !key.is_empty());
    let translated = translate(labels.iter().copied());
    assert_eq!(translated.problems, [], "every label above is supported");
    assert_eq!(translated.routers.len(), 1);
    assert_eq!(translated.middlewares.len(), 14);

    let (status, answer) = daemon_validates(&body(vec![app_of(&labels, "shop", "acme")])).await;
    assert_eq!(status, 200, "{answer}");
}
