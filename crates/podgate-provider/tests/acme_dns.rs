//! DNS-01 solvers of the provider: RFC 2136 with TSIG and the webhook, the trust rule,
//! zone selection, propagation checks, CNAME delegation, and a wildcard certificate from `pebble`.
//!
//! The solver talks to the in-process authoritative server of `common::dns_server`. Every wait has
//! a deadline; the end-to-end test needs `pebble` and the `podgate` binary and fails without them
//! (nothing is skipped). The test that captures logs is `acme_dns_logs.rs`: it needs its own
//! binary because of how `tracing` caches callsites.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::dns_server::{
    Answer, DnsServer, KEY_NAME, SECRET, TOKEN, Update, WebhookServer, acme_claims, b64, challenge,
    claims, config, file, refusal, rfc2136_zone, scratch, timing, tsig_server, webhook_zone,
    within,
};
use common::{AppExt, app, daemon, free_ports, pebble};
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use podgate_provider::acme::dns::{Backend, DnsError, DnsSolver, Timing, solver};
use podgate_provider::acme::events::Solver;
use podgate_provider::{Config, ConfigError, UpstreamPolicy};
use serde_json::Value;

#[tokio::test]
async fn rfc2136_present_cleanup() {
    let dir = scratch("present");
    let dns = tsig_server("acme.test", SECRET).await;
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let config = config(&dir, &rfc2136_zone("acme.test", &dns, &secret, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    within(
        "present",
        solver.present(challenge(name, "v1"), acme_claims()),
    )
    .await
    .expect("published");
    assert_eq!(dns.txt(name), ["v1"]);
    assert_eq!(
        dns.updates(),
        [Update {
            add: true,
            name: format!("{name}."),
            value: "v1".into()
        }]
    );

    within("cleanup", solver.cleanup(challenge(name, "v1"))).await;
    assert!(dns.txt(name).is_empty(), "{:?}", dns.txt(name));
    assert_eq!(dns.updates().len(), 2);
    assert!(!dns.updates()[1].add);
}

#[tokio::test]
async fn rfc2136_wrong_tsig_refused() {
    let dir = scratch("wrongkey");
    // The server knows another key than the one the provider signs with.
    let dns = tsig_server("acme.test", b"not-the-key-the-provider-has").await;
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let config = config(&dir, &rfc2136_zone("acme.test", &dns, &secret, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    let err = within(
        "present",
        solver.present(challenge(name, "v1"), acme_claims()),
    )
    .await
    .expect_err("a wrong key is refused");
    assert!(refusal(&err).contains("refused the update"), "{err}");
    assert!(!refusal(&err).contains(&b64(SECRET)), "{err}");
    assert!(dns.refused() >= 1);
    assert!(dns.txt(name).is_empty());
    assert!(dns.updates().is_empty());
}

#[tokio::test]
async fn webhook_present_cleanup() {
    let dir = scratch("hook");
    let dns = Arc::new(DnsServer::start("acme.test", None).await);
    let operator = Arc::clone(&dns);
    // The webhook stands in for the operator's DNS API: it writes the record it is told to.
    let hook = WebhookServer::start(move |request, _| {
        let body: Value = serde_json::from_str(&request.body).expect("JSON body");
        let (fqdn, value) = (
            body["fqdn"].as_str().unwrap_or(""),
            body["value"].as_str().unwrap_or(""),
        );
        if request.path.ends_with("/present") {
            operator.set_txt(fqdn, value);
        } else {
            operator.clear_txt(fqdn, value);
        }
        Answer::Status(200)
    })
    .await;
    let token = file(&dir, "token", &format!("{TOKEN}\n"), 0o600);
    let config = config(&dir, &webhook_zone("acme.test", &hook, &token, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    within(
        "present",
        solver.present(challenge(name, "v1"), acme_claims()),
    )
    .await
    .expect("published");
    within("cleanup", solver.cleanup(challenge(name, "v1"))).await;

    let seen = hook.requests();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        (&*seen[0].method, &*seen[0].path),
        ("POST", "/hook/present")
    );
    assert_eq!(
        (&*seen[1].method, &*seen[1].path),
        ("POST", "/hook/cleanup")
    );
    for request in &seen {
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        let body: Value = serde_json::from_str(&request.body).expect("JSON");
        assert_eq!(
            body,
            serde_json::json!({"fqdn": "_acme-challenge.acme.test.", "value": "v1"})
        );
    }
    assert!(dns.txt(name).is_empty());
}

#[tokio::test]
async fn webhook_failure_retried() {
    let dir = scratch("hookretry");
    let dns = Arc::new(DnsServer::start("acme.test", None).await);
    let operator = Arc::clone(&dns);
    // A server error, a connection that never answers, a rate limit, then success. A `401` is
    // a refusal retrying would not change.
    let hook = WebhookServer::start(move |request, number| {
        if request.body.contains("\"nope\"") {
            return Answer::Status(401);
        }
        match number {
            0 => Answer::Status(500),
            1 => Answer::Hang,
            2 => Answer::Status(429),
            _ => {
                operator.set_txt("_acme-challenge.acme.test", "v1");
                Answer::Status(200)
            }
        }
    })
    .await;
    let token = file(&dir, "token", TOKEN, 0o600);
    let mut config = config(&dir, &webhook_zone("acme.test", &hook, &token, &[&dns]));
    let zone = &mut config.acme.as_mut().expect("acme").dns[0];
    let Backend::Webhook { timeout, .. } = &mut zone.backend else {
        panic!("a webhook zone");
    };
    *timeout = Duration::from_millis(300);
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    within(
        "present",
        solver.present(challenge(name, "v1"), acme_claims()),
    )
    .await
    .expect("published after retries");
    assert_eq!(hook.requests().len(), 4, "{:?}", hook.requests());
    assert_eq!(dns.txt(name), ["v1"]);

    let err = within(
        "present",
        solver.present(challenge(name, "nope"), acme_claims()),
    )
    .await
    .expect_err("a 401 is final");
    assert!(refusal(&err).contains("401"), "{err}");
    assert_eq!(hook.requests().len(), 5, "no retry after a refusal");
}

#[tokio::test]
async fn ready_only_after_all_authoritative_servers_have_value() {
    let dir = scratch("ready");
    let primary = tsig_server("acme.test", SECRET).await;
    // A secondary that has not received the record yet.
    let secondary = Arc::new(DnsServer::start("acme.test", None).await);
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let config = config(
        &dir,
        &rfc2136_zone("acme.test", &primary, &secret, &[&primary, &secondary]),
    );
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    let present = tokio::spawn(solver.present(challenge(name, "v1"), acme_claims()));
    let start = Instant::now();
    while secondary.queries(name) < 5 {
        assert!(
            start.elapsed() < common::DEADLINE,
            "the secondary was never asked"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(primary.txt(name), ["v1"], "the primary has it");
    assert!(
        !present.is_finished(),
        "ready was reported while the secondary lacked the value"
    );

    secondary.set_txt(name, "v1");
    within("present", present)
        .await
        .expect("task")
        .expect("ready once every server has it");
    assert!(secondary.txt(name).contains(&"v1".to_owned()));
}

#[tokio::test]
async fn dns_foreign_name_refused() {
    let dir = scratch("foreign");
    let dns = tsig_server("acme.test", SECRET).await;
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    // The zone is the operator's, and several tenants have apps in it.
    let config = config(&dir, &rfc2136_zone("acme.test", &dns, &secret, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");

    let cases = [
        (
            "an app of another tenant claims the name",
            claims(&[("evil", "globex", &["acme.test"])]),
            "_acme-challenge.acme.test",
        ),
        (
            "no app claims it",
            claims(&[("shop", "acme", &["shop.acme.test"])]),
            "_acme-challenge.acme.test",
        ),
        (
            "the tenant claims a host below, not the name",
            claims(&[("shop", "acme", &["*.acme.test"])]),
            "_acme-challenge.deep.shop.acme.test",
        ),
        (
            "not a challenge name",
            claims(&[("shop", "acme", &["acme.test"])]),
            "acme.test",
        ),
    ];
    for (why, claims, name) in cases {
        let err = within("present", solver.present(challenge(name, "v1"), claims))
            .await
            .expect_err(why);
        assert!(refusal(&err).starts_with("foreign_name"), "{why}: {err}");
    }
    assert!(
        dns.updates().is_empty(),
        "nothing was published: {:?}",
        dns.updates()
    );
}

#[tokio::test]
async fn dns_no_zone_no_solver() {
    let dir = scratch("nozone");
    let dns = tsig_server("acme.test", SECRET).await;
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let config = config(&dir, &rfc2136_zone("acme.test", &dns, &secret, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");

    // Even a name the requester owns is not published outside the configured zones.
    let owned = claims(&[("shop", "acme", &["acme.test", "other.org"])]);
    let err = within(
        "present",
        solver.present(challenge("_acme-challenge.other.org", "v1"), owned),
    )
    .await
    .expect_err("no zone");
    assert!(refusal(&err).starts_with("no_solver"), "{err}");
    assert!(dns.updates().is_empty());

    // Without any `[[acme.dns]]` the factory returns the solver that reports `no_solver`.
    let bare = self::config(&dir, "");
    let none = solver_of(&bare);
    let err = within(
        "present",
        none.present(challenge("_acme-challenge.acme.test", "v1"), acme_claims()),
    )
    .await
    .expect_err("no solver");
    assert!(refusal(&err).starts_with("no_solver"), "{err}");
}

fn solver_of(config: &Config) -> Arc<dyn Solver> {
    solver(config).expect("solver")
}

#[tokio::test]
async fn cleanup_leaves_other_values() {
    let dir = scratch("others");
    let dns = tsig_server("acme.test", SECRET).await;
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let config = config(&dir, &rfc2136_zone("acme.test", &dns, &secret, &[&dns]));
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";

    // An apex and its wildcard are one name with two values; a third value is not ours.
    dns.set_txt(name, "someone-elses");
    for value in ["apex", "wildcard"] {
        within(
            "present",
            solver.present(challenge(name, value), acme_claims()),
        )
        .await
        .expect("published");
    }
    assert_eq!(dns.txt(name), ["someone-elses", "apex", "wildcard"]);

    within("cleanup", solver.cleanup(challenge(name, "apex"))).await;
    assert_eq!(dns.txt(name), ["someone-elses", "wildcard"]);
    within("cleanup", solver.cleanup(challenge(name, "wildcard"))).await;
    assert_eq!(dns.txt(name), ["someone-elses"]);

    // A challenge that ended before anything was published removes nothing.
    within(
        "cleanup",
        solver.cleanup(challenge(name, "never-published")),
    )
    .await;
    assert_eq!(dns.txt(name), ["someone-elses"]);
}

#[tokio::test]
async fn cname_delegation_followed() {
    let dir = scratch("cname");
    // `_acme-challenge.acme.test` is a CNAME into a validation zone with its own server and key.
    let front = tsig_server("acme.test", SECRET).await;
    let back = tsig_server("validation.test", SECRET).await;
    front.add_cname(
        "_acme-challenge.acme.test",
        "_acme-challenge.validation.test",
    );
    let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);
    let zones = format!(
        "{}{}",
        rfc2136_zone("acme.test", &front, &secret, &[&front]),
        rfc2136_zone("validation.test", &back, &secret, &[&back]),
    );
    let config = config(&dir, &zones);
    let solver = DnsSolver::with_timing(&config, timing()).expect("solver");
    let name = "_acme-challenge.acme.test";
    let target = "_acme-challenge.validation.test";

    within(
        "present",
        solver.present(challenge(name, "v1"), acme_claims()),
    )
    .await
    .expect("published through the delegation");
    assert_eq!(back.txt(target), ["v1"]);
    assert!(
        front.updates().is_empty(),
        "the delegating zone is never written"
    );

    within("cleanup", solver.cleanup(challenge(name, "v1"))).await;
    assert!(back.txt(target).is_empty());

    // A delegation to a zone the operator did not configure is refused, never followed blindly.
    front.add_cname("_acme-challenge.acme.test", "_acme-challenge.elsewhere.org");
    let err = within(
        "present",
        solver.present(challenge(name, "v2"), acme_claims()),
    )
    .await
    .expect_err("outside the zones");
    assert!(refusal(&err).starts_with("no_solver"), "{err}");

    // With `cname_follow = false` the name itself is written, whatever is delegated. The front
    // server answers a CNAME for it, so the value never shows there: the record is written and
    // verification fails until the solver gives up.
    let mut off = self::config(&dir, &zones);
    for zone in &mut off.acme.as_mut().expect("acme").dns {
        zone.cname_follow = false;
        zone.propagation_timeout = Duration::from_millis(200);
    }
    front.add_cname(
        "_acme-challenge.acme.test",
        "_acme-challenge.validation.test",
    );
    let quick = Timing {
        give_up: Duration::from_millis(100),
        ..timing()
    };
    let solver = DnsSolver::with_timing(&off, quick).expect("solver");
    let err = within(
        "present",
        solver.present(challenge(name, "v3"), acme_claims()),
    )
    .await
    .expect_err("not visible");
    assert!(refusal(&err).starts_with("gave_up"), "{err}");
    assert_eq!(front.updates().len(), 1, "written at the name itself");
}

#[tokio::test]
async fn dns_secret_file_permissions() {
    let dir = scratch("modes");
    let dns = tsig_server("acme.test", SECRET).await;
    let hook = WebhookServer::start(|_, _| Answer::Status(200)).await;

    for (kind, wide) in [("rfc2136", 0o644), ("rfc2136", 0o640), ("webhook", 0o604)] {
        let secret = file(&dir, "secret", &b64(SECRET), wide);
        let zone = if kind == "rfc2136" {
            rfc2136_zone("acme.test", &dns, &secret, &[&dns])
        } else {
            webhook_zone("acme.test", &hook, &secret, &[&dns])
        };
        let err = DnsSolver::new(&config(&dir, &zone)).expect_err("a readable secret is refused");
        assert!(matches!(err, DnsError::Secret { .. }), "{err:?}");
        let shown = format!(
            "{err:#?} {err} {}",
            std::error::Error::source(&err).map_or(String::new(), |s| s.to_string())
        );
        assert!(
            shown.contains(&format!("{wide:04o}")),
            "the mode is named: {shown}"
        );
        assert!(shown.contains("secret"), "the path is named: {shown}");
        assert!(!shown.contains(&b64(SECRET)), "{shown}");

        // The factory the program uses refuses the same way.
        assert!(solver(&config(&dir, &zone)).is_err());
    }

    // Private files work, and a missing one is named.
    let secret = file(&dir, "secret", &b64(SECRET), 0o600);
    DnsSolver::new(&config(
        &dir,
        &rfc2136_zone("acme.test", &dns, &secret, &[&dns]),
    ))
    .expect("a private file");
    let missing = dir.join("absent");
    let err = DnsSolver::new(&config(
        &dir,
        &rfc2136_zone("acme.test", &dns, &missing, &[&dns]),
    ))
    .expect_err("a missing file");
    assert!(matches!(err, DnsError::Secret { .. }), "{err:?}");
}

#[test]
fn dns_zone_settings_name_the_bad_field() {
    let base = |entry: &str| {
        format!(
            "admin_socket = \"/x.sock\"\n[acme]\nenabled = true\nstate_dir = \"/s\"\ndirectory_url = \"https://ca.test/dir\"\nissuer_node = \"n1\"\n[[acme.dns]]\n{entry}"
        )
    };
    let field_of = |entry: &str| match Config::parse(&base(entry)) {
        Err(ConfigError::Invalid { field, reason }) => format!("{field}: {reason}"),
        Err(other) => other.to_string(),
        Ok(_) => String::from("accepted"),
    };
    let rfc = "zone = \"a.test\"\nkind = \"rfc2136\"\nserver = \"127.0.0.1\"\ntsig_key_name = \"k.a.test\"\ntsig_secret_file = \"/k\"\n";
    assert!(
        field_of(&format!("{rfc}tsig_algorithm = \"hmac-sha256\"\n")) == "accepted",
        "a complete entry parses"
    );
    assert!(
        field_of(&format!("{rfc}tsig_algorithm = \"hmac-sha1\"\n")).contains("unknown variant")
    );
    assert!(field_of(rfc).starts_with("acme.dns[0].tsig_algorithm"));
    assert!(
        field_of(&format!(
            "{rfc}tsig_algorithm = \"hmac-sha256\"\nurl = \"http://x\"\n"
        ))
        .starts_with("acme.dns[0].url")
    );
    assert!(
        field_of(
            "zone = \"a.test\"\nkind = \"webhook\"\nurl = \"ftp://x\"\nbearer_token_file = \"/t\"\n"
        )
        .starts_with("acme.dns[0].url")
    );
    assert!(
        field_of("zone = \"*.a.test\"\nkind = \"webhook\"\nurl = \"http://x\"\nbearer_token_file = \"/t\"\n")
            .starts_with("acme.dns[0].zone")
    );
    assert!(
        field_of("zone = \"a.test\"\nkind = \"webhook\"\nurl = \"http://x\"\nbearer_token_file = \"/t\"\ntoken = \"inline\"\n")
            .contains("unknown field"),
        "a secret value has no place in the configuration"
    );
    assert!(
        field_of("zone = \"a.test\"\nkind = \"webhook\"\nurl = \"http://x\"\nbearer_token_file = \"/t\"\ncheck_resolvers = [\"nope\"]\n")
            .starts_with("acme.dns[0].check_resolvers")
    );
}

// ---- a wildcard certificate from pebble, through the provider and the RFC 2136 solver ----------

fn count_events(events: &[Value], kind: &str, kind_type: &str) -> usize {
    events
        .iter()
        .filter(|event| event["kind"] == kind && event["type"] == kind_type)
        .count()
}

async fn https_get(
    daemon: &daemon::Daemon,
    root: &rustls_pki_types::CertificateDer<'static>,
    host: &str,
) -> Result<(u16, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).map_err(|e| e.to_string())?;
    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(daemon.tls)
        .await
        .map_err(|e| e.to_string())?;
    let name =
        rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
    let mut tls = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_rustls::TlsConnector::from(Arc::new(tls_config)).connect(name, tcp),
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

#[tokio::test]
async fn wildcard_issued_through_provider_rfc2136() {
    let work = tokio::time::timeout(Duration::from_secs(300), async {
        let dir = scratch("e2e");
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "podgate_provider=info".into()),
            )
            .with_test_writer()
            .try_init();
        let policy = dir.join("upstream-policy.json");
        std::fs::write(&policy, daemon::LOOPBACK_POLICY).expect("policy");
        // The test's DNS server is pebble's resolver and the zone's primary: pebble validates
        // the TXT records the provider wrote by RFC 2136, nothing else.
        let dns = Arc::new(
            DnsServer::start(
                "a.test",
                Some((KEY_NAME, TsigAlgorithm::HmacSha256, SECRET.to_vec())),
            )
            .await,
        );
        let ports = free_ports(2);
        let pebble = pebble::Pebble::start_with_dns(
            pebble::Pki::new(&dir),
            pebble::Validation::default(),
            Some(dns.addr),
        )
        .await;
        let ca_file = pebble.pki.ca_pem.display().to_string();
        let daemon = daemon::Daemon::start(
            &policy,
            (ports[0], ports[1]),
            &[
                ("NODE_NAME", "n1"),
                ("ACME_CA_FILE", &ca_file),
                ("ACME_DNS_ZONES", "a.test"),
            ],
        )
        .await;
        let (backend, _backend_task) = daemon::backend("from-the-backend").await;
        let secret = file(&dir, "tsig.key", &b64(SECRET), 0o600);

        let extra = format!(
            "debounce_ms = 20\nmax_delay_ms = 200\nresync_secs = 2\nupstream_policy_file = {:?}\n[[tenant]]\nid = \"acme\"\nhosts = [\"a.test\", \"*.a.test\"]\n[acme]\nenabled = true\nstate_dir = {:?}\ndirectory_url = {:?}\nissuer_node = \"n1\"\ncontact = [\"mailto:ops@example.test\"]\n{}[[source]]\nkind = \"fake\"\nname = \"local\"\n",
            policy.display().to_string(),
            dir.join("state").display().to_string(),
            pebble.directory,
            rfc2136_zone("a.test", &dns, &secret, &[&dns]),
        );
        let config = common::config(&daemon.admin, &extra);
        let dns_solver = DnsSolver::with_timing(
            &config,
            Timing {
                poll_interval: Duration::from_millis(100),
                ..Timing::default()
            },
        )
        .expect("solver");
        let mut engine =
            podgate_provider::Engine::new(config, UpstreamPolicy::load(&policy).expect("policy"))
                .with_tuning(common::fast_tuning())
                .with_dns_solver(Arc::new(dns_solver));
        let (source, handle) = common::scripted("local");
        engine.add_source(source).expect("source");
        let mut shop = app(
            "local",
            "shop",
            &["a.test", "*.a.test"],
            &format!("http://{backend}"),
        )
        .mapped("acme");
        shop.app.tls.challenge = podgate_model::ChallengeKind::Dns01;
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

        let root = pebble.root().await;
        let start = Instant::now();
        let mut served = Vec::new();
        for host in ["a.test", "www.a.test"] {
            loop {
                match https_get(&daemon, &root, host).await {
                    Ok((200, body)) => {
                        served.push(body);
                        break;
                    }
                    other => assert!(
                        start.elapsed() < Duration::from_secs(200),
                        "{host} is not served over TLS: {other:?}\nprovider: {:?}\nevents: {:?}\ndns updates: {:?}\n--- pebble.log\n{}",
                        status.borrow(),
                        daemon.events().await,
                        dns.updates(),
                        pebble.pki.read("pebble.log")
                    ),
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        assert_eq!(served, ["from-the-backend", "from-the-backend"]);

        // pebble created one authorization per identifier it did not reuse, and the provider
        // published exactly one record for each challenge the daemon emitted.
        let created = pebble.authorizations_created();
        let events = daemon.events().await;
        let challenges = count_events(&events, "acme_challenge", "dns-01");
        assert_eq!(challenges, created, "{events:?}");
        let added: Vec<Update> = dns
            .updates()
            .into_iter()
            .filter(|update| update.add)
            .collect();
        assert_eq!(added.len(), challenges, "{added:?}");
        assert!(
            added
                .iter()
                .all(|update| update.name == "_acme-challenge.a.test.")
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event["kind"] == "certificate_issued")
                .count(),
            1
        );
        let issued = events
            .iter()
            .find(|event| event["kind"] == "certificate_issued")
            .expect("issued");
        assert_eq!(issued["hosts"], serde_json::json!(["*.a.test", "a.test"]));

        // Once the order ends the daemon says so and the provider removes what it wrote.
        let start = Instant::now();
        while !dns.txt("_acme-challenge.a.test").is_empty() {
            assert!(
                start.elapsed() < common::DEADLINE,
                "records left behind: {:?}",
                dns.txt("_acme-challenge.a.test")
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(20), run)
            .await
            .expect("the provider stops")
            .expect("no panic")
            .expect("clean stop");
    });
    Box::pin(work)
        .await
        .expect("the end-to-end test finished in time");
}
