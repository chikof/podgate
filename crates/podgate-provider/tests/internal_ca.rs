//! The internal CA: `ca init`, the name-constrained intermediate, leaves that
//! `openssl verify` accepts, the provider task that issues, renews and re-pushes them, the
//! tenant and wildcard rules, the key hygiene, and the `ca` command.
//!
//! The chain tests need `openssl` on `PATH` (`devenv shell`), or `OPENSSL_BIN`; a missing one
//! fails them. The daemon test needs the daemon binary (`target/debug/podgate` or `PODGATE_BIN`).

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::ca::{internal, key_lines, pki, scratch, want, wants};
use common::{AppExt, Harness, app, daemon};
use podgate_provider::ca::cli;
use podgate_provider::ca::init::{InitOptions, init};
use podgate_provider::ca::issue::Signer;
use podgate_provider::ca::names::SuffixError;
use podgate_provider::ca::trust::{export_root, status};
use podgate_provider::ca::{Ca, CaError, Secret, unix_now};
use podgate_provider::source::State;
use podgate_provider::{Config, Merger, UpstreamPolicy};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

const UP: &str = "http://10.0.0.5:8080";
const DAY: i64 = 86_400;

// ---- helpers ---------------------------------------------------------------------------------

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

fn openssl(args: &[&str]) -> (bool, String) {
    let binary = std::env::var("OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_owned());
    let output = std::process::Command::new(&binary)
        .args(args)
        .output()
        .unwrap_or_else(|err| {
            panic!("cannot run `{binary}`: {err}; `openssl` must be on PATH (devenv shell) or OPENSSL_BIN set")
        });
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

/// `openssl verify` of the first certificate of `chain_pem` against `root`, taking the rest as
/// intermediates. Returns whether it passed and what openssl said.
fn verify(work: &Path, root: &Path, chain_pem: &str, hostname: Option<&str>) -> (bool, String) {
    let chain = work.join("chain.pem");
    std::fs::write(&chain, chain_pem).expect("chain file");
    let (root, chain) = (root.display().to_string(), chain.display().to_string());
    let mut args = vec![
        "verify",
        "-purpose",
        "sslserver",
        "-CAfile",
        &root,
        "-untrusted",
        &chain,
    ];
    if let Some(name) = hostname {
        args.extend(["-verify_hostname", name]);
    }
    args.push(&chain);
    openssl(&args)
}

fn parse(pem: &str) -> Vec<u8> {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("PEM");
    block.contents
}

fn with_cert<T>(pem: &str, read: impl FnOnce(&X509Certificate<'_>) -> T) -> T {
    let der = parse(pem);
    let (_, cert) = X509Certificate::from_der(&der).expect("certificate");
    read(&cert)
}

fn dns_names(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.subject_alternative_name()
        .expect("SAN parses")
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|name| match name {
                    GeneralName::DNSName(dns) => (*dns).to_owned(),
                    other => panic!("a SAN that is not a dNSName: {other:?}"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn leaf_hosts(put: &common::Put) -> Vec<Vec<String>> {
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

fn pems_in(path: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(path).expect("list").flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(pems_in(&path));
        } else {
            found.push(path);
        }
    }
    found
}

// ---- ca init ---------------------------------------------------------------------------------

#[test]
fn ca_init_creates_chain() {
    let before = unix_now();
    let p = pki("init", &["internal", "svc.cluster.local"]);
    let (root, intermediate) = (&p.made.root_cert, &p.made.intermediate_cert);

    with_cert(root, |cert| {
        let basic = cert.basic_constraints().expect("parses").expect("present");
        assert!(basic.critical && basic.value.ca);
        assert_eq!(basic.value.path_len_constraint, Some(1));
        assert_eq!(
            cert.subject().as_raw(),
            cert.issuer().as_raw(),
            "self-signed"
        );
        let years =
            (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) / DAY;
        assert_eq!(years, 3650, "a root lives ten years");
        assert!(cert.validity().not_before.timestamp() <= before);
        assert!(
            cert.key_usage()
                .expect("parses")
                .expect("present")
                .value
                .key_cert_sign()
        );
        assert!(
            cert.name_constraints().expect("parses").is_none(),
            "the root itself is unconstrained"
        );
    });
    let root_subject = with_cert(root, |cert| cert.subject().as_raw().to_vec());
    with_cert(intermediate, |cert| {
        let basic = cert.basic_constraints().expect("parses").expect("present");
        assert!(basic.critical && basic.value.ca);
        assert_eq!(
            basic.value.path_len_constraint,
            Some(0),
            "it signs leaves only"
        );
        assert_eq!(
            cert.issuer().as_raw(),
            root_subject.as_slice(),
            "issued by the root"
        );
        assert!(
            cert.key_usage()
                .expect("parses")
                .expect("present")
                .value
                .key_cert_sign()
        );
    });
    // The intermediate verifies against the root, as openssl sees it.
    let intermediate_file = p.work.join("intermediate.pem");
    std::fs::write(&intermediate_file, intermediate).expect("file");
    let (ok, said) = openssl(&[
        "verify",
        "-CAfile",
        &p.root_file().display().to_string(),
        "-x509_strict",
        &intermediate_file.display().to_string(),
    ]);
    assert!(
        ok,
        "the intermediate does not verify against the root: {said}"
    );

    // What the directory holds: the intermediate and the root certificate, never the root key.
    for name in [
        "intermediate.key.pem",
        "intermediate.cert.pem",
        "root.cert.pem",
    ] {
        assert!(p.dir.join(name).is_file(), "{name}");
    }
    let root_key =
        std::fs::read_to_string(&p.root_key).expect("the root key is where it was asked");
    assert!(root_key.contains("PRIVATE KEY"));
    assert_eq!(
        p.made
            .suffixes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["internal", "svc.cluster.local"]
    );
    assert_eq!(
        p.made.root_fingerprint,
        export_root(&p.dir).expect("export").fingerprint
    );
}

#[test]
fn ca_intermediate_has_critical_name_constraints() {
    let p = pki("constraints", &["svc.cluster.local", "internal"]);
    with_cert(&p.made.intermediate_cert, |cert| {
        let extension = cert.name_constraints().expect("parses").expect("present");
        assert!(extension.critical, "NameConstraints must be critical");
        let mut permitted: Vec<String> = extension
            .value
            .permitted_subtrees
            .iter()
            .flatten()
            .map(|subtree| match &subtree.base {
                GeneralName::DNSName(name) => (*name).to_owned(),
                other => panic!("a permitted subtree that is not DNS: {other:?}"),
            })
            .collect();
        permitted.sort();
        assert_eq!(
            permitted,
            ["internal", "svc.cluster.local"],
            "exactly the allowed suffixes"
        );
        let excluded = extension
            .value
            .excluded_subtrees
            .as_ref()
            .expect("IP ranges are excluded");
        assert!(
            excluded
                .iter()
                .all(|subtree| matches!(subtree.base, GeneralName::IPAddress(_))),
            "{excluded:?}"
        );
    });
}

#[test]
fn ca_init_refuses_public_suffix() {
    let work = scratch("public");
    for suffix in ["com", "co.uk", "uk", "foo.ck"] {
        let dir = work.join(format!("ca-{suffix}"));
        let key = work.join(format!("{suffix}.key"));
        let refused = init(&InitOptions::new(
            dir.clone(),
            key.clone(),
            vec![suffix.to_owned()],
        ));
        assert!(
            matches!(&refused, Err(CaError::Suffix(SuffixError::Public(name))) if &**name == suffix),
            "{suffix}: {refused:?}"
        );
        assert!(
            !key.exists(),
            "{suffix}: no root key is written for a refused list"
        );
        assert!(
            !dir.join("intermediate.cert.pem").exists(),
            "{suffix}: nothing was initialized"
        );
    }
    // One public suffix in a list refuses the whole list.
    let mixed = init(&InitOptions::new(
        work.join("ca-mixed"),
        work.join("mixed.key"),
        vec!["internal".into(), "com".into()],
    ));
    assert!(
        matches!(mixed, Err(CaError::Suffix(SuffixError::Public(_)))),
        "{mixed:?}"
    );
    // Private names and a longer name under a registry suffix are fine, and so is the override.
    for suffix in [
        "internal",
        "lan",
        "home.arpa",
        "svc.cluster.local",
        "example.co.uk",
    ] {
        let ok = init(&InitOptions::new(
            work.join(format!("ca-ok-{suffix}")),
            work.join(format!("ok-{suffix}.key")),
            vec![suffix.to_owned()],
        ));
        assert!(ok.is_ok(), "{suffix}: {ok:?}");
    }
    let mut forced = InitOptions::new(
        work.join("ca-forced"),
        work.join("forced.key"),
        vec!["com".into()],
    );
    forced.allow_public_suffix = true;
    assert!(init(&forced).is_ok(), "--allow-public-suffix overrides");
    let empty = init(&InitOptions::new(
        work.join("ca-empty"),
        work.join("empty.key"),
        Vec::new(),
    ));
    assert!(
        matches!(empty, Err(CaError::Suffix(SuffixError::Empty))),
        "{empty:?}"
    );
}

// ---- leaves and the chain --------------------------------------------------------------------

#[test]
fn ca_leaf_verifies_with_openssl() {
    let p = pki("verify", &["internal", "svc.cluster.local"]);
    let ca = p.ca("");
    let now = unix_now();
    let leaf = ca
        .issue(&["a.internal", "b.svc.cluster.local"], now, 14)
        .expect("leaf");
    let root = p.root_file();

    let (ok, said) = verify(&p.work, &root, &leaf.chain_pem, Some("a.internal"));
    assert!(ok, "openssl rejects the leaf: {said}");
    let (ok, said) = verify(&p.work, &root, &leaf.chain_pem, Some("b.svc.cluster.local"));
    assert!(ok, "{said}");
    let (ok, _) = verify(&p.work, &root, &leaf.chain_pem, Some("other.internal"));
    assert!(!ok, "the leaf must not verify for a name it does not hold");

    // Without the intermediate in the chain the leaf does not reach the root: the pushed PEM
    // carries it.
    assert_eq!(
        leaf.chain_pem.matches("BEGIN CERTIFICATE").count(),
        2,
        "leaf, then intermediate"
    );

    let leaf_pem = leaf
        .chain_pem
        .split_inclusive("-----END CERTIFICATE-----\n")
        .next()
        .expect("leaf");
    with_cert(leaf_pem, |cert| {
        assert_eq!(
            dns_names(cert),
            ["a.internal", "b.svc.cluster.local"],
            "dNSName SANs only"
        );
        let basic = cert.basic_constraints().expect("parses");
        assert!(
            basic.is_none_or(|extension| !extension.value.ca),
            "a leaf is no CA"
        );
        let usage = cert
            .extended_key_usage()
            .expect("parses")
            .expect("present")
            .value;
        assert!(usage.server_auth && !usage.client_auth, "serverAuth only");
        let days =
            (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp()) / DAY;
        assert_eq!(days, 14, "leaf_days is the validity");
        assert_eq!(
            cert.public_key().algorithm.algorithm.to_id_string(),
            "1.2.840.10045.2.1",
            "ECDSA"
        );
        assert_eq!(
            cert.public_key().subject_public_key.data.len(),
            65,
            "P-256 uncompressed point"
        );
        assert!(
            cert.validity().not_after.timestamp()
                <= with_cert(&p.made.intermediate_cert, |i| i
                    .validity()
                    .not_after
                    .timestamp())
        );
    });
}

#[test]
fn ca_name_outside_constraints_fails_openssl() {
    let p = pki("outside", &["internal"]);
    // What a thief of the intermediate key can do: sign anything, with no provider in the way.
    let config = p.config("");
    let _ = config;
    let key =
        Secret::new(std::fs::read_to_string(p.dir.join("intermediate.key.pem")).expect("key"));
    let signer = Signer::from_pem(&p.made.intermediate_cert, &key).expect("signer");
    let root = p.root_file();
    let now = unix_now();

    // The control: the same signing path for an allowed name verifies.
    let good = signer
        .issue_unchecked(&["a.internal"], now, 14)
        .expect("leaf");
    let (ok, said) = verify(&p.work, &root, &good.chain_pem, Some("a.internal"));
    assert!(ok, "the control leaf must verify: {said}");

    for name in ["www.example.com", "a.notinternal", "internal.example.org"] {
        let bad = signer
            .issue_unchecked(&[name], now, 14)
            .expect("signed anyway");
        let (ok, said) = verify(&p.work, &root, &bad.chain_pem, None);
        assert!(
            !ok,
            "{name} verified although outside the constraints: {said}"
        );
        assert!(
            said.contains("permitted subtree violation"),
            "{name}: {said}"
        );
    }
    // A mixed leaf fails as a whole: one bad name spoils the certificate.
    let mixed = signer
        .issue_unchecked(&["a.internal", "www.example.com"], now, 14)
        .expect("signed");
    let (ok, said) = verify(&p.work, &root, &mixed.chain_pem, None);
    assert!(
        !ok && said.contains("permitted subtree violation"),
        "{said}"
    );
}

#[test]
fn ca_refuses_names_outside_suffixes() {
    let p = pki("refuse", &["internal"]);
    let mut ca = p.ca("");
    let now = unix_now();
    for name in [
        "a.example.com",
        "a.notinternal",
        "internal.example.org",
        "a.internal.example.com",
    ] {
        let refused = ca.issue(&[name], now, 14);
        assert!(
            matches!(refused, Err(CaError::NotAllowed(_))),
            "{name}: {refused:?}"
        );
    }
    assert!(
        ca.issue(&["a.internal", "b.example.com"], now, 14).is_err(),
        "one bad name refuses all"
    );

    // reconcile reports the refusal with the stable code and stores nothing.
    let report = ca
        .reconcile(
            &wants(vec![
                want("bad", "default", &["a.example.com"]),
                want("ok", "default", &["a.internal"]),
            ]),
            now,
        )
        .expect("reconcile");
    assert_eq!(report.issued, ["ok".into()]);
    assert_eq!(report.refused.len(), 1);
    assert_eq!(report.refused[0].code, "internal_name_not_allowed");
    assert_eq!(&*report.refused[0].app, "bad");
    assert_eq!(ca.view(now).certificates().len(), 1);

    // The merge refuses the app with the same code, and the pushed snapshot has no leaf for it.
    let merger = Merger::new(&p.config(""), UpstreamPolicy::builtin());
    let mut states = BTreeMap::new();
    states.insert(
        Box::<str>::from("local"),
        State {
            apps: vec![
                internal(app("local", "bad", &["a.example.com"], UP)),
                internal(app("local", "good", &["a.internal"], UP)),
            ],
            certificates: Vec::new(),
        },
    );
    let merged = merger.merge_all(
        &states,
        &BTreeSet::new(),
        &podgate_provider::acme::BrokerView::off(),
        &ca.view(now),
    );
    let finding = merged
        .findings()
        .iter()
        .find(|f| f.code == "internal_name_not_allowed")
        .expect("a report");
    assert!(
        finding.dropped && finding.declared_by.contains("local:bad"),
        "{finding:?}"
    );
    let ids: Vec<&str> = merged.snapshot().apps.iter().map(|a| &*a.id).collect();
    assert_eq!(ids, ["local-good"]);
    assert_eq!(merged.snapshot().certificates.len(), 1);

    // An internal app with no [ca] section at all is refused too, not served without a cert.
    let no_ca = Merger::new(
        &common::config(
            Path::new("/nonexistent/admin.sock"),
            "[[source]]\nkind = \"fake\"\nname = \"local\"\n",
        ),
        UpstreamPolicy::builtin(),
    );
    let merged = no_ca.merge(&states, &BTreeSet::new());
    assert!(
        merged
            .findings()
            .iter()
            .any(|f| f.code == "internal_ca_not_configured"),
        "{:?}",
        merged.findings()
    );
    assert!(merged.snapshot().apps.is_empty());
}

// ---- the provider task: issue, renew, re-push ------------------------------------------------

async fn first_leaf_push(h: &Harness, what: &str) -> common::Put {
    let puts = h
        .admin
        .wait_puts(what, |puts| puts.iter().any(|p| !leaf_hosts(p).is_empty()))
        .await;
    puts.into_iter()
        .find(|p| !leaf_hosts(p).is_empty())
        .expect("a push with a leaf")
}

#[tokio::test]
async fn ca_internal_app_gets_certificate() {
    let p = pki("app", &["internal"]);
    let h = Harness::start(&p.toml(""), &["local"]);
    h.source("local").apps(vec![
        internal(app("local", "a", &["a.internal"], UP)),
        // An app that wants ACME is none of the CA's business.
        app("local", "plain", &["plain.test"], UP),
    ]);
    let put = first_leaf_push(&h, "a push with the internal certificate").await;
    assert_eq!(
        leaf_hosts(&put),
        [["a.internal"]],
        "one leaf, for the internal app only"
    );
    let cert = &put.body["certificates"][0];
    let chain = cert["cert_pem"].as_str().expect("chain");
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 2);
    assert!(
        cert["key_pem"]
            .as_str()
            .is_some_and(|k| k.contains("PRIVATE KEY")),
        "the daemon needs the key"
    );
    let (ok, said) = verify(&p.work, &p.root_file(), chain, Some("a.internal"));
    assert!(ok, "{said}");
    let mode: Vec<(&str, &str)> = put.body["apps"]
        .as_array()
        .expect("apps")
        .iter()
        .map(|a| {
            (
                a["id"].as_str().expect("id"),
                a["tls"]["mode"].as_str().expect("mode"),
            )
        })
        .collect();
    assert!(mode.contains(&("local-a", "internal")), "{mode:?}");
    assert!(
        put.body["acme"].is_null(),
        "no ACME object without an [acme] section"
    );
    // It is on disk, key included, before it was pushed.
    let stored = pems_in(&p.dir.join("certs"));
    assert!(stored.iter().any(|path| {
        std::fs::read_to_string(path)
            .is_ok_and(|text| text == cert["key_pem"].as_str().unwrap_or_default())
    }));
    h.stop().await.expect("clean stop");
}

#[test]
fn ca_leaf_renewed_at_two_thirds() {
    let p = pki("renew", &["internal"]);
    let mut ca = p.ca("leaf_days = 3");
    let t0 = unix_now();
    let w = wants(vec![want("a", "default", &["a.internal"])]);

    let first = ca.reconcile(&w, t0).expect("first");
    assert_eq!(first.issued, ["a".into()]);
    let issued_pem = ca.view(t0).certificates()[0].cert_pem.clone();
    let issued_key = ca.view(t0).certificates()[0].key_pem.clone();
    let (not_before, not_after) = with_cert(&issued_pem, |c| {
        (
            c.validity().not_before.timestamp(),
            c.validity().not_after.timestamp(),
        )
    });
    let renew_at = podgate_provider::ca::renew_at(not_before, not_after);
    assert_eq!(
        renew_at,
        not_before + (not_after - not_before) * 2 / 3,
        "two thirds of the lifetime"
    );
    assert_eq!(ca.next_renewal(&w), Some(renew_at));
    assert!(
        renew_at > t0 + DAY && renew_at < t0 + 3 * DAY,
        "{renew_at} vs {t0}"
    );

    // Before two thirds: nothing happens, the same certificate stays.
    for at in [t0 + 1, t0 + DAY, renew_at - 1] {
        let report = ca.reconcile(&w, at).expect("reconcile");
        assert!(
            report.issued.is_empty(),
            "renewed too early at +{}s",
            at - t0
        );
        assert_eq!(ca.view(at).certificates()[0].cert_pem, issued_pem);
    }
    // At two thirds: a new leaf replaces it, in the view and on disk.
    let report = ca.reconcile(&w, renew_at).expect("renewal");
    assert_eq!(report.issued, ["a".into()]);
    let view = ca.view(renew_at);
    assert_eq!(
        view.certificates().len(),
        1,
        "the old leaf is replaced, not added"
    );
    assert_ne!(view.certificates()[0].cert_pem, issued_pem);
    assert_ne!(
        view.certificates()[0].key_pem,
        issued_key,
        "a fresh key too"
    );
    let renewed_after = with_cert(&view.certificates()[0].cert_pem, |c| {
        c.validity().not_after.timestamp()
    });
    assert!(renewed_after > not_after, "the new leaf outlives the old");
    let status = status(&p.dir).expect("status");
    assert_eq!(status.leaves.len(), 1, "one leaf on disk");

    // An expired leaf is never shown, and an app that no longer wants the hosts stops getting it
    // pushed (the merge selects by what apps want).
    assert!(ca.view(renewed_after + 1).certificates().is_empty());
    assert!(!wants(vec![want("a", "default", &["other.internal"])]).holds(&["a.internal".into()]));
}

#[tokio::test]
async fn ca_certificates_repushed_after_restart() {
    let p = pki("restart", &["internal"]);
    let h = Harness::start(&p.toml(""), &["local"]);
    h.source("local")
        .apps(vec![internal(app("local", "a", &["a.internal"], UP))]);
    let first = first_leaf_push(&h, "the first leaf push").await;
    let cert = first.body["certificates"][0]["cert_pem"]
        .as_str()
        .expect("chain")
        .to_owned();
    let stored_before = pems_in(&p.dir.join("certs")).len();

    // podgate restarts: it forgot its snapshot, and the running provider pushes it all again.
    h.admin.restart();
    let puts = h
        .admin
        .wait_puts("a push after the podgate restart", |puts| {
            puts.iter()
                .any(|p| p.version == 1 && !leaf_hosts(p).is_empty())
                && puts.len() >= 2
        })
        .await;
    let again = puts.last().expect("a push");
    assert_eq!(
        again.body["certificates"][0]["cert_pem"],
        cert.as_str(),
        "the same leaf, not a new one"
    );
    let admin = h.stop_keep_admin().await;

    // The provider restarts: the leaf comes from the directory, with no new issuance.
    let h2 = Harness::start_with(admin, &p.toml(""), &["local"]);
    h2.source("local")
        .apps(vec![internal(app("local", "a", &["a.internal"], UP))]);
    h2.admin.restart();
    let puts = h2
        .admin
        .wait_puts("a push after the provider restart", |puts| {
            puts.iter().any(|p| !leaf_hosts(p).is_empty())
        })
        .await;
    let last = puts
        .iter()
        .rev()
        .find(|p| !leaf_hosts(p).is_empty())
        .expect("a leaf push");
    assert_eq!(last.body["certificates"][0]["cert_pem"], cert.as_str());
    assert_eq!(
        pems_in(&p.dir.join("certs")).len(),
        stored_before,
        "nothing was issued again"
    );
    h2.stop().await.expect("clean stop");
}

// ---- the daemon serves it --------------------------------------------------------------------

async fn https_get(
    addr: std::net::SocketAddr,
    root_pem: &str,
    host: &str,
) -> Result<(u16, String), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(parse(root_pem)))
        .map_err(|e| e.to_string())?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(addr)
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
async fn ca_daemon_serves_internal_certificate() {
    let p = pki("daemon", &["internal"]);
    let policy = p.work.join("policy.json");
    std::fs::write(&policy, daemon::LOOPBACK_POLICY).expect("policy");
    let daemon = daemon::Daemon::start_free(&policy, &[("NODE_NAME", "n1")]).await;
    let (backend, _task) = daemon::backend("from-the-backend").await;

    let config = common::config(&daemon.admin, &p.toml_full(""));
    let mut engine =
        podgate_provider::Engine::new(config, UpstreamPolicy::load(&policy).expect("policy"))
            .with_tuning(common::fast_tuning());
    let (source, handle) = common::scripted("local");
    engine.add_source(source).expect("source");
    handle.apps(vec![internal(app(
        "local",
        "a",
        &["a.internal"],
        &format!("http://{backend}"),
    ))]);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(async move {
        engine
            .run(async {
                let _ = stopped.await;
            })
            .await
    });

    // A client that trusts only the internal root reaches the backend over TLS: the daemon serves
    // the certificate the snapshot carries, and ordered nothing.
    let start = Instant::now();
    let body = loop {
        match https_get(daemon.tls, &p.made.root_cert, "a.internal").await {
            Ok((200, body)) => break body,
            other => assert!(
                start.elapsed() < Duration::from_secs(30),
                "a.internal is not served over TLS: {other:?}"
            ),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(body, "from-the-backend");
    let events = daemon.events().await;
    assert!(
        events.iter().all(|e| !e["kind"]
            .as_str()
            .is_some_and(|k| k.starts_with("acme_") || k.starts_with("certificate_"))),
        "{events:?}"
    );
    // The certificate is the CA's: a client that does not trust the root refuses it.
    let other_root = pki("daemon-other", &["internal"]);
    let refused = https_get(daemon.tls, &other_root.made.root_cert, "a.internal").await;
    assert!(
        refused.is_err(),
        "a different root must not verify: {refused:?}"
    );
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(20), run)
        .await
        .expect("stops")
        .expect("no panic")
        .expect("clean stop");
}

// ---- tenants and wildcards -------------------------------------------------------------------

#[tokio::test]
async fn ca_tenant_cannot_get_foreign_host() {
    let p = pki("tenant", &["internal"]);
    let mut ca = p.ca("");
    let now = unix_now();

    // Defence in depth: whatever reaches the CA, a host the tenant does not own gets no leaf.
    let report = ca
        .reconcile(
            &wants(vec![
                want("steals", "acme", &["a.globex.internal"]),
                want("owns", "acme", &["a.acme.internal"]),
                want("nobody", "ghost", &["x.internal"]),
            ]),
            now,
        )
        .expect("reconcile");
    assert_eq!(report.issued, ["owns".into()]);
    let codes: BTreeMap<&str, &str> = report.refused.iter().map(|r| (&*r.app, r.code)).collect();
    assert_eq!(codes["steals"], "foreign_host_claim");
    assert_eq!(codes["nobody"], "unknown_tenant");
    let hosts: Vec<Vec<Box<str>>> = ca
        .view(now)
        .certificates()
        .iter()
        .map(|c| c.hosts.clone())
        .collect();
    assert_eq!(hosts, [vec![Box::<str>::from("a.acme.internal")]]);

    // Through the whole provider: the merge drops the app before the CA is asked.
    let h = Harness::start(&p.toml(""), &["local"]);
    h.source("local").apps(vec![
        internal(app("local", "steals", &["a.globex.internal"], UP)).mapped("acme"),
        internal(app("local", "owns", &["b.acme.internal"], UP)).mapped("acme"),
    ]);
    let put = first_leaf_push(&h, "a push with the tenant's own leaf").await;
    assert_eq!(leaf_hosts(&put), [["b.acme.internal"]]);
    assert!(!common::app_ids(&put.body).contains(&"local-steals".to_owned()));
    let status = h.status.borrow().clone();
    assert!(
        status
            .findings
            .iter()
            .any(|f| f.code == "foreign_host_claim"),
        "{:?}",
        status.findings
    );
    assert!(
        pems_in(&p.dir.join("certs"))
            .iter()
            .all(|path| !std::fs::read_to_string(path)
                .unwrap_or_default()
                .contains("globex")),
        "nothing was issued for the foreign host"
    );
    h.stop().await.expect("clean stop");
}

#[test]
fn ca_wildcard_requires_setting() {
    let p = pki("wildcard", &["internal"]);
    let now = unix_now();
    let w = wants(vec![want("w", "default", &["*.w.internal"])]);

    // Off (the default): refused by the CA and by the merge, with the stable code.
    let mut off = p.ca("");
    let report = off.reconcile(&w, now).expect("reconcile");
    assert!(report.issued.is_empty());
    assert_eq!(report.refused[0].code, "internal_name_not_allowed");
    assert!(
        report.refused[0].reason.contains("allow_wildcards"),
        "{}",
        report.refused[0].reason
    );
    assert!(off.issue(&["*.w.internal"], now, 14).is_err());
    let mut states = BTreeMap::new();
    states.insert(
        Box::<str>::from("local"),
        State {
            apps: vec![internal(app("local", "w", &["*.w.internal"], UP))],
            certificates: Vec::new(),
        },
    );
    let merged =
        Merger::new(&p.config(""), UpstreamPolicy::builtin()).merge(&states, &BTreeSet::new());
    assert!(
        merged
            .findings()
            .iter()
            .any(|f| f.code == "internal_name_not_allowed" && f.dropped),
        "{:?}",
        merged.findings()
    );
    assert!(merged.snapshot().apps.is_empty());

    // On: a wildcard leaf that openssl accepts for a name under it.
    let mut on = p.ca("allow_wildcards = true");
    let report = on.reconcile(&w, now).expect("reconcile");
    assert_eq!(report.issued, ["w".into()]);
    let shown = on.view(now);
    let cert = &shown.certificates()[0];
    assert_eq!(cert.hosts, [Box::<str>::from("*.w.internal")]);
    let (ok, said) = verify(
        &p.work,
        &p.root_file(),
        &cert.cert_pem,
        Some("x.w.internal"),
    );
    assert!(ok, "{said}");
    let merged = Merger::new(
        &p.config("allow_wildcards = true"),
        UpstreamPolicy::builtin(),
    )
    .merge_all(
        &states,
        &BTreeSet::new(),
        &podgate_provider::acme::BrokerView::off(),
        &on.view(now),
    );
    assert_eq!(merged.snapshot().apps.len(), 1);
    assert_eq!(merged.snapshot().certificates.len(), 1);
}

// ---- key hygiene -----------------------------------------------------------------------------

#[test]
fn ca_root_key_not_in_state_dir() {
    let p = pki("rootkey", &["internal"]);
    let root_key = std::fs::read_to_string(&p.root_key).expect("root key");
    let body = key_lines(&root_key);
    assert!(!body.is_empty());
    assert_eq!(mode_of(&p.root_key), 0o600, "the root key file is private");
    for file in pems_in(&p.dir) {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        assert!(
            body.iter().all(|line| !text.contains(line.as_str())),
            "the root key is in the state directory: {}",
            file.display()
        );
        assert!(
            !file.to_string_lossy().contains("root.key")
                && !file.to_string_lossy().contains("root.key.pem"),
            "{}",
            file.display()
        );
    }
    // After a leaf is issued, still not.
    let mut ca = p.ca("");
    ca.reconcile(
        &wants(vec![want("a", "default", &["a.internal"])]),
        unix_now(),
    )
    .expect("issue");
    for file in pems_in(&p.dir) {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        assert!(
            body.iter().all(|line| !text.contains(line.as_str())),
            "{}",
            file.display()
        );
    }
    // The root key cannot be asked to land beside the intermediate, and an existing file is
    // never overwritten.
    let inside = init(&InitOptions::new(
        p.work.join("ca2"),
        p.work.join("ca2").join("root.key"),
        vec!["internal".into()],
    ));
    assert!(
        matches!(inside, Err(CaError::RootKeyInStateDir(_))),
        "{inside:?}"
    );
    assert!(!p.work.join("ca2").join("root.key").exists());
    let again = init(&InitOptions::new(
        p.dir.clone(),
        p.work.join("elsewhere.key"),
        vec!["internal".into()],
    ));
    assert!(
        matches!(again, Err(CaError::AlreadyInitialized(_))),
        "init never replaces a CA: {again:?}"
    );
    let clobber = init(&InitOptions::new(
        p.work.join("ca3"),
        p.root_key.clone(),
        vec!["internal".into()],
    ));
    assert!(matches!(clobber, Err(CaError::Exists(_))), "{clobber:?}");
    assert_eq!(
        std::fs::read_to_string(&p.root_key).expect("root key"),
        root_key,
        "the root key was not overwritten"
    );
}

#[test]
fn ca_state_permissions() {
    let p = pki("perms", &["internal"]);
    let mut ca = p.ca("");
    ca.reconcile(
        &wants(vec![want("a", "default", &["a.internal"])]),
        unix_now(),
    )
    .expect("issue");
    assert_eq!(mode_of(&p.dir), 0o700);
    assert_eq!(mode_of(&p.dir.join("certs")), 0o700);
    let files = pems_in(&p.dir);
    assert!(files.len() >= 6, "{files:?}");
    for file in files {
        assert_eq!(mode_of(&file), 0o600, "{}", file.display());
    }
    // A directory that others can read is refused, not repaired.
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let config = p.config("");
    let opened = Ca::open(config.ca.as_ref().expect("[ca]"), &config);
    assert!(matches!(opened, Err(CaError::Store(_))), "{opened:?}");
    std::fs::set_permissions(&p.dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::set_permissions(
        p.dir.join("intermediate.key.pem"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("chmod");
    let opened = Ca::open(config.ca.as_ref().expect("[ca]"), &config);
    assert!(
        matches!(opened, Err(CaError::Store(_))),
        "a readable CA key stops the provider: {opened:?}"
    );
}

// ---- the ca command --------------------------------------------------------------------------

fn run_cli(args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cli::run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn cli_config(work: &Path, dir: &Path, extra: &str) -> String {
    let file = work.join("provider.toml");
    std::fs::write(
        &file,
        format!(
            "admin_socket = \"/nonexistent/admin.sock\"\n[ca]\nenabled = true\ndir = {:?}\nallowed_suffixes = [\"internal\", \"svc.cluster.local\"]\n{extra}\n",
            dir.display().to_string()
        ),
    )
    .expect("config file");
    file.display().to_string()
}

#[test]
fn ca_export_root() {
    let work = scratch("export");
    let (dir, key) = (work.join("ca"), work.join("root.key"));
    let config = cli_config(&work, &dir, "");
    let (code, out, err) = run_cli(&[
        "init",
        "--config",
        &config,
        "--root-key-out",
        &key.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("root key written to") && out.contains("offline"),
        "{out}"
    );
    assert_eq!(mode_of(&key), 0o600);

    let (code, out, err) = run_cli(&["export-root", "--config", &config]);
    assert_eq!(code, 0, "{err}");
    let root_pem = std::fs::read_to_string(dir.join("root.cert.pem")).expect("root");
    assert!(out.contains(&root_pem), "the PEM is printed: {out}");
    // The fingerprint is the SHA-256 of the DER, as openssl prints it.
    let root_file = work.join("root.pem");
    std::fs::write(&root_file, &root_pem).expect("root");
    let (ok, said) = openssl(&[
        "x509",
        "-in",
        &root_file.display().to_string(),
        "-noout",
        "-fingerprint",
        "-sha256",
    ]);
    assert!(ok, "{said}");
    let expected = said
        .trim()
        .split_once('=')
        .expect("openssl output")
        .1
        .to_owned();
    assert!(
        out.contains(&format!("SHA-256 fingerprint: {expected}")),
        "{out} vs {expected}"
    );
    let exported = export_root(&dir).expect("export");
    assert_eq!(exported.fingerprint, expected);
    assert_eq!(exported.pem, root_pem);
    let (code, pem_only, _) = run_cli(&["export-root", "--config", &config, "--pem-only"]);
    assert_eq!(code, 0);
    assert_eq!(pem_only, root_pem, "--pem-only is the PEM and nothing else");

    // `ca init` again is refused, and the command reports a missing CA.
    let (code, _, err) = run_cli(&[
        "init",
        "--config",
        &config,
        "--root-key-out",
        &work.join("second.key").display().to_string(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("already holds a CA"), "{err}");
    let empty = cli_config(
        &scratch("export-empty"),
        &scratch("export-empty").join("none"),
        "",
    );
    let (code, _, err) = run_cli(&["export-root", "--config", &empty]);
    assert_eq!(code, 1);
    assert!(err.contains("ca init"), "{err}");
}

#[test]
fn ca_status_reports_expiry() {
    let work = scratch("status");
    let (dir, key) = (work.join("ca"), work.join("root.key"));
    let config = cli_config(&work, &dir, "");
    let before = unix_now();
    let (code, _, err) = run_cli(&[
        "init",
        "--config",
        &config,
        "--root-key-out",
        &key.display().to_string(),
        "--intermediate-days",
        "400",
    ]);
    assert_eq!(code, 0, "{err}");

    // An operator leaf under the same rules, and a provider-issued one.
    let out_dir = work.join("leaf");
    let (code, out, err) = run_cli(&[
        "issue",
        "--config",
        &config,
        "--out",
        &out_dir.display().to_string(),
        "--days",
        "30",
        "tools.internal",
        "db.svc.cluster.local",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("tools.internal.cert.pem"), "{out}");
    assert_eq!(mode_of(&out_dir.join("tools.internal.key.pem")), 0o600);
    let chain = std::fs::read_to_string(out_dir.join("tools.internal.cert.pem")).expect("leaf");
    let root = work.join("root.pem");
    std::fs::write(
        &root,
        std::fs::read_to_string(dir.join("root.cert.pem")).expect("root"),
    )
    .expect("file");
    let (ok, said) = verify(&work, &root, &chain, Some("db.svc.cluster.local"));
    assert!(ok, "the operator's leaf verifies: {said}");
    let (code, _, err) = run_cli(&[
        "issue",
        "--config",
        &config,
        "--out",
        &work.join("bad").display().to_string(),
        "www.example.com",
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("allowed_suffixes"), "{err}");
    assert!(
        !work.join("bad").exists(),
        "nothing is written for a refused name"
    );

    let reading = ca_leaf_for_status(&work, &dir, &config);
    let (code, out, err) = run_cli(&["status", "--config", &config]);
    assert_eq!(code, 0, "{err}");
    let report = status(&dir).expect("status");
    let day = |secs: i64| secs / DAY;
    assert_eq!(day(report.root.not_after - before), 3650, "{report:?}");
    assert_eq!(day(report.intermediate.not_after - before), 400);
    assert_eq!(report.leaves.len(), 1);
    assert_eq!(
        report.leaves[0].hosts,
        [Box::<str>::from("status.internal")]
    );
    assert_eq!(
        report.permitted.iter().map(|p| &**p).collect::<Vec<_>>(),
        ["internal", "svc.cluster.local"]
    );
    assert!(
        report.leaves[0].renew_at < report.leaves[0].not_after
            && report.leaves[0].renew_at > before
    );
    // The text names every expiry, with a date and the days left.
    for needle in [
        "root: expires",
        "intermediate: expires",
        "status.internal",
        "days left",
        "permitted: internal, svc.cluster.local",
        "leaves: 1",
    ] {
        assert!(out.contains(needle), "{needle:?} missing from:\n{out}");
    }
    assert!(
        out.contains(&format!(
            "{}-",
            with_cert(
                &std::fs::read_to_string(dir.join("root.cert.pem")).expect("root"),
                |c| {
                    time::OffsetDateTime::from_unix_timestamp(c.validity().not_after.timestamp())
                        .expect("date")
                        .year()
                }
            )
        )),
        "the root's expiry year: {out}"
    );
    let _ = reading;
}

/// Issues one leaf through the provider's own path so `status` has a leaf to show.
fn ca_leaf_for_status(_work: &Path, dir: &Path, config_file: &str) -> usize {
    let config = Config::load(Path::new(config_file)).expect("config");
    let settings = config.ca.clone().expect("[ca]");
    let mut ca = Ca::open(&settings, &config).expect("open");
    let report = ca
        .reconcile(
            &wants(vec![want("status", "default", &["status.internal"])]),
            unix_now(),
        )
        .expect("issue");
    assert_eq!(report.issued.len(), 1);
    pems_in(&dir.join("certs")).len()
}

#[test]
fn ca_rotates_the_intermediate_under_the_same_root() {
    let work = scratch("rotate");
    let (dir, key) = (work.join("ca"), work.join("root.key"));
    let config = cli_config(&work, &dir, "");
    let (code, _, err) = run_cli(&[
        "init",
        "--config",
        &config,
        "--root-key-out",
        &key.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    let root = work.join("root.pem");
    std::fs::write(
        &root,
        std::fs::read_to_string(dir.join("root.cert.pem")).expect("root"),
    )
    .expect("file");
    let old = std::fs::read_to_string(dir.join("intermediate.cert.pem")).expect("old");

    let (code, out, err) = run_cli(&[
        "rotate",
        "--config",
        &config,
        "--root-key",
        &key.display().to_string(),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("restart the provider"), "{out}");
    let new = std::fs::read_to_string(dir.join("intermediate.cert.pem")).expect("new");
    assert_ne!(old, new);
    // The new intermediate is constrained the same way and verifies against the same root; a
    // leaf signed under it verifies, and so does a leaf under the old one (overlap).
    let (code, issued, err) = run_cli(&[
        "issue",
        "--config",
        &config,
        "--out",
        &work.join("leaf").display().to_string(),
        "x.internal",
    ]);
    assert_eq!(code, 0, "{issued}{err}");
    let chain = std::fs::read_to_string(work.join("leaf/x.internal.cert.pem")).expect("leaf");
    let (ok, said) = verify(&work, &root, &chain, Some("x.internal"));
    assert!(ok, "{said}");
    with_cert(&new, |cert| {
        let extension = cert.name_constraints().expect("parses").expect("present");
        assert!(extension.critical);
    });
    let wrong = work.join("wrong.key");
    std::fs::write(
        &wrong,
        std::fs::read_to_string(dir.join("intermediate.key.pem")).expect("key"),
    )
    .expect("file");
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let (code, _, err) = run_cli(&[
        "rotate",
        "--config",
        &config,
        "--root-key",
        &wrong.display().to_string(),
    ]);
    assert_eq!(code, 1);
    assert!(err.contains("does not belong"), "{err}");
}

#[test]
fn ca_provider_refuses_suffixes_wider_than_its_intermediate() {
    let p = pki("wider", &["internal"]);
    let config = common::config(
        Path::new("/nonexistent/admin.sock"),
        &p.toml_full("").replace(
            "allowed_suffixes = [\"internal\"]",
            "allowed_suffixes = [\"internal\", \"example.org\"]",
        ),
    );
    let opened = Ca::open(config.ca.as_ref().expect("[ca]"), &config);
    assert!(
        matches!(opened, Err(CaError::SuffixNotPermitted { .. })),
        "{opened:?}"
    );
    // A narrower list is fine: the provider may be stricter than the certificate.
    let config = common::config(
        Path::new("/nonexistent/admin.sock"),
        &p.toml_full("").replace(
            "allowed_suffixes = [\"internal\"]",
            "allowed_suffixes = [\"a.internal\"]",
        ),
    );
    let ca = Ca::open(config.ca.as_ref().expect("[ca]"), &config).expect("a narrower list opens");
    assert!(ca.issue(&["b.internal"], unix_now(), 14).is_err());
    assert!(ca.issue(&["x.a.internal"], unix_now(), 14).is_ok());
}

#[test]
fn ca_section_is_validated() {
    let bad = |ca: &str| {
        Config::parse(&format!(
            "admin_socket = \"/x.sock\"\n[ca]\nenabled = true\n{ca}\n"
        ))
        .expect_err("refused")
        .to_string()
    };
    assert!(bad("allowed_suffixes = [\"internal\"]").contains("ca.dir"));
    assert!(bad("dir = \"/x\"").contains("allowed_suffixes"));
    assert!(
        bad("dir = \"/x\"\nallowed_suffixes = [\"internal\"]\nleaf_days = 91")
            .contains("ca.leaf_days")
    );
    assert!(
        bad("dir = \"/x\"\nallowed_suffixes = [\"internal\"]\nleaf_days = 0")
            .contains("ca.leaf_days")
    );
    assert!(bad("dir = \"/x\"\nallowed_suffixes = [\"in valid\"]").contains("not a DNS suffix"));
    assert!(
        bad("dir = \"/x\"\nallowed_suffixes = [\"internal\"]\nroot_key_file = \"/k\"")
            .contains("unknown field")
    );
    let off = Config::parse("admin_socket = \"/x.sock\"\n[ca]\nenabled = false\n")
        .expect("disabled sections are ignored");
    assert!(off.ca.is_none());
}
