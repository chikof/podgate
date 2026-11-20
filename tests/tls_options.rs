//! End to end: per-app TLS options (minimum version, cipher suites, ALPN, client authentication
//! modes, strict SNI) and the default certificate, through the real binary.

mod common;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::{Podgate, TestCa, TestCert, TestClient, Upstream, app, serving, snapshot};
use rustls::crypto::ring::{cipher_suite, default_provider};
use rustls::pki_types::ServerName;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, RootCertStore, SupportedCipherSuite, SupportedProtocolVersion};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const POLICY_BODY: &str = r#"{"error":"tls policy"}"#;

type Versions = &'static [&'static SupportedProtocolVersion];

fn tls13() -> Versions {
    static VERSIONS: [&SupportedProtocolVersion; 1] = [&TLS13];
    &VERSIONS
}

fn tls12() -> Versions {
    static VERSIONS: [&SupportedProtocolVersion; 1] = [&TLS12];
    &VERSIONS
}

fn both() -> Versions {
    static VERSIONS: [&SupportedProtocolVersion; 2] = [&TLS12, &TLS13];
    &VERSIONS
}

/// A client trusting `trusted`, offering `versions`, `suites` (`None`: every suite of the
/// provider) and `alpn`, presenting `client` when asked.
fn client_config(
    trusted: &[&TestCert],
    versions: Versions,
    suites: Option<Vec<SupportedCipherSuite>>,
    alpn: &[&[u8]],
    client: Option<&TestClient>,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.der.clone()).expect("trust the server");
    }
    let mut provider = default_provider();
    if let Some(suites) = suites {
        provider.cipher_suites = suites;
    }
    let builder = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .expect("protocol versions")
        .with_root_certificates(roots);
    let mut config = match client {
        Some(client) => builder
            .with_client_auth_cert(client.chain.clone(), client.key.clone_key())
            .expect("client certificate"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

fn plain_client(server: &TestCert, versions: Versions) -> Arc<ClientConfig> {
    client_config(&[server], versions, None, &[], None)
}

/// The leaf certificate the server presented in a handshake for `name`, or why it failed.
async fn served_cert(
    podgate: &Podgate,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> io::Result<Vec<u8>> {
    timeout(Duration::from_secs(10), async {
        let tcp = TcpStream::connect(podgate.tls_addr).await?;
        let stream = TlsConnector::from(config).connect(name, tcp).await?;
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(leaf.as_ref().to_vec())
    })
    .await
    .expect("handshake in time")
}

fn dns(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).expect("server name")
}

/// An app `id` for `hosts` with `tls` merged into its `tls` object.
fn with_tls(id: &str, hosts: &[&str], upstream: &Upstream, tls: &Value) -> Value {
    let mut app = app(id, hosts, &[serving("r1", upstream.addr)]);
    app["tls"]
        .as_object_mut()
        .expect("tls object")
        .extend(tls.as_object().expect("tls options").clone());
    app
}

struct Fixture {
    podgate: Podgate,
    server: TestCert,
    _upstream: Upstream,
}

/// `a.test` with the TLS options `tls` and a certificate for it.
async fn start(tls: &Value) -> Fixture {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("body").await;
    let server = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[with_tls("a", &["a.test"], &upstream, tls)]);
    pushed["certificates"] = json!([server.entry(&["a.test"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    Fixture {
        podgate,
        server,
        _upstream: upstream,
    }
}

impl Fixture {
    async fn get(&self, config: Arc<ClientConfig>) -> io::Result<common::Response> {
        self.podgate
            .try_https_get(config, "a.test", "a.test", "/")
            .await
    }
}

#[tokio::test]
async fn tls_min_version_13_refuses_tls12() {
    let fx = start(&json!({"min_version": "1.3"})).await;

    let served = fx
        .get(plain_client(&fx.server, tls13()))
        .await
        .expect("a TLS 1.3 client is served");
    assert_eq!((served.status, served.body.as_str()), (200, "body"));

    fx.get(plain_client(&fx.server, tls12()))
        .await
        .expect_err("a client that only offers TLS 1.2 fails the handshake");

    let offering_both = fx
        .get(plain_client(&fx.server, both()))
        .await
        .expect("a client that offers both negotiates 1.3");
    assert_eq!(offering_both.status, 200, "{offering_both:?}");
}

#[tokio::test]
async fn tls_unenforceable_options_rejected() {
    let fx = start(&json!({})).await;
    let upstream = Upstream::start("x").await;
    let unenforceable = [
        json!({"max_version": "1.3"}),
        json!({"curves": ["X25519"]}),
        json!({"session_tickets": false}),
        json!({"alpn": ["h3"]}),
    ];
    for (version, tls) in (2_u64..).zip(&unenforceable) {
        let pushed = snapshot(version, &[with_tls("a", &["a.test"], &upstream, tls)]);
        let response = fx.podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{tls}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "unsupported_setting",
            "{tls}"
        );
    }
    let served = fx
        .get(plain_client(&fx.server, tls13()))
        .await
        .expect("the previous snapshot still serves");
    assert_eq!(served.status, 200, "{served:?}");
}

#[tokio::test]
async fn tls_unsupported_cipher_rejected() {
    let fx = start(&json!({})).await;
    let upstream = Upstream::start("x").await;
    let tls = json!({"cipher_suites": ["TLS_RSA_WITH_RC4_128_SHA"]});
    let response = fx
        .podgate
        .push_snapshot(&snapshot(2, &[with_tls("a", &["a.test"], &upstream, &tls)]))
        .await;
    assert_eq!(response.status, 422, "{response:?}");
    let entry = &response.json()["conflicts"][0];
    assert_eq!(entry["code"], "unsupported_setting");
    let message = entry["message"].as_str().expect("message");
    assert!(message.contains("TLS_RSA_WITH_RC4_128_SHA"), "{message}");
    assert!(
        message.contains("TLS13_AES_256_GCM_SHA384"),
        "lists what is supported: {message}"
    );
}

#[tokio::test]
async fn tls_cipher_suites_restrict() {
    let fx = start(&json!({"cipher_suites": ["TLS13_AES_256_GCM_SHA384"]})).await;
    let aes128 = cipher_suite::TLS13_AES_128_GCM_SHA256;
    let aes256 = cipher_suite::TLS13_AES_256_GCM_SHA384;
    let client = |suites| client_config(&[&fx.server], tls13(), Some(suites), &[], None);

    fx.get(client(vec![aes128]))
        .await
        .expect_err("a client that offers no allowed suite fails the handshake");

    let slipped = fx
        .get(client(vec![aes128, aes256]))
        .await
        .expect("a client that offers an allowed suite handshakes");
    assert_eq!(
        slipped.status, 421,
        "it negotiated its first choice, AES-128"
    );
    assert_eq!(slipped.body, POLICY_BODY);

    let allowed = fx.get(client(vec![aes256])).await.expect("allowed suite");
    assert_eq!((allowed.status, allowed.body.as_str()), (200, "body"));
}

/// One HTTP/2 request to `a.test` on a connection that offered `alpn`, over `config`.
async fn h2_get(fx: &Fixture, config: Arc<ClientConfig>) -> io::Result<(u16, String)> {
    let tcp = TcpStream::connect(fx.podgate.tls_addr).await?;
    let tls = TlsConnector::from(config)
        .connect(dns("a.test"), tcp)
        .await?;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "h2 negotiated"
    );
    let (mut client, connection) = h2::client::handshake(tls).await.map_err(io::Error::other)?;
    tokio::spawn(connection);
    let request = http::Request::get("https://a.test/")
        .body(())
        .map_err(io::Error::other)?;
    let (response, _) = client
        .send_request(request, true)
        .map_err(io::Error::other)?;
    let response = response.await.map_err(io::Error::other)?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut text = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
        text.extend_from_slice(&chunk);
    }
    Ok((status, String::from_utf8_lossy(&text).into_owned()))
}

#[tokio::test]
async fn tls_alpn_h1_only() {
    let fx = start(&json!({"alpn": ["http/1.1"]})).await;
    let offer = |alpn: &[&[u8]]| client_config(&[&fx.server], tls13(), None, alpn, None);

    let (status, body) = Box::pin(h2_get(&fx, offer(&[b"h2", b"http/1.1"])))
        .await
        .expect("the h2 connection is made");
    assert_eq!(status, 421, "the connection negotiated h2");
    assert_eq!(body, POLICY_BODY);

    fx.get(offer(&[b"h2"]))
        .await
        .expect_err("a client that only speaks h2 fails the handshake");

    let served = fx
        .get(offer(&[b"http/1.1"]))
        .await
        .expect("an HTTP/1.1 client is served");
    assert_eq!((served.status, served.body.as_str()), (200, "body"));
}

#[tokio::test]
async fn tls_client_auth_modes() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("ok").await;
    let server = TestCert::new(&["request.test", "require.test", "verify.test", "strict.test"]);
    let ca = TestCa::new("trusted ca");
    let stranger = TestCa::new("other ca").client("mallory");
    let alice = ca.client("alice");
    let apps = [
        with_tls(
            "request",
            &["request.test"],
            &upstream,
            &json!({"client_auth": "request"}),
        ),
        with_tls(
            "require",
            &["require.test"],
            &upstream,
            &json!({"client_auth": "require"}),
        ),
        with_tls(
            "verify",
            &["verify.test"],
            &upstream,
            &json!({"client_auth": "verify_if_given", "client_ca_pem": ca.pem}),
        ),
        with_tls(
            "strict",
            &["strict.test"],
            &upstream,
            &json!({"client_auth": "require_and_verify", "client_ca_pem": ca.pem}),
        ),
    ];
    let mut pushed = snapshot(1, &apps);
    pushed["certificates"] =
        json!([server.entry(&["request.test", "require.test", "verify.test", "strict.test"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");

    let status = |host: &'static str, client: Option<&TestClient>| {
        let config = client_config(&[&server], tls13(), None, &[], client);
        let podgate = &podgate;
        async move {
            podgate
                .try_https_get(config, host, host, "/")
                .await
                .expect("handshake and response")
                .status
        }
    };
    // (host, no certificate, a certificate of the CA, a certificate of another CA)
    let expected = [
        ("request.test", 200, 200, 200),
        ("require.test", 403, 200, 200),
        ("verify.test", 200, 200, 403),
        ("strict.test", 403, 200, 403),
    ];
    for (host, none, valid, wrong) in expected {
        assert_eq!(
            status(host, None).await,
            none,
            "{host} without a certificate"
        );
        assert_eq!(
            status(host, Some(&alice)).await,
            valid,
            "{host} with the CA's certificate"
        );
        assert_eq!(
            status(host, Some(&stranger)).await,
            wrong,
            "{host} with another CA's"
        );
    }

    let invalid = [
        json!({"client_auth": "verify_if_given"}),
        json!({"client_auth": "require_and_verify"}),
        json!({"client_auth": "require", "client_ca_pem": ca.pem}),
        json!({"client_auth": "request", "pass_client_cert": true}),
    ];
    for (version, tls) in (2_u64..).zip(&invalid) {
        let pushed = snapshot(version, &[with_tls("bad", &["bad.test"], &upstream, tls)]);
        let response = podgate.push_snapshot(&pushed).await;
        assert_eq!(response.status, 422, "{tls}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_client_auth",
            "{tls}"
        );
    }
}

/// `known.a.test` has its own certificate, `*.a.test` is strict, `*.b.test` is not.
struct Strict {
    podgate: Podgate,
    known: TestCert,
    default: TestCert,
    upstream: Upstream,
}

fn default_entry(cert: &TestCert) -> Value {
    json!({"hosts": [], "cert_pem": cert.cert_pem, "key_pem": cert.key_pem, "default": true})
}

async fn start_strict(with_default: bool) -> Strict {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("body").await;
    let known = TestCert::new(&["known.a.test"]);
    let default = TestCert::new(&["other.a.test", "other.b.test", "nobody.test", "127.0.0.1"]);
    let apps = [
        with_tls(
            "strict",
            &["*.a.test"],
            &upstream,
            &json!({"sni_strict": true}),
        ),
        with_tls("lenient", &["*.b.test"], &upstream, &json!({})),
    ];
    let mut pushed = snapshot(1, &apps);
    let mut certificates = vec![known.entry(&["known.a.test"])];
    if with_default {
        certificates.push(default_entry(&default));
    }
    pushed["certificates"] = Value::Array(certificates);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    Strict {
        podgate,
        known,
        default,
        upstream,
    }
}

impl Strict {
    async fn cert_for(&self, name: ServerName<'static>) -> io::Result<Vec<u8>> {
        let config = client_config(&[&self.known, &self.default], both(), None, &[], None);
        served_cert(&self.podgate, config, name).await
    }
}

#[tokio::test]
async fn tls_sni_strict_refuses_unknown_sni() {
    let fx = start_strict(true).await;
    assert_eq!(
        fx.cert_for(dns("known.a.test")).await.expect("known name"),
        fx.known.der.as_ref(),
        "a name with its own certificate gets it"
    );
    fx.cert_for(dns("other.a.test"))
        .await
        .expect_err("a strict app's name without a certificate fails, default certificate or not");
    assert_eq!(
        fx.cert_for(dns("other.b.test")).await.expect("lenient app"),
        fx.default.der.as_ref(),
        "a lenient app's name gets the default certificate"
    );
}

#[tokio::test]
async fn tls_default_certificate_for_unknown_sni() {
    let fx = start_strict(false).await;
    fx.cert_for(dns("other.b.test"))
        .await
        .expect_err("no default certificate: the handshake fails as before");

    let mut pushed = snapshot(
        2,
        &[with_tls("lenient", &["*.b.test"], &fx.upstream, &json!({}))],
    );
    pushed["certificates"] = json!([default_entry(&fx.default)]);
    let response = fx.podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    for name in [dns("other.b.test"), dns("nobody.test")] {
        assert_eq!(
            fx.cert_for(name.clone())
                .await
                .expect("default certificate"),
            fx.default.der.as_ref(),
            "{name:?}"
        );
    }
    let no_sni = ServerName::try_from("127.0.0.1").expect("an IP address sends no SNI");
    assert_eq!(
        fx.cert_for(no_sni).await.expect("no SNI"),
        fx.default.der.as_ref()
    );

    let mut twice = snapshot(
        3,
        &[with_tls("lenient", &["*.b.test"], &fx.upstream, &json!({}))],
    );
    twice["certificates"] = json!([default_entry(&fx.default), default_entry(&fx.known)]);
    let response = fx.podgate.push_snapshot(&twice).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "invalid_certificate"
    );
}

#[tokio::test]
async fn tls_options_conflict_between_apps_same_host() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let pinned = with_tls(
        "pinned",
        &["x.a.test"],
        &upstream,
        &json!({"min_version": "1.3"}),
    );
    let wide = with_tls("wide", &["*.a.test"], &upstream, &json!({}));
    let response = podgate.push_snapshot(&snapshot(1, &[pinned, wide])).await;
    assert_eq!(response.status, 422, "{response:?}");
    let conflict = &response.json()["conflicts"][0];
    assert_eq!(conflict["code"], "tls_policy_conflict");
    assert_eq!(
        conflict["declared_by"],
        json!(["tests/pinned", "tests/wide"])
    );

    let same = json!({"min_version": "1.3"});
    let pinned = with_tls("pinned", &["x.a.test"], &upstream, &same);
    let wide = with_tls("wide", &["*.a.test"], &upstream, &same);
    let response = podgate.push_snapshot(&snapshot(2, &[pinned, wide])).await;
    assert_eq!(
        response.status, 200,
        "apps that agree share a host: {response:?}"
    );
}

#[tokio::test]
async fn plan_lists_tls_option_weakening() {
    let podgate = Podgate::start().await;
    let upstream = Upstream::start("x").await;
    let ca = TestCa::new("ca").pem;
    let apps = |tls: [Value; 5]| -> Vec<Value> {
        ["min", "suites", "strict", "auth", "tight"]
            .iter()
            .zip(tls)
            .map(|(name, tls)| {
                let host = format!("{name}.test");
                with_tls(name, &[host.as_str()], &upstream, &tls)
            })
            .collect()
    };
    let aes256 = "TLS13_AES_256_GCM_SHA384";
    let live = apps([
        json!({"min_version": "1.3"}),
        json!({"cipher_suites": [aes256]}),
        json!({"sni_strict": true}),
        json!({"client_auth": "require_and_verify", "client_ca_pem": ca}),
        json!({}),
    ]);
    assert_eq!(podgate.push_snapshot(&snapshot(1, &live)).await.status, 200);

    let candidate = apps([
        json!({}),
        json!({"cipher_suites": [aes256, "TLS13_AES_128_GCM_SHA256"]}),
        json!({}),
        json!({"client_auth": "verify_if_given", "client_ca_pem": ca}),
        json!({"min_version": "1.3", "sni_strict": true}),
    ]);
    let response = podgate
        .admin_post("/v1/snapshot/plan", &snapshot(2, &candidate))
        .await;
    assert_eq!(response.status, 200, "{response:?}");
    let listed: Vec<(String, String)> = response.json()["posture_changes"]
        .as_array()
        .expect("posture_changes")
        .iter()
        .map(|change| {
            (
                change["host"].as_str().expect("host").to_owned(),
                change["kind"].as_str().expect("kind").to_owned(),
            )
        })
        .collect();
    let expected = [
        ("auth.test", "client_auth_relaxed"),
        ("min.test", "tls_min_version_lowered"),
        ("strict.test", "sni_strict_disabled"),
        ("suites.test", "tls_cipher_suites_widened"),
    ];
    assert_eq!(
        listed,
        expected.map(|(host, kind)| (host.to_owned(), kind.to_owned())),
        "tightening `tight.test` is not listed"
    );
}

#[tokio::test]
async fn tls_floor_13_applies_to_every_app() {
    let podgate = Podgate::start_with_env(&[("TLS_MIN_VERSION", "1.3")]).await;
    let upstream = Upstream::start("body").await;
    let server = TestCert::new(&["a.test"]);
    let mut pushed = snapshot(1, &[with_tls("a", &["a.test"], &upstream, &json!({}))]);
    pushed["certificates"] = json!([server.entry(&["a.test"])]);
    assert_eq!(podgate.push_snapshot(&pushed).await.status, 200);

    let get = |versions| {
        let config = plain_client(&server, versions);
        podgate.try_https_get(config, "a.test", "a.test", "/")
    };
    let served = get(tls13()).await.expect("TLS 1.3 is served");
    assert_eq!((served.status, served.body.as_str()), (200, "body"));
    get(tls12())
        .await
        .expect_err("an app with no options still gets the process floor");

    let low = with_tls("a", &["a.test"], &upstream, &json!({"min_version": "1.2"}));
    let response = podgate.push_snapshot(&snapshot(2, &[low])).await;
    assert_eq!(response.status, 422, "{response:?}");
    assert_eq!(
        response.json()["conflicts"][0]["code"],
        "unsupported_setting"
    );
}
