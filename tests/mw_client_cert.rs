//! The `pass_tls_client_cert` middleware: the verified client certificate, or fields
//! of it, reach the upstream in Traefik's headers, and nothing a client sends in those headers
//! ever does.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{
    Podgate, Response, TestCa, TestCert, TestClient, app, serving, snapshot, with_middleware,
};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const FORGED: &[(&str, &str)] = &[
    ("X-Forwarded-Tls-Client-Cert", "FORGED"),
    ("X-Forwarded-Tls-Client-Cert-Info", "FORGED"),
    ("X-Forwarded-Tls-Client-Cert-Subject", "FORGED"),
    ("x_forwarded_tls_client_cert", "FORGED"),
    ("X_Forwarded_Tls_Client_Cert_Info", "FORGED"),
];

/// A backend that answers with the head of the request it got as the body.
async fn echo_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&chunk[..read]),
                    }
                }
                let body = String::from_utf8_lossy(&head).into_owned();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    addr
}

/// The values of the request header `name` in the echoed head, case-insensitively.
fn values(echoed: &str, name: &str) -> Vec<String> {
    echoed
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(got, _)| got.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

fn value(echoed: &str, name: &str) -> Option<String> {
    let mut all = values(echoed, name);
    assert!(all.len() <= 1, "{name} sent twice: {all:?}");
    all.pop()
}

/// No header of the reserved family, in any spelling, and none of the forged values.
fn assert_clean(echoed: &str) {
    let lower = echoed.to_ascii_lowercase();
    assert!(
        !lower.contains("x-forwarded-tls-client-cert") && !lower.contains("x_forwarded_tls"),
        "a certificate header reached the upstream: {echoed}"
    );
    assert!(!echoed.contains("FORGED"), "forged value: {echoed}");
}

fn client_config(server: &TestCert, client: Option<&TestClient>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(server.der.clone()).expect("trust the server");
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("protocol versions")
        .with_root_certificates(roots);
    Arc::new(match client {
        Some(client) => builder
            .with_client_auth_cert(client.chain.clone(), client.key.clone_key())
            .expect("client certificate"),
        None => builder.with_no_client_auth(),
    })
}

/// An app on `host` that verifies client certificates against `ca` when sent, with the
/// `pass_tls_client_cert` middleware `config` if any.
fn mtls_app(host: &str, echo: SocketAddr, ca: &TestCa, config: Option<Value>) -> Value {
    let mut built = app(host, &[host], &[serving("r1", echo)]);
    built["tls"]["client_ca_pem"] = json!(ca.pem);
    built["tls"]["client_auth"] = json!("verify_if_given");
    match config {
        Some(config) => with_middleware(built, "cert", "pass_tls_client_cert", config),
        None => built,
    }
}

async fn push(podgate: &Podgate, server: &TestCert, hosts: &[&str], apps: &[Value]) {
    let mut pushed = snapshot(1, apps);
    pushed["certificates"] = json!([server.entry(hosts)]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
}

async fn https(
    podgate: &Podgate,
    server: &TestCert,
    client: Option<&TestClient>,
    host: &str,
    headers: &[(&str, &str)],
) -> Response {
    let response = podgate
        .try_https_get_with_headers(client_config(server, client), host, host, "/", headers)
        .await
        .expect("handshake and response");
    assert_eq!(response.status, 200, "{response:?}");
    response
}

/// The certificate every field test uses: all the fields Traefik can pass, with fixed values.
fn alice(ca: &TestCa) -> TestClient {
    use rcgen::string::Ia5String;
    use rcgen::{DnType, SanType};
    ca.client_with(|params| {
        let name = &mut params.distinguished_name;
        name.push(DnType::CountryName, "DE");
        name.push(DnType::StateOrProvinceName, "Bavaria");
        name.push(DnType::LocalityName, "Munich");
        name.push(DnType::OrganizationName, "Acme GmbH");
        name.push(DnType::OrganizationalUnitName, "Eng");
        name.push(DnType::CommonName, "alice");
        name.push(DnType::CustomDnType(vec![2, 5, 4, 5]), "42");
        name.push(
            DnType::CustomDnType(vec![0, 9, 2342, 19_200_300, 100, 1, 25]),
            "example",
        );
        params.subject_alt_names = vec![
            SanType::DnsName(Ia5String::try_from("alice.example.com").expect("dns")),
            SanType::Rfc822Name(Ia5String::try_from("alice@example.com").expect("mail")),
            SanType::IpAddress("10.0.0.1".parse().expect("ip")),
            SanType::URI(Ia5String::try_from("spiffe://x/y").expect("uri")),
        ];
        params.serial_number = Some(rcgen::SerialNumber::from(1_234_567_890_u64));
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
    })
}

const ALICE_ALL_FIELDS: &str = "Subject%3D%22DC%3Dexample%2CC%3DDE%2CST%3DBavaria%2CL%3DMunich%2CO%3DAcme+GmbH%2COU%3DEng%2CSN%3D42%2CCN%3Dalice%22\
%3BIssuer%3D%22CN%3Dtrusted+ca%22%3BSerialNumber%3D%221234567890%22%3BNB%3D%221577836800%22%3BNA%3D%222208988800%22\
%3BSAN%3D%22alice.example.com%2Calice%40example.com%2C10.0.0.1%2Cspiffe%3A%2F%2Fx%2Fy%22";

#[tokio::test]
async fn client_cert_pem_header() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (TestCert::new(&["pem.test"]), TestCa::new("trusted ca"));
    push(
        &podgate,
        &server,
        &["pem.test"],
        &[mtls_app(
            "pem.test",
            echo,
            &ca,
            Some(json!({ "pem": true })),
        )],
    )
    .await;
    let alice = alice(&ca);

    let echoed = https(&podgate, &server, Some(&alice), "pem.test", &[])
        .await
        .body;
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert"),
        Some(STANDARD.encode(&alice.chain[0])),
        "the base64 DER of the leaf, no armor, nothing escaped: {echoed}"
    );
    assert_eq!(value(&echoed, "x-forwarded-tls-client-cert-info"), None);
}

#[tokio::test]
async fn client_cert_info_header_format() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (TestCert::new(&["info.test"]), TestCa::new("trusted ca"));
    let config = json!({ "info": {
        "not_after": true, "not_before": true, "sans": true, "serial_number": true,
        "subject": { "country": true, "province": true, "locality": true, "organization": true,
            "organizational_unit": true, "common_name": true, "serial_number": true,
            "domain_component": true },
        "issuer": { "common_name": true },
    } });
    push(
        &podgate,
        &server,
        &["info.test"],
        &[mtls_app("info.test", echo, &ca, Some(config))],
    )
    .await;

    let echoed = https(&podgate, &server, Some(&alice(&ca)), "info.test", &[])
        .await
        .body;
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert-info").as_deref(),
        Some(ALICE_ALL_FIELDS),
        "{echoed}"
    );
    assert_eq!(value(&echoed, "x-forwarded-tls-client-cert"), None);
}

#[tokio::test]
async fn client_cert_headers_stripped_without_middleware() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (TestCert::new(&["without.test"]), TestCa::new("trusted ca"));
    let plain = app("plain.test", &["plain.test"], &[serving("r1", echo)]);
    push(
        &podgate,
        &server,
        &["without.test"],
        &[mtls_app("without.test", echo, &ca, None), plain],
    )
    .await;

    let with_cert = https(&podgate, &server, Some(&alice(&ca)), "without.test", FORGED).await;
    assert_clean(&with_cert.body);
    let without_cert = https(&podgate, &server, None, "without.test", FORGED).await;
    assert_clean(&without_cert.body);
    assert_clean(
        &podgate
            .get_with_headers("plain.test", "/", FORGED)
            .await
            .body,
    );
    assert_clean(
        &podgate
            .get_with_headers("without.test", "/", FORGED)
            .await
            .body,
    );
}

#[tokio::test]
async fn client_cert_headers_overwritten_with_middleware() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (
        TestCert::new(&["both.test", "pemonly.test"]),
        TestCa::new("trusted ca"),
    );
    let all = json!({ "pem": true, "info": { "subject": { "common_name": true } } });
    push(
        &podgate,
        &server,
        &["both.test", "pemonly.test"],
        &[
            mtls_app("both.test", echo, &ca, Some(all)),
            mtls_app("pemonly.test", echo, &ca, Some(json!({ "pem": true }))),
        ],
    )
    .await;
    let alice = alice(&ca);

    let echoed = https(&podgate, &server, Some(&alice), "both.test", FORGED)
        .await
        .body;
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert"),
        Some(STANDARD.encode(&alice.chain[0])),
        "{echoed}"
    );
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert-info").as_deref(),
        Some("Subject%3D%22CN%3Dalice%22"),
        "{echoed}"
    );
    assert!(!echoed.contains("FORGED"), "{echoed}");
    assert_eq!(
        values(&echoed.to_ascii_lowercase(), "x_forwarded_tls_client_cert"),
        Vec::<String>::new()
    );

    let echoed = https(&podgate, &server, Some(&alice), "pemonly.test", FORGED)
        .await
        .body;
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert"),
        Some(STANDARD.encode(&alice.chain[0]))
    );
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert-info"),
        None,
        "the header this route's middleware does not set is stripped too: {echoed}"
    );
    assert!(!echoed.contains("FORGED"), "{echoed}");
}

#[tokio::test]
async fn client_cert_absent_sets_nothing() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (TestCert::new(&["opt.test"]), TestCa::new("trusted ca"));
    let all = json!({ "pem": true, "info": { "subject": { "common_name": true } } });
    push(
        &podgate,
        &server,
        &["opt.test"],
        &[mtls_app("opt.test", echo, &ca, Some(all))],
    )
    .await;

    let no_cert = https(&podgate, &server, None, "opt.test", FORGED).await;
    assert_clean(&no_cert.body);
    let plain_http = podgate.get_with_headers("opt.test", "/", FORGED).await;
    assert_eq!(plain_http.status, 200, "{plain_http:?}");
    assert_clean(&plain_http.body);
}

#[tokio::test]
async fn client_cert_from_another_apps_handshake_is_never_passed() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let server = TestCert::new(&["a.test", "b.test"]);
    let (ca_a, ca_b) = (TestCa::new("ca a"), TestCa::new("ca b"));
    let a = mtls_app("a.test", echo, &ca_a, None);
    let mut b = mtls_app("b.test", echo, &ca_b, Some(json!({ "pem": true })));
    b["allow_domain_fronting"] = json!(true);
    push(&podgate, &server, &["a.test", "b.test"], &[a, b]).await;
    let from_a = ca_a.client("alice");

    let fronted = podgate
        .try_https_get(
            client_config(&server, Some(&from_a)),
            "a.test",
            "b.test",
            "/",
        )
        .await
        .expect("handshake and response");
    assert_eq!(
        fronted.status, 403,
        "b's CA never accepted a certificate a's CA signed: {fronted:?}"
    );
    assert_clean(&fronted.body);
    let own = https(&podgate, &server, Some(&from_a), "a.test", &[]).await;
    assert_clean(&own.body);
}

#[tokio::test]
async fn client_cert_info_field_selection() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let hosts = ["cn.test", "san.test", "serial.test", "empty.test"];
    let (server, ca) = (TestCert::new(&hosts), TestCa::new("trusted ca"));
    let selections = [
        (
            "cn.test",
            json!({ "info": { "subject": { "common_name": true } } }),
        ),
        (
            "san.test",
            json!({ "info": { "sans": true, "issuer": { "common_name": true } } }),
        ),
        (
            "serial.test",
            json!({ "info": { "serial_number": true, "not_before": true } }),
        ),
        (
            "empty.test",
            json!({ "info": { "subject": { "country": true } } }),
        ),
    ];
    let apps: Vec<Value> = selections
        .iter()
        .map(|(host, config)| mtls_app(host, echo, &ca, Some(config.clone())))
        .collect();
    push(&podgate, &server, &hosts, &apps).await;
    let alice = alice(&ca);

    async fn info(
        podgate: &Podgate,
        server: &TestCert,
        host: &str,
        client: &TestClient,
    ) -> Option<String> {
        let echoed = https(podgate, server, Some(client), host, &[]).await.body;
        value(&echoed, "x-forwarded-tls-client-cert-info")
    }
    assert_eq!(
        info(&podgate, &server, "cn.test", &alice).await.as_deref(),
        Some("Subject%3D%22CN%3Dalice%22")
    );
    assert_eq!(
        info(&podgate, &server, "san.test", &alice).await.as_deref(),
        Some(
            "Issuer%3D%22CN%3Dtrusted+ca%22%3BSAN%3D%22alice.example.com%2Calice%40example.com%2C10.0.0.1%2Cspiffe%3A%2F%2Fx%2Fy%22"
        )
    );
    assert_eq!(
        info(&podgate, &server, "serial.test", &alice)
            .await
            .as_deref(),
        Some("SerialNumber%3D%221234567890%22%3BNB%3D%221577836800%22")
    );
    let bob = ca.client("bob");
    assert_eq!(
        info(&podgate, &server, "empty.test", &bob).await,
        None,
        "a selected part the certificate lacks sends no field, and no header when nothing is left"
    );
}

#[tokio::test]
async fn client_cert_oversized_chain_omitted() {
    use rcgen::string::Ia5String;
    use rcgen::{DnType, SanType};

    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let (server, ca) = (TestCert::new(&["big.test"]), TestCa::new("trusted ca"));
    let config = json!({ "pem": true, "info": { "subject": { "common_name": true } } });
    push(
        &podgate,
        &server,
        &["big.test"],
        &[mtls_app("big.test", echo, &ca, Some(config))],
    )
    .await;
    let big = ca.client_with(|params| {
        params.distinguished_name.push(DnType::CommonName, "big");
        params.subject_alt_names = (0..600)
            .map(|index| {
                let name = format!("host-{index:04}.example.test");
                SanType::DnsName(Ia5String::try_from(name).expect("dns"))
            })
            .collect();
    });
    assert!(
        STANDARD.encode(&big.chain[0]).len() > 8 * 1024,
        "the test certificate must exceed the cap"
    );

    let echoed = https(&podgate, &server, Some(&big), "big.test", FORGED)
        .await
        .body;
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert"),
        None,
        "an oversized chain is omitted, not cut: {echoed}"
    );
    assert!(!echoed.contains("FORGED"), "{echoed}");
    assert_eq!(
        value(&echoed, "x-forwarded-tls-client-cert-info").as_deref(),
        Some("Subject%3D%22CN%3Dbig%22"),
        "the info header is still sent"
    );
    let metrics = podgate.admin_get("/metrics").await.body;
    assert!(
        metrics.contains("podgate_client_cert_header_omitted_total{header=\"pem\"} 1\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("podgate_client_cert_header_omitted_total{header=\"info\"} 0\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn client_cert_middleware_needs_an_app_that_verifies() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let ca = TestCa::new("trusted ca");
    let unverified = |tls: Value| {
        let mut built = app("x.test", &["x.test"], &[serving("r1", echo)]);
        for (key, value) in tls.as_object().expect("object") {
            built["tls"][key] = value.clone();
        }
        with_middleware(
            built,
            "cert",
            "pass_tls_client_cert",
            json!({ "pem": true }),
        )
    };
    for (version, tls) in (1_u64..).zip([
        json!({}),
        json!({ "client_auth": "request" }),
        json!({ "client_auth": "require" }),
    ]) {
        let response = podgate
            .push_snapshot(&snapshot(version, &[unverified(tls.clone())]))
            .await;
        assert_eq!(response.status, 422, "{tls}: {response:?}");
        assert_eq!(
            response.json()["conflicts"][0]["code"],
            "invalid_middleware",
            "{tls}: {response:?}"
        );
    }
    let ok = unverified(json!({ "client_ca_pem": ca.pem }));
    assert_eq!(
        podgate.push_snapshot(&snapshot(10, &[ok])).await.status,
        200
    );
}

#[tokio::test]
async fn pass_client_cert_field_rejected_with_pointer() {
    let podgate = Podgate::start().await;
    let echo = echo_upstream().await;
    let ca = TestCa::new("trusted ca");
    let with_field = |value: Value| {
        let mut built = mtls_app("old.test", echo, &ca, None);
        built["tls"]["pass_client_cert"] = value;
        built
    };

    let rejected = podgate
        .push_snapshot(&snapshot(1, &[with_field(json!(true))]))
        .await;
    assert_eq!(rejected.status, 422, "{rejected:?}");
    let conflict = &rejected.json()["conflicts"][0];
    assert_eq!(conflict["code"], "unsupported_setting", "{rejected:?}");
    let message = conflict["message"].as_str().expect("message");
    assert!(
        message.contains("tls.pass_client_cert") && message.contains("pass_tls_client_cert"),
        "the message names the field and its replacement: {message}"
    );

    for (version, value) in (2_u64..).zip([json!(false), Value::Null]) {
        let accepted = podgate
            .push_snapshot(&snapshot(version, &[with_field(value.clone())]))
            .await;
        assert_eq!(accepted.status, 200, "{value}: {accepted:?}");
    }
}
