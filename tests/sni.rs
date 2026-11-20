//! The SNI of a TLS connection must match the host its requests name.

mod common;

use std::sync::Arc;

use common::{Podgate, TestCert, Upstream, app, serving, snapshot};
use http::Request;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const MISDIRECTED: &str = r#"{"error":"misdirected request"}"#;

/// Apps `a.test` and `b.test` with their own upstreams and one certificate valid for both, so
/// a client can complete a handshake for either name. `allow_b` sets `allow_domain_fronting`
/// on `b.test`.
async fn start(allow_b: bool) -> (Podgate, TestCert, [Upstream; 2]) {
    let podgate = Podgate::start().await;
    let upstreams = [
        Upstream::start("body a").await,
        Upstream::start("body b").await,
    ];
    let cert = TestCert::new(&["a.test", "b.test"]);
    let a = app("a", &["a.test"], &[serving("r1", upstreams[0].addr)]);
    let mut b = app("b", &["b.test"], &[serving("r1", upstreams[1].addr)]);
    if allow_b {
        b["allow_domain_fronting"] = Value::Bool(true);
    }
    let mut pushed = snapshot(1, &[a, b]);
    pushed["certificates"] = json!([cert.entry(&["a.test", "b.test"])]);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{response:?}");
    (podgate, cert, upstreams)
}

#[tokio::test]
async fn sni_mismatch_is_421() {
    let (podgate, cert, _upstreams) = start(false).await;

    let response = podgate.https_get("a.test", "b.test", "/", &cert).await;
    assert_eq!(response.status, 421, "{response:?}");
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.body, MISDIRECTED);

    let unknown = podgate.https_get("a.test", "nope.test", "/", &cert).await;
    assert_eq!(
        unknown.status, 421,
        "an unknown host must not reveal a 404: {unknown:?}"
    );
}

#[tokio::test]
async fn sni_match_served() {
    let (podgate, cert, _upstreams) = start(false).await;

    let response = podgate.https_get("a.test", "a.test", "/", &cert).await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "body a");

    let cased = podgate.https_get("b.test", "B.Test:8443", "/", &cert).await;
    assert_eq!(
        cased.status, 200,
        "case and port do not make a mismatch: {cased:?}"
    );
    assert_eq!(cased.body, "body b");
}

#[tokio::test]
async fn sni_plain_http_is_not_checked() {
    let (podgate, _cert, _upstreams) = start(false).await;

    let response = podgate.get("b.test", "/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(response.body, "body b");
}

#[tokio::test]
async fn sni_domain_fronting_opt_in() {
    let (podgate, cert, _upstreams) = start(true).await;

    let fronted = podgate.https_get("a.test", "b.test", "/", &cert).await;
    assert_eq!(fronted.status, 200, "b.test opted in: {fronted:?}");
    assert_eq!(fronted.body, "body b");

    let refused = podgate.https_get("b.test", "a.test", "/", &cert).await;
    assert_eq!(refused.status, 421, "a.test did not opt in: {refused:?}");
}

/// An HTTP/2 request on a TLS connection, with `scheme` and `authority` as the client states
/// them. Returns the status and body.
async fn h2_get(
    podgate: &Podgate,
    cert: &TestCert,
    sni: &str,
    scheme: &str,
    authority: &str,
) -> (u16, String) {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert.der.clone())
        .expect("trust the test certificate");
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(sni.to_owned()).expect("server name");
    let tcp = TcpStream::connect(podgate.tls_addr).await.expect("connect");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .expect("handshake");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "h2 negotiated"
    );

    let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(connection);
    let request = Request::get(format!("{scheme}://{authority}/"))
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send request");
    let response = response.await.expect("response");
    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut text = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        body.flow_control()
            .release_capacity(chunk.len())
            .expect("release capacity");
        text.extend_from_slice(&chunk);
    }
    (status, String::from_utf8(text).expect("utf-8 body"))
}

#[tokio::test]
async fn sni_h2_scheme_http() {
    let (podgate, cert, _upstreams) = start(false).await;

    let (status, body) = Box::pin(h2_get(&podgate, &cert, "a.test", "http", "b.test")).await;
    assert_eq!(status, 421, ":scheme http must not skip the check");
    assert_eq!(body, MISDIRECTED);

    let (status, body) = Box::pin(h2_get(&podgate, &cert, "a.test", "https", "b.test")).await;
    assert_eq!(status, 421);
    assert_eq!(body, MISDIRECTED);

    let (status, body) = Box::pin(h2_get(&podgate, &cert, "a.test", "http", "a.test")).await;
    assert_eq!((status, body.as_str()), (200, "body a"));
}
