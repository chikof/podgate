//! The listener's pre-TLS hook: reads the ClientHello before the handshake starts, but only
//! when something needs it.
//!
//! Three things do. On-demand TLS waits for a certificate of the SNI ([`crate::acme`]), a TLS
//! policy closes a connection whose hello offers no version, suite or ALPN protocol
//! the app of that SNI allows (see [`super::options`]), and while the snapshot holds a pending
//! TLS-ALPN-01 challenge a hello that offers only `acme-tls/1` is answered here,
//! because the listener's ALPN list cannot carry that protocol. With none of them configured
//! the hook reads nothing, so hosts without options or challenges pay nothing.
//!
//! The hook reads the ClientHello (rustls' `Acceptor` parses it, so no TLS parsing lives here),
//! then puts every byte back with `Stream::rewind` so the handshake sees the connection
//! untouched. It never closes a connection it could not read or parse: the handshake decides,
//! and the request check of [`super::options::enforce`] is the authority either way.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use pingora::listeners::PreTlsProcess;
use pingora::protocols::l4::stream::Stream;
use pingora::{Error, ErrorType};
use rustls::CipherSuite;
use rustls::server::Acceptor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::options::Violation;
use crate::acme::{Acme, alpn01};
use crate::host;
use crate::table::TableHandle;

/// Longest a client may take to send its ClientHello before the hook gives up reading it.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// A ClientHello larger than a TLS record cannot be one.
const MAX_HELLO: usize = 17 * 1024;
/// Longest the hook waits to write the alert that tells a refused client why.
const ALERT_TIMEOUT: Duration = Duration::from_secs(1);

/// What the hook needs from a ClientHello.
#[derive(Debug, Default)]
pub(crate) struct Hello {
    /// The SNI as sent.
    pub(crate) server_name: Option<String>,
    /// Whether its `supported_versions` offer TLS 1.3 (a hello without the extension offers at
    /// most TLS 1.2); `None` when the hello is not in one record. The suites cannot tell: a
    /// client that only enables TLS 1.2 still lists the TLS 1.3 suites of its provider.
    pub(crate) offers_tls13: Option<bool>,
    /// The cipher suites the client offers.
    pub(crate) suites: Vec<CipherSuite>,
    /// The ALPN protocols the client offers; empty when it sends none.
    pub(crate) alpn: Vec<Vec<u8>>,
}

/// The pre-TLS hook of the TLS listeners: on-demand certificate waits and TLS policy refusals,
/// both from one read of the ClientHello.
#[derive(Debug, Clone)]
pub struct PreHandshake {
    acme: Acme,
    table: TableHandle,
    reads: Arc<AtomicU64>,
}

impl PreHandshake {
    /// The hook for listeners serving the table behind `table`; `acme` waits for on-demand
    /// certificates.
    #[must_use]
    pub fn new(acme: Acme, table: TableHandle) -> Self {
        Self {
            acme,
            table,
            reads: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many ClientHellos this hook (and its clones) has read.
    #[must_use]
    pub fn hello_reads(&self) -> u64 {
        self.reads.load(Ordering::Relaxed)
    }

    /// Why the connection of `hello` can never be served, when every app that may serve its SNI
    /// has a policy it cannot satisfy. An app without a policy, or no app at all, leaves the
    /// decision to the handshake.
    fn violation(&self, hello: &Hello) -> Option<Violation> {
        let name = host::normalize(hello.server_name.as_deref()?);
        let table = self.table.load();
        let mut first = None;
        for app in table.may_serve(&name) {
            let violation = app.tls_options()?.hello_violation(hello)?;
            first.get_or_insert(violation);
        }
        first
    }
}

#[async_trait]
impl PreTlsProcess for PreHandshake {
    async fn process(&self, stream: &mut Stream) -> pingora::Result<()> {
        {
            let table = self.table.load();
            let acme = table.acme();
            if !acme.on_demand_enabled() && !table.tls_hello_policy() && !acme.alpn_pending() {
                return Ok(());
            }
        }
        self.reads.fetch_add(1, Ordering::Relaxed);
        let Some(hello) = peek(stream).await else {
            return Ok(());
        };
        if hello.alpn == [alpn01::PROTOCOL] {
            return Err(self
                .acme
                .answer_alpn01(stream, hello.server_name.as_deref())
                .await);
        }
        if let Some(violation) = self.violation(&hello) {
            // Best effort: the client learns why, but the refusal does not depend on it.
            let _ = timeout(ALERT_TIMEOUT, stream.write_all(&violation.alert())).await;
            return Err(Error::explain(
                ErrorType::TLSHandshakeFailure,
                "the ClientHello offers nothing the app's TLS options allow",
            ));
        }
        if let Some(name) = &hello.server_name {
            self.acme.await_certificate(&host::normalize(name)).await;
        }
        Ok(())
    }
}

/// The ClientHello of the connection; the stream is left as it was.
async fn peek(stream: &mut Stream) -> Option<Hello> {
    let mut seen = Vec::new();
    let hello = timeout(HELLO_TIMEOUT, read_hello(stream, &mut seen))
        .await
        .ok()
        .flatten();
    stream.rewind(&seen);
    hello
}

/// Reads records into `seen` until rustls has a whole ClientHello. `None` when the connection
/// ends, errors or sends something that is not a ClientHello.
async fn read_hello(stream: &mut Stream, seen: &mut Vec<u8>) -> Option<Hello> {
    let mut acceptor = Acceptor::default();
    let mut chunk = [0_u8; 2048];
    while seen.len() < MAX_HELLO {
        let read = stream
            .read(&mut chunk)
            .await
            .ok()
            .filter(|read| *read > 0)?;
        seen.extend_from_slice(&chunk[..read]);
        let mut rest = &chunk[..read];
        while !rest.is_empty() {
            acceptor.read_tls(&mut rest).ok().filter(|used| *used > 0)?;
            if let Some(accepted) = acceptor.accept().ok()? {
                let hello = accepted.client_hello();
                return Some(Hello {
                    offers_tls13: offers_tls13(seen),
                    server_name: hello.server_name().map(str::to_owned),
                    suites: hello.cipher_suites().to_vec(),
                    alpn: hello
                        .alpn()
                        .map(|protocols| protocols.map(<[u8]>::to_vec).collect())
                        .unwrap_or_default(),
                });
            }
        }
    }
    None
}

/// Whether the ClientHello at the start of `bytes` offers TLS 1.3 in `supported_versions`; `None`
/// when it does not parse as one whole record, in which case nothing is concluded from it.
fn offers_tls13(bytes: &[u8]) -> Option<bool> {
    const HANDSHAKE: u8 = 22;
    const CLIENT_HELLO: u8 = 1;
    const SUPPORTED_VERSIONS: u16 = 43;
    const TLS13: u16 = 0x0304;

    let mut record = Reader(bytes);
    (record.u8()? == HANDSHAKE).then_some(())?;
    record.skip(2)?;
    let length = record.u16()?;
    let mut message = Reader(record.take(length.into())?);
    (message.u8()? == CLIENT_HELLO).then_some(())?;
    let length = message.u24()?;
    let mut hello = Reader(message.take(length)?);
    hello.skip(2 + 32)?;
    let session_id = hello.u8()?;
    hello.skip(session_id.into())?;
    let suites = hello.u16()?;
    hello.skip(suites.into())?;
    let compression = hello.u8()?;
    hello.skip(compression.into())?;
    let length = hello.u16()?;
    let mut extensions = Reader(hello.take(length.into())?);
    while !extensions.is_empty() {
        let kind = extensions.u16()?;
        let length = extensions.u16()?;
        let data = extensions.take(length.into())?;
        if kind == SUPPORTED_VERSIONS {
            let mut data = Reader(data);
            let length = data.u8()?;
            let mut versions = Reader(data.take(length.into())?);
            while !versions.is_empty() {
                if versions.u16()? == TLS13 {
                    return Some(true);
                }
            }
            return Some(false);
        }
    }
    Some(false)
}

/// A cursor over big-endian TLS wire data; every read fails with `None` at the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(count)?;
        self.0 = rest;
        Some(head)
    }

    fn skip(&mut self, count: usize) -> Option<()> {
        self.take(count).map(drop)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u24(&mut self) -> Option<usize> {
        let [a, b, c] = *self.take(3)? else {
            return None;
        };
        Some(usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::ServerName;
    use rustls::version::{TLS12, TLS13};
    use rustls::{ClientConfig, ClientConnection, RootCertStore};
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::events::EventFeed;
    use podgate_model::Snapshot;

    fn hook(tls: &serde_json::Value) -> PreHandshake {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "tls": tls,
                "routers": [{"name": "all", "match": {"host": ["a.test"]}, "service": "web"}],
                "revisions": [{"id": "r1", "weight": 100, "state": "serving", "services": [
                    {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:1"}]}]}],
            }],
        }))
        .expect("valid snapshot");
        let table = TableHandle::new();
        table.apply(&snapshot).expect("compiles");
        PreHandshake::new(
            Acme::new(table.clone(), EventFeed::new(), None, None),
            table,
        )
    }

    /// The first flight of a client for `a.test` that offers only `version`.
    fn client_hello(version: &'static rustls::SupportedProtocolVersion) -> Vec<u8> {
        let config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[version])
            .expect("protocol versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("a.test").expect("server name"),
        )
        .expect("client connection");
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).expect("write hello");
        bytes
    }

    /// A connection whose client has sent `bytes`: the server side as a Pingora stream, and the
    /// client side.
    async fn connected(bytes: &[u8]) -> (Stream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let mut client = TcpStream::connect(listener.local_addr().expect("addr"))
            .await
            .expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        client.write_all(bytes).await.expect("send hello");
        (Stream::from(server), client)
    }

    #[test]
    fn the_supported_versions_extension_says_whether_tls13_is_offered() {
        assert_eq!(offers_tls13(&client_hello(&TLS13)), Some(true));
        assert_eq!(offers_tls13(&client_hello(&TLS12)), Some(false));
        let hello = client_hello(&TLS13);
        assert_eq!(offers_tls13(&hello[..hello.len() - 1]), None, "truncated");
        assert_eq!(offers_tls13(b"GET / HTTP/1.1\r\n\r\n"), None, "not TLS");
    }

    #[tokio::test]
    async fn tls_no_options_no_hello_read() {
        let hello = client_hello(&TLS13);
        let plain = hook(&json!({"mode": "acme"}));
        let (mut stream, _client) = connected(&hello).await;
        plain.process(&mut stream).await.expect("passes");
        assert_eq!(plain.hello_reads(), 0, "nothing asked for the hello");

        let sni_only = hook(&json!({"mode": "acme", "sni_strict": true}));
        let (mut stream, _client) = connected(&hello).await;
        sni_only.process(&mut stream).await.expect("passes");
        assert_eq!(
            sni_only.hello_reads(),
            0,
            "strict SNI is decided by the resolver"
        );

        let pinned = hook(&json!({"mode": "acme", "min_version": "1.3"}));
        let (mut stream, _client) = connected(&hello).await;
        pinned.process(&mut stream).await.expect("TLS 1.3 passes");
        assert_eq!(pinned.hello_reads(), 1);
        let mut again = vec![0_u8; hello.len()];
        stream.read_exact(&mut again).await.expect("bytes put back");
        assert_eq!(again, hello, "the handshake sees the hello untouched");
    }

    #[tokio::test]
    async fn tls_min_version_13_closes_a_tls12_hello_with_an_alert() {
        let pinned = hook(&json!({"mode": "acme", "min_version": "1.3"}));
        let (mut stream, mut client) = connected(&client_hello(&TLS12)).await;
        pinned
            .process(&mut stream)
            .await
            .expect_err("a TLS 1.2 only client is refused");
        drop(stream);
        let mut alert = Vec::new();
        client
            .read_to_end(&mut alert)
            .await
            .expect("alert and close");
        assert_eq!(alert, [21, 3, 3, 0, 2, 2, 70], "fatal protocol_version");
    }

    /// A hook for a table whose one app proves `a.test` with TLS-ALPN-01 and whose snapshot
    /// holds the pushed `challenges`.
    fn alpn_hook(challenges: &serde_json::Value) -> PreHandshake {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "acme": {"issuer_node": "n1", "directory_url": "https://acme.test/dir", "challenges": challenges},
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test",
                "tls": {"mode": "acme", "challenge": "tls-alpn-01"},
                "routers": [{"name": "all", "match": {"host": ["a.test"]}, "service": "web"}],
                "revisions": [{"id": "r1", "weight": 100, "state": "serving", "services": [
                    {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:1"}]}]}],
            }],
        }))
        .expect("valid snapshot");
        let table = TableHandle::new();
        table.apply(&snapshot).expect("compiles");
        PreHandshake::new(
            Acme::new(table.clone(), EventFeed::new(), None, None),
            table,
        )
    }

    /// The first flight of a client for `a.test` that offers exactly `alpn`.
    fn client_hello_offering(alpn: &[&[u8]]) -> Vec<u8> {
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("a.test").expect("server name"),
        )
        .expect("client connection");
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).expect("write hello");
        bytes
    }

    #[tokio::test]
    async fn alpn01_hello_is_read_only_while_a_challenge_is_pending() {
        let hello = client_hello_offering(&[b"h2", b"http/1.1"]);

        let idle = alpn_hook(&json!([]));
        let (mut stream, _client) = connected(&hello).await;
        idle.process(&mut stream).await.expect("passes");
        assert_eq!(idle.hello_reads(), 0, "no pending challenge: no read");

        let pending = alpn_hook(&json!([{"name": "a.test", "key_authorization": "tok.k"}]));
        let (mut stream, _client) = connected(&hello).await;
        pending
            .process(&mut stream)
            .await
            .expect("a normal hello is handed on");
        assert_eq!(pending.hello_reads(), 1);
        let mut again = vec![0_u8; hello.len()];
        stream.read_exact(&mut again).await.expect("bytes put back");
        assert_eq!(
            again, hello,
            "the listener's handshake sees the hello untouched"
        );

        // Offering `acme-tls/1` next to a normal protocol is a normal hello too.
        let mixed = client_hello_offering(&[b"acme-tls/1", b"h2"]);
        let (mut stream, _client) = connected(&mixed).await;
        pending.process(&mut stream).await.expect("handed on");
    }

    #[tokio::test]
    async fn alpn01_only_hello_without_a_pending_challenge_is_refused() {
        let pending = alpn_hook(&json!([{"name": "b.test", "key_authorization": "tok.k"}]));
        let (mut stream, mut client) = connected(&client_hello_offering(&[b"acme-tls/1"])).await;
        pending
            .process(&mut stream)
            .await
            .expect_err("no challenge is pending for a.test");
        drop(stream);
        let mut alert = Vec::new();
        client
            .read_to_end(&mut alert)
            .await
            .expect("alert and close");
        assert_eq!(
            alert,
            [21, 3, 3, 0, 2, 2, 120],
            "fatal no_application_protocol"
        );
    }
}
