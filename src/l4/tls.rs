//! TLS on TCP routers: what a `tcp` entry point reads of a connection before it
//! picks a router, and how a terminating router completes the handshake.
//!
//! **Peeking.** An entry point with a router that has `tls` reads the start of each connection
//! before routing it: `peek` reads up to [`HELLO_CAP`] bytes for at most `HELLO_TIMEOUT`,
//! with the ClientHello parser of the HTTPS listener (`crate::tls::hello`, rustls' `Acceptor`;
//! nothing here parses TLS). The answer is an `Offer`: a ClientHello with its server name and
//! ALPN protocols, or "not TLS" (the first byte is no handshake record, so only routers without
//! `tls` can take it). Nothing arrives, a malformed hello, one over the cap or a client that
//! leaves first is a refusal. The bytes read go back to the stream with `rewind`, so a
//! passthrough server and the TLS handshake both see the connection from its first byte.
//!
//! **Memory.** The peek buffer is at most [`HELLO_CAP`] (16 KiB, one copy buffer) and exists
//! before a router, so before a tenant, is known: it is charged to nobody. Once the router is
//! chosen the tenant is charged the two copy buffers (32 KiB) and the bytes are copied into the
//! stream's rewind buffer, which makes 16 KiB twice for a moment, inside that charge. The peek
//! buffer is dropped before the copy starts, so a connection never holds the peek buffer and
//! the copy buffers together.
//!
//! **Termination.** `Terminator::accept` runs the handshake with the app's certificates:
//! on-demand certificates are awaited like the HTTPS hook does, the app's TLS options (spec
//! 0057: version and suites; the ALPN allowance of `h2` and `http/1.1` is HTTP's and does not
//! apply) refuse a hello at once, `client_auth` decides whether the client is asked
//! for a certificate and whether the one it sent is enough, and the certificate comes from the
//! live table's `CertStore` with its OCSP staple, like the HTTPS resolver. Differences from the
//! HTTPS resolver, both because the router and so the app are known before the handshake:
//!
//! - A certificate is served only for a name the router's tenant claims (`Owners`), else the
//!   default certificate (unless the app is `sni_strict`). A catch-all router therefore cannot
//!   terminate for another tenant's name, however the client spells it.
//! - The client certificate request follows this app, not every app that may serve the name.
//!
//! Every handshake here is a full one: session resumption is off, so a resumed session can never
//! skip the client certificate check of the app the connection routes to.
//!
//! The ALPN protocol the handshake negotiates is the first protocol the router's `alpn` leaves
//! name that the client offered; a router that names none negotiates none.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use pingora::listeners::tls::Acceptor;
use pingora::protocols::Ssl;
use pingora::protocols::Stream;
use pingora::protocols::l4::stream::Stream as L4Stream;
use pingora::tls::sign::CertifiedKey;
use pingora::tls::{ClientHello, ResolvesServerCert};
use rustls::server::NoServerSessionStorage;
use rustls::{ServerConfig, version};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use super::tcp::COPY_BUFFER;
use crate::acme::Acme;
use crate::clientauth::{self, ClientChain, HandshakeVerifier};
use crate::host::{self, HostMap};
use crate::router::matcher::Hello;
use crate::table::{CompiledApp, RoutingTable};
use crate::tls::hello::{HELLO_TIMEOUT, Hello as Parsed, Unread, read_hello};
use crate::tls::ocsp::Staples;

/// The most a connection may send before its ClientHello is complete: one copy buffer.
pub const HELLO_CAP: usize = COPY_BUFFER;
/// Longest a terminating router's handshake may take after the router is chosen.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest the entry point waits to write the alert that tells a refused client why.
const ALERT_TIMEOUT: Duration = Duration::from_secs(1);

/// What the start of a connection offered.
#[derive(Debug, Default)]
pub(super) struct Offer {
    tls: bool,
    hello: Parsed,
}

impl Offer {
    /// A connection that is not TLS, or one the entry point did not read.
    pub(super) fn none() -> Self {
        Self::default()
    }

    /// Whether the connection starts with a ClientHello.
    pub(super) fn is_tls(&self) -> bool {
        self.tls
    }

    /// The server name, normalized, when the client sent one.
    pub(super) fn server_name(&self) -> Option<&str> {
        self.hello.server_name.as_deref()
    }

    /// The offer as the matcher leaves read it.
    pub(super) fn hello(&self) -> Hello<'_> {
        Hello {
            server_name: self.hello.server_name.as_deref(),
            alpn: &self.hello.alpn,
        }
    }
}

/// Why a connection was given up on while its start was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cause {
    /// No complete ClientHello within `HELLO_TIMEOUT`.
    Timeout,
    /// The client left, or sent a malformed hello, or one over [`HELLO_CAP`].
    Invalid,
}

/// Reads the start of `stream` into an `Offer` and the bytes read, which the caller puts back
/// with `rewind` once it has charged the tenant.
pub(super) async fn peek(stream: &mut L4Stream) -> Result<(Offer, Vec<u8>), Cause> {
    let mut seen = Vec::new();
    match timeout(HELLO_TIMEOUT, read_hello(stream, &mut seen, HELLO_CAP)).await {
        Err(_) => Err(Cause::Timeout),
        Ok(Ok(mut hello)) => {
            hello.server_name = hello
                .server_name
                .map(|name| host::normalize(&name).into_owned());
            Ok((Offer { tls: true, hello }, seen))
        }
        Ok(Err(Unread::NotTls)) => Ok((Offer::none(), seen)),
        Ok(Err(Unread::Broken)) => Err(Cause::Invalid),
    }
}

/// Which tenant claims each name of one table: the literal host claims of its HTTP routers and
/// of its TCP routers (`sni`, passthrough or terminating). A name has one tenant, because two
/// tenants claiming one pattern, or a name under another's wildcard, is a conflict at compile
/// time.
#[derive(Debug, Default)]
pub(super) struct Owners(HostMap<Box<str>>);

impl Owners {
    pub(super) fn of(table: &RoutingTable) -> Self {
        let mut owners = HostMap::default();
        for app in table.apps() {
            let http = app.routers().iter().flat_map(|router| router.patterns());
            let tcp = app.l4().tcp().claims();
            for pattern in http.chain(tcp) {
                owners.insert(pattern.clone(), Box::from(app.tenant()));
            }
        }
        Self(owners)
    }

    /// The tenant that claims the normalized `name`, if any.
    pub(super) fn tenant_of(&self, name: &str) -> Option<&str> {
        self.0.lookup(name).map(AsRef::as_ref)
    }
}

/// Why a terminating router did not complete its handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failed {
    /// The handshake failed or took longer than [`HANDSHAKE_TIMEOUT`].
    Handshake,
    /// The ClientHello or the negotiated version or suite broke the app's TLS options.
    Policy,
    /// The client certificate did not satisfy the app's `client_auth`.
    ClientCert,
}

/// Completes the TLS handshake of terminating TCP routers.
#[derive(Clone)]
pub struct Terminator {
    acme: Acme,
    staples: Staples,
    base: Arc<ServerConfig>,
}

impl std::fmt::Debug for Terminator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Terminator").finish_non_exhaustive()
    }
}

/// Picks the certificate of one terminated connection; see the module docs.
#[derive(Debug)]
struct Choose {
    table: Arc<RoutingTable>,
    owners: Arc<Owners>,
    staples: Staples,
    tenant: Box<str>,
    ask: bool,
    strict: bool,
}

impl ResolvesServerCert for Choose {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        clientauth::decide(self.ask);
        let certificates = self.table.certificates();
        let key = match client_hello.server_name() {
            None => certificates.default_certificate().cloned(),
            Some(name) => {
                let name = host::normalize(name);
                let owned = self.owners.tenant_of(&name) == Some(&*self.tenant);
                owned
                    .then(|| certificates.lookup(&name))
                    .flatten()
                    .or_else(|| {
                        certificates
                            .default_certificate()
                            .filter(|_| !self.strict)
                            .cloned()
                    })
            }
        };
        key.map(|key| self.staples.attach(key))
    }
}

impl Terminator {
    /// A terminator that serves the certificates of the live table, waits for on-demand
    /// certificates through `acme` and attaches the OCSP staples of `staples`.
    ///
    /// # Errors
    ///
    /// rustls' error when the TLS provider cannot build a configuration.
    pub fn new(acme: Acme, staples: Staples) -> Result<Self, rustls::Error> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&version::TLS12, &version::TLS13])?
            .with_client_cert_verifier(Arc::new(HandshakeVerifier::new()))
            .with_cert_resolver(Arc::new(Unset));
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Self {
            acme,
            staples,
            base: Arc::new(config),
        })
    }

    /// Runs the handshake of `app` on `client`, which has been put back to its first byte, and
    /// returns the decrypted stream. `hello` is what `peek` read, `protocols` the ALPN protocols
    /// the router can negotiate; `table` and `owners` are the ones the router was chosen from.
    pub(super) async fn accept(
        &self,
        mut client: L4Stream,
        table: &Arc<RoutingTable>,
        owners: &Arc<Owners>,
        app: &CompiledApp,
        offer: &Offer,
        protocols: &[Box<[u8]>],
    ) -> Result<Stream, Failed> {
        let hello = &offer.hello;
        let options = app.tls_options();
        if let Some(violation) =
            options.and_then(|options| options.transport_hello_violation(hello))
        {
            // Best effort: the client learns why, but the refusal does not depend on it.
            let _ = timeout(ALERT_TIMEOUT, client.write_all(&violation.alert())).await;
            return Err(Failed::Policy);
        }
        if let Some(name) = offer.server_name()
            && owners.tenant_of(name) == Some(app.tenant())
        {
            self.acme.await_certificate(name).await;
        }
        let offered: HashSet<&[u8]> = hello.alpn.iter().map(Vec::as_slice).collect();
        let mut config = (*self.base).clone();
        config.alpn_protocols = protocols
            .iter()
            .filter(|protocol| offered.contains(&***protocol))
            .map(|protocol| protocol.to_vec())
            .collect();
        config.cert_resolver = Arc::new(Choose {
            table: Arc::clone(table),
            owners: Arc::clone(owners),
            staples: self.staples.clone(),
            tenant: app.tenant().into(),
            ask: app.client_auth().is_some(),
            strict: options.is_some_and(|options| options.sni_strict()),
        });
        let acceptor = Acceptor::from_server_config(Arc::new(config));
        let handshake = Box::pin(timeout(HANDSHAKE_TIMEOUT, acceptor.tls_handshake(client))).await;
        clientauth::forget();
        let Ok(Ok(tls)) = handshake else {
            return Err(Failed::Handshake);
        };
        if let Some(options) = options
            && let Some(digest) = tls.ssl_digest()
            && options
                .transport_violation(&digest.version, &digest.cipher)
                .is_some()
        {
            return Err(Failed::Policy);
        }
        if let Some(auth) = app.client_auth() {
            let chain = tls
                .get_ssl()
                .and_then(|ssl| ClientChain::new(ssl.peer_cert_chain_der()));
            if !clientauth::allows(auth, chain.as_ref()) {
                return Err(Failed::ClientCert);
            }
        }
        Ok(Box::new(tls))
    }
}

/// The resolver of the base configuration: a connection always replaces it with a `Choose`, so
/// a handshake that somehow kept this one serves no certificate.
#[derive(Debug)]
struct Unset;

impl ResolvesServerCert for Unset {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

#[cfg(test)]
mod test {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore};

    use super::*;

    /// The first flight of a TLS client with `name` (none: no server name) offering `alpn`.
    fn client_hello(name: Option<&str>, alpn: &[&str]) -> Vec<u8> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions")
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
        let server = ServerName::try_from(name.unwrap_or("192.0.2.1").to_owned()).expect("name");
        let mut connection = ClientConnection::new(Arc::new(config), server).expect("client");
        let mut bytes = Vec::new();
        connection.write_tls(&mut bytes).expect("hello");
        bytes
    }

    async fn peek_bytes(bytes: &[u8], cap: usize) -> (Result<Parsed, Unread>, usize) {
        let mut source = bytes;
        let mut seen = Vec::new();
        let read = read_hello(&mut source, &mut seen, cap).await;
        (read, seen.len())
    }

    #[tokio::test]
    async fn l4_client_hello_parser_table() {
        let cases: [(Option<&str>, &[&str]); 5] = [
            (Some("a.test"), &[]),
            (Some("a.test"), &["h2", "http/1.1"]),
            (Some("deep.sub.a.test"), &["postgresql"]),
            (None, &[]),
            (None, &["h2"]),
        ];
        for (name, alpn) in cases {
            let bytes = client_hello(name, alpn);
            let (read, used) = peek_bytes(&bytes, HELLO_CAP).await;
            let hello = read.expect("a ClientHello");
            assert_eq!(hello.server_name.as_deref(), name, "{name:?} {alpn:?}");
            let offered: Vec<&[u8]> = hello.alpn.iter().map(Vec::as_slice).collect();
            let wanted: Vec<&[u8]> = alpn.iter().map(|name| name.as_bytes()).collect();
            assert_eq!(offered, wanted, "{name:?} {alpn:?}");
            assert_eq!(used, bytes.len(), "the whole hello is read, no more");
        }
    }

    #[tokio::test]
    async fn l4_client_hello_bounds_and_garbage() {
        let hello = client_hello(Some("a.test"), &[]);
        // Not TLS: the first byte says so, and what was read is kept for the replay.
        let (read, used) = peek_bytes(b"GET / HTTP/1.1\r\n", HELLO_CAP).await;
        assert_eq!(read.err(), Some(Unread::NotTls));
        assert_eq!(used, 16);
        // A client that leaves mid-hello, or sends nothing.
        for cut in [0, 1, 5, hello.len() - 1] {
            assert_eq!(
                peek_bytes(&hello[..cut], HELLO_CAP).await.0.err(),
                Some(Unread::Broken),
                "{cut}"
            );
        }
        // Handshake bytes that are not a ClientHello.
        assert_eq!(
            peek_bytes(&[0x16, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], HELLO_CAP)
                .await
                .0
                .err(),
            Some(Unread::Broken)
        );
        // A record of the largest size TLS allows, which no cap of 16 KiB can hold whole, is
        // refused after exactly `cap` bytes.
        let mut oversized = vec![0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0x00, 0x3f, 0xfc];
        oversized.resize(30_000, 0);
        let (read, used) = peek_bytes(&oversized, HELLO_CAP).await;
        assert_eq!(read.err(), Some(Unread::Broken));
        assert_eq!(used, HELLO_CAP, "never reads past the cap");
        // A record that announces more than TLS allows is refused by rustls at once.
        let mut absurd = vec![0x16, 0x03, 0x01, 0x4e, 0x20, 0x01, 0x00, 0x4e, 0x1c];
        absurd.resize(30_000, 0);
        let (read, used) = peek_bytes(&absurd, HELLO_CAP).await;
        assert_eq!(read.err(), Some(Unread::Broken));
        assert!(used <= HELLO_CAP);
        // A hello that fits only in a smaller cap is refused by that cap.
        let capped = |cap| async move {
            peek_bytes(&client_hello(Some("a.test"), &[]), cap)
                .await
                .0
                .err()
        };
        assert_eq!(capped(hello.len() - 1).await, Some(Unread::Broken));
        assert_eq!(capped(hello.len()).await, None);
    }
}
