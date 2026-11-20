//! Client certificate authentication per app: an app with `tls.client_ca_pem` only
//! serves TLS clients whose certificate chains to that CA.
//!
//! Two layers, because Pingora builds one rustls `ServerConfig` for the whole listener and rustls
//! asks the config's verifier, not the SNI, whether to request a certificate:
//!
//! 1. **Handshake** (`HandshakeVerifier`). The listener's verifier requests a client
//!    certificate only for a connection whose SNI belongs to an app with a client CA. The TLS
//!    resolver sees the SNI first and leaves its answer in a thread-local (`decide`); rustls
//!    reads it back in the same call when it decides whether to send the `CertificateRequest`
//!    (`HandshakeVerifier::offer_client_auth`). The verifier proves the client holds the
//!    private key of the certificate it sent but does not judge the chain, and it never makes a
//!    certificate mandatory: it cannot know the app. [`ClearDecision`] wraps the pre-TLS hook so
//!    a decision no handshake consumed (a resumed session) never reaches the next connection on
//!    that thread.
//! 2. **Request** ([`admit`]). Before routing, the chain the connection presented is checked
//!    against the CA of the app the request is routed to, whatever the SNI was. A request with
//!    no chain, or a chain from another CA, gets `403`. This is the check that enforces the
//!    policy: a client that handshook with the SNI of an app without a client CA and then names
//!    an mTLS app in `Host` (allowed when the target sets `allow_domain_fronting`)
//!    gets `403` too, and so does any request to such an app on the plain HTTP listener.
//!
//! The chain is judged by rustls' `WebPkiClientVerifier` built from the app's CA at snapshot
//! compile time; a PEM it cannot use rejects the snapshot with `422` (`invalid_client_ca`).
//! The verdict is memoized per connection for 30 seconds, so a request costs a signature check
//! once per connection and app, not once per request.
//!
//! An app that sets `tls.pass_client_cert` also receives the verified certificate's subject in
//! [`SUBJECT_HEADER`]. The header is removed from every request first, so a client cannot set
//! it.

use std::cell::Cell;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::listeners::PreTlsProcess;
use pingora::protocols::l4::stream::Stream;
use pingora::proxy::Session;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, UnixTime, pem::PemObject};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use serde_json::{Value, json};
use thiserror::Error;

use crate::error::AppError;
use crate::route;
use crate::snapshot::App;
use crate::sni;
use crate::table::RoutingTable;

/// The request header that carries the verified client certificate's subject to an app with
/// `pass_client_cert`. Removed from every incoming request.
pub const SUBJECT_HEADER: &str = "x-forwarded-tls-client-cert-subject";

/// How long a connection's verdict on its client certificate is reused before the chain is
/// checked again, so a certificate that expires mid-connection stops working soon after.
const MEMO_TTL: Duration = Duration::from_secs(30);

thread_local! {
    /// What the resolver decided for the handshake in progress on this thread; `None` when no
    /// decision is pending.
    static REQUEST_CERT: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Records that the handshake now being resolved on this thread does (`true`) or does not
/// request a client certificate. Called by the TLS certificate resolver, which sees the SNI.
pub(crate) fn decide(request: bool) {
    REQUEST_CERT.set(Some(request));
}

/// Drops a pending decision no handshake used.
fn forget() {
    REQUEST_CERT.set(None);
}

/// A `tls.client_ca_pem` the compiler refuses, with where it was declared.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("app {app} ({declared_by}) tls.client_ca_pem: {reason}")]
pub struct Rejection {
    /// The declaring app.
    pub app: Box<str>,
    /// Its `declared_by` source.
    pub declared_by: Box<str>,
    /// What is wrong with the PEM.
    pub reason: Box<str>,
}

impl Rejection {
    /// The object in the `conflicts` list of a `422` body: `code` (`invalid_client_ca`),
    /// `message`, `app` and `declared_by`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "code": "invalid_client_ca", "message": self.to_string(),
            "app": self.app, "declared_by": self.declared_by,
        })
    }
}

/// The messages of `rejections`, separated by `; `.
pub(crate) fn join(rejections: &[Rejection]) -> String {
    rejections
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// The compiled `client_ca_pem` of one app: judges client certificate chains against it.
#[derive(Debug)]
pub struct ClientAuth {
    verifier: Arc<dyn ClientCertVerifier>,
}

impl ClientAuth {
    /// Compiles the client CA of `app`, if it declares one.
    ///
    /// # Errors
    ///
    /// [`Rejection`] when the PEM holds no certificate, a block that is not one, or a
    /// certificate that cannot be a trust anchor.
    pub fn compile(app: &App) -> Result<Option<Arc<Self>>, Rejection> {
        let Some(pem) = &app.tls.client_ca_pem else {
            return Ok(None);
        };
        let reject = |reason: String| Rejection {
            app: app.id.clone(),
            declared_by: app.declared_by.clone(),
            reason: reason.into(),
        };
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|err| reject(err.to_string()))?;
            roots.add(cert).map_err(|err| reject(err.to_string()))?;
        }
        if roots.is_empty() {
            return Err(reject("holds no certificate".into()));
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(ring::default_provider()),
        )
        .build()
        .map_err(|err| reject(err.to_string()))?;
        Ok(Some(Arc::new(Self { verifier })))
    }

    /// Whether `chain` (leaf first) is valid now and signed by this CA.
    fn accepts(&self, chain: &[CertificateDer<'_>]) -> bool {
        let Some((leaf, intermediates)) = chain.split_first() else {
            return false;
        };
        self.verifier
            .verify_client_cert(leaf, intermediates, UnixTime::now())
            .is_ok()
    }
}

/// The client certificate chain a TLS connection presented, recorded when the handshake
/// completes, and the last verdict on it.
#[derive(Debug)]
pub(crate) struct ClientChain {
    certs: Vec<CertificateDer<'static>>,
    memo: Mutex<Option<Memo>>,
}

#[derive(Debug)]
struct Memo {
    auth: Arc<ClientAuth>,
    at: Instant,
    accepted: bool,
}

impl ClientChain {
    /// The chain of a connection; `None` when the client sent no certificate.
    pub(crate) fn new(certs: Option<&[CertificateDer<'static>]>) -> Option<Self> {
        let certs = certs.filter(|certs| !certs.is_empty())?;
        Some(Self {
            certs: certs.to_vec(),
            memo: Mutex::new(None),
        })
    }

    /// Whether the chain satisfies `auth`, reusing the last verdict for the same compiled CA.
    fn satisfies(&self, auth: &Arc<ClientAuth>) -> bool {
        let mut memo = self.memo.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(known) = memo.as_ref()
            && Arc::ptr_eq(&known.auth, auth)
            && known.at.elapsed() < MEMO_TTL
        {
            return known.accepted;
        }
        let accepted = auth.accepts(&self.certs);
        *memo = Some(Memo {
            auth: Arc::clone(auth),
            at: Instant::now(),
            accepted,
        });
        accepted
    }

    /// The leaf's subject, one line of printable ASCII (anything else becomes `?`).
    fn subject(&self) -> Option<String> {
        let (_, leaf) = x509_parser::parse_x509_certificate(self.certs.first()?).ok()?;
        let subject = leaf.subject().to_string();
        Some(
            subject
                .chars()
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        '?'
                    }
                })
                .collect(),
        )
    }
}

/// Checks the client certificate of a request against the app it is routed to, and fills or
/// clears [`SUBJECT_HEADER`]. Runs after the SNI check and before routing.
///
/// A request for a host no app claims passes: routing answers it.
///
/// # Errors
///
/// [`AppError::ClientCertRequired`] when the routed app has a client CA and the connection
/// presented no certificate chain that it accepts, including every plain HTTP connection.
pub fn admit(session: &mut Session, table: &RoutingTable) -> Result<(), AppError> {
    session.req_header_mut().remove_header(SUBJECT_HEADER);
    let Some(host) = route::request_host(session.req_header()).map(|host| host.into_owned()) else {
        return Ok(());
    };
    let Some((_, app)) = table.find_app(&host) else {
        return Ok(());
    };
    let Some(auth) = app.client_auth() else {
        return Ok(());
    };
    let chain = sni::client_chain(session);
    if !chain.is_some_and(|chain| chain.satisfies(auth)) {
        return Err(AppError::ClientCertRequired);
    }
    let subject = app
        .tls()
        .pass_client_cert
        .then(|| chain.and_then(ClientChain::subject))
        .flatten();
    if let Some(subject) = subject {
        session
            .req_header_mut()
            .insert_header(SUBJECT_HEADER, subject)
            .map_err(|err| AppError::Internal(anyhow::anyhow!("subject header: {err}")))?;
    }
    Ok(())
}

/// The listener's client certificate verifier: requests a certificate only when the resolver
/// said the SNI needs one (see the module docs) and proves possession of the key, not the chain.
#[derive(Debug)]
pub(crate) struct HandshakeVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl HandshakeVerifier {
    pub(crate) fn new() -> Self {
        Self {
            algorithms: ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for HandshakeVerifier {
    /// `true` when no decision is pending: rustls also asks when it creates the connection,
    /// before the SNI is known, and a `false` there would stop a TLS 1.2 client from
    /// authenticating later.
    fn offer_client_auth(&self) -> bool {
        REQUEST_CERT.take().unwrap_or(true)
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // `admit` judges the chain against the CA of the app the request is routed to.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Wraps the pre-TLS hook of the listener: once it is done, the connection's rustls state is
/// created in the same poll, and no decision of an earlier handshake may be pending then.
#[derive(Debug)]
pub struct ClearDecision<H>(pub H);

#[async_trait]
impl<H: PreTlsProcess + Send + Sync> PreTlsProcess for ClearDecision<H> {
    async fn process(&self, stream: &mut Stream) -> pingora::Result<()> {
        let result = self.0.process(stream).await;
        forget();
        result
    }
}

#[cfg(test)]
pub(crate) fn test_ca_pem(name: &str) -> String {
    test_ca(name).0
}

/// A CA's PEM and the client certificate chain it signed.
#[cfg(test)]
fn test_ca(name: &str) -> (String, Vec<CertificateDer<'static>>) {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let issuer =
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("key")).expect("CA");
    let key = KeyPair::generate().expect("client key");
    let leaf = CertificateParams::new(Vec::<String>::new())
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("leaf");
    (issuer.pem(), vec![leaf.der().clone()])
}

#[cfg(test)]
mod test {
    use super::*;

    fn app_with(ca: Option<&str>) -> App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "hosts": ["a.test"],
            "tls": {"mode": "acme", "client_ca_pem": ca},
            "revisions": [],
        }))
        .expect("valid app")
    }

    #[test]
    fn no_ca_means_no_client_auth() {
        assert!(
            ClientAuth::compile(&app_with(None))
                .expect("compiles")
                .is_none()
        );
    }

    #[test]
    fn accepts_only_chains_signed_by_its_ca() {
        let (pem, chain) = test_ca("mine");
        let (_, stranger) = test_ca("other");
        let auth = ClientAuth::compile(&app_with(Some(&pem)))
            .expect("compiles")
            .expect("has a CA");
        assert!(auth.accepts(&chain));
        assert!(!auth.accepts(&stranger));
        assert!(!auth.accepts(&[]));
    }

    #[test]
    fn rejects_pem_without_a_usable_certificate() {
        for bad in [
            "",
            "not a pem",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        ] {
            let err = ClientAuth::compile(&app_with(Some(bad))).expect_err(bad);
            assert_eq!(&*err.app, "a");
        }
    }

    #[test]
    fn a_pending_decision_is_used_once_and_missing_means_ask() {
        let verifier = HandshakeVerifier::new();
        forget();
        assert!(
            verifier.offer_client_auth(),
            "unknown at connection creation"
        );
        decide(false);
        assert!(!verifier.offer_client_auth());
        assert!(verifier.offer_client_auth(), "consumed by the first read");
        decide(false);
        forget();
        assert!(verifier.offer_client_auth(), "a stale decision is dropped");
    }
}
