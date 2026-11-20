//! Client certificate authentication per app: an app with
//! `tls.client_ca_pem` only serves TLS clients whose certificate chains to that CA. With
//! `tls.client_auth` the app picks the mode instead: `request` (ask, trust nothing), `require`
//! (some certificate), `verify_if_given` (a certificate, when sent, must chain to the CA) or
//! `require_and_verify` (the default with a CA).
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
//! The certificate also reaches the app's upstream, when the route has a `pass_tls_client_cert`
//! middleware: `verified_chain` gives it the chain only when this app's CA accepted it.
//! The `x-forwarded-tls-client-cert*` request headers are removed earlier, in the entry stage
//! (`middleware::pass_tls_client_cert::strip`), whatever the app is.

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
use crate::router::Matched;
use crate::sni;
use crate::table::{CompiledApp, RoutingTable};
use podgate_model::{App, ClientAuthMode};

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

/// A `tls.client_ca_pem` or `tls.client_auth` the compiler refuses, with where it was declared.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("app {app} ({declared_by}) {field}: {reason}")]
pub struct Rejection {
    /// The declaring app.
    pub app: Box<str>,
    /// Its `declared_by` source.
    pub declared_by: Box<str>,
    /// The code of the `422` entry: `invalid_client_ca` or `invalid_client_auth`.
    pub code: &'static str,
    /// The setting that is wrong.
    pub field: &'static str,
    /// What is wrong with it.
    pub reason: Box<str>,
}

impl Rejection {
    /// The object in the `conflicts` list of a `422` body: `code`, `message`, `app` and
    /// `declared_by`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "code": self.code, "message": self.to_string(),
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

/// The compiled client authentication of one app: whether clients are asked for a certificate,
/// and the CA that judges the chains they send.
#[derive(Debug)]
pub struct ClientAuth {
    mode: ClientAuthMode,
    /// Present for the modes that judge the chain.
    verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl ClientAuth {
    /// Compiles the client authentication of `app`, if it declares any: `tls.client_auth`, or
    /// `tls.client_ca_pem` alone, which means `require_and_verify`.
    ///
    /// # Errors
    ///
    /// [`Rejection`] when the PEM holds no certificate, a block that is not one, or a
    /// certificate that cannot be a trust anchor; when a mode that judges the chain has no CA
    /// or a mode that does not has one.
    pub fn compile(app: &App) -> Result<Option<Arc<Self>>, Rejection> {
        let tls = &app.tls;
        let mode = match (tls.client_auth, &tls.client_ca_pem) {
            (None, None) => return Ok(None),
            (None, Some(_)) => ClientAuthMode::RequireAndVerify,
            (Some(mode), _) => mode,
        };
        let reject = |code, field, reason: String| Rejection {
            app: app.id.clone(),
            declared_by: app.declared_by.clone(),
            code,
            field,
            reason: reason.into(),
        };
        let judges = matches!(
            mode,
            ClientAuthMode::VerifyIfGiven | ClientAuthMode::RequireAndVerify
        );
        let verifier = match (&tls.client_ca_pem, judges) {
            (None, true) => {
                return Err(reject(
                    "invalid_client_auth",
                    "tls.client_auth",
                    "this mode judges the chain and needs tls.client_ca_pem".into(),
                ));
            }
            (Some(_), false) => {
                return Err(reject(
                    "invalid_client_auth",
                    "tls.client_auth",
                    "tls.client_ca_pem is not used by this mode: use verify_if_given or require_and_verify"
                        .into(),
                ));
            }
            (None, false) => None,
            (Some(pem), true) => Some(
                verifier_of(pem)
                    .map_err(|reason| reject("invalid_client_ca", "tls.client_ca_pem", reason))?,
            ),
        };
        Ok(Some(Arc::new(Self { mode, verifier })))
    }

    /// How clients are asked for a certificate.
    #[must_use]
    pub fn mode(&self) -> ClientAuthMode {
        self.mode
    }

    /// Whether this mode judges the chain a client sends (`verify_if_given`,
    /// `require_and_verify`): only then is a certificate that got through verified.
    fn judges(&self) -> bool {
        self.verifier.is_some()
    }

    /// Whether `chain` (leaf first) is valid now and signed by this CA.
    fn accepts(&self, chain: &[CertificateDer<'_>]) -> bool {
        let (Some((leaf, intermediates)), Some(verifier)) = (chain.split_first(), &self.verifier)
        else {
            return false;
        };
        verifier
            .verify_client_cert(leaf, intermediates, UnixTime::now())
            .is_ok()
    }
}

/// Whether going from mode `old` to `new` (`None`: no client authentication) asks less of
/// clients: it drops the requirement or stops judging the chain. Going to `require_and_verify`,
/// or from `request` to any mode, asks more.
#[must_use]
pub(crate) fn relaxes(old: ClientAuthMode, new: Option<ClientAuthMode>) -> bool {
    match new {
        None => true,
        Some(new) => {
            new != old && new != ClientAuthMode::RequireAndVerify && old != ClientAuthMode::Request
        }
    }
}

/// The verifier of the CA certificates in `pem`.
fn verifier_of(pem: &str) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = cert.map_err(|err| err.to_string())?;
        roots.add(cert).map_err(|err| err.to_string())?;
    }
    if roots.is_empty() {
        return Err("holds no certificate".into());
    }
    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(ring::default_provider()))
        .build()
        .map_err(|err| err.to_string())
}

/// Whether a connection that presented `chain` (`None`: no certificate) is served under `auth`.
fn allows(auth: &Arc<ClientAuth>, chain: Option<&ClientChain>) -> bool {
    match auth.mode {
        ClientAuthMode::Request => true,
        ClientAuthMode::Require => chain.is_some(),
        ClientAuthMode::VerifyIfGiven => chain.is_none_or(|chain| chain.satisfies(auth)),
        ClientAuthMode::RequireAndVerify => chain.is_some_and(|chain| chain.satisfies(auth)),
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
}

/// Checks the client certificate of a request against the app of the router it matched. Runs
/// right after the match and the SNI check, before the middleware chain and anything else that
/// answers.
///
/// The app is the one the v2 router actually matched, whatever kind of router it was (exact
/// host, wildcard, `host_regexp`, no host at all): there is no second host lookup that could
/// disagree with routing.
///
/// A request no router matched passes: routing answers it `404`.
///
/// # Errors
///
/// [`AppError::ClientCertRequired`] when the matched app's `tls.client_auth` mode is not
/// satisfied: no certificate chain for `require`, none that its CA accepts for
/// `require_and_verify` (including every plain HTTP connection), a chain its CA refuses for
/// `verify_if_given`.
pub fn admit(
    session: &Session,
    table: &RoutingTable,
    matched: Option<Matched>,
) -> Result<(), AppError> {
    let Some(app) = matched.and_then(|matched| table.app(matched.app)) else {
        return Ok(());
    };
    let Some(auth) = app.client_auth() else {
        return Ok(());
    };
    if allows(auth, sni::client_chain(session)) {
        Ok(())
    } else {
        Err(AppError::ClientCertRequired)
    }
}

/// The certificates (leaf first, as the client sent them) of the session's TLS connection, when
/// `app`'s client CA accepted them: the app's own `tls.client_ca_pem` judged this chain, never
/// the CA of the app the TLS handshake was for. `None` on plain HTTP, when the client sent no
/// certificate, when `app` has no client authentication, and for the modes that do not judge
/// the chain (`request`, `require`): a certificate nobody verified is never passed on.
///
/// Only the first certificate is the one the CA signed; the others are what the client sent
/// along and are not judged.
pub(crate) fn verified_chain<'a>(
    session: &'a Session,
    app: &CompiledApp,
) -> Option<&'a [CertificateDer<'static>]> {
    let auth = app.client_auth()?;
    let chain = sni::client_chain(session)?;
    (auth.judges() && chain.satisfies(auth)).then_some(chain.certs.as_slice())
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
            "id": "a", "tenant": "t", "declared_by": "test", "routers": [],
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
