//! The TLS listener: certificates come from the live snapshot and are chosen by SNI per
//! handshake, so a pushed certificate serves new connections without a restart. The same SNI
//! decides whether the client is asked for a certificate (see [`crate::clientauth`]).
//!
//! A name no certificate covers gets the certificate marked `default: true` when the snapshot
//! has one, unless an app that may serve the name sets `sni_strict`; then the handshake fails.
//! A handshake with no SNI is treated like an unknown name. Per-app version, suite and ALPN
//! options are in [`Options`], and the pre-TLS hook that reads the ClientHello for them and for
//! on-demand certificates is [`PreHandshake`].

mod hello;
pub mod ocsp;
mod options;

use std::sync::Arc;

use pingora::listeners::tls::TlsSettings;
use pingora::tls::sign::CertifiedKey;
use pingora::tls::{
    CertificateDer, ClientHello, CryptoProvider, PrivateKeyDer, ResolvesServerCert,
    install_default_crypto_provider,
};
use rustls_pki_types::pem::PemObject;
use thiserror::Error;

use crate::clientauth::{self, HandshakeVerifier};
use crate::host::{self, HostMap, HostPattern};
use crate::sni;
use crate::table::TableHandle;
use ocsp::{Candidate, Staples};
use podgate_model::Certificate;

pub use hello::PreHandshake;
pub use options::{Options, Violation, enforce};

/// A certificate in a snapshot that cannot be served.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid certificate for {hosts}: {reason}")]
pub struct CertError {
    /// The certificate's declared hosts, comma separated.
    pub hosts: Box<str>,
    /// What is wrong with it.
    pub reason: Box<str>,
}

/// Parsed certificates of one snapshot, looked up by host.
#[derive(Debug, Default)]
pub struct CertStore {
    by_host: HostMap<Arc<CertifiedKey>>,
    expiries: Vec<(Box<str>, u64)>,
    default: Option<Arc<CertifiedKey>>,
    summaries: Vec<Summary>,
    ocsp: Vec<Candidate>,
}

/// What the read-only overview says about one certificate: never the chain or the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The hosts the snapshot declares for it.
    pub hosts: Box<[Box<str>]>,
    /// The issuer's distinguished name; `None` when the leaf cannot be parsed.
    pub issuer: Option<Box<str>>,
    /// End of validity in seconds since the Unix epoch; `None` when the leaf cannot be parsed.
    pub not_after: Option<i64>,
    /// Whether it is the `default` certificate, served for names no certificate covers.
    pub default: bool,
}

impl Summary {
    fn of(hosts: &[Box<str>], default: bool, key: &CertifiedKey) -> Self {
        let parsed = key
            .cert
            .first()
            .and_then(|leaf| x509_parser::parse_x509_certificate(leaf).ok());
        Self {
            hosts: hosts.into(),
            issuer: parsed
                .as_ref()
                .map(|(_, cert)| cert.issuer().to_string().into()),
            not_after: parsed
                .as_ref()
                .map(|(_, cert)| cert.validity().not_after.timestamp()),
            default,
        }
    }
}

impl CertStore {
    /// Parses every certificate and indexes it under its hosts.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] for a bad host, unreadable PEM, an unsupported or mismatched key,
    /// a host claimed by two certificates, or a second `default` certificate.
    pub fn build(certificates: &[Certificate]) -> Result<Self, CertError> {
        let mut by_host = HostMap::default();
        let mut expiries = Vec::new();
        let mut default = None;
        let mut summaries = Vec::with_capacity(certificates.len());
        let mut ocsp = Vec::new();
        for certificate in certificates {
            let hosts = certificate.hosts.join(",");
            let reject = |reason: String| CertError {
                hosts: hosts.as_str().into(),
                reason: reason.into(),
            };
            let key = Arc::new(parse_certified_key(certificate).map_err(reject)?);
            let not_after = key
                .cert
                .first()
                .and_then(|leaf| x509_parser::parse_x509_certificate(leaf).ok())
                .and_then(|(_, parsed)| {
                    u64::try_from(parsed.validity().not_after.timestamp()).ok()
                });
            if certificate.default && default.replace(Arc::clone(&key)).is_some() {
                return Err(reject("a second certificate is marked default".into()));
            }
            summaries.push(Summary::of(&certificate.hosts, certificate.default, &key));
            ocsp.extend(Candidate::of(certificate, &key));
            for raw in &certificate.hosts {
                expiries.extend(not_after.map(|at| (raw.clone(), at)));
                let pattern = HostPattern::parse(raw).map_err(|err| reject(err.to_string()))?;
                if by_host.insert(pattern, Arc::clone(&key)).is_some() {
                    return Err(reject(format!("host {raw:?} has a second certificate")));
                }
            }
        }
        Ok(Self {
            by_host,
            expiries,
            default,
            summaries,
            ocsp,
        })
    }

    /// The certificates of the snapshot as the overview shows them, in snapshot order.
    #[must_use]
    pub fn summaries(&self) -> &[Summary] {
        &self.summaries
    }

    /// The certificates that want an OCSP staple, for the refresher.
    #[must_use]
    pub fn ocsp_candidates(&self) -> &[Candidate] {
        &self.ocsp
    }

    /// The certificate for a server name from the client hello, if the snapshot has one.
    #[must_use]
    pub fn lookup(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        self.by_host.lookup(&host::normalize(server_name)).cloned()
    }

    /// Each declared host with the Unix time its certificate stops being valid, in snapshot
    /// order. A certificate whose validity cannot be read has no entry.
    #[must_use]
    pub fn expiries(&self) -> &[(Box<str>, u64)] {
        &self.expiries
    }

    /// The certificate marked `default: true`, served for names no certificate covers.
    #[must_use]
    pub fn default_certificate(&self) -> Option<&Arc<CertifiedKey>> {
        self.default.as_ref()
    }
}

fn parse_certified_key(certificate: &Certificate) -> Result<CertifiedKey, String> {
    install_default_crypto_provider();
    let provider = CryptoProvider::get_default().ok_or("no crypto provider installed")?;
    let chain = CertificateDer::pem_slice_iter(certificate.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("cert_pem: {err}"))?;
    if chain.is_empty() {
        return Err("cert_pem holds no certificate".into());
    }
    let key = PrivateKeyDer::from_pem_slice(certificate.key_pem.as_bytes())
        .map_err(|err| format!("key_pem: {err}"))?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| format!("key_pem: {err}"))?;
    let certified = CertifiedKey::new(chain, signing_key);
    certified
        .keys_match()
        .map_err(|err| format!("key does not match the certificate: {err}"))?;
    Ok(certified)
}

/// Picks the certificate of the live routing table for each handshake: the one covering the
/// SNI, else the default certificate unless an app that may serve the name is `sni_strict`.
/// Without a certificate the handshake aborts. Also tells the client verifier whether this SNI
/// belongs to an app that asks for client certificates. The chosen certificate carries its
/// OCSP staple when the registry has a verified one; a handshake never waits for it.
#[derive(Debug)]
struct SniResolver {
    table: TableHandle,
    staples: Staples,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.choose(&client_hello)
            .map(|key| self.staples.attach(key))
    }
}

impl SniResolver {
    fn choose(&self, client_hello: &ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let table = self.table.load();
        let certificates = table.certificates();
        let Some(name) = client_hello.server_name() else {
            clientauth::decide(false);
            return certificates.default_certificate().cloned();
        };
        // Ask for a client certificate when any app that may serve this host wants one: a
        // literal claimant, or an app with a `host_regexp` or host-free router. The request
        // check (`clientauth::admit`) judges the app the request really matched.
        let (mut ask, mut strict) = (false, false);
        for app in table.may_serve(&host::normalize(name)) {
            ask |= app.client_auth().is_some();
            strict |= app
                .tls_options()
                .is_some_and(|options| options.sni_strict());
        }
        clientauth::decide(ask);
        certificates.lookup(name).or_else(|| {
            certificates
                .default_certificate()
                .filter(|_| !strict)
                .cloned()
        })
    }
}

/// Settings for the TLS listener: HTTP/2 and HTTP/1.1 over rustls, certificate chosen by SNI
/// from the table behind `table`, with the OCSP staples of `staples` attached.
///
/// # Errors
///
/// Fails when Pingora rejects the settings.
pub fn listener_settings(table: TableHandle, staples: Staples) -> pingora::Result<TlsSettings> {
    // Pingora ignores the file paths once a resolver is set.
    let mut settings = TlsSettings::with_callbacks(Box::new(sni::CaptureServerName))?;
    settings.set_cert_resolver(Arc::new(SniResolver { table, staples }));
    settings.set_client_cert_verifier(Arc::new(HandshakeVerifier::new()));
    settings.enable_h2();
    Ok(settings)
}
