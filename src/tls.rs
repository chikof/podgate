//! The TLS listener: certificates come from the live snapshot and are chosen by SNI per
//! handshake, so a pushed certificate serves new connections without a restart. The same SNI
//! decides whether the client is asked for a certificate (see [`crate::clientauth`]).

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
use podgate_model::Certificate;

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
}

impl CertStore {
    /// Parses every certificate and indexes it under its hosts.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] for a bad host, unreadable PEM, an unsupported or mismatched key,
    /// or a host claimed by two certificates.
    pub fn build(certificates: &[Certificate]) -> Result<Self, CertError> {
        let mut by_host = HostMap::default();
        for certificate in certificates {
            let hosts = certificate.hosts.join(",");
            let reject = |reason: String| CertError {
                hosts: hosts.as_str().into(),
                reason: reason.into(),
            };
            let key = Arc::new(parse_certified_key(certificate).map_err(reject)?);
            for raw in &certificate.hosts {
                let pattern = HostPattern::parse(raw).map_err(|err| reject(err.to_string()))?;
                if by_host.insert(pattern, Arc::clone(&key)).is_some() {
                    return Err(reject(format!("host {raw:?} has a second certificate")));
                }
            }
        }
        Ok(Self { by_host })
    }

    /// The certificate for a server name from the client hello, if the snapshot has one.
    #[must_use]
    pub fn lookup(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        self.by_host.lookup(&host::normalize(server_name)).cloned()
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

/// Picks the certificate of the live routing table for each handshake. No SNI or no matching
/// certificate aborts the handshake. Also tells the client verifier whether this SNI belongs to
/// an app with a client CA.
#[derive(Debug)]
struct SniResolver {
    table: TableHandle,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        let table = self.table.load();
        // Ask for a client certificate when any app that may serve this host wants one: a
        // literal claimant, or an app with a `host_regexp` or host-free router. The request
        // check (`clientauth::admit`) judges the app the request really matched.
        clientauth::decide(
            table
                .may_serve(&host::normalize(name))
                .any(|app| app.client_auth().is_some()),
        );
        table.certificates().lookup(name)
    }
}

/// Settings for the TLS listener: HTTP/2 and HTTP/1.1 over rustls, certificate chosen by SNI
/// from the table behind `table`.
///
/// # Errors
///
/// Fails when Pingora rejects the settings.
pub fn listener_settings(table: TableHandle) -> pingora::Result<TlsSettings> {
    // Pingora ignores the file paths once a resolver is set.
    let mut settings = TlsSettings::with_callbacks(Box::new(sni::CaptureServerName))?;
    settings.set_cert_resolver(Arc::new(SniResolver { table }));
    settings.set_client_cert_verifier(Arc::new(HandshakeVerifier::new()));
    settings.enable_h2();
    Ok(settings)
}
