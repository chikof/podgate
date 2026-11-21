//! Trust bundles: the root certificates of a trust domain, with the rustls verifiers built from
//! them once, when the bundle arrives, not once per connection.

use std::fmt;
use std::sync::Arc;

use pingora::utils::tls::WrappedX509;
use pingora::utils::tls::parse_x509;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Most roots a bundle may hold: a trust domain rotating its CA holds a handful.
const MAX_ROOTS: usize = 64;

/// A bundle the process cannot use.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleError {
    /// The bytes are not a sequence of DER certificates.
    #[error("the bundle is not a sequence of DER certificates")]
    Der,
    /// No certificate at all.
    #[error("the bundle holds no certificate")]
    Empty,
    /// More than [`MAX_ROOTS`].
    #[error("the bundle holds more than {MAX_ROOTS} certificates")]
    TooMany,
    /// rustls refuses a certificate as a trust anchor.
    #[error("the bundle holds a certificate that cannot be a trust anchor")]
    Anchor,
}

/// The certificates of `der`, a concatenation of DER certificates, as the Workload API sends
/// them.
///
/// # Errors
///
/// [`BundleError::Der`] when anything that is not a whole certificate remains.
pub(crate) fn split_der(der: &[u8]) -> Result<Vec<CertificateDer<'static>>, BundleError> {
    let mut rest = der;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (after, _) = x509_parser::parse_x509_certificate(rest).map_err(|_| BundleError::Der)?;
        let used = rest.len() - after.len();
        out.push(CertificateDer::from(rest[..used].to_vec()));
        rest = after;
    }
    Ok(out)
}

/// The roots of one trust domain and what verifies certificates against them.
pub struct Bundle {
    roots: Arc<[WrappedX509]>,
    digest: [u8; 16],
    server: Arc<WebPkiServerVerifier>,
    client: Arc<dyn ClientCertVerifier>,
}

impl Bundle {
    /// Builds the bundle of `der`, a concatenation of DER certificates.
    ///
    /// # Errors
    ///
    /// [`BundleError`] when it holds no certificate, too many, something that is not one, or one
    /// that cannot be a trust anchor.
    pub fn from_der(der: &[u8]) -> Result<Self, BundleError> {
        let certs = split_der(der)?;
        if certs.is_empty() {
            return Err(BundleError::Empty);
        }
        if certs.len() > MAX_ROOTS {
            return Err(BundleError::TooMany);
        }
        let mut store = RootCertStore::empty();
        let mut hash = Sha256::new();
        for cert in &certs {
            store.add(cert.clone()).map_err(|_| BundleError::Anchor)?;
            hash.update(cert.as_ref());
        }
        let store = Arc::new(store);
        let provider = Arc::new(ring::default_provider());
        let server =
            WebPkiServerVerifier::builder_with_provider(Arc::clone(&store), Arc::clone(&provider))
                .build()
                .map_err(|_| BundleError::Anchor)?;
        let client = WebPkiClientVerifier::builder_with_provider(store, provider)
            .build()
            .map_err(|_| BundleError::Anchor)?;
        let mut digest = [0_u8; 16];
        digest.copy_from_slice(&hash.finalize()[..16]);
        Ok(Self {
            roots: certs
                .into_iter()
                .map(|cert| WrappedX509::new(cert.as_ref().to_vec(), parse_x509))
                .collect(),
            digest,
            server,
            client,
        })
    }

    /// The roots as Pingora wants them for a peer.
    #[must_use]
    pub fn roots(&self) -> Arc<[WrappedX509]> {
        Arc::clone(&self.roots)
    }

    /// A digest of the roots: equal bundles give equal values.
    #[must_use]
    pub fn digest(&self) -> [u8; 16] {
        self.digest
    }

    /// The verifier of server certificates (it still checks the name, which a SPIFFE verifier
    /// ignores).
    #[must_use]
    pub(crate) fn server(&self) -> &Arc<WebPkiServerVerifier> {
        &self.server
    }

    /// The verifier of client certificates.
    #[must_use]
    pub(crate) fn client(&self) -> &Arc<dyn ClientCertVerifier> {
        &self.client
    }
}

impl fmt::Debug for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bundle")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod test {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

    use super::*;

    fn root() -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer =
            CertifiedIssuer::self_signed(params, KeyPair::generate().expect("key")).expect("ca");
        issuer.der().as_ref().to_vec()
    }

    #[test]
    fn splits_a_concatenation() {
        let (one, two) = (root(), root());
        let both = [one.clone(), two.clone()].concat();
        let certs = split_der(&both).expect("two certs");
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].as_ref(), one.as_slice());
        assert_eq!(certs[1].as_ref(), two.as_slice());
        assert!(Bundle::from_der(&both).is_ok());
    }

    #[test]
    fn refuses_what_is_not_a_bundle() {
        assert_eq!(Bundle::from_der(&[]).err(), Some(BundleError::Empty));
        assert_eq!(Bundle::from_der(b"not der").err(), Some(BundleError::Der));
        let mut cut = root();
        cut.pop();
        assert_eq!(Bundle::from_der(&cut).err(), Some(BundleError::Der));
    }
}
