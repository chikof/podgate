//! X.509 SVIDs: a workload's certificate chain and private key, as the Workload API hands them
//! over, and the SPIFFE ID found in a certificate.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use pingora::utils::tls::CertKey;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::CertifiedKey;
use thiserror::Error;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

use super::bundle::{BundleError, split_der};
use super::policy::SpiffeId;

/// Most certificates in the chain of one SVID.
const MAX_CHAIN: usize = 8;

/// An SVID the process cannot use.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SvidError {
    /// The certificate bytes are not DER certificates, or there is no leaf.
    #[error("the SVID chain is not a sequence of DER certificates")]
    Chain,
    /// The leaf has no SPIFFE ID in its URI SAN, or more than one URI SAN.
    #[error("the SVID leaf has no single SPIFFE ID in its URI SAN")]
    Id,
    /// The ID the agent announced is not the one in the certificate.
    #[error("the SVID announces {announced} but its certificate says {found}")]
    Mismatch {
        /// What the response's `spiffe_id` field said.
        announced: Box<str>,
        /// What the leaf certificate says.
        found: Box<str>,
    },
    /// The private key is not one rustls can sign with, or does not belong to the leaf.
    #[error("the SVID private key is unusable or does not match the leaf")]
    Key,
}

/// The single SPIFFE ID in the URI SANs of `cert`: `None` when there is none, more than one URI
/// SAN, or a URI that is no SPIFFE ID.
#[must_use]
pub(crate) fn id_in(cert: &X509Certificate<'_>) -> Option<SpiffeId> {
    let Ok(Some(extension)) = cert.subject_alternative_name() else {
        return None;
    };
    let mut uris = extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        });
    let (Some(uri), None) = (uris.next(), uris.next()) else {
        return None;
    };
    SpiffeId::parse(uri).ok()
}

/// The SPIFFE ID of the certificate `der`, per [`id_in`].
#[must_use]
pub(crate) fn id_of_der(der: &[u8]) -> Option<SpiffeId> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    rest.is_empty().then(|| id_in(&cert)).flatten()
}

/// One identity the agent issued to this process.
pub struct Svid {
    id: SpiffeId,
    hint: Box<str>,
    serial: Box<str>,
    not_after: SystemTime,
    cert_key: Arc<CertKey>,
}

impl Svid {
    /// Builds an SVID from the fields of a Workload API `X509SVID`: its announced `spiffe_id`,
    /// the chain (leaf first) as concatenated DER, the private key as PKCS#8 DER, and its hint.
    ///
    /// # Errors
    ///
    /// [`SvidError`] when the chain does not parse, the leaf's ID is not the announced one, or
    /// the key is not the leaf's.
    pub fn parse(
        announced: &str,
        chain_der: &[u8],
        key_der: &[u8],
        hint: &str,
    ) -> Result<Self, SvidError> {
        let chain = split_der(chain_der).map_err(|_: BundleError| SvidError::Chain)?;
        if chain.is_empty() || chain.len() > MAX_CHAIN {
            return Err(SvidError::Chain);
        }
        let (_, leaf) =
            x509_parser::parse_x509_certificate(chain[0].as_ref()).map_err(|_| SvidError::Chain)?;
        let id = id_in(&leaf).ok_or(SvidError::Id)?;
        if id.to_string() != announced {
            return Err(SvidError::Mismatch {
                announced: announced.into(),
                found: id.to_string().into(),
            });
        }
        let key = PrivateKeyDer::try_from(key_der.to_vec()).map_err(|_| SvidError::Key)?;
        let signing = any_supported_type(&key).map_err(|_| SvidError::Key)?;
        CertifiedKey::new(chain.clone(), signing)
            .keys_match()
            .map_err(|_| SvidError::Key)?;
        let seconds = leaf.validity().not_after.timestamp();
        let not_after =
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds).unwrap_or(0));
        let serial = leaf.raw_serial_as_string().into_boxed_str();
        let cert_key = Arc::new(CertKey::new(
            chain.iter().map(|cert| cert.as_ref().to_vec()).collect(),
            key_der.to_vec(),
        ));
        Ok(Self {
            id,
            hint: hint.into(),
            serial,
            not_after,
            cert_key,
        })
    }

    /// The SPIFFE ID of the workload.
    #[must_use]
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    /// The agent's label for this identity; empty when it has none.
    #[must_use]
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// The serial number of the leaf, as hex.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// When the leaf expires.
    #[must_use]
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// Whether the SVID has not expired at `now`.
    #[must_use]
    pub fn valid_at(&self, now: SystemTime) -> bool {
        now < self.not_after
    }

    /// The chain and key as Pingora presents them to a server.
    #[must_use]
    pub fn cert_key(&self) -> Arc<CertKey> {
        Arc::clone(&self.cert_key)
    }
}

impl fmt::Debug for Svid {
    /// Names the identity and never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Svid")
            .field("id", &self.id.to_string())
            .field("hint", &self.hint)
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
