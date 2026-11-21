//! What the proxy knows about one certificate before it asks for a staple: its fingerprint, the
//! `CertID` hashes the responder must echo, the responder URL from the certificate's own
//! Authority Information Access, and the request to send.

use pingora::tls::CertificateDer;
use podgate_model::OcspMode;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::der::Encode;
use x509_cert::der::asn1::{Null, ObjectIdentifier, OctetString};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{CertId, OcspRequest, Request, TbsRequest, Version};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::reason::Reason;

/// `id-sha1`, the hash every responder accepts (RFC 5019 section 2.1.1).
pub(super) const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
/// `id-sha256`, accepted in a response when the responder prefers it.
pub(super) const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// The TLS Feature extension of RFC 7633.
const TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";
/// The `status_request` feature value inside it.
const STATUS_REQUEST: u8 = 5;
/// A request this proxy builds never comes near this; it keeps the GET target small.
const MAX_REQUEST: usize = 512;

/// A SHA-256 digest of a certificate's DER: how the registry names a certificate across
/// snapshots.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// The fingerprint of the certificate with DER encoding `der`.
    #[must_use]
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0[..6] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

/// The facts a response is checked against, and the request that asks for it.
#[derive(Debug)]
pub struct Identity {
    /// The leaf's serial number without leading zero bytes.
    pub(super) serial: Box<[u8]>,
    pub(super) name_sha1: [u8; 20],
    pub(super) key_sha1: [u8; 20],
    pub(super) name_sha256: [u8; 32],
    pub(super) key_sha256: [u8; 32],
    responder: Box<str>,
    request: Box<[u8]>,
}

impl Identity {
    /// Decides whether the certificate whose chain is `chain` (leaf first) gets a staple under
    /// `mode`, and builds what a fetch needs.
    ///
    /// `None`: the mode does not call for one (`off`, `auto` without must-staple, `on` without
    /// an OCSP responder in the certificate). `Some(Err(_))`: the certificate should be stapled
    /// and cannot be.
    #[must_use]
    pub fn of(chain: &[CertificateDer<'_>], mode: OcspMode) -> Option<Result<Self, Reason>> {
        if mode == OcspMode::Off {
            return None;
        }
        let (_, leaf) = X509Certificate::from_der(chain.first()?).ok()?;
        let must_staple = has_must_staple(&leaf);
        let responder = responder_url(&leaf);
        let wanted = match mode {
            OcspMode::Auto => must_staple,
            OcspMode::On => responder.is_some(),
            OcspMode::Off => false,
        };
        if !wanted {
            return None;
        }
        let Some(responder) = responder else {
            return Some(Err(Reason::NoResponder));
        };
        let Some(issuer_der) = chain.get(1) else {
            return Some(Err(Reason::NoIssuer));
        };
        let Ok((_, issuer)) = X509Certificate::from_der(issuer_der) else {
            return Some(Err(Reason::NoIssuer));
        };
        if issuer.subject().as_raw() != leaf.issuer().as_raw() {
            return Some(Err(Reason::NoIssuer));
        }
        Some(Self::build(&leaf, &issuer, responder))
    }

    fn build(
        leaf: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
        responder: Box<str>,
    ) -> Result<Self, Reason> {
        let name = leaf.issuer().as_raw();
        let key = issuer.public_key().subject_public_key.data.as_ref();
        let mut identity = Self {
            serial: trim_zeros(leaf.raw_serial()).into(),
            name_sha1: Sha1::digest(name).into(),
            key_sha1: Sha1::digest(key).into(),
            name_sha256: Sha256::digest(name).into(),
            key_sha256: Sha256::digest(key).into(),
            responder,
            request: Box::default(),
        };
        let request = identity.encode_request().map_err(|_| Reason::Malformed)?;
        if request.len() >= MAX_REQUEST {
            return Err(Reason::Malformed);
        }
        identity.request = request.into();
        Ok(identity)
    }

    fn encode_request(&self) -> Result<Vec<u8>, x509_cert::der::Error> {
        let cert_id = CertId {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: SHA1,
                parameters: Some(Null.into()),
            },
            issuer_name_hash: OctetString::new(self.name_sha1)?,
            issuer_key_hash: OctetString::new(self.key_sha1)?,
            serial_number: SerialNumber::new(&self.serial)?,
        };
        OcspRequest {
            tbs_request: TbsRequest {
                version: Version::V1,
                requestor_name: None,
                request_list: vec![Request {
                    req_cert: cert_id,
                    single_request_extensions: None,
                }],
                request_extensions: None,
            },
            optional_signature: None,
        }
        .to_der()
    }

    /// The responder URL the certificate names.
    #[must_use]
    pub fn responder(&self) -> &str {
        &self.responder
    }

    /// The DER `OCSPRequest` for this certificate: one `CertID` hashed with SHA-1, no nonce and
    /// no signature (RFC 5019), under 512 bytes.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }
}

pub(super) fn trim_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[start..]
}

/// Whether the TLS Feature extension lists `status_request`, which makes the certificate
/// must-staple (RFC 7633). The value is `SEQUENCE OF INTEGER`; a malformed one means no.
fn has_must_staple(leaf: &X509Certificate<'_>) -> bool {
    leaf.extensions()
        .iter()
        .filter(|extension| extension.oid.to_id_string() == TLS_FEATURE)
        .any(|extension| {
            let [0x30, len, items @ ..] = extension.value else {
                return false;
            };
            let (features, rest) = items.as_chunks::<3>();
            usize::from(*len) == items.len()
                && *len < 0x80
                && rest.is_empty()
                && features.contains(&[0x02, 0x01, STATUS_REQUEST])
        })
}

/// The first `http` or `https` OCSP responder URL in the certificate's Authority Information
/// Access.
fn responder_url(leaf: &X509Certificate<'_>) -> Option<Box<str>> {
    leaf.extensions().iter().find_map(|extension| {
        let ParsedExtension::AuthorityInfoAccess(access) = extension.parsed_extension() else {
            return None;
        };
        access.iter().find_map(|description| {
            if description.access_method != OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                return None;
            }
            match &description.access_location {
                GeneralName::URI(uri)
                    if uri.starts_with("http://") || uri.starts_with("https://") =>
                {
                    Some(Box::from(*uri))
                }
                _ => None,
            }
        })
    })
}
