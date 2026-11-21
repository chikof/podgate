//! Judging an OCSP response before it may be stapled.
//!
//! A response is served only when all of this holds: it is a well-formed `successful`
//! `BasicOCSPResponse` with exactly one single response; that response names this certificate's
//! serial and issuer (name hash and key hash); it says `good`; `thisUpdate` is not in the future
//! and `nextUpdate` is; and it is signed by the issuer or by a delegated responder that the
//! issuer signed and that carries `id-kp-OCSPSigning`. Signatures are checked with the
//! signature algorithms of rustls's crypto provider, the same code that verifies TLS
//! certificates, so no extra crypto library is linked. The structures are parsed by the
//! RustCrypto `x509-ocsp` crate.

use std::time::SystemTime;

use pingora::tls::{CryptoProvider, install_default_crypto_provider};
use sha1::Sha1;
use sha2::Digest;
use x509_cert::Certificate;
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::{Decode, Encode, Header, Reader, SliceReader};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, SingleResponse,
};

use super::identity::{Identity, SHA1, SHA256, trim_zeros};
use super::reason::Reason;

/// The most bytes of a response this proxy reads or serves.
pub const MAX_RESPONSE: usize = 64 * 1024;

const OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// A response that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The response exactly as the responder sent it: what is stapled.
    pub der: Vec<u8>,
    /// When the responder says the status was true.
    pub this_update: SystemTime,
    /// When the status stops being valid.
    pub next_update: SystemTime,
}

/// Verifies `response` for the certificate described by `identity` at time `now`.
/// `issuer_der` is the issuer certificate from the served chain.
///
/// # Errors
///
/// The [`Reason`] of the first check that fails. [`Reason::Revoked`] means the responder says the
/// certificate is revoked.
pub fn verify(
    response: &[u8],
    identity: &Identity,
    issuer_der: &[u8],
    now: SystemTime,
) -> Result<Verified, Reason> {
    if response.len() > MAX_RESPONSE {
        return Err(Reason::Oversized);
    }
    let outer = OcspResponse::from_der(response).map_err(|_| Reason::Malformed)?;
    if outer.response_status != OcspResponseStatus::Successful {
        return Err(Reason::NotSuccessful);
    }
    let bytes = outer.response_bytes.ok_or(Reason::Malformed)?;
    if bytes.response_type != OCSP_BASIC {
        return Err(Reason::NotBasic);
    }
    let basic_der = bytes.response.as_bytes();
    let basic = BasicOcspResponse::from_der(basic_der).map_err(|_| Reason::Malformed)?;
    let signed = signed_bytes(basic_der).ok_or(Reason::Malformed)?;
    let [single] = basic.tbs_response_data.responses.as_slice() else {
        return Err(Reason::ResponseCount);
    };
    check_identity(single, identity)?;
    match single.cert_status {
        CertStatus::Good(_) => {}
        CertStatus::Revoked(_) => return Err(Reason::Revoked),
        CertStatus::Unknown(_) => return Err(Reason::UnknownStatus),
    }
    let this_update = single.this_update.0.to_system_time();
    let next_update = single
        .next_update
        .ok_or(Reason::NoNextUpdate)?
        .0
        .to_system_time();
    if this_update > now {
        return Err(Reason::NotYetValid);
    }
    if next_update <= now || next_update <= this_update {
        return Err(Reason::Expired);
    }
    let issuer = Certificate::from_der(issuer_der).map_err(|_| Reason::NoIssuer)?;
    let signer = signer_key(&basic, &issuer, now)?;
    verify_signature(
        &signer,
        &basic.signature_algorithm,
        signed,
        basic.signature.raw_bytes(),
    )?;
    Ok(Verified {
        der: response.to_vec(),
        this_update,
        next_update,
    })
}

/// The single response must be about this certificate: its serial, then its issuer.
fn check_identity(single: &SingleResponse, identity: &Identity) -> Result<(), Reason> {
    let id = &single.cert_id;
    if trim_zeros(id.serial_number.as_bytes()) != &*identity.serial {
        return Err(Reason::WrongSerial);
    }
    let (name, key): (&[u8], &[u8]) = if id.hash_algorithm.oid == SHA1 {
        (&identity.name_sha1, &identity.key_sha1)
    } else if id.hash_algorithm.oid == SHA256 {
        (&identity.name_sha256, &identity.key_sha256)
    } else {
        return Err(Reason::WrongIssuer);
    };
    if id.issuer_name_hash.as_bytes() == name && id.issuer_key_hash.as_bytes() == key {
        Ok(())
    } else {
        Err(Reason::WrongIssuer)
    }
}

/// The exact bytes of `tbsResponseData` inside a `BasicOCSPResponse`, which the signature covers.
/// They are cut from the input rather than re-encoded, so a responder that encodes something in
/// a different but valid way is still checked against what it signed.
fn signed_bytes(basic: &[u8]) -> Option<&[u8]> {
    let mut reader = SliceReader::new(basic).ok()?;
    Header::decode(&mut reader).ok()?;
    let start = usize::try_from(reader.position()).ok()?;
    let inner = Header::decode(&mut reader).ok()?;
    let end = usize::try_from(reader.position())
        .ok()?
        .checked_add(usize::try_from(inner.length).ok()?)?;
    basic.get(start..end)
}

/// The public key that must have signed the response: the issuer's, or a delegated responder's
/// that the issuer vouches for.
fn signer_key(
    basic: &BasicOcspResponse,
    issuer: &Certificate,
    now: SystemTime,
) -> Result<SubjectPublicKeyInfoOwned, Reason> {
    let issuer_key = &issuer.tbs_certificate.subject_public_key_info;
    let responder = &basic.tbs_response_data.responder_id;
    let is_issuer = match responder {
        ResponderId::ByName(name) => *name == issuer.tbs_certificate.subject,
        ResponderId::ByKey(hash) => {
            hash.as_bytes() == Sha1::digest(key_bytes(issuer_key)).as_slice()
        }
    };
    if is_issuer {
        return Ok(issuer_key.clone());
    }
    let delegated = basic
        .certs
        .iter()
        .flatten()
        .find(|cert| match responder {
            ResponderId::ByName(name) => *name == cert.tbs_certificate.subject,
            ResponderId::ByKey(hash) => {
                hash.as_bytes()
                    == Sha1::digest(key_bytes(&cert.tbs_certificate.subject_public_key_info))
                        .as_slice()
            }
        })
        .ok_or(Reason::ResponderNotAuthorized)?;
    authorize(delegated, issuer, now)?;
    Ok(delegated.tbs_certificate.subject_public_key_info.clone())
}

fn key_bytes(spki: &SubjectPublicKeyInfoOwned) -> &[u8] {
    spki.subject_public_key.raw_bytes()
}

/// A delegated responder certificate is accepted when the issuer itself signed it, it is valid
/// now, and it carries the OCSP signing extended key usage (RFC 6960 section 4.2.2.2).
fn authorize(delegated: &Certificate, issuer: &Certificate, now: SystemTime) -> Result<(), Reason> {
    let tbs = &delegated.tbs_certificate;
    if tbs.issuer != issuer.tbs_certificate.subject {
        return Err(Reason::ResponderNotAuthorized);
    }
    let validity = &tbs.validity;
    if validity.not_before.to_system_time() > now || validity.not_after.to_system_time() <= now {
        return Err(Reason::ResponderNotAuthorized);
    }
    let signing = tbs
        .extensions
        .iter()
        .flatten()
        .filter(|extension| extension.extn_id == EXTENDED_KEY_USAGE)
        .filter_map(|extension| ExtendedKeyUsage::from_der(extension.extn_value.as_bytes()).ok())
        .any(|usage| usage.0.contains(&OCSP_SIGNING));
    if !signing {
        return Err(Reason::ResponderNotAuthorized);
    }
    let signed = tbs.to_der().map_err(|_| Reason::Malformed)?;
    verify_signature(
        &issuer.tbs_certificate.subject_public_key_info,
        &delegated.signature_algorithm,
        &signed,
        delegated.signature.raw_bytes(),
    )
    .map_err(|reason| match reason {
        Reason::BadSignature => Reason::ResponderNotAuthorized,
        other => other,
    })
}

/// The content of an `AlgorithmIdentifier`, without its `SEQUENCE` header: the form the crypto
/// provider describes its algorithms in.
fn alg_content(alg: &AlgorithmIdentifierOwned) -> Option<Vec<u8>> {
    let der = alg.to_der().ok()?;
    let (tag, rest) = der.split_first()?;
    let (length, rest) = rest.split_first()?;
    (*tag == 0x30 && *length < 0x80 && usize::from(*length) == rest.len()).then(|| rest.to_vec())
}

/// Verifies `signature` over `message` with `key`, using the algorithm the response names and
/// the verification algorithms of the process's rustls crypto provider.
fn verify_signature(
    key: &SubjectPublicKeyInfoOwned,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Reason> {
    install_default_crypto_provider();
    let provider = CryptoProvider::get_default().ok_or(Reason::UnsupportedAlgorithm)?;
    let signature_id = alg_content(algorithm).ok_or(Reason::UnsupportedAlgorithm)?;
    let key_id = alg_content(&key.algorithm).ok_or(Reason::UnsupportedAlgorithm)?;
    let mut known = false;
    for candidate in provider.signature_verification_algorithms.all {
        if candidate.signature_alg_id().as_ref() != signature_id
            || candidate.public_key_alg_id().as_ref() != key_id
        {
            continue;
        }
        known = true;
        if candidate
            .verify_signature(key_bytes(key), message, signature)
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(if known {
        Reason::BadSignature
    } else {
        Reason::UnsupportedAlgorithm
    })
}
