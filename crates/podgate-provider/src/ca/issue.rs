//! Signing leaf certificates with the intermediate.
//!
//! A leaf is ECDSA P-256 with `dNSName` subject alternative names only, the `serverAuth`
//! extended key usage and no CA capability. Its validity is `days` from the moment of issue and
//! never reaches past the intermediate's.

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

use super::init::BACKDATE_SECS;
use super::trust::{describe, distinguished_name, parse_cert, permitted_dns};
use super::{CaError, Secret, date_time};

/// A leaf as issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    /// The chain served to clients: the leaf, then the intermediate.
    pub chain_pem: String,
    /// The leaf's private key.
    pub key: Secret,
    /// Start of validity, unix seconds.
    pub not_before: i64,
    /// End of validity, unix seconds.
    pub not_after: i64,
}

/// The intermediate: its key, its certificate and what the certificate permits.
pub struct Signer {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    not_after: i64,
    permitted: Vec<Box<str>>,
}

/// The key is never shown.
impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("not_after", &self.not_after)
            .field("permitted", &self.permitted)
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Reads the intermediate. The key must belong to the certificate, and the certificate must
    /// carry a critical `NameConstraints` extension with permitted DNS subtrees: an
    /// unconstrained intermediate is refused.
    ///
    /// # Errors
    ///
    /// [`CaError`] when the PEM is not what `ca init` writes, the key does not match, or the
    /// certificate is not name-constrained.
    pub fn from_pem(cert_pem: &str, key: &Secret) -> Result<Self, CaError> {
        let key_pair = KeyPair::from_pem(key.expose()).map_err(|_| CaError::Certificate {
            what: "intermediate key",
            reason: "is not a PEM private key".into(),
        })?;
        let der = super::pem_der(cert_pem)?;
        let cert = parse_cert(&der, "intermediate certificate")?;
        if cert.public_key().subject_public_key.data.as_ref() != key_pair.public_key_raw() {
            return Err(CaError::Certificate {
                what: "intermediate key",
                reason: "does not belong to intermediate.cert.pem".into(),
            });
        }
        let permitted = permitted_dns(&cert)
            .filter(|permitted| !permitted.is_empty())
            .ok_or(CaError::Unconstrained)?;
        let info = describe(cert_pem)?;
        let issuer = Issuer::new(issuer_params(distinguished_name(&cert)), key_pair);
        Ok(Self {
            issuer,
            cert_pem: cert_pem.to_owned(),
            not_after: info.not_after,
            permitted,
        })
    }

    /// The DNS subtrees the certificate permits, as written in it.
    #[must_use]
    pub fn permitted(&self) -> &[Box<str>] {
        &self.permitted
    }

    /// The intermediate certificate, PEM.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The end of the intermediate's validity, unix seconds.
    #[must_use]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    /// Signs a leaf for `names` with no policy check at all: the intermediate's
    /// `NameConstraints` are what hold when a name is outside the suffixes. The provider goes
    /// through [`super::Ca::issue`], which refuses first; this is what a thief of the key has,
    /// and what the tests use to prove the extension is enough.
    ///
    /// # Errors
    ///
    /// [`CaError`] when `names` is empty or not DNS names, or the intermediate has expired.
    pub fn issue_unchecked(&self, names: &[&str], now: i64, days: u32) -> Result<Leaf, CaError> {
        if now >= self.not_after {
            return Err(CaError::IntermediateExpired);
        }
        let Some(first) = names.first() else {
            return Err(CaError::Certificate {
                what: "leaf",
                reason: "has no names".into(),
            });
        };
        let mut params = CertificateParams::default();
        params.subject_alt_names = names
            .iter()
            .map(|name| {
                (*name)
                    .to_owned()
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|_| CaError::Certificate {
                        what: "leaf",
                        reason: format!("{name:?} is not a DNS name").into(),
                    })
            })
            .collect::<Result<_, _>>()?;
        let mut subject = DistinguishedName::new();
        if first.len() <= 64 {
            subject.push(DnType::CommonName, *first);
        }
        params.distinguished_name = subject;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let not_before = now - BACKDATE_SECS;
        let not_after = (now + i64::from(days) * 86_400).min(self.not_after);
        params.not_before = date_time(not_before)?;
        params.not_after = date_time(not_after)?;
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(Leaf {
            chain_pem: format!("{}{}", cert.pem(), self.cert_pem),
            key: Secret::new(key.serialize_pem()),
            not_before,
            not_after,
        })
    }
}

fn issuer_params(name: DistinguishedName) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}
