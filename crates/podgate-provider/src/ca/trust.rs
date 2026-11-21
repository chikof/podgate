//! Reading the CA's certificates: `export-root`, `status`, and the parsing the rest of the CA
//! shares. Nothing here reads a key.

use std::fmt::Write as _;
use std::path::Path;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

use super::store::CaStore;
use super::{CaError, fingerprint, pem_der, renew_at};

/// What a certificate says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// The subject, in the form x509-parser prints.
    pub subject: String,
    /// Start of validity, unix seconds.
    pub not_before: i64,
    /// End of validity, unix seconds.
    pub not_after: i64,
    /// SHA-256 of the DER, upper-case hex pairs joined by `:`.
    pub fingerprint: String,
}

pub(super) fn parse_cert<'a>(
    der: &'a [u8],
    what: &'static str,
) -> Result<X509Certificate<'a>, CaError> {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, cert)| cert)
        .map_err(|_| CaError::Certificate {
            what,
            reason: "is not an X.509 certificate".into(),
        })
}

/// The DNS subtrees a critical `NameConstraints` extension permits. `None` when the certificate
/// has no such extension, or it is not critical.
pub(super) fn permitted_dns(cert: &X509Certificate<'_>) -> Option<Vec<Box<str>>> {
    let extension = cert
        .name_constraints()
        .ok()
        .flatten()
        .filter(|extension| extension.critical)?;
    Some(
        extension
            .value
            .permitted_subtrees
            .iter()
            .flatten()
            .filter_map(|subtree| match &subtree.base {
                GeneralName::DNSName(name) => Some((*name).into()),
                _ => None,
            })
            .collect(),
    )
}

/// Describes the first certificate of `pem`.
///
/// # Errors
///
/// [`CaError::Certificate`] when it is not a PEM certificate.
pub fn describe(pem: &str) -> Result<CertInfo, CaError> {
    let der = pem_der(pem)?;
    let cert = parse_cert(&der, "certificate")?;
    Ok(CertInfo {
        subject: cert.subject().to_string(),
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
        fingerprint: fingerprint(&der),
    })
}

/// The root to hand to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootExport {
    /// The root certificate, PEM.
    pub pem: String,
    /// Its SHA-256 fingerprint, upper-case hex pairs joined by `:`.
    pub fingerprint: String,
}

/// The root certificate of the CA in `dir` and its fingerprint.
///
/// # Errors
///
/// [`CaError::NotInitialized`] when `dir` holds no CA.
pub fn export_root(dir: &Path) -> Result<RootExport, CaError> {
    let store = open(dir)?;
    let pem = store.root_cert()?;
    Ok(RootExport {
        fingerprint: describe(&pem)?.fingerprint,
        pem,
    })
}

fn open(dir: &Path) -> Result<CaStore, CaError> {
    CaStore::open_existing(dir)?
        .filter(|store| store.is_initialized().unwrap_or(false))
        .ok_or_else(|| CaError::NotInitialized(dir.display().to_string().into()))
}

/// One leaf in a [`Status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafStatus {
    /// The names it holds.
    pub hosts: Vec<Box<str>>,
    /// End of validity, unix seconds.
    pub not_after: i64,
    /// When the provider issues the next one (two thirds of the lifetime), unix seconds.
    pub renew_at: i64,
}

/// The CA directory at a glance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The root.
    pub root: CertInfo,
    /// The intermediate.
    pub intermediate: CertInfo,
    /// The DNS subtrees the intermediate permits.
    pub permitted: Vec<Box<str>>,
    /// The stored leaves, by hosts.
    pub leaves: Vec<LeafStatus>,
}

/// Reads the expiry of the root, the intermediate and every stored leaf from `dir`.
///
/// # Errors
///
/// [`CaError::NotInitialized`] when `dir` holds no CA; [`CaError::Store`] when a file cannot be
/// read.
pub fn status(dir: &Path) -> Result<Status, CaError> {
    let store = open(dir)?;
    let intermediate_pem = store.intermediate_cert()?;
    let der = pem_der(&intermediate_pem)?;
    let permitted =
        permitted_dns(&parse_cert(&der, "intermediate certificate")?).unwrap_or_default();
    let mut leaves = Vec::new();
    for leaf in store.leaves()? {
        let info = describe(&leaf.cert_pem)?;
        leaves.push(LeafStatus {
            hosts: leaf.hosts,
            not_after: info.not_after,
            renew_at: renew_at(info.not_before, info.not_after),
        });
    }
    leaves.sort_by(|a, b| a.hosts.cmp(&b.hosts));
    Ok(Status {
        root: describe(&store.root_cert()?)?,
        intermediate: describe(&intermediate_pem)?,
        permitted,
        leaves,
    })
}

fn days_left(not_after: i64, now: i64) -> String {
    let secs = not_after - now;
    if secs < 0 {
        format!("expired {} days ago", -secs / 86_400)
    } else {
        format!("{} days left", secs / 86_400)
    }
}

impl Status {
    /// The text `ca status` prints, relative to `now` (unix seconds).
    #[must_use]
    pub fn render(&self, now: i64) -> String {
        let mut out = String::new();
        for (what, info) in [("root", &self.root), ("intermediate", &self.intermediate)] {
            let _ = writeln!(
                out,
                "{what}: expires {} ({}), sha256 {}",
                iso(info.not_after),
                days_left(info.not_after, now),
                info.fingerprint
            );
        }
        let _ = writeln!(out, "permitted: {}", join(&self.permitted));
        let _ = writeln!(out, "leaves: {}", self.leaves.len());
        for leaf in &self.leaves {
            let _ = writeln!(
                out,
                "  {}: expires {} ({}), renewed at {}",
                join(&leaf.hosts),
                iso(leaf.not_after),
                days_left(leaf.not_after, now),
                iso(leaf.renew_at)
            );
        }
        out
    }
}

fn join(names: &[Box<str>]) -> String {
    names
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&str>>()
        .join(", ")
}

/// `2026-11-21T12:00:00Z`.
fn iso(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

/// The subject of `cert` as rcgen writes it, so a certificate signed with it names the right
/// issuer. The CA writes only an organization and a common name.
pub(super) fn distinguished_name(cert: &X509Certificate<'_>) -> rcgen::DistinguishedName {
    let mut name = rcgen::DistinguishedName::new();
    for organization in cert.subject().iter_organization() {
        if let Ok(text) = organization.as_str() {
            name.push(rcgen::DnType::OrganizationName, text);
        }
    }
    for common in cert.subject().iter_common_name() {
        if let Ok(text) = common.as_str() {
            name.push(rcgen::DnType::CommonName, text);
        }
    }
    name
}
