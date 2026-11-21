//! `ca init`: makes the root and the name-constrained intermediate.
//!
//! The root key is written once to a path the operator chooses, outside the CA directory, to be
//! stored offline. The intermediate's key and certificate go into the CA directory and are the
//! only CA key material the running provider holds. The intermediate carries a critical
//! `NameConstraints` extension that permits exactly the allowed suffixes, so a stolen
//! intermediate key can only mint names under them, even for clients that trust the root.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType, GeneralSubtree,
    IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};

use super::names::{Suffix, parse_suffixes};
use super::store::{CaStore, Chain};
use super::trust::{distinguished_name, parse_cert, permitted_dns};
use super::{CaError, Secret, date_time, fingerprint, pem_der, unix_now};
use crate::acme::store::{StoreError, read_secret_file};

/// The root's lifetime when `--root-days` is not given: ten years.
pub const ROOT_DAYS: u32 = 3650;
/// The intermediate's lifetime when `--intermediate-days` is not given: five years.
pub const INTERMEDIATE_DAYS: u32 = 1825;
/// Certificates start this long before they are made, so a client with a slow clock accepts them.
pub(super) const BACKDATE_SECS: i64 = 300;
/// The organization of both CA certificates.
pub(super) const ORGANIZATION: &str = "podgate internal CA";

/// What `ca init` needs.
#[derive(Debug, Clone)]
pub struct InitOptions {
    /// The CA directory (mode `0700`), made when missing.
    pub dir: PathBuf,
    /// Where the root key is written, mode `0600`, created new. Must be outside `dir`.
    pub root_key_out: PathBuf,
    /// The permitted suffixes.
    pub suffixes: Vec<String>,
    /// Accept TLDs and registry suffixes such as `co.uk`.
    pub allow_public_suffix: bool,
    /// The root's lifetime in days.
    pub root_days: u32,
    /// The intermediate's lifetime in days.
    pub intermediate_days: u32,
    /// The time of issue, unix seconds.
    pub now: i64,
}

impl InitOptions {
    /// Options with the documented lifetimes and the current time.
    #[must_use]
    pub fn new(dir: PathBuf, root_key_out: PathBuf, suffixes: Vec<String>) -> Self {
        Self {
            dir,
            root_key_out,
            suffixes,
            allow_public_suffix: false,
            root_days: ROOT_DAYS,
            intermediate_days: INTERMEDIATE_DAYS,
            now: unix_now(),
        }
    }
}

/// What `ca init` made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initialized {
    /// The root certificate, PEM.
    pub root_cert: String,
    /// Its SHA-256 fingerprint, upper-case hex pairs joined by `:`.
    pub root_fingerprint: String,
    /// The intermediate certificate, PEM.
    pub intermediate_cert: String,
    /// The suffixes the intermediate permits.
    pub suffixes: Vec<Suffix>,
}

/// The intermediate's subject name.
pub(super) fn intermediate_name(common_name: &str) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::OrganizationName, ORGANIZATION);
    name.push(DnType::CommonName, common_name);
    name
}

fn ca_params(
    name: DistinguishedName,
    path_len: u8,
    now: i64,
    days: u32,
) -> Result<CertificateParams, CaError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time(now - BACKDATE_SECS)?;
    params.not_after = date_time(now + i64::from(days) * 86_400)?;
    Ok(params)
}

/// The constraints of the intermediate: DNS names under the suffixes, no IP address at all.
pub(super) fn constraints(suffixes: &[Suffix]) -> NameConstraints {
    NameConstraints {
        permitted_subtrees: suffixes
            .iter()
            .map(|suffix| GeneralSubtree::DnsName(suffix.to_string()))
            .collect(),
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    }
}

/// The root key is written like every secret here: a new file, mode `0600`, `fsync`ed.
pub(super) fn write_new_secret(path: &Path, text: &str) -> Result<(), CaError> {
    let io_err = |op: &'static str| {
        move |source: io::Error| {
            CaError::Store(StoreError::Io {
                op,
                path: path.display().to_string().into(),
                source,
            })
        }
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                CaError::Exists(path.display().to_string().into())
            } else {
                io_err("create")(err)
            }
        })?;
    file.write_all(text.as_bytes()).map_err(io_err("write"))?;
    file.sync_all().map_err(io_err("fsync"))
}

/// Makes a root and an intermediate, writes the root key to `options.root_key_out` and the
/// intermediate into the CA directory.
///
/// # Errors
///
/// [`CaError`] for a bad or public suffix list, a root key path inside the CA directory or one
/// that exists, a directory that is already initialized, or a failed write. Nothing is written
/// before the checks pass.
pub fn init(options: &InitOptions) -> Result<Initialized, CaError> {
    let suffixes = parse_suffixes(&options.suffixes, options.allow_public_suffix)?;
    let store = CaStore::create(&options.dir)?;
    if store.is_initialized()? {
        return Err(CaError::AlreadyInitialized(
            options.dir.display().to_string().into(),
        ));
    }
    refuse_root_key_in(&options.root_key_out, store.dir())?;

    let root_key = KeyPair::generate()?;
    let root_key_pem = Secret::new(root_key.serialize_pem());
    let mut root_name = DistinguishedName::new();
    root_name.push(DnType::OrganizationName, ORGANIZATION);
    root_name.push(
        DnType::CommonName,
        format!(
            "podgate internal root {}",
            short_id(root_key.public_key_raw())
        ),
    );
    let root_params = ca_params(root_name, 1, options.now, options.root_days)?;
    let root = rcgen::CertifiedIssuer::self_signed(root_params, root_key)?;

    let intermediate_key = KeyPair::generate()?;
    let mut params = ca_params(
        intermediate_name(&format!(
            "podgate internal intermediate {}",
            short_id(intermediate_key.public_key_raw())
        )),
        0,
        options.now,
        options.intermediate_days,
    )?;
    params.name_constraints = Some(constraints(&suffixes));
    let intermediate = params.signed_by(&intermediate_key, &root)?;

    let (root_cert, intermediate_cert) = (root.pem(), intermediate.pem());
    let intermediate_key = Secret::new(intermediate_key.serialize_pem());
    // Order: the root key first, so a failure later never loses the only copy; the directory's
    // commit point, the intermediate certificate, last.
    write_new_secret(&options.root_key_out, root_key_pem.expose())?;
    store.save_chain(&Chain {
        root_cert: &root_cert,
        intermediate_key: &intermediate_key,
        intermediate_cert: &intermediate_cert,
    })?;
    Ok(Initialized {
        root_fingerprint: fingerprint(&pem_der(&root_cert)?),
        root_cert,
        intermediate_cert,
        suffixes,
    })
}

fn short_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .skip(1)
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A root key inside the CA directory would put the offline key on the online node.
fn refuse_root_key_in(path: &Path, dir: &Path) -> Result<(), CaError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent =
        std::fs::canonicalize(parent.unwrap_or_else(|| Path::new("."))).map_err(|source| {
            CaError::Store(StoreError::Io {
                op: "resolve",
                path: path.display().to_string().into(),
                source,
            })
        })?;
    let dir = std::fs::canonicalize(dir).map_err(|source| {
        CaError::Store(StoreError::Io {
            op: "resolve",
            path: dir.display().to_string().into(),
            source,
        })
    })?;
    if parent.starts_with(&dir) {
        return Err(CaError::RootKeyInStateDir(
            path.display().to_string().into(),
        ));
    }
    Ok(())
}

/// What `ca rotate` needs.
#[derive(Debug, Clone)]
pub struct RotateOptions {
    /// The CA directory.
    pub dir: PathBuf,
    /// The root key file, brought back from offline storage for this one command.
    pub root_key: PathBuf,
    /// The new intermediate's lifetime in days.
    pub intermediate_days: u32,
    /// The time of issue, unix seconds.
    pub now: i64,
}

/// Replaces the intermediate with a new key and certificate under the same root, permitting the
/// same suffixes. Leaves issued under the old intermediate stay valid until they expire; the
/// provider takes the new intermediate when it restarts.
///
/// # Errors
///
/// [`CaError`] when the directory holds no CA, the root key is not private or does not belong to
/// the root certificate, or a write fails.
pub fn rotate(options: &RotateOptions) -> Result<Initialized, CaError> {
    let store = CaStore::open_existing(&options.dir)?
        .filter(|store| store.is_initialized().unwrap_or(false))
        .ok_or_else(|| CaError::NotInitialized(options.dir.display().to_string().into()))?;
    let root_cert = store.root_cert()?;
    let root_der = pem_der(&root_cert)?;
    let root = parse_cert(&root_der, "root certificate")?;
    let root_key =
        KeyPair::from_pem(read_secret_file(&options.root_key)?.expose()).map_err(|_| {
            CaError::Certificate {
                what: "root key",
                reason: "is not a PEM private key".into(),
            }
        })?;
    if root.public_key().subject_public_key.data.as_ref() != root_key.public_key_raw() {
        return Err(CaError::Certificate {
            what: "root key",
            reason: "does not belong to root.cert.pem".into(),
        });
    }
    let previous = pem_der(&store.intermediate_cert()?)?;
    let permitted = permitted_dns(&parse_cert(&previous, "intermediate certificate")?)
        .filter(|permitted| !permitted.is_empty())
        .ok_or(CaError::Unconstrained)?;
    let suffixes = permitted
        .iter()
        .map(|text| Suffix::parse(text))
        .collect::<Result<Vec<_>, _>>()?;

    let issuer = Issuer::new(
        ca_params(distinguished_name(&root), 1, options.now, ROOT_DAYS)?,
        root_key,
    );
    let key = KeyPair::generate()?;
    let mut params = ca_params(
        intermediate_name(&format!(
            "podgate internal intermediate {}",
            short_id(key.public_key_raw())
        )),
        0,
        options.now,
        options.intermediate_days,
    )?;
    params.name_constraints = Some(constraints(&suffixes));
    let intermediate_cert = params.signed_by(&key, &issuer)?.pem();
    store.replace_intermediate(&Secret::new(key.serialize_pem()), &intermediate_cert)?;
    Ok(Initialized {
        root_fingerprint: fingerprint(&root_der),
        root_cert,
        intermediate_cert,
        suffixes,
    })
}
