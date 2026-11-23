//! The TLS settings of both roles, built from the operator's files.
//!
//! Servers speak TLS 1.3 only and require a client certificate that chains to the configured CA;
//! there is no mode without it. Clients pin one CA per peer and never use the platform's roots.
//! An error names the setting, never the content of a file.

use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::config::ConfigError;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn read(field: &str, path: &Path) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|source| ConfigError::Read {
        field: field.into(),
        path: path.display().to_string().into(),
        source,
    })
}

fn certificates(field: &str, path: &Path) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let pem = read(field, path)?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::invalid(field, "is not valid PEM certificates"))?;
    if chain.is_empty() {
        return Err(ConfigError::invalid(field, "holds no certificate"));
    }
    Ok(chain)
}

fn private_key(field: &str, path: &Path) -> Result<PrivateKeyDer<'static>, ConfigError> {
    let pem = read(field, path)?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|_| ConfigError::invalid(field, "holds no private key"))
}

/// The CA certificates of `path` as a root store.
///
/// # Errors
///
/// [`ConfigError`] naming `field` when the file is unreadable, empty or holds no usable CA.
pub fn roots(field: &str, path: &Path) -> Result<RootCertStore, ConfigError> {
    let mut roots = RootCertStore::empty();
    for cert in certificates(field, path)? {
        roots.add(cert).map_err(|_| {
            ConfigError::invalid(field, "holds a certificate that is not a valid CA")
        })?;
    }
    Ok(roots)
}

/// A certificate chain and its key, kept only to build configurations.
pub struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

impl Identity {
    /// Reads `cert_file` and `key_file`; `prefix` names the table, like `client`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming `<prefix>.cert_file` or `<prefix>.key_file`.
    pub fn load(prefix: &str, cert_file: &Path, key_file: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            chain: certificates(&format!("{prefix}.cert_file"), cert_file)?,
            key: private_key(&format!("{prefix}.key_file"), key_file)?,
        })
    }

    /// A client configuration that trusts `roots` only and presents this identity.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the key does not match the certificate.
    pub fn client_config(
        &self,
        prefix: &str,
        roots: RootCertStore,
    ) -> Result<Arc<rustls::ClientConfig>, ConfigError> {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConfigError::invalid(prefix, "TLS 1.3 is unavailable"))?
            .with_root_certificates(roots)
            .with_client_auth_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|_| {
                ConfigError::invalid(prefix, "cert_file and key_file do not belong together")
            })?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }

    /// A server configuration that presents this identity and requires a client certificate
    /// signed by `client_roots`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the key does not match the certificate.
    pub fn server_config(
        &self,
        prefix: &str,
        client_roots: RootCertStore,
    ) -> Result<Arc<rustls::ServerConfig>, ConfigError> {
        let verifier =
            WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider())
                .build()
                .map_err(|_| {
                    ConfigError::invalid(format!("{prefix}.client_ca_file"), "has no usable CA")
                })?;
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| ConfigError::invalid(prefix, "TLS 1.3 is unavailable"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(self.chain.clone(), self.key.clone_key())
            .map_err(|_| {
                ConfigError::invalid(prefix, "cert_file and key_file do not belong together")
            })?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}
