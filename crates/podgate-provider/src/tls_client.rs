//! The TLS settings of an outbound client that talks to a server of the operator's: a CA to trust
//! instead of the platform's roots, and an optional client certificate. The files are read by the
//! source; this turns their PEM into a rustls configuration.
//!
//! An error names the setting (`tls.ca_file`, `tls.cert_file`, `tls.key_file`), never the content
//! of a file.

use std::sync::Arc;

use hyper_rustls::ConfigBuilderExt as _;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// The PEM of the TLS settings, read from the files by the source.
#[derive(Default)]
pub(crate) struct TlsPem {
    pub(crate) ca: Option<Vec<u8>>,
    pub(crate) cert: Option<Vec<u8>>,
    pub(crate) key: Option<Vec<u8>>,
}

pub(crate) fn tls_config(pem: TlsPem) -> Result<rustls::ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| format!("TLS: {err}"))?;
    let builder = match pem.ca {
        Some(ca) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(&ca) {
                let cert = cert.map_err(|err| format!("tls.ca_file: {err}"))?;
                roots
                    .add(cert)
                    .map_err(|err| format!("tls.ca_file: {err}"))?;
            }
            if roots.is_empty() {
                return Err("tls.ca_file: holds no certificate".to_owned());
            }
            builder.with_root_certificates(roots)
        }
        None => builder
            .with_native_roots()
            .map_err(|err| format!("cannot load the platform's root certificates ({err})"))?,
    };
    match (pem.cert, pem.key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| format!("tls.cert_file: {err}"))?;
            if chain.is_empty() {
                return Err("tls.cert_file: holds no certificate".to_owned());
            }
            // The error of a bad key names the file, never its content.
            let key = PrivateKeyDer::from_pem_slice(&key)
                .map_err(|_| "tls.key_file: holds no private key".to_owned())?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|err| format!("tls.cert_file and tls.key_file: {err}"))
        }
        _ => Ok(builder.with_no_client_auth()),
    }
}
