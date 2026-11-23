//! A private certificate authority for the tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Pki {
    issuer: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    pub ca_pem: String,
}

impl Pki {
    pub fn new() -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "federation test ca");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().expect("key"))
                .expect("self-signed CA");
        let ca_pem = issuer.pem();
        Self { issuer, ca_pem }
    }

    pub fn ca_file(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.pem"));
        std::fs::write(&path, &self.ca_pem).expect("write CA");
        path
    }

    /// A certificate for `127.0.0.1` and `localhost`, valid now, and its key, as files.
    pub fn server_files(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let (cert, key) = self.leaf(vec!["127.0.0.1".to_owned(), "localhost".to_owned()], name);
        self.write(dir, name, &cert, &key)
    }

    /// A client certificate with no names.
    pub fn client_files(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let (cert, key) = self.leaf(Vec::new(), name);
        self.write(dir, name, &cert, &key)
    }

    fn leaf(&self, names: Vec<String>, cn: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(names).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let cert = params.signed_by(&key, &self.issuer).expect("sign");
        (cert.pem(), key.serialize_pem())
    }

    fn write(&self, dir: &Path, name: &str, cert: &str, key: &str) -> (PathBuf, PathBuf) {
        let cert_path = dir.join(format!("{name}.pem"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert).expect("write cert");
        std::fs::write(&key_path, key).expect("write key");
        (cert_path, key_path)
    }

    /// A server configuration for the fake peers: this CA's server certificate, and a client
    /// certificate required from `client_ca`.
    pub fn server_config(&self, client_ca: &Pki) -> Arc<rustls::ServerConfig> {
        let dir = super::Dir::new();
        let (cert, key) = self.server_files(&dir.0, "srv");
        let ca = client_ca.ca_file(&dir.0, "client-ca");
        let identity =
            podgate_federation::tls::Identity::load("srv", &cert, &key).expect("identity");
        identity
            .server_config(
                "srv",
                podgate_federation::tls::roots("srv", &ca).expect("roots"),
            )
            .expect("server config")
    }
}

impl Pki {
    /// A client certificate that expired years ago.
    pub fn expired_client_files(&self, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let cert = params.signed_by(&key, &self.issuer).expect("sign");
        self.write(dir, name, &cert.pem(), &key.serialize_pem())
    }
}
