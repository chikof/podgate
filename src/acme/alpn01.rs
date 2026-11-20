//! TLS-ALPN-01 (RFC 8737): the CA proves a host by opening a TLS connection to port
//! 443 that offers only the ALPN protocol `acme-tls/1`, and expects a self-signed certificate for
//! the host that carries the critical `acmeIdentifier` extension: the SHA-256 of the key
//! authorization. No HTTP follows; the CA closes after the handshake.
//!
//! **Where it is answered.** Pingora's rustls listener builds one `ServerConfig` and its ALPN
//! list can only be `h2`, `http/1.1` or one custom protocol (`TlsSettings::set_alpn`;
//! `CustomALPN::new` panics on `h2` and `http/1.1`), so `acme-tls/1` cannot be added next to
//! them. rustls then fails a hello that shares no protocol with that list before any
//! certificate resolver could help (`rustls/src/server/hs.rs`, ALPN negotiation). The listener
//! therefore never offers the protocol, and the challenge is answered ahead of it: the pre-TLS
//! hook ([`crate::tls::PreHandshake`]) reads the ClientHello, and when it offers exactly
//! `acme-tls/1` hands the connection to [`Acme::answer_alpn01`], which runs a handshake of its
//! own with a dedicated `ServerConfig` and closes the connection. Any other hello, h2 and
//! `http/1.1` clients included, takes the listener's path untouched, so normal clients never
//! see the protocol or the challenge certificate.
//!
//! **What is answered.** Only a name that an `acme` app claims exactly with
//! `tls.challenge: "tls-alpn-01"` and for which the snapshot's `acme.challenges` holds
//! `{name, key_authorization}`, which the control plane pushes after the issuer's
//! `acme_challenge {type: "tls-alpn-01", ...}` event. The certificate and its key are generated
//! once per challenge in memory and live exactly as long as the table that holds the challenge;
//! they are never added to the certificate store or the expiry gauge.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use pingora::protocols::l4::stream::Stream;
use pingora::{Error, ErrorType};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use super::Acme;
use crate::compile::{Invalid, Rejected};
use crate::host::{self, HostPattern};
use crate::tls::Violation;
use podgate_model::{ChallengeKind, Snapshot, TlsMode};

/// The ALPN protocol of the challenge, RFC 8737 section 6.2.
pub(crate) const PROTOCOL: &[u8] = b"acme-tls/1";
/// TLS-ALPN-01 answers a snapshot may list.
pub(super) const MAX_ANSWERS: usize = 1024;
/// Longest the whole challenge handshake and close may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest to wait for the alert that tells a refused client why.
const ALERT_TIMEOUT: Duration = Duration::from_secs(1);

/// One pushed TLS-ALPN-01 answer: the key authorization, and the TLS config that serves its
/// challenge certificate, built on first use.
#[derive(Debug)]
pub(super) struct Answer {
    key_authorization: Box<str>,
    config: OnceLock<Option<Arc<ServerConfig>>>,
}

impl Answer {
    pub(super) fn new(key_authorization: Box<str>) -> Self {
        Self {
            key_authorization,
            config: OnceLock::new(),
        }
    }

    pub(super) fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// The TLS config that offers only `acme-tls/1` and answers with the challenge certificate
    /// for `name`; `None` when it cannot be built.
    fn config(&self, name: &str) -> Option<&Arc<ServerConfig>> {
        self.config
            .get_or_init(|| {
                server_config(name, &self.key_authorization)
                    .inspect_err(|err| tracing::warn!(%err, name, "acme: TLS-ALPN-01 certificate"))
                    .ok()
            })
            .as_ref()
    }
}

/// Serves one certificate to every handshake. `ServerConfigBuilder::with_single_cert` would
/// check it with webpki, which refuses the critical `acmeIdentifier` extension as unknown.
#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// A TLS config whose only ALPN protocol is `acme-tls/1`, serving the challenge certificate.
fn server_config(name: &str, key_authorization: &str) -> Result<Arc<ServerConfig>, Box<str>> {
    let (cert, key) = challenge_certificate(name, key_authorization).map_err(|e| e.to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::from(key))
        .map_err(|e| e.to_string())?;
    let fixed = Fixed(Arc::new(CertifiedKey::new(vec![cert], signing_key)));
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(fixed));
    config.alpn_protocols = vec![PROTOCOL.to_vec()];
    Ok(Arc::new(config))
}

/// The throwaway self-signed certificate of RFC 8737 section 3: `name` as its only subject
/// alternative name, and the critical `acmeIdentifier` extension (`1.3.6.1.5.5.7.1.31`) holding
/// the DER OCTET STRING of the SHA-256 of `key_authorization`, with a fresh key.
///
/// # Errors
///
/// [`rcgen::Error`] when `name` is not a valid DNS name or the key cannot be generated.
pub(crate) fn challenge_certificate(
    name: &str,
    key_authorization: &str,
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), rcgen::Error> {
    let digest = Sha256::digest(key_authorization.as_bytes());
    let mut params = CertificateParams::new(vec![name.to_owned()])?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(&digest));
    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok((
        certificate.der().clone(),
        PrivatePkcs8KeyDer::from(key.serialize_der()),
    ))
}

/// Compile rules of `tls.challenge: "tls-alpn-01"`, over the literal host claims of every app
/// (`claims[i]` for `snapshot.apps[i]`):
///
/// - `tls_alpn_wildcard`: a wildcard host; the CA forbids proving one over TLS-ALPN-01.
/// - `tls_alpn_needs_acme_mode`: an `on_demand` app, whose certificates are always ordered over
///   HTTP-01, so the setting would be ignored.
pub(crate) fn reject(snapshot: &Snapshot, claims: &[Vec<HostPattern>]) -> Vec<Rejected> {
    let mut rejected = Vec::new();
    for (app, patterns) in snapshot.apps.iter().zip(claims) {
        if app.tls.challenge != ChallengeKind::TlsAlpn01 {
            continue;
        }
        let mut problem = |invalid: Invalid| {
            rejected.push(Rejected::new(app, "tls.challenge", invalid));
        };
        if app.tls.mode != TlsMode::Acme {
            problem(Invalid::new(
                "tls_alpn_needs_acme_mode",
                "challenge tls-alpn-01 needs tls.mode acme: an on_demand certificate is ordered over http-01",
            ));
        }
        for pattern in patterns {
            if let HostPattern::Wildcard(base) = pattern {
                let host = format!("*.{base}");
                problem(
                    Invalid::new(
                        "tls_alpn_wildcard",
                        format!("wildcard {host} cannot be proven over tls-alpn-01: use dns-01"),
                    )
                    .with("host", host.as_str()),
                );
            }
        }
    }
    rejected
}

impl Acme {
    /// Takes over a connection whose ClientHello offers exactly `acme-tls/1`, for SNI `name`:
    /// completes a handshake with the challenge certificate when the live table has a pending
    /// TLS-ALPN-01 challenge for it, else sends a fatal `no_application_protocol` alert. Either
    /// way the connection is over afterwards, so the returned error is what the pre-TLS hook
    /// hands back to end it: the connection never reaches the TLS listener or `request_filter`.
    pub(crate) async fn answer_alpn01(
        &self,
        stream: &mut Stream,
        name: Option<&str>,
    ) -> Box<Error> {
        let config = {
            let table = self.shared.table.load();
            name.map(host::normalize).and_then(|name| {
                let answer = table.acme().alpn_answer(&name)?;
                answer.config(&name).cloned()
            })
        };
        let Some(config) = config else {
            // Best effort: the client learns why, but the refusal does not depend on it.
            let _ = timeout(ALERT_TIMEOUT, stream.write_all(&Violation::Alpn.alert())).await;
            return Error::explain(
                ErrorType::TLSHandshakeFailure,
                "acme-tls/1 offered for a name with no pending TLS-ALPN-01 challenge",
            );
        };
        let handshake = async {
            let mut tls = TlsAcceptor::from(config).accept(&mut *stream).await?;
            tls.shutdown().await
        };
        match timeout(HANDSHAKE_TIMEOUT, handshake).await {
            Ok(Ok(())) => Error::explain(
                ErrorType::TLSHandshakeFailure,
                "TLS-ALPN-01 challenge answered; connection closed",
            ),
            Ok(Err(_)) | Err(_) => Error::explain(
                ErrorType::TLSHandshakeFailure,
                "TLS-ALPN-01 handshake failed",
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const NAME: &str = "a.test";
    const KEY_AUTHORIZATION: &str = "token.thumbprint";

    #[test]
    fn alpn01_cert_has_acme_identifier() {
        let (der, _key) = challenge_certificate(NAME, KEY_AUTHORIZATION).expect("certificate");
        let (_, cert) = x509_parser::parse_x509_certificate(&der).expect("parses");

        let extension = cert
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("the acmeIdentifier extension");
        assert!(extension.critical, "RFC 8737: the extension is critical");
        let mut expected = vec![0x04, 0x20];
        expected.extend_from_slice(&Sha256::digest(KEY_AUTHORIZATION.as_bytes()));
        assert_eq!(extension.value, expected, "DER OCTET STRING of the SHA-256");

        let alt = cert
            .subject_alternative_name()
            .expect("well formed")
            .expect("has a subject alternative name");
        let names: Vec<String> = alt
            .value
            .general_names
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["DNSName(a.test)"], "the host is the only name");
    }

    #[test]
    fn alpn01_config_offers_only_the_challenge_protocol() {
        let answer = Answer::new(KEY_AUTHORIZATION.into());
        let config = answer.config(NAME).expect("config builds");
        assert_eq!(config.alpn_protocols, [PROTOCOL.to_vec()]);
        assert!(
            std::ptr::eq(config, answer.config(NAME).expect("cached")),
            "built once per challenge"
        );
    }
}
