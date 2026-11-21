//! Judging certificates by SPIFFE ID: the verifier of upstream servers and the rule for clients.
//!
//! Both do what the SPIFFE standard asks of an X.509-SVID peer: the chain must lead to a root of
//! the peer's trust domain, and the single SPIFFE ID in the leaf's URI SAN must be one the
//! caller allows. The DNS name is not checked, because a SPIFFE identity replaces it.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};

use super::Store;
use super::bundle::Bundle;
use super::policy::{IdPattern, SpiffeId, any_matches};
use super::svid::id_of_der;

fn refused() -> Error {
    Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

/// Verifies the certificate of an upstream server: a chain to the trust domain's bundle and a
/// SPIFFE ID that both the transport's `ids` and the tenant's `allowed_server_ids` permit.
///
/// It is built per connection from the bundle that is live at that moment, and is what
/// `pool_key` of the connection stands for: the bundle's digest is part of it.
#[derive(Debug)]
pub(crate) struct ServerVerifier {
    bundle: Arc<Bundle>,
    trust_domain: Box<str>,
    ids: Arc<[IdPattern]>,
    allowed: Arc<[IdPattern]>,
}

impl ServerVerifier {
    pub(crate) fn new(
        bundle: Arc<Bundle>,
        trust_domain: &str,
        ids: &Arc<[IdPattern]>,
        allowed: &Arc<[IdPattern]>,
    ) -> Self {
        Self {
            bundle,
            trust_domain: trust_domain.into(),
            ids: Arc::clone(ids),
            allowed: Arc::clone(allowed),
        }
    }

    /// Whether `id` is a server this verifier accepts.
    fn accepts(&self, id: &SpiffeId) -> bool {
        id.trust_domain() == &*self.trust_domain
            && any_matches(&self.ids, id)
            && any_matches(&self.allowed, id)
    }
}

impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.bundle.server().verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            // A SPIFFE leaf names no DNS host; the chain and validity checks come before the
            // name check, so this is the only failure that is expected.
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => {}
            Err(err) => return Err(err),
        }
        let id = id_of_der(end_entity.as_ref()).ok_or_else(refused)?;
        if self.accepts(&id) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(refused())
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.bundle
            .server()
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.bundle
            .server()
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.bundle.server().supported_verify_schemes()
    }
}

/// A server certificate verifier that refuses everything; what a connection gets when no usable
/// identity or bundle exists. It is never reached in practice, because the dial itself is
/// refused first.
#[derive(Debug)]
pub(crate) struct RefuseAll;

impl ServerCertVerifier for RefuseAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Err(refused())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(refused())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(refused())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Vec::new()
    }
}

/// What a client of an app with `tls.spiffe_client` must be: a certificate that chains to the
/// live bundle of `trust_domain` and carries one of `allowed_ids`.
#[derive(Debug, Clone)]
pub struct ClientRule {
    trust_domain: Box<str>,
    allowed_ids: Arc<[IdPattern]>,
}

impl ClientRule {
    pub(crate) fn new(trust_domain: &str, allowed_ids: Vec<IdPattern>) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            allowed_ids: allowed_ids.into(),
        }
    }

    /// The trust domain the clients' bundle belongs to.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// The patterns a client's ID must match.
    #[must_use]
    pub fn allowed_ids(&self) -> &[IdPattern] {
        &self.allowed_ids
    }

    /// The SPIFFE ID of the client that sent `chain` (leaf first), when its chain leads to the
    /// bundle `store` has for the trust domain right now and the leaf's ID is allowed.
    #[must_use]
    pub fn verify(
        &self,
        store: &Store,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Option<SpiffeId> {
        let (leaf, intermediates) = chain.split_first()?;
        let bundle = store.bundle(&self.trust_domain)?;
        bundle
            .client()
            .verify_client_cert(leaf, intermediates, now)
            .ok()?;
        let id = id_of_der(leaf.as_ref())?;
        (id.trust_domain() == &*self.trust_domain && any_matches(&self.allowed_ids, &id))
            .then_some(id)
    }
}
