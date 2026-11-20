//! Upstream transports: `servers_transport` objects that a `loadbalancer` names with
//! `transport`. They decide how podgate talks TLS to the servers of that service.
//!
//! ```json
//! { "name": "internal", "type": "servers_transport",
//!   "server_name": "backend.internal", "ca_pem": "-----BEGIN CERTIFICATE-----...",
//!   "client_cert": { "cert_pem": "...", "key_pem": "..." },
//!   "insecure_skip_verify": false, "min_tls_version": "1.2" }
//! ```
//!
//! | Field | Meaning |
//! |---|---|
//! | `server_name` | The name sent as SNI and checked against the certificate. Default: the URL host; for an IP literal URL no SNI is sent and the certificate must carry the IP as a SAN. |
//! | `ca_pem` | The only trust anchors: the platform roots are not added to them. |
//! | `client_cert` | `cert_pem` (leaf first) and `key_pem` presented to a server that asks for one. Redacted in `Debug` and explain. |
//! | `insecure_skip_verify` | Do not verify the server's certificate or name. Allowed, and a posture change in a plan (`upstream_tls_verification_disabled`). |
//! | `min_tls_version` | `"1.2"`, the floor Pingora's rustls connector always applies. `"1.3"` has no knob there and is refused with `unsupported_setting`. |
//!
//! A `https://` server with no transport uses [`Transport::default`]: platform roots, URL host as
//! SNI. A transport with TLS fields named by a service with an `http://` server is refused
//! (`invalid_service`), so a setting never goes unused without notice. Timeouts, HTTP/2 and the
//! idle pool size are a later spec's fields; until then they are unknown fields (`invalid_transport`).
//!
//! # Security
//!
//! Everything is checked when the snapshot is compiled, because Pingora's rustls connector
//! panics on a malformed certificate or key and silently skips verification when the SNI is
//! empty: an empty `server_name` is refused, and an IP literal URL passes its address as the
//! name, which rustls verifies against the SAN of the certificate without sending SNI.
//!
//! [`Transport::fingerprint`] hashes every field, the client certificate and key included. The
//! connection pool keys on it ([`crate::pool`]), so two transports never share a connection:
//! Pingora's own reuse hash identifies a client certificate by its serial number only.

use std::fmt;
use std::sync::Arc;

use pingora::upstreams::peer::HttpPeer;
use pingora::utils::tls::{CertKey, WrappedX509, parse_x509};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::Server;
use crate::compile::Invalid;
use podgate_model::Declared;

/// The `type` of a transport in a snapshot.
pub(super) const KIND: &str = "servers_transport";

/// What `min_tls_version: "1.2"` means: Pingora's rustls connector offers TLS 1.2 and 1.3 only.
const MIN_TLS: &str = "1.2";

/// What explain shows in place of the client certificate.
const REDACTED: &str = "[redacted]";

/// The fields of a `servers_transport`, but for `client_cert`, which [`client_cert`] reads by
/// hand so that no parse error quotes the key.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    ca_pem: Option<String>,
    #[serde(default)]
    insecure_skip_verify: bool,
    #[serde(default)]
    min_tls_version: Option<String>,
}

/// The JSON Schema of a `servers_transport`: [`Config`] plus `client_cert`, which is read by hand
/// and so is not a field of it.
pub(super) fn schema() -> Value {
    let mut schema = crate::admin::schema::of::<Config>();
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert(
            "client_cert".to_owned(),
            serde_json::json!({
                "type": "object",
                "description": "The certificate chain (leaf first) and private key, PEM, presented to a server that asks for one.",
                "properties": { "cert_pem": { "type": "string" }, "key_pem": { "type": "string" } },
                "required": ["cert_pem", "key_pem"],
                "additionalProperties": false
            }),
        );
    }
    schema
}

/// A compiled `servers_transport`.
pub struct Transport {
    server_name: Option<Box<str>>,
    ca: Option<Arc<[WrappedX509]>>,
    client_cert: Option<Arc<CertKey>>,
    insecure_skip_verify: bool,
    min_tls_version: Option<&'static str>,
    fingerprint: u64,
}

/// A transport and the name it was declared under.
#[derive(Debug)]
pub struct Named {
    /// The declared name, unique among the app's transports.
    pub name: Box<str>,
    /// The compiled transport, shared by every service that names it.
    pub transport: Arc<Transport>,
}

/// What explain shows of a transport. The client certificate is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary<'a> {
    /// The SNI and certificate name override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<&'a str>,
    /// Whether the transport trusts its own CA instead of the platform roots.
    pub ca: bool,
    /// `"[redacted]"` when the transport presents a client certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<&'static str>,
    /// Whether the server's certificate is not verified.
    pub insecure_skip_verify: bool,
    /// The TLS version floor, when the transport sets one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_tls_version: Option<&'static str>,
}

/// One server of a service together with the transport that reaches it.
#[derive(Debug, Clone, Copy)]
pub struct Upstream<'a> {
    /// The server.
    pub server: &'a Server,
    /// How to talk to it.
    pub transport: &'a Transport,
}

impl Transport {
    /// Compiles one declared transport.
    ///
    /// # Errors
    ///
    /// `invalid_transport` for an unknown type or field, a certificate, CA or key that does not
    /// parse or that rustls refuses, an empty or malformed `server_name`, or `ca_pem` combined
    /// with `insecure_skip_verify`; `unsupported_setting` for `min_tls_version: "1.3"`.
    pub fn compile(declared: &Declared) -> Result<Self, Invalid> {
        let invalid = |message: String| Invalid::new("invalid_transport", message);
        if &*declared.kind != KIND {
            return Err(invalid(format!(
                "unknown transport type {}, expected {KIND}",
                declared.kind
            )));
        }
        let mut fields: Map<String, Value> = declared.config.clone();
        let client = fields.remove("client_cert");
        let config: Config = serde_json::from_value(Value::Object(fields))
            .map_err(|err| invalid(err.to_string()))?;

        let server_name = match config.server_name {
            None => None,
            Some(name) => {
                // An empty name would make Pingora skip verification altogether.
                if name.is_empty() || ServerName::try_from(name.as_str()).is_err() {
                    return Err(invalid(
                        "server_name is not a valid DNS name or IP address".to_owned(),
                    ));
                }
                Some(name.into_boxed_str())
            }
        };
        let min_tls_version = match config.min_tls_version.as_deref() {
            None => None,
            Some("1.2") => Some(MIN_TLS),
            Some("1.3") => {
                return Err(Invalid::new(
                    "unsupported_setting",
                    "min_tls_version 1.3: Pingora's rustls connector offers TLS 1.2 and 1.3 and \
                     has no knob to drop 1.2",
                ));
            }
            Some(_) => {
                return Err(invalid(
                    "min_tls_version must be \"1.2\" or \"1.3\"".to_owned(),
                ));
            }
        };
        if config.ca_pem.is_some() && config.insecure_skip_verify {
            return Err(invalid(
                "ca_pem has no effect with insecure_skip_verify, drop one of them".to_owned(),
            ));
        }
        let ca = config
            .ca_pem
            .as_deref()
            .map(trust_anchors)
            .transpose()
            .map_err(invalid)?;
        let pems = client
            .as_ref()
            .map(client_cert)
            .transpose()
            .map_err(invalid)?;
        let fingerprint = fingerprint(
            server_name.as_deref(),
            config.ca_pem.as_deref(),
            pems.as_ref()
                .map(|(cert, key)| (cert.as_str(), key.as_str())),
            config.insecure_skip_verify,
            min_tls_version,
        );
        let client_cert = pems
            .map(|(cert, key)| load_client_cert(&cert, &key))
            .transpose()
            .map_err(invalid)?;
        Ok(Self {
            server_name,
            ca,
            client_cert,
            insecure_skip_verify: config.insecure_skip_verify,
            min_tls_version,
            fingerprint,
        })
    }

    /// A digest of every field, the client certificate and its key included. Equal
    /// configurations give equal values within a process; the connection pool keys on it.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Whether the transport sets anything only a TLS connection uses.
    #[must_use]
    pub fn has_tls_settings(&self) -> bool {
        self.server_name.is_some()
            || self.ca.is_some()
            || self.client_cert.is_some()
            || self.insecure_skip_verify
            || self.min_tls_version.is_some()
    }

    /// Whether the transport connects without verifying the server's certificate.
    #[must_use]
    pub fn insecure_skip_verify(&self) -> bool {
        self.insecure_skip_verify
    }

    /// What explain shows.
    #[must_use]
    pub fn summary(&self) -> Summary<'_> {
        Summary {
            server_name: self.server_name.as_deref(),
            ca: self.ca.is_some(),
            client_cert: self.client_cert.as_ref().map(|_| REDACTED),
            insecure_skip_verify: self.insecure_skip_verify,
            min_tls_version: self.min_tls_version,
        }
    }
}

impl Default for Transport {
    /// The transport of a server that names none: platform roots, the URL host as SNI.
    fn default() -> Self {
        Self {
            server_name: None,
            ca: None,
            client_cert: None,
            insecure_skip_verify: false,
            min_tls_version: None,
            fingerprint: fingerprint(None, None, None, false, None),
        }
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("server_name", &self.server_name)
            .field("ca", &self.ca.as_ref().map(|ca| ca.len()))
            .field("client_cert", &self.client_cert.as_ref().map(|_| REDACTED))
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("min_tls_version", &self.min_tls_version)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl Upstream<'_> {
    /// A peer for the server: TLS when the server is `https://`, with the transport's name, trust
    /// anchors and client certificate. The caller sets timeouts and the pool partition.
    #[must_use]
    pub fn peer(self) -> HttpPeer {
        let server = self.server;
        if !server.tls {
            return HttpPeer::new(server.addr, false, String::new());
        }
        // Never empty: an empty SNI makes Pingora skip verification. An IP literal is verified
        // against the certificate's IP SAN and is not sent as SNI.
        let sni = self
            .transport
            .server_name
            .as_deref()
            .map_or_else(|| server.addr.ip().to_string(), str::to_owned);
        let mut peer = HttpPeer::new(server.addr, true, sni);
        if self.transport.insecure_skip_verify {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }
        peer.options.ca.clone_from(&self.transport.ca);
        peer.client_cert_key.clone_from(&self.transport.client_cert);
        peer
    }

    /// What the connection pool keys on besides who asks: the transport and whether the
    /// connection is TLS, so TLS and plain connections never mix.
    #[must_use]
    pub fn pool_key(self) -> u64 {
        crate::compile::hash_of(&(self.transport.fingerprint, self.server.tls))
    }
}

impl<'a> Upstream<'a> {
    /// What explain shows: the transport of a TLS server, nothing for a plain one.
    #[must_use]
    pub fn summary(self) -> Option<Summary<'a>> {
        self.server.tls.then(|| self.transport.summary())
    }
}

/// Parses `ca_pem` into trust anchors Pingora can use and rustls accepts.
fn trust_anchors(pem: &str) -> Result<Arc<[WrappedX509]>, String> {
    let ders = certificates(pem, "ca_pem")?;
    let mut store = RootCertStore::empty();
    for der in &ders {
        store
            .add(der.clone())
            .map_err(|_| "ca_pem holds a certificate that cannot be a trust anchor".to_owned())?;
    }
    Ok(ders
        .into_iter()
        .map(|der| WrappedX509::new(der.as_ref().to_vec(), parse_x509))
        .collect())
}

/// The PEM certificates of `pem`, each checked to parse as X.509, at least one.
fn certificates(pem: &str, field: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let ders: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| format!("{field} is not valid PEM"))?;
    if ders.is_empty() {
        return Err(format!("{field} holds no certificate"));
    }
    for der in &ders {
        // Pingora parses these again and panics on a failure: refuse here.
        match x509_parser::parse_x509_certificate(der) {
            Ok(([], _)) => {}
            _ => {
                return Err(format!(
                    "{field} holds a certificate that is not valid X.509"
                ));
            }
        }
    }
    Ok(ders)
}

/// Reads `client_cert` as `{cert_pem, key_pem}` without quoting either in an error.
fn client_cert(value: &Value) -> Result<(String, String), String> {
    let shape = || "client_cert must be an object with exactly cert_pem and key_pem strings";
    let object = value.as_object().ok_or_else(|| shape().to_owned())?;
    let field = |name: &str| object.get(name).and_then(Value::as_str).map(str::to_owned);
    match (object.len(), field("cert_pem"), field("key_pem")) {
        (2, Some(cert), Some(key)) => Ok((cert, key)),
        _ => Err(shape().to_owned()),
    }
}

/// Parses the chain and key and proves rustls can present them, the way Pingora will.
fn load_client_cert(cert_pem: &str, key_pem: &str) -> Result<Arc<CertKey>, String> {
    let chain = certificates(cert_pem, "client_cert.cert_pem")?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|_| "client_cert.key_pem is not a PEM private key".to_owned())?;
    // Pingora keeps the DER bytes and converts them back with `try_into().unwrap()`.
    let bytes = key.secret_der().to_vec();
    let key = PrivateKeyDer::try_from(bytes.clone())
        .map_err(|_| "client_cert.key_pem is not a PKCS#8, PKCS#1 or SEC1 key".to_owned())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS versions unavailable".to_owned())?
        .with_root_certificates(RootCertStore::empty())
        .with_client_auth_cert(chain.clone(), key)
        .map_err(|_| "client_cert.key_pem does not match cert_pem or is unusable".to_owned())?;
    Ok(Arc::new(CertKey::new(
        chain.into_iter().map(|der| der.as_ref().to_vec()).collect(),
        bytes,
    )))
}

/// Hashes every field, each with a presence flag and a length, so no two configurations collide
/// by moving bytes between fields.
fn fingerprint(
    server_name: Option<&str>,
    ca_pem: Option<&str>,
    client: Option<(&str, &str)>,
    insecure_skip_verify: bool,
    min_tls_version: Option<&str>,
) -> u64 {
    let mut hash = Sha256::new();
    let mut field = |value: Option<&str>| match value {
        None => hash.update([0]),
        Some(value) => {
            hash.update([1]);
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value.as_bytes());
        }
    };
    field(server_name);
    field(ca_pem);
    field(client.map(|(cert, _)| cert));
    field(client.map(|(_, key)| key));
    field(Some(if insecure_skip_verify { "1" } else { "0" }));
    field(min_tls_version);
    let digest = hash.finalize();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(head)
}

/// The transport a service names, looked up among the app's.
///
/// # Errors
///
/// `unknown_transport` when `name` is not declared.
pub(super) fn find(transports: &[Named], name: &str) -> Result<Arc<Transport>, Invalid> {
    transports
        .iter()
        .find(|named| &*named.name == name)
        .map(|named| Arc::clone(&named.transport))
        .ok_or_else(|| {
            Invalid::new(
                "unknown_transport",
                format!("transport {name} is not declared by the app"),
            )
        })
}

#[cfg(test)]
mod test {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use serde_json::json;

    use super::*;

    struct Pems {
        ca: String,
        cert: String,
        key: String,
    }

    fn pems(serial: u64) -> Pems {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer =
            CertifiedIssuer::self_signed(params, KeyPair::generate().expect("key")).expect("ca");
        let key = KeyPair::generate().expect("client key");
        let mut leaf = CertificateParams::new(vec!["client".to_owned()]).expect("params");
        leaf.serial_number = Some(serial.into());
        let leaf = leaf.signed_by(&key, &issuer).expect("leaf");
        Pems {
            ca: issuer.pem(),
            cert: leaf.pem(),
            key: key.serialize_pem(),
        }
    }

    fn compile(fields: &Value) -> Result<Transport, Invalid> {
        let mut declared = json!({ "name": "t", "type": "servers_transport" });
        declared
            .as_object_mut()
            .expect("object")
            .extend(fields.as_object().expect("fields").clone());
        Transport::compile(&serde_json::from_value(declared).expect("declared"))
    }

    fn code(fields: &Value) -> &'static str {
        compile(fields).expect_err("refused").code
    }

    #[test]
    fn compiles_every_field_and_the_default() {
        let p = pems(1);
        let transport = compile(&json!({
            "server_name": "backend.internal",
            "ca_pem": p.ca,
            "client_cert": { "cert_pem": p.cert, "key_pem": p.key },
            "min_tls_version": "1.2",
        }))
        .expect("compiles");
        assert!(transport.has_tls_settings());
        assert!(!transport.insecure_skip_verify());
        assert!(!compile(&json!({})).expect("empty").has_tls_settings());
        assert!(!Transport::default().has_tls_settings());
        assert_eq!(
            Transport::default().fingerprint(),
            compile(&json!({})).expect("empty").fingerprint()
        );
    }

    #[test]
    fn malformed_transports_are_refused_with_their_codes() {
        let p = pems(1);
        let cert =
            |cert: &str, key: &str| json!({ "client_cert": { "cert_pem": cert, "key_pem": key } });
        assert_eq!(code(&json!({ "ca_pem": "not a pem" })), "invalid_transport");
        assert_eq!(code(&json!({ "ca_pem": "" })), "invalid_transport");
        assert_eq!(code(&json!({ "server_name": "" })), "invalid_transport");
        assert_eq!(code(&json!({ "server_name": "a b" })), "invalid_transport");
        assert_eq!(
            code(&json!({ "min_tls_version": "1.1" })),
            "invalid_transport"
        );
        assert_eq!(
            code(&json!({ "min_tls_version": "1.3" })),
            "unsupported_setting"
        );
        assert_eq!(code(&json!({ "http2": true })), "invalid_transport");
        assert_eq!(code(&cert(&p.cert, "garbage")), "invalid_transport");
        assert_eq!(code(&cert(&p.cert, &pems(2).key)), "invalid_transport");
        assert_eq!(code(&cert("garbage", &p.key)), "invalid_transport");
        assert_eq!(code(&json!({ "client_cert": "x" })), "invalid_transport");
        assert_eq!(
            code(&json!({ "client_cert": { "cert_pem": p.cert } })),
            "invalid_transport"
        );
        assert_eq!(
            code(&json!({ "ca_pem": p.ca, "insecure_skip_verify": true })),
            "invalid_transport"
        );
    }

    #[test]
    fn transport_fingerprint_covers_every_field() {
        let (a, b) = (pems(1), pems(1));
        let with = |fields: Value| compile(&fields).expect("compiles").fingerprint();
        let base = with(
            json!({ "ca_pem": a.ca, "client_cert": { "cert_pem": a.cert, "key_pem": a.key } }),
        );
        assert_eq!(
            base,
            with(
                json!({ "ca_pem": a.ca, "client_cert": { "cert_pem": a.cert, "key_pem": a.key } })
            )
        );
        let others = [
            with(json!({ "ca_pem": a.ca })),
            with(
                json!({ "ca_pem": b.ca, "client_cert": { "cert_pem": a.cert, "key_pem": a.key } }),
            ),
            with(
                json!({ "ca_pem": a.ca, "client_cert": { "cert_pem": b.cert, "key_pem": b.key } }),
            ),
            with(
                json!({ "ca_pem": a.ca, "client_cert": { "cert_pem": a.cert, "key_pem": a.key }, "server_name": "x" }),
            ),
            with(
                json!({ "ca_pem": a.ca, "client_cert": { "cert_pem": a.cert, "key_pem": a.key }, "min_tls_version": "1.2" }),
            ),
            with(json!({ "insecure_skip_verify": true })),
            with(json!({})),
        ];
        for (index, other) in others.iter().enumerate() {
            assert_ne!(base, *other, "variant {index}");
            for later in &others[index + 1..] {
                assert_ne!(other, later);
            }
        }
    }

    #[test]
    fn debug_and_summary_never_show_the_client_certificate() {
        let p = pems(1);
        let transport = compile(&json!({
            "client_cert": { "cert_pem": p.cert, "key_pem": p.key },
        }))
        .expect("compiles");
        let shown = format!("{transport:?} {:?}", transport.summary());
        let body = p.key.lines().nth(1).expect("key body");
        assert!(
            !shown.contains(body) && !shown.contains("PRIVATE KEY"),
            "{shown}"
        );
        assert_eq!(transport.summary().client_cert, Some("[redacted]"));
    }

    fn server(url: &str, tls: bool) -> Server {
        Server {
            url: url.into(),
            addr: "127.0.0.1:9000".parse().expect("addr"),
            tls,
            weight: 1,
            state: Arc::default(),
        }
    }

    #[test]
    fn pool_key_separates_tls_from_plain_and_one_transport_from_another() {
        let (a, b) = (pems(1), pems(1));
        let with_cert = |p: &Pems| {
            compile(&json!({ "client_cert": { "cert_pem": p.cert, "key_pem": p.key } }))
                .expect("compiles")
        };
        let (ta, tb) = (with_cert(&a), with_cert(&b));
        let plain = server("http://127.0.0.1:9000", false);
        let tls = server("https://127.0.0.1:9000", true);
        let key =
            |server: &Server, transport: &Transport| Upstream { server, transport }.pool_key();
        assert_eq!(key(&tls, &ta), key(&tls, &ta));
        assert_ne!(key(&tls, &ta), key(&plain, &ta), "TLS and plain never mix");
        assert_ne!(key(&tls, &ta), key(&tls, &tb), "other client certificate");
        assert_ne!(key(&tls, &ta), key(&tls, &Transport::default()));
    }

    #[test]
    fn a_tls_peer_always_names_a_server_and_verifies_unless_told_not_to() {
        let tls = server("https://127.0.0.1:9000", true);
        let peer = Upstream {
            server: &tls,
            transport: &Transport::default(),
        }
        .peer();
        assert!(peer.is_tls());
        assert_eq!(
            peer.sni, "127.0.0.1",
            "an IP literal is verified, never an empty name"
        );
        assert!(peer.options.verify_cert && peer.options.verify_hostname);

        let named =
            compile(&json!({ "server_name": "backend.test", "insecure_skip_verify": true }))
                .expect("compiles");
        let peer = Upstream {
            server: &tls,
            transport: &named,
        }
        .peer();
        assert_eq!(peer.sni, "backend.test");
        assert!(!peer.options.verify_cert && !peer.options.verify_hostname);

        let plain = server("http://127.0.0.1:9000", false);
        let peer = Upstream {
            server: &plain,
            transport: &named,
        }
        .peer();
        assert!(!peer.is_tls() && peer.sni.is_empty());
    }
}
