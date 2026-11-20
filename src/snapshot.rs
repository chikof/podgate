//! The routing snapshot the control plane pushes: the JSON model of `PUT /v1/snapshot`.
//!
//! The entities and fields are the table in `docs/architecture.md` (`### Snapshot`). Later specs
//! add optional fields; give each `#[serde(default)]` so an absent field means the feature is
//! off, and never `deny_unknown_fields`, so an older podgate still accepts a newer snapshot.

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::skew::SkewSecret;

/// The complete desired state of one node. Replaces the previous snapshot as a whole.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Strictly increasing; a snapshot not newer than the live one is refused.
    pub version: u64,
    /// Tenants that own apps.
    pub tenants: Vec<Tenant>,
    /// Apps served by this node.
    pub apps: Vec<App>,
    /// Certificates served on the TLS listener, chosen by SNI. Change 0014 fills this from ACME.
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    /// Key that signs the session cookie pinning a browser to a revision, at least 16
    /// bytes (a shorter one rejects the snapshot with `422`). Absent: skew protection is off. Never
    /// logged.
    #[serde(default)]
    pub skew_secret: Option<SkewSecret>,
    /// Seconds after this snapshot goes live during which a 5xx spike in the apps it changed
    /// restores the previous snapshot. Absent: 60. `0`: never revert. Capped at 300.
    #[serde(default)]
    pub revert_window_secs: Option<u64>,
    /// ACME issuance settings. Absent: no certificate is ordered; only
    /// `certificates` are served.
    #[serde(default)]
    pub acme: Option<Acme>,
}

/// One tenant of the PaaS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique id; apps name it in [`App::tenant`].
    pub id: Box<str>,
    /// Fair-share weight against other tenants.
    pub weight: u32,
    /// Resource limits.
    pub budget: Budget,
}

/// Resource limits of a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Most requests the tenant may have in flight.
    pub max_inflight: u32,
    /// Most bytes of proxy memory the tenant may buffer.
    pub max_buffer_bytes: u64,
}

/// One app: the hosts it answers for and the revisions behind them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    /// Unique id.
    pub id: Box<str>,
    /// Owning [`Tenant::id`].
    pub tenant: Box<str>,
    /// Free text naming the source of this declaration; used in errors and explain output.
    pub declared_by: Box<str>,
    /// Exact host names, or names with one leading `*.` wildcard.
    pub hosts: Vec<Box<str>>,
    /// TLS policy.
    pub tls: TlsPolicy,
    /// Deployed revisions, split by weight and state.
    pub revisions: Vec<Revision>,
    /// Serve TLS requests whose `Host` differs from the SNI. Absent: refuse them
    /// with `421`.
    #[serde(default)]
    pub allow_domain_fronting: bool,
    /// Keep request and response bodies (up to 64 KiB) of failed requests for replay.
    /// Absent: record headers only.
    #[serde(default)]
    pub record_bodies: bool,
    /// Let the app sleep with no upstreams and wake on its first request. Absent:
    /// a request to an app with no upstream gets `503`.
    #[serde(default)]
    pub scale_to_zero: Option<ScaleToZero>,
    /// WASM request filters, run in order on the request headers. Absent: none.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Ramp one serving revision up while it stays healthy, and pull it back when it does not
    ///. Absent: revisions share traffic by their weights.
    #[serde(default)]
    pub canary: Option<Canary>,
}

/// Canary policy of an app: the rollout of one revision, judged by its own `5xx` rate.
///
/// The snapshot owns the policy; podgate owns the live share at runtime (see [`crate::canary`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Canary {
    /// The canary's [`Revision::id`]; it must be `serving`. Its own `weight` is ignored: the
    /// canary's share replaces it.
    pub revision: Box<str>,
    /// Percent of new sessions the canary gains per healthy interval, `1..=100`. It is also the
    /// share the canary starts with.
    pub step_percent: u32,
    /// Seconds between two judgments, at least `1`.
    pub interval_secs: u64,
    /// At this many `5xx` per thousand requests of the canary, or more, it is pulled back to
    /// `0`. `1..=1000`.
    pub max_error_permille: u32,
}

/// Scale-to-zero policy of an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaleToZero {
    /// Seconds without a request after which the app is reported idle (`app_idle`).
    pub idle_secs: u64,
    /// Seconds a request waits for the app to wake before it gets `503`.
    #[serde(default = "default_wake_timeout_secs")]
    pub wake_timeout_secs: u64,
}

fn default_wake_timeout_secs() -> u64 {
    30
}

/// One WASM request filter of an app: a proxy-wasm module and the limits it runs under.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// The module in the WebAssembly binary format, standard base64.
    pub wasm_base64: String,
    /// Instructions the filter may execute per request; running out ends the request with `500`.
    pub fuel: u64,
    /// Most bytes of linear memory the filter may hold; growing past it ends the request with
    /// `500`.
    pub max_memory_bytes: u64,
}

impl fmt::Debug for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Filter")
            .field(
                "wasm_base64",
                &format_args!("{} bytes", self.wasm_base64.len()),
            )
            .field("fuel", &self.fuel)
            .field("max_memory_bytes", &self.max_memory_bytes)
            .finish()
    }
}

/// How an app gets certificates, plus optional client authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// Where certificates come from.
    pub mode: TlsMode,
    /// PEM of the CA that must sign client certificates. Absent: no client authentication.
    #[serde(default)]
    pub client_ca_pem: Option<String>,
    /// Pass the verified client certificate's subject to the app in the
    /// `x-forwarded-tls-client-cert-subject` request header. Needs `client_ca_pem`.
    /// Absent: the header is never sent.
    #[serde(default)]
    pub pass_client_cert: bool,
}

/// Certificate source for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Issued for the app's declared hosts.
    Acme,
    /// Issued at the first handshake for a matching host.
    OnDemand,
}

/// One deployed version of an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    /// Unique within its app.
    pub id: Box<str>,
    /// Backends of this revision.
    pub upstreams: Vec<SocketAddr>,
    /// Share of new traffic against the app's other serving revisions.
    pub weight: u16,
    /// Whether the revision takes new traffic.
    pub state: RevisionState,
}

/// Lifecycle state of a revision; see `docs/architecture.md` (`### Revision states`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionState {
    /// Gets new sessions by weight.
    Serving,
    /// Gets no new sessions; still serves pinned ones.
    Retiring,
    /// Gets no new requests; in-flight requests finish.
    Draining,
}

/// A certificate chain and its private key, served for the listed hosts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// Hosts the certificate answers for: exact names or `*.` wildcards.
    pub hosts: Vec<Box<str>>,
    /// Leaf certificate first, PEM.
    pub cert_pem: String,
    /// PKCS#8, PKCS#1 or SEC1 private key, PEM.
    pub key_pem: String,
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("hosts", &self.hosts)
            .field("cert_pem", &format_args!("{} bytes", self.cert_pem.len()))
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

/// How certificates are issued and which node issues them. `crate::acme` reads
/// every field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acme {
    /// `NODE_NAME` of the one node that orders certificates. Every other node ignores the
    /// ordering fields and only serves `challenges`.
    pub issuer_node: Box<str>,
    /// The ACME directory URL, `https://...`.
    pub directory_url: String,
    /// Contact URIs of the account, such as `mailto:ops@example.com`. Used when podgate creates
    /// the account itself; ignored with `account_key_pem`.
    #[serde(default)]
    pub contact: Vec<String>,
    /// External account binding for CAs that require one. Excludes `account_key_pem`.
    #[serde(default)]
    pub eab: Option<ExternalAccount>,
    /// PKCS#8 PEM key of the ACME account, so every restart and every issuer node uses the same
    /// account. Absent: the issuer creates a fresh account in memory.
    #[serde(default)]
    pub account_key_pem: Option<String>,
    /// HTTP-01 answers the control plane pushes back after an `acme_challenge` event. Every
    /// node serves them on the plain HTTP listener.
    #[serde(default)]
    pub challenges: Vec<Challenge>,
    /// Hosts the control plane asks the issuer to get certificates for: the hosts of
    /// `certificate_requested` events it approved. Only hosts of `on_demand` apps count.
    #[serde(default)]
    pub requested_hosts: Vec<Box<str>>,
}

/// External account binding credentials, as a CA hands them out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAccount {
    /// The key identifier.
    pub key_id: String,
    /// The HMAC key, base64url.
    pub hmac_key: String,
}

/// One HTTP-01 answer: `GET /.well-known/acme-challenge/<token>` returns `key_authorization`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The challenge token.
    pub token: Box<str>,
    /// The key authorization to answer with.
    pub key_authorization: Box<str>,
}

impl fmt::Debug for Acme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acme")
            .field("issuer_node", &self.issuer_node)
            .field("directory_url", &self.directory_url)
            .field("contact", &self.contact)
            .field("eab", &self.eab.as_ref().map(|_| "[redacted]"))
            .field(
                "account_key_pem",
                &self.account_key_pem.as_ref().map(|_| "[redacted]"),
            )
            .field("challenges", &self.challenges)
            .field("requested_hosts", &self.requested_hosts)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const JSON: &str = r#"{
        "version": 7,
        "tenants": [{"id": "t1", "weight": 1, "budget": {"max_inflight": 10, "max_buffer_bytes": 1024}}],
        "apps": [{
            "id": "a", "tenant": "t1", "declared_by": "paas/a", "hosts": ["a.test", "*.a.test"],
            "tls": {"mode": "on_demand"},
            "revisions": [{"id": "r1", "upstreams": ["127.0.0.1:9000"], "weight": 100, "state": "serving"}],
            "future_field": true
        }]
    }"#;

    #[test]
    fn parses_the_documented_shape_and_ignores_unknown_fields() {
        let snapshot: Snapshot = serde_json::from_str(JSON).expect("valid snapshot");
        assert_eq!(snapshot.version, 7);
        assert!(snapshot.certificates.is_empty());
        let app = &snapshot.apps[0];
        assert_eq!(app.tls.mode, TlsMode::OnDemand);
        assert_eq!(app.tls.client_ca_pem, None);
        assert_eq!(app.revisions[0].state, RevisionState::Serving);
        assert_eq!(app.revisions[0].upstreams[0].port(), 9000);
    }

    #[test]
    fn rejects_unknown_states() {
        let bad = JSON.replace("serving", "sleeping");
        assert!(serde_json::from_str::<Snapshot>(&bad).is_err());
    }

    #[test]
    fn debug_hides_the_private_key() {
        let cert = Certificate {
            hosts: vec!["a.test".into()],
            cert_pem: "CERT".into(),
            key_pem: "SECRET".into(),
        };
        let shown = format!("{cert:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
    }
}
