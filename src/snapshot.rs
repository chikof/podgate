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
}

/// How an app gets certificates, plus optional client authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// Where certificates come from.
    pub mode: TlsMode,
    /// PEM of the CA that must sign client certificates. Absent: no client authentication.
    #[serde(default)]
    pub client_ca_pem: Option<String>,
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
