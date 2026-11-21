//! The routing snapshot the control plane pushes: the JSON model of `PUT /v1/snapshot`.
//!
//! This crate depends on `serde` and `serde_json` only, so a program that builds snapshots does not
//! compile the proxy. The daemon compiles a [`Snapshot`] into its routing table and parses the
//! kind configuration held in [`Declared`].
//!
//! The entities and fields are in `docs/architecture.md` (`## Snapshot model v2`). Envelope
//! entities ([`Snapshot`], [`App`], [`Router`], [`Revision`]) ignore unknown fields, so an older
//! podgate accepts a newer snapshot that only adds optional envelope fields; give each new field
//! `#[serde(default)]` so an absent field means the feature is off. Kind-tagged objects
//! ([`Declared`]) are the opposite: their configuration belongs to the kind's module, which
//! parses it strictly, so a misspelt option is refused instead of turning a feature off.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod entry_point;
mod l4;
mod observe;
mod secret;

pub use entry_point::{EntryPointPolicy, UnderscoreHeaders};
pub use l4::{Tcp, Udp};
pub use observe::Observability;
pub use secret::SkewSecret;

/// The complete desired state of one node. Replaces the previous snapshot as a whole.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// Request-time policy per entry point. Absent: the defaults of every entry point.
    #[serde(default)]
    pub entry_points: Vec<EntryPointPolicy>,
    /// Access log, metrics and tracing settings. Absent: the process defaults.
    #[serde(default)]
    pub observability: Option<Observability>,
}

/// One tenant of the PaaS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Budget {
    /// Most requests the tenant may have in flight.
    pub max_inflight: u32,
    /// Most bytes of proxy memory the tenant may buffer.
    pub max_buffer_bytes: u64,
}

/// One app: the unit of tenancy and deployment. It owns its routers, middlewares, services and
/// transports; every name resolves inside the app only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct App {
    /// Unique id.
    pub id: Box<str>,
    /// Owning [`Tenant::id`].
    pub tenant: Box<str>,
    /// Free text naming the source of this declaration; used in errors and explain output.
    pub declared_by: Box<str>,
    /// TLS policy.
    pub tls: TlsPolicy,
    /// Routers: what the app answers for and where each request goes.
    pub routers: Vec<Router>,
    /// Middlewares routers may name in their `chain`.
    #[serde(default)]
    pub middlewares: Vec<Declared>,
    /// Names of middlewares that run before every router's own chain.
    #[serde(default)]
    pub default_chain: Vec<Box<str>>,
    /// Services shared by every revision. A revision's own services are in [`Revision::services`].
    #[serde(default)]
    pub services: Vec<Declared>,
    /// Upstream transports services may name. Not built yet.
    #[serde(default)]
    pub transports: Vec<Declared>,
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
    /// Ramp one serving revision up while it stays healthy, and pull it back when it does not
    ///. Absent: revisions share traffic by their weights.
    #[serde(default)]
    pub canary: Option<Canary>,
    /// TCP routers and services. Not built yet.
    #[serde(default)]
    pub tcp: Option<Tcp>,
    /// UDP routers and services.
    #[serde(default)]
    pub udp: Option<Udp>,
    /// Which forwarding headers the app's upstreams receive. Absent: the default set,
    /// [`Forwarded::default`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<Forwarded>,
}

/// The forwarding headers an app's upstreams receive. Every field is optional; an absent one has
/// the default below, so `{}` is the same as no object at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four independent switches of one JSON object; an enum would be a worse wire format"
)]
pub struct Forwarded {
    /// Write `X-Forwarded-For`, `-Proto`, `-Host` and `-Port`. Default `true`.
    #[serde(default = "enabled")]
    pub x_forwarded: bool,
    /// Write `X-Real-IP`. Default `true`.
    #[serde(default = "enabled")]
    pub real_ip: bool,
    /// Also write the RFC 7239 `Forwarded` header. Default `false`.
    #[serde(default)]
    pub rfc7239: bool,
    /// Write `X-Forwarded-Server` with the node's name. Default `false`: the header tells the
    /// app which host proxies it, which it does not need.
    #[serde(default)]
    pub server: bool,
}

impl Default for Forwarded {
    fn default() -> Self {
        Self {
            x_forwarded: true,
            real_ip: true,
            rfc7239: false,
            server: false,
        }
    }
}

fn enabled() -> bool {
    true
}

/// One router: a matcher, a middleware chain and a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Router {
    /// Unique among the app's routers.
    pub name: Box<str>,
    /// Entry points the router listens on. Absent: every HTTP and HTTPS entry point.
    #[serde(default)]
    pub entry_points: Option<Vec<Box<str>>>,
    /// The matcher tree, parsed by the daemon's `router::matcher`: an object with exactly one key.
    #[serde(rename = "match")]
    pub matcher: Value,
    /// Higher goes first among the routers of one tenant. Absent: `0`. Never orders routers of
    /// different tenants.
    #[serde(default)]
    pub priority: Option<i32>,
    /// Names of middlewares that run after the app's `default_chain`, in order.
    #[serde(default)]
    pub chain: Vec<Box<str>>,
    /// The service that answers, by name: one of the revision's services, else one of the app's.
    pub service: Box<str>,
    /// Per-router observability overrides: `{"access_log": false}` silences the router, `true`
    /// logs it. Metrics and tracing overrides are not built yet.
    #[serde(default)]
    pub observability: Option<Value>,
    /// Source of this router when it differs from the app's.
    #[serde(default)]
    pub declared_by: Option<Box<str>>,
}

/// A kind-tagged, named object: a middleware, service or transport.
///
/// The envelope only knows the name and the type; the module of that type owns the rest and
/// parses it strictly.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Declared {
    /// Unique among the app's objects of this kind of object.
    pub name: Box<str>,
    /// The type, such as `loadbalancer` or `wasm`.
    #[serde(rename = "type")]
    pub kind: Box<str>,
    /// The type's own fields.
    #[serde(flatten)]
    pub config: Map<String, Value>,
}

impl fmt::Debug for Declared {
    /// Like the derive, but every `key_pem` in the configuration, at any depth, shows as
    /// `[redacted]`: a transport's client certificate key must not reach a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn redacted(value: &Value) -> Value {
            match value {
                Value::Object(map) => Value::Object(
                    map.iter()
                        .map(|(key, value)| {
                            let shown = if key == "key_pem" {
                                Value::from("[redacted]")
                            } else {
                                redacted(value)
                            };
                            (key.clone(), shown)
                        })
                        .collect(),
                ),
                Value::Array(items) => Value::Array(items.iter().map(redacted).collect()),
                other => other.clone(),
            }
        }
        f.debug_struct("Declared")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("config", &redacted(&Value::Object(self.config.clone())))
            .finish()
    }
}

/// Canary policy of an app: the rollout of one revision, judged by its own `5xx` rate.
///
/// The snapshot owns the policy; podgate owns the live share at runtime (see `crate::canary` in
/// the daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// How an app gets certificates, plus optional client authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct TlsPolicy {
    /// Where certificates come from.
    pub mode: TlsMode,
    /// PEM of the CA that must sign client certificates. Absent: no client authentication.
    #[serde(default)]
    pub client_ca_pem: Option<String>,
    /// Removed in change 0055; a snapshot that sets it to `true` is rejected with
    /// `unsupported_setting`, which names the `pass_tls_client_cert` middleware as the
    /// replacement. `false` and absent are accepted and mean nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_client_cert: Option<bool>,
    /// How the issuer proves the app's hosts to the CA. Absent: `http-01`.
    #[serde(default)]
    pub challenge: ChallengeKind,
    /// How client certificates are asked for and judged. Absent: `require_and_verify`
    /// when `client_ca_pem` is set, no client authentication otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth: Option<ClientAuthMode>,
    /// Lowest TLS version a connection to this app may have. Absent: the listener's floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<TlsVersion>,
    /// Not enforceable per app: the compiler rejects it with `unsupported_setting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<TlsVersion>,
    /// The cipher suites a connection to this app may negotiate, by rustls name. Absent: every
    /// suite of the listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suites: Option<Vec<String>>,
    /// Not enforceable per app: the compiler rejects it with `unsupported_setting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curves: Option<Vec<String>>,
    /// The ALPN protocols a connection to this app may negotiate: `h2` and `http/1.1`. Absent:
    /// both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    /// Refuse a handshake for a name of this app that has no certificate, instead of serving the
    /// default certificate.
    #[serde(default, skip_serializing_if = "is_false")]
    pub sni_strict: bool,
    /// Not enforceable per app: the compiler rejects it with `unsupported_setting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_tickets: Option<bool>,
    /// Verify client certificates as SPIFFE X.509-SVIDs: against the live bundle of a
    /// trust domain, by SPIFFE ID. Only for a tenant the operator's SPIFFE policy allows
    /// `client_identity`. Excludes `client_ca_pem`. Absent: no SPIFFE client verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_client: Option<SpiffeClient>,
    /// Whether HTTP/3 may serve this app. Absent: yes, unless the app has a
    /// `client_ca_pem` or `client_auth`, `cipher_suites`, or an `alpn` without `h2`, which HTTP/3
    /// cannot honour. `true` together with one of those is rejected with `unsupported_setting`.
    /// Only matters on an HTTPS entry point with the `;http3` option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http3: Option<bool>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(value: &bool) -> bool {
    !*value
}

impl TlsPolicy {
    /// Whether `self` and `other` ask the same of a TLS handshake: everything but where
    /// certificates come from (the ACME `challenge` is compared, though).
    /// Apps that share a host must agree on it.
    #[must_use]
    pub fn same_handshake_policy(&self, other: &Self) -> bool {
        self.client_ca_pem == other.client_ca_pem
            && self.challenge == other.challenge
            && self.client_auth == other.client_auth
            && self.min_version == other.min_version
            && self.max_version == other.max_version
            && self.cipher_suites == other.cipher_suites
            && self.curves == other.curves
            && self.alpn == other.alpn
            && self.sni_strict == other.sni_strict
            && self.session_tickets == other.session_tickets
            && self.http3 == other.http3
            && self.spiffe_client == other.spiffe_client
    }
}

/// `tls.spiffe_client`: clients are judged as SPIFFE X.509-SVIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SpiffeClient {
    /// The trust domain whose live bundle a client certificate must chain to.
    pub trust_domain: String,
    /// SPIFFE IDs, or patterns (`*` for one path segment, a final `**` for one or more), of which
    /// a client certificate must carry one. All are in `trust_domain`.
    pub allowed_ids: Vec<String>,
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum TlsVersion {
    /// TLS 1.2.
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    V1_3,
}

/// Whether and how clients are asked for a certificate (Traefik's `clientAuthType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    /// Ask for a certificate; serve clients with none and trust none.
    Request,
    /// Require some certificate; the chain is not judged.
    Require,
    /// A certificate, when sent, must chain to `client_ca_pem`; none is fine.
    VerifyIfGiven,
    /// A certificate that chains to `client_ca_pem` is required.
    RequireAndVerify,
}

/// The ACME challenge the issuer answers for an `acme` app's hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ChallengeKind {
    /// Answered over plain HTTP by every node; cannot prove a wildcard.
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// Answered with a TXT record the control plane publishes; proves wildcards and hosts
    /// that cannot serve plain HTTP.
    #[serde(rename = "dns-01")]
    Dns01,
    /// Answered on the TLS listener with a challenge certificate, so only port 443 must be
    /// reachable; cannot prove a wildcard.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// Certificate source for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Issued for the app's declared hosts.
    Acme,
    /// Issued at the first handshake for a matching host.
    OnDemand,
    /// Served from the certificates the snapshot carries, which the operator's internal CA
    /// issued; podgate orders nothing.
    Internal,
}

/// One deployed version of an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Revision {
    /// Unique within its app.
    pub id: Box<str>,
    /// Whether the revision takes new traffic.
    pub state: RevisionState,
    /// Share of new traffic against the app's other serving revisions.
    pub weight: u16,
    /// The services of this release. A router's service is looked up here first.
    #[serde(default)]
    pub services: Vec<Declared>,
}

/// Lifecycle state of a revision; see `docs/architecture.md` (`### Revision states`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RevisionState {
    /// Gets new sessions by weight.
    Serving,
    /// Gets no new sessions; still serves pinned ones.
    Retiring,
    /// Gets no new requests; in-flight requests finish.
    Draining,
}

/// Whether podgate staples an OCSP response to a certificate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OcspMode {
    /// Staple only when the certificate carries the TLS Feature `status_request` (must-staple)
    /// extension.
    #[default]
    Auto,
    /// Staple whenever the certificate names an OCSP responder in its Authority Information
    /// Access.
    On,
    /// Never staple.
    Off,
}

impl OcspMode {
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde's skip_serializing_if passes a reference"
    )]
    fn is_auto(&self) -> bool {
        *self == Self::Auto
    }
}

/// A certificate chain and its private key, served for the listed hosts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Certificate {
    /// Hosts the certificate answers for: exact names or `*.` wildcards.
    pub hosts: Vec<Box<str>>,
    /// Leaf certificate first, PEM.
    pub cert_pem: String,
    /// PKCS#8, PKCS#1 or SEC1 private key, PEM.
    pub key_pem: String,
    /// Serve this certificate for a name no other certificate covers, and for a handshake with
    /// no SNI, unless the app that owns the name sets `sni_strict`. At most one.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
    /// OCSP stapling: `auto` (default), `on` or `off`. The responder always comes from the
    /// certificate itself, never from the snapshot.
    #[serde(default, skip_serializing_if = "OcspMode::is_auto")]
    pub ocsp: OcspMode,
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

/// How certificates are issued and which node issues them. the daemon's `acme` module reads
/// every field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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
    /// HTTP-01 and TLS-ALPN-01 answers the control plane pushes back after an `acme_challenge`
    /// event. Every node serves the HTTP-01 ones on the plain HTTP listener and answers the
    /// TLS-ALPN-01 ones on the TLS listener.
    #[serde(default)]
    pub challenges: Vec<Challenge>,
    /// Hosts the control plane asks the issuer to get certificates for: the hosts of
    /// `certificate_requested` events it approved. Only hosts of `on_demand` apps count.
    #[serde(default)]
    pub requested_hosts: Vec<Box<str>>,
    /// DNS-01 TXT records the control plane has published and sees on the zone's authoritative
    /// servers, pushed back after `acme_challenge` events of type `dns-01`. The
    /// issuer tells the CA to validate a challenge only once it is listed here.
    #[serde(default)]
    pub dns_ready: Vec<DnsReady>,
}

/// One published DNS-01 TXT record. Carries no credential: it names a record that is already
/// public.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DnsReady {
    /// The record's name, `_acme-challenge.<domain>`.
    pub name: Box<str>,
    /// The record's value: base64url of the SHA-256 of the key authorization. It tells apart
    /// the challenges of an apex and its wildcard, which share one name.
    pub value: Box<str>,
}

/// External account binding credentials, as a CA hands them out.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ExternalAccount {
    /// The key identifier.
    pub key_id: String,
    /// The HMAC key, base64url.
    pub hmac_key: String,
}

/// One challenge answer pushed back after an `acme_challenge` event. Exactly one of `token`
/// (HTTP-01: `GET /.well-known/acme-challenge/<token>` returns `key_authorization`) and `name`
/// (TLS-ALPN-01: the host that an `acme-tls/1` handshake proves with a challenge
/// certificate over `key_authorization`) is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Challenge {
    /// The HTTP-01 challenge token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Box<str>>,
    /// The host of a TLS-ALPN-01 challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Box<str>>,
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
            .field("dns_ready", &self.dns_ready)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn declared_debug_redacts_every_key_pem() {
        let declared: Declared = serde_json::from_str(
            r#"{"name": "t", "type": "servers_transport", "server_name": "x.test",
                "client_cert": {"cert_pem": "CERT", "key_pem": "SECRET"},
                "more": [{"key_pem": "SECRET2"}]}"#,
        )
        .expect("declared");
        let shown = format!("{declared:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("[redacted]") && shown.contains("CERT") && shown.contains("x.test"));
    }

    #[test]
    fn declared_keeps_the_kind_fields_apart_from_name_and_type() {
        let declared: Declared = serde_json::from_str(
            r#"{"name": "web", "type": "loadbalancer", "servers": [], "algorithm": "round_robin"}"#,
        )
        .expect("parses");
        assert_eq!(&*declared.name, "web");
        assert_eq!(&*declared.kind, "loadbalancer");
        assert_eq!(declared.config.len(), 2);
        let back = serde_json::to_value(&declared).expect("serializes");
        assert_eq!(back["type"], "loadbalancer");
        assert_eq!(back["algorithm"], "round_robin");
    }

    #[test]
    fn a_router_reads_match_as_raw_json() {
        let router: Router = serde_json::from_str(
            r#"{"name": "r", "match": {"host": "a.test"}, "service": "web", "future_field": 1}"#,
        )
        .expect("unknown fields are ignored");
        assert_eq!(router.matcher["host"], "a.test");
        assert_eq!(router.priority, None);
        assert!(router.chain.is_empty());
    }

    #[test]
    fn model_roundtrip_is_stable() {
        let input = serde_json::json!({
            "version": 7,
            "tenants": [{"id": "acme", "weight": 2, "budget": {"max_inflight": 100, "max_buffer_bytes": 1_048_576}}],
            "apps": [{
                "id": "shop",
                "tenant": "acme",
                "declared_by": "podkit/agent",
                "tls": {"mode": "on_demand", "client_ca_pem": "ca", "challenge": "dns-01"},
                "routers": [{
                    "name": "web",
                    "entry_points": ["websecure"],
                    "match": {"host": "shop.test"},
                    "priority": 5,
                    "chain": ["strip"],
                    "service": "web",
                    "observability": {"access_log": false},
                    "declared_by": "label"
                }],
                "middlewares": [{"name": "strip", "type": "strip_prefix", "prefix": "/api"}],
                "default_chain": ["headers"],
                "services": [{"name": "web", "type": "loadbalancer", "servers": [{"url": "http://10.0.0.1:80"}]}],
                "transports": [{"name": "t", "type": "transport", "insecure": true}],
                "revisions": [{
                    "id": "r7",
                    "state": "retiring",
                    "weight": 10,
                    "services": [{"name": "web", "type": "loadbalancer", "servers": []}]
                }],
                "allow_domain_fronting": true,
                "record_bodies": true,
                "forwarded": {"x_forwarded": false, "real_ip": false, "rfc7239": true, "server": true},
                "scale_to_zero": {"idle_secs": 300, "wake_timeout_secs": 12},
                "canary": {"revision": "r8", "step_percent": 10, "interval_secs": 30, "max_error_permille": 20},
                "tcp": {
                    "routers": [{"name": "db", "service": "pg"}],
                    "services": [{"name": "pg", "type": "loadbalancer"}],
                    "middlewares": [{"name": "allow", "type": "ip_allow"}]
                },
                "udp": {"routers": [{"name": "dns", "service": "d"}], "services": [{"name": "d", "type": "loadbalancer"}]}
            }],
            "certificates": [{"hosts": ["*.shop.test"], "cert_pem": "cert", "key_pem": "key"}],
            "skew_secret": "abababababababab",
            "revert_window_secs": 90,
            "acme": {
                "issuer_node": "node-a",
                "directory_url": "https://acme.test/dir",
                "contact": ["mailto:ops@shop.test"],
                "eab": {"key_id": "kid", "hmac_key": "hmac"},
                "account_key_pem": "key",
                "challenges": [{"token": "t", "key_authorization": "t.k"}],
                "requested_hosts": ["x.shop.test"],
                "dns_ready": [{"name": "_acme-challenge.shop.test", "value": "v"}]
            },
            "entry_points": [{
                "name": "websecure",
                "tenants": ["acme"],
                "forwarded_headers": {"trusted": ["10.0.0.0/8"]},
                "proxy_protocol": {"trusted": []},
                "timeouts": {"idle_secs": 60},
                "http2": {"max_streams": 100},
                "redirect": {"to": "web"},
                "allow_encoded_slash": true,
                "max_header_bytes": 16384,
                "underscore_headers": "delete"
            }],
            "observability": {
                "access_log": {"format": "json"},
                "metrics": {"enabled": true},
                "tracing": {"sample": 0.1}
            }
        });

        let snapshot: Snapshot = serde_json::from_value(input.clone()).expect("parses");
        assert_eq!(serde_json::to_value(&snapshot).expect("to value"), input);

        let first = serde_json::to_string(&snapshot).expect("serializes");
        let again: Snapshot = serde_json::from_str(&first).expect("reparses");
        assert_eq!(again, snapshot);
        assert_eq!(serde_json::to_string(&again).expect("serializes"), first);
    }
}
