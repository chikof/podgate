//! SPIFFE workload identity: podgate fetches its X.509 SVIDs and the trust bundles
//! from a SPIFFE Workload API (`SPIFFE_ENDPOINT_SOCKET`, the agent's unix socket), presents an
//! SVID to upstreams that require mutual TLS, verifies those upstreams by SPIFFE ID, and verifies
//! the SVIDs of clients of apps that ask for it. Reference: `docs/ref/spiffe.md`.
//!
//! # One identity per tenant
//!
//! podgate is one workload with, usually, one SVID. If every tenant's upstream connections
//! presented it, a tenant able to name an address a mesh service trusts would act with the
//! platform's authority (a confused deputy). The operator's policy (`SPIFFE_POLICY_FILE`, see
//! [`policy`]) therefore gives each tenant its own SVID, by the agent's `hint`, and the server
//! IDs it may talk to. A tenant the file does not list has no SPIFFE at all (`spiffe_not_allowed`).
//! The snapshot can set neither the socket nor the policy; it only selects, within what the
//! policy allows.
//!
//! # Moving parts
//!
//! - [`client`]: the Workload API, gRPC over the socket.
//! - [`Service`]: the background service that keeps two streams open and feeds the [`Store`].
//! - [`Store`]: the last good SVIDs and bundles. A lookup never returns an expired SVID.
//! - [`Binding`]: a `servers_transport` with `spiffe`, bound to its tenant at compile time. It
//!   fills a peer with the tenant's SVID, a verifier for the server and the bundle, or, when
//!   there is no usable SVID or bundle, refuses to dial: a request never falls back to
//!   presenting another identity or none.
//! - [`ClientRule`]: what an app's `tls.spiffe_client` asks of clients.

pub mod bundle;
pub mod client;
pub mod policy;
pub mod svid;
pub mod verifier;

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::HeaderName;
use pingora::connectors::L4Connect;
use pingora::http::RequestHeader;
use pingora::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora::protocols::l4::stream::Stream;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorType};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use bundle::Bundle;
pub use policy::{IdPattern, Policy, SpiffeId};
pub use svid::Svid;
pub use verifier::ClientRule;

use crate::compile::Invalid;
use crate::table::CompiledApp;
use client::{ClientError, X509BundlesResponse, X509SvidResponse};
use verifier::{RefuseAll, ServerVerifier};

/// The request header that carries the verified SPIFFE ID of the client to the app.
pub const CLIENT_ID_HEADER: &str = "x-forwarded-tls-client-spiffe-id";

/// Most IDs a transport or an app may list.
const MAX_IDS: usize = 64;

/// The first wait before the agent is tried again.
const MIN_BACKOFF: Duration = Duration::from_millis(200);

/// The longest wait before the agent is tried again.
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Removes the SPIFFE ID header, in every spelling, from `request`. Runs on every request in the
/// entry stage: the header is only ever written from a certificate podgate verified.
pub fn strip(request: &mut RequestHeader) {
    let forged: Vec<HeaderName> = request
        .headers
        .keys()
        .filter(|name| {
            name.as_str().len() == CLIENT_ID_HEADER.len()
                && name
                    .as_str()
                    .bytes()
                    .zip(CLIENT_ID_HEADER.bytes())
                    .all(|(got, want)| {
                        got.eq_ignore_ascii_case(&want) || (got == b'_' && want == b'-')
                    })
        })
        .cloned()
        .collect();
    for name in forged {
        request.remove_header(&name);
    }
}

/// Why no SVID can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Unavailable {
    /// The agent has not issued an SVID with the tenant's hint (yet, or any more).
    #[error("the agent has issued no SVID with the tenant's hint")]
    NoSvid,
    /// The SVID with the hint has expired and no fresh one has arrived.
    #[error("the tenant's SVID has expired")]
    Expired,
}

#[derive(Clone)]
struct Stamped {
    seq: u64,
    bundle: Arc<Bundle>,
}

#[derive(Default, Clone)]
struct State {
    svids: Vec<Arc<Svid>>,
    /// The bundles the SVID stream carried: the SVID's own domain and the federated ones.
    from_svid: BTreeMap<Box<str>, Stamped>,
    /// The bundles of the bundle stream.
    from_bundles: BTreeMap<Box<str>, Stamped>,
}

/// The identities and trust bundles the agent last sent. Shared by the refresher, which writes
/// it, and every transport and app that reads it.
#[derive(Default)]
pub struct Store {
    state: ArcSwap<State>,
    seq: AtomicU64,
}

impl Store {
    /// An empty store: no SVID, no bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    /// The SVID whose hint is `hint`, as long as it has not expired.
    ///
    /// # Errors
    ///
    /// [`Unavailable`] when there is none, or the one there is has expired. Nothing else is
    /// returned instead: an expired or missing identity is never replaced by another.
    pub fn svid(&self, hint: &str) -> Result<Arc<Svid>, Unavailable> {
        self.svid_at(hint, SystemTime::now())
    }

    fn svid_at(&self, hint: &str, now: SystemTime) -> Result<Arc<Svid>, Unavailable> {
        let state = self.state.load();
        let mut seen = false;
        for svid in state.svids.iter().filter(|svid| svid.hint() == hint) {
            seen = true;
            if svid.valid_at(now) {
                return Ok(Arc::clone(svid));
            }
        }
        Err(if seen {
            Unavailable::Expired
        } else {
            Unavailable::NoSvid
        })
    }

    /// The live bundle of `trust_domain`; `None` when the agent has sent none.
    #[must_use]
    pub fn bundle(&self, trust_domain: &str) -> Option<Arc<Bundle>> {
        let state = self.state.load();
        let a = state.from_svid.get(trust_domain);
        let b = state.from_bundles.get(trust_domain);
        match (a, b) {
            (Some(a), Some(b)) => Some(Arc::clone(if a.seq > b.seq {
                &a.bundle
            } else {
                &b.bundle
            })),
            (Some(one), None) | (None, Some(one)) => Some(Arc::clone(&one.bundle)),
            (None, None) => None,
        }
    }

    /// Replaces the SVIDs and the bundles that came with them.
    pub fn set_svids(&self, svids: Vec<Svid>, bundles: BTreeMap<Box<str>, Bundle>) {
        let seq = self.next_seq();
        let svids: Vec<Arc<Svid>> = svids.into_iter().map(Arc::new).collect();
        let stamped: BTreeMap<Box<str>, Stamped> = bundles
            .into_iter()
            .map(|(domain, bundle)| {
                (
                    domain,
                    Stamped {
                        seq,
                        bundle: Arc::new(bundle),
                    },
                )
            })
            .collect();
        self.state.rcu(|old| State {
            svids: svids.clone(),
            from_svid: stamped.clone(),
            from_bundles: old.from_bundles.clone(),
        });
    }

    /// Replaces the bundles of the bundle stream.
    pub fn set_bundles(&self, bundles: BTreeMap<Box<str>, Bundle>) {
        let seq = self.next_seq();
        let stamped: BTreeMap<Box<str>, Stamped> = bundles
            .into_iter()
            .map(|(domain, bundle)| {
                (
                    domain,
                    Stamped {
                        seq,
                        bundle: Arc::new(bundle),
                    },
                )
            })
            .collect();
        self.state.rcu(|old| State {
            svids: old.svids.clone(),
            from_svid: old.from_svid.clone(),
            from_bundles: stamped.clone(),
        });
    }

    fn apply_svids(&self, response: X509SvidResponse) {
        let mut svids = Vec::new();
        let mut bundles: BTreeMap<Box<str>, Bundle> = BTreeMap::new();
        for item in response.svids {
            match Svid::parse(
                &item.spiffe_id,
                &item.x509_svid,
                &item.x509_svid_key,
                &item.hint,
            ) {
                Ok(svid) => {
                    match Bundle::from_der(&item.bundle) {
                        Ok(bundle) => {
                            bundles.insert(svid.id().trust_domain().into(), bundle);
                        }
                        Err(err) => {
                            tracing::warn!(id = %svid.id(), %err, "SPIFFE: unusable bundle")
                        }
                    }
                    svids.push(svid);
                }
                Err(err) => tracing::warn!(id = %item.spiffe_id, %err, "SPIFFE: unusable SVID"),
            }
        }
        for (name, der) in response.federated_bundles {
            add_bundle(&mut bundles, &name, &der);
        }
        self.set_svids(svids, bundles);
    }

    fn apply_bundles(&self, response: X509BundlesResponse) {
        let mut bundles = BTreeMap::new();
        for (name, der) in response.bundles {
            add_bundle(&mut bundles, &name, &der);
        }
        self.set_bundles(bundles);
    }
}

fn add_bundle(into: &mut BTreeMap<Box<str>, Bundle>, name: &str, der: &[u8]) {
    let Ok(domain) = policy::parse_trust_domain(name) else {
        tracing::warn!(
            trust_domain = name,
            "SPIFFE: bundle for a name that is no trust domain"
        );
        return;
    };
    match Bundle::from_der(der) {
        Ok(bundle) => {
            into.insert(domain, bundle);
        }
        Err(err) => tracing::warn!(trust_domain = name, %err, "SPIFFE: unusable bundle"),
    }
}

impl fmt::Debug for Store {
    /// Counts, never keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.load();
        f.debug_struct("Store")
            .field("svids", &state.svids.len())
            .field(
                "bundles",
                &(state.from_svid.len() + state.from_bundles.len()),
            )
            .finish()
    }
}

struct Inner {
    policy: Policy,
    store: Arc<Store>,
    socket: PathBuf,
}

/// The process's SPIFFE configuration: the agent's socket, the operator's policy, and the store
/// the refresher fills. Cheap to clone; [`Spiffe::default`] is a process with no SPIFFE.
#[derive(Clone, Default)]
pub struct Spiffe {
    inner: Option<Arc<Inner>>,
}

impl fmt::Debug for Spiffe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            None => f.write_str("Spiffe(off)"),
            Some(inner) => f.debug_tuple("Spiffe").field(&inner.socket).finish(),
        }
    }
}

/// The `spiffe` object of a `servers_transport`: the trust domain whose bundle verifies the
/// server and the IDs it may have. The tenant's own SVID is the client certificate; the tenant's
/// policy (`SPIFFE_POLICY_FILE`) decides whether this is allowed and which IDs may be named.
#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// SPIFFE IDs, or patterns (`*` for one path segment, a final `**` for one or more), of which
    /// the server's certificate must carry one. Each must fall under the tenant's
    /// `allowed_server_ids`.
    pub ids: Vec<String>,
    /// The trust domain whose bundle the server's certificate must chain to. Every ID is in it.
    pub trust_domain: String,
}

/// The `tls.spiffe_client` object of an app, in `podgate_model`.
pub use podgate_model::SpiffeClient;

fn not_allowed(message: impl Into<String>) -> Invalid {
    Invalid::new("spiffe_not_allowed", message)
}

fn patterns(
    what: &str,
    texts: &[String],
    trust_domain: &str,
    code: &'static str,
) -> Result<Vec<IdPattern>, Invalid> {
    if texts.is_empty() {
        return Err(Invalid::new(code, format!("{what}: list at least one ID")));
    }
    if texts.len() > MAX_IDS {
        return Err(Invalid::new(code, format!("{what}: at most {MAX_IDS} IDs")));
    }
    texts
        .iter()
        .map(|text| {
            let pattern = IdPattern::parse(text)
                .map_err(|err| Invalid::new(code, format!("{what}: {text}: {err}")))?;
            if pattern.trust_domain() != trust_domain {
                return Err(Invalid::new(
                    code,
                    format!("{what}: {text} is not in the trust domain {trust_domain}"),
                ));
            }
            Ok(pattern)
        })
        .collect()
}

impl Spiffe {
    /// SPIFFE with the agent at `socket` and `policy`.
    #[must_use]
    pub fn new(socket: PathBuf, policy: Policy) -> Self {
        Self {
            inner: Some(Arc::new(Inner {
                policy,
                store: Arc::new(Store::new()),
                socket,
            })),
        }
    }

    /// Whether the process has an agent and a policy.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// The store the refresher fills; `None` when SPIFFE is off.
    #[must_use]
    pub fn store(&self) -> Option<&Arc<Store>> {
        self.inner.as_ref().map(|inner| &inner.store)
    }

    /// The background service that keeps the store current; `None` when SPIFFE is off.
    #[must_use]
    pub fn service(&self) -> Option<Service> {
        self.inner.as_ref().map(|inner| Service {
            socket: inner.socket.clone(),
            store: Arc::clone(&inner.store),
        })
    }

    fn tenant_policy(&self, tenant: &str) -> Result<(&Inner, &policy::TenantPolicy), Invalid> {
        let inner = self.inner.as_deref().ok_or_else(|| {
            not_allowed("SPIFFE is not configured on this process (SPIFFE_ENDPOINT_SOCKET)")
        })?;
        let policy = inner.policy.tenant(tenant).ok_or_else(|| {
            not_allowed(format!(
                "tenant {tenant} is not in the SPIFFE policy, so it cannot use SPIFFE"
            ))
        })?;
        Ok((inner, policy))
    }

    /// Binds the `spiffe` object of a transport of `tenant`.
    ///
    /// # Errors
    ///
    /// `spiffe_not_allowed` when SPIFFE is off, the tenant is not in the policy or has
    /// `upstream_mtls` off; `spiffe_server_id_not_allowed` when an ID does not fall under the
    /// tenant's `allowed_server_ids`; `invalid_transport` for IDs that do not parse, a trust
    /// domain that does not, an ID outside the trust domain, or none or too many IDs.
    pub fn bind_upstream(&self, tenant: &str, config: &UpstreamConfig) -> Result<Binding, Invalid> {
        let (inner, policy) = self.tenant_policy(tenant)?;
        if !policy.upstream_mtls() {
            return Err(not_allowed(format!(
                "tenant {tenant} may not use SPIFFE for upstream mTLS"
            )));
        }
        let trust_domain = policy::parse_trust_domain(&config.trust_domain).map_err(|err| {
            Invalid::new("invalid_transport", format!("spiffe.trust_domain: {err}"))
        })?;
        let ids = patterns(
            "spiffe.ids",
            &config.ids,
            &trust_domain,
            "invalid_transport",
        )?;
        for id in &ids {
            if !policy
                .allowed_server_ids()
                .iter()
                .any(|allowed| allowed.covers(id))
            {
                return Err(Invalid::new(
                    "spiffe_server_id_not_allowed",
                    format!(
                        "spiffe.ids: {id} is outside the server IDs tenant {tenant} may talk to"
                    ),
                ));
            }
        }
        let Some(hint) = policy.svid_hint() else {
            return Err(not_allowed(format!("tenant {tenant} has no svid_hint")));
        };
        Ok(Binding {
            tenant: tenant.into(),
            hint: hint.into(),
            store: Arc::clone(&inner.store),
            trust_domain,
            ids: ids.into(),
            allowed: policy.allowed_server_ids().to_vec().into(),
        })
    }

    /// Binds the `tls.spiffe_client` of an app of `tenant`.
    ///
    /// # Errors
    ///
    /// `spiffe_not_allowed` when SPIFFE is off, the tenant is not in the policy, has
    /// `client_identity` off, or may not verify clients of the trust domain;
    /// `invalid_client_auth` for IDs that do not parse, a trust domain that does not, an ID
    /// outside the trust domain, or none or too many IDs.
    pub fn bind_client(
        &self,
        tenant: &str,
        config: &SpiffeClient,
    ) -> Result<(ClientRule, Arc<Store>), Invalid> {
        let (inner, policy) = self.tenant_policy(tenant)?;
        if !policy.client_identity() {
            return Err(not_allowed(format!(
                "tenant {tenant} may not verify client identities with SPIFFE"
            )));
        }
        let trust_domain = policy::parse_trust_domain(&config.trust_domain).map_err(|err| {
            Invalid::new(
                "invalid_client_auth",
                format!("tls.spiffe_client.trust_domain: {err}"),
            )
        })?;
        if !policy.allows_client_trust_domain(&trust_domain) {
            return Err(not_allowed(format!(
                "tenant {tenant} may not verify clients of the trust domain {trust_domain}"
            )));
        }
        let ids = patterns(
            "tls.spiffe_client.allowed_ids",
            &config.allowed_ids,
            &trust_domain,
            "invalid_client_auth",
        )?;
        Ok((
            ClientRule::new(&trust_domain, ids),
            Arc::clone(&inner.store),
        ))
    }
}

/// A transport's `spiffe` object tied to its tenant: what it takes to fill a peer.
#[derive(Clone)]
pub struct Binding {
    tenant: Box<str>,
    hint: Box<str>,
    store: Arc<Store>,
    trust_domain: Box<str>,
    ids: Arc<[IdPattern]>,
    allowed: Arc<[IdPattern]>,
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Binding")
            .field("tenant", &self.tenant)
            .field("trust_domain", &self.trust_domain)
            .field("ids", &self.ids.len())
            .finish_non_exhaustive()
    }
}

/// What explain shows of a transport's `spiffe`: no key, no certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// The trust domain of the bundle.
    pub trust_domain: Box<str>,
    /// The IDs the server may have.
    pub ids: Vec<String>,
}

impl Binding {
    /// Makes `peer` present the tenant's SVID and verify the server by bundle and SPIFFE ID, or,
    /// when there is no unexpired SVID or no bundle, refuse to connect at all. Nothing is ever
    /// presented in place of the tenant's identity.
    pub fn apply(&self, peer: &mut HttpPeer) {
        let svid = self.store.svid(&self.hint);
        let bundle = self.store.bundle(&self.trust_domain);
        match (svid, bundle) {
            (Ok(svid), Some(bundle)) => {
                peer.client_cert_key = Some(svid.cert_key());
                peer.options.ca = Some(bundle.roots());
                peer.options.server_cert_verifier = Some(Arc::new(ServerVerifier::new(
                    bundle,
                    &self.trust_domain,
                    &self.ids,
                    &self.allowed,
                )));
            }
            (svid, bundle) => {
                let reason = match (svid, bundle) {
                    (Err(Unavailable::NoSvid), _) => format!(
                        "no SPIFFE SVID for tenant {}: the agent has issued none with its hint",
                        self.tenant
                    ),
                    (Err(Unavailable::Expired), _) => {
                        format!("the SPIFFE SVID of tenant {} has expired", self.tenant)
                    }
                    (Ok(_), _) => format!(
                        "no SPIFFE trust bundle for {}: the agent has sent none",
                        self.trust_domain
                    ),
                };
                // Pingora would fall back to the platform roots without a CA; the verifier makes
                // sure nothing is accepted should a dial happen anyway.
                peer.options.server_cert_verifier = Some(Arc::new(RefuseAll));
                peer.options.custom_l4 = Some(Arc::new(Refuse {
                    reason: reason.into(),
                }));
            }
        }
    }

    /// What the transport's fingerprint and explain use.
    #[must_use]
    pub fn summary(&self) -> Summary {
        Summary {
            trust_domain: self.trust_domain.clone(),
            ids: self.ids.iter().map(ToString::to_string).collect(),
        }
    }
}

/// What `peer` was given by [`Binding::apply`]: a digest of the SVID's certificate (its serial
/// is in it) and of the bundle's roots. Part of the pool key, so a connection made with a
/// rotated identity or bundle is never mixed with one made with the old.
#[must_use]
pub fn peer_identity(peer: &HttpPeer) -> [u8; 16] {
    let mut hash = Sha256::new();
    match &peer.client_cert_key {
        Some(cert_key) => {
            hash.update([1]);
            hash.update(cert_key.leaf().borrow_raw_cert());
        }
        None => hash.update([0]),
    }
    if let Some(roots) = &peer.options.ca {
        for root in roots.iter() {
            hash.update(root.borrow_raw_cert());
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&hash.finalize()[..16]);
    out
}

/// A dial that fails: what a peer without a usable identity connects with.
#[derive(Debug)]
struct Refuse {
    reason: Box<str>,
}

#[async_trait]
impl L4Connect for Refuse {
    async fn connect(&self, _: &PingoraAddr) -> pingora::Result<Stream> {
        Error::e_explain(ErrorType::ConnectError, self.reason.to_string())
    }
}

/// Keeps the [`Store`] current: two streams to the agent, each reopened with backoff when it
/// ends. While the agent is away the store keeps what it has; [`Store::svid`] stops serving an
/// SVID the moment it expires.
pub struct Service {
    socket: PathBuf,
    store: Arc<Store>,
}

impl Service {
    /// The service for `store` and the agent at `socket`, for tests that run no process.
    #[must_use]
    pub fn new(socket: PathBuf, store: Arc<Store>) -> Self {
        Self { socket, store }
    }

    async fn svids(&self) {
        keep_watching(
            &self.socket,
            client::FETCH_X509_SVID,
            |response: X509SvidResponse| {
                self.store.apply_svids(response);
            },
        )
        .await;
    }

    async fn bundles(&self) {
        keep_watching(
            &self.socket,
            client::FETCH_X509_BUNDLES,
            |response: X509BundlesResponse| self.store.apply_bundles(response),
        )
        .await;
    }

    /// Runs both streams until the process shuts down.
    pub async fn run(&self, mut shutdown: ShutdownWatch) {
        tokio::select! {
            () = async { tokio::join!(self.svids(), self.bundles()); } => {}
            _ = shutdown.changed() => {}
        }
    }
}

#[async_trait]
impl BackgroundService for Service {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.run(shutdown).await;
    }
}

async fn keep_watching<M: Message + Default>(
    socket: &std::path::Path,
    method: &'static str,
    mut on: impl FnMut(M),
) {
    let mut delay = MIN_BACKOFF;
    let mut healthy = false;
    loop {
        let mut received = false;
        let result = client::watch(socket, method, |message| {
            received = true;
            on(message);
        })
        .await;
        if received {
            delay = MIN_BACKOFF;
            healthy = true;
        }
        match result {
            Err(ClientError::Closed) | Ok(()) => {
                tracing::info!(method, "SPIFFE: the agent closed the stream");
            }
            Err(err) if healthy => {
                tracing::warn!(method, %err, "SPIFFE: lost the agent; the last identities stay until they expire");
                healthy = false;
            }
            Err(err) => tracing::debug!(method, %err, "SPIFFE: the agent is not reachable"),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(MAX_BACKOFF);
    }
}

/// The `kind` strings of the SPIFFE posture changes of a plan.
pub mod kind {
    /// The host's services now trust a SPIFFE ID, or its clients a trust domain, they did not.
    pub const TRUST_ADDED: &str = "spiffe_trust_added";
    /// The host still verifies clients as SPIFFE SVIDs but admits IDs it did not.
    pub const CLIENT_LOOSENED: &str = "spiffe_client_loosened";
    /// The host no longer verifies clients as SPIFFE SVIDs.
    pub const CLIENT_REMOVED: &str = "spiffe_client_removed";
}

/// What a swap from `live` to `candidate` relaxes in SPIFFE trust: IDs or trust domains newly
/// trusted (upstream `ids`, a client's trust domain), `allowed_ids` that admit more, and a
/// `spiffe_client` that is gone.
pub(crate) fn relaxations(live: &CompiledApp, candidate: &CompiledApp) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let old: Vec<IdPattern> = live
        .spiffe_trust()
        .iter()
        .filter_map(|text| IdPattern::parse(text).ok())
        .collect();
    let mut added = candidate
        .spiffe_trust()
        .iter()
        .filter_map(|text| IdPattern::parse(text).ok())
        .any(|new| !old.iter().any(|known| known.covers(&new)));
    let rule = |app: &CompiledApp| {
        app.client_auth()
            .and_then(|auth| auth.spiffe_rule())
            .cloned()
    };
    match (rule(live), rule(candidate)) {
        (Some(_), None) => kinds.push(kind::CLIENT_REMOVED),
        (Some(old), Some(new)) if old.trust_domain() != new.trust_domain() => {
            added = true;
        }
        (Some(old), Some(new)) => {
            if new
                .allowed_ids()
                .iter()
                .any(|id| !old.allowed_ids().iter().any(|known| known.covers(id)))
            {
                kinds.push(kind::CLIENT_LOOSENED);
            }
        }
        (None, Some(_)) => added = true,
        (None, None) => {}
    }
    if added {
        kinds.push(kind::TRUST_ADDED);
    }
    kinds
}

#[cfg(test)]
mod test {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SanType};
    use rustls::pki_types::pem::PemObject;

    use super::*;

    struct Issued {
        chain: Vec<u8>,
        key: Vec<u8>,
        root: Vec<u8>,
    }

    fn issue(id: &str, days: i64) -> Issued {
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("params");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer =
            CertifiedIssuer::self_signed(ca, KeyPair::generate().expect("key")).expect("ca");
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![SanType::URI(id.try_into().expect("uri"))];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(days);
        let leaf = params.signed_by(&key, &issuer).expect("leaf");
        Issued {
            chain: leaf.der().as_ref().to_vec(),
            key: key.serialize_der(),
            root: issuer.der().as_ref().to_vec(),
        }
    }

    fn svid(id: &str, hint: &str, days: i64) -> (Svid, Vec<u8>) {
        let issued = issue(id, days);
        (
            Svid::parse(id, &issued.chain, &issued.key, hint).expect("svid"),
            issued.root,
        )
    }

    #[test]
    fn the_store_serves_by_hint_and_never_an_expired_svid() {
        let store = Store::new();
        let (web, root) = svid("spiffe://td/ns/acme/sa/web", "acme", 1);
        let (gone, _) = svid("spiffe://td/ns/gone/sa/web", "gone", -1);
        let bundle = Bundle::from_der(&root).expect("bundle");
        store.set_svids(vec![web, gone], BTreeMap::from([("td".into(), bundle)]));
        assert_eq!(
            store.svid("acme").expect("acme").id().to_string(),
            "spiffe://td/ns/acme/sa/web"
        );
        assert_eq!(store.svid("gone").err(), Some(Unavailable::Expired));
        assert_eq!(store.svid("other").err(), Some(Unavailable::NoSvid));
        assert!(store.bundle("td").is_some());
        assert!(store.bundle("elsewhere").is_none());
        let later = SystemTime::now() + Duration::from_secs(3 * 86_400);
        assert_eq!(
            store.svid_at("acme", later).err(),
            Some(Unavailable::Expired)
        );
    }

    #[test]
    fn a_newer_bundle_wins_whichever_stream_it_came_from() {
        let store = Store::new();
        let (_, old) = svid("spiffe://td/a", "h", 1);
        let (_, new) = svid("spiffe://td/a", "h", 1);
        store.set_svids(
            Vec::new(),
            BTreeMap::from([("td".into(), Bundle::from_der(&old).expect("old"))]),
        );
        store.set_bundles(BTreeMap::from([(
            "td".into(),
            Bundle::from_der(&new).expect("new"),
        )]));
        let wanted = Bundle::from_der(&new).expect("new").digest();
        assert_eq!(store.bundle("td").expect("bundle").digest(), wanted);
        let (_, newest) = svid("spiffe://td/a", "h", 1);
        store.set_svids(
            Vec::new(),
            BTreeMap::from([("td".into(), Bundle::from_der(&newest).expect("newest"))]),
        );
        let wanted = Bundle::from_der(&newest).expect("newest").digest();
        assert_eq!(store.bundle("td").expect("bundle").digest(), wanted);
    }

    #[test]
    fn an_svid_is_refused_when_its_pieces_disagree() {
        let issued = issue("spiffe://td/ns/a", 1);
        assert_eq!(
            Svid::parse("spiffe://td/ns/other", &issued.chain, &issued.key, "h").err(),
            Some(svid::SvidError::Mismatch {
                announced: "spiffe://td/ns/other".into(),
                found: "spiffe://td/ns/a".into()
            })
        );
        let other = issue("spiffe://td/ns/a", 1);
        assert_eq!(
            Svid::parse("spiffe://td/ns/a", &issued.chain, &other.key, "h").err(),
            Some(svid::SvidError::Key)
        );
        assert_eq!(
            Svid::parse("spiffe://td/ns/a", b"junk", &issued.key, "h").err(),
            Some(svid::SvidError::Chain)
        );
    }

    #[test]
    fn debug_never_shows_a_key() {
        let issued = issue("spiffe://td/ns/a", 1);
        let svid = Svid::parse("spiffe://td/ns/a", &issued.chain, &issued.key, "h").expect("svid");
        let shown = format!("{svid:?}");
        let key = issued
            .key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!shown.contains(&key) && !shown.contains("key"), "{shown}");
        let pem = KeyPair::generate().expect("key").serialize_pem();
        assert!(rustls::pki_types::PrivateKeyDer::from_pem_slice(pem.as_bytes()).is_ok());
    }

    #[test]
    fn the_id_header_is_stripped_in_every_spelling() {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request
            .append_header("X-Forwarded-Tls-Client-Spiffe-Id", "spiffe://evil/a")
            .expect("header");
        request
            .append_header("x_forwarded_tls_client_spiffe_id", "spiffe://evil/b")
            .expect("header");
        request.append_header("x-other", "kept").expect("header");
        strip(&mut request);
        assert_eq!(request.headers.len(), 1);
        assert!(request.headers.contains_key("x-other"));
    }
}
