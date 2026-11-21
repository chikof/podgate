//! What is configured and how it is doing: the logic behind `GET /v1/overview`.
//!
//! [`render`] reads the live [`RoutingTable`], the same compiled table the proxy routes with, and
//! the runtime registries that outlive it (server health and ejection live in the table's
//! servers; in-flight counters, tenant budgets and response outcomes in their own registries). It
//! never reads a snapshot: the snapshot is where the secrets are. A middleware reaches the view
//! through its [`Stage::describe`](crate::middleware::Stage::describe) only, and a test fails
//! when any built kind describes itself with a field named like a secret.
//!
//! The document is bounded. Every list takes at most `limit` items, and the whole body never
//! exceeds `max_bytes`: an item that does not fit ends its list, and `apps` carries a `next`
//! cursor to continue from. An app that alone is larger than the room is replaced by a stub with
//! its counts.

use std::io::Write as _;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::budget::Budgets;
use crate::canary;
use crate::entry::EntryPoint;
use crate::inflight::Inflight;
use crate::outcomes::{Counts, Outcomes, RING_SECS};
use crate::router::CompiledRouter;
use crate::service::{self, outlier};
use crate::table::{CompiledApp, CompiledRevision, RoutingTable};
use crate::tls::Summary as CertSummary;
use podgate_model::{Budget, ChallengeKind, RevisionState, ScaleToZero, TlsMode};

/// Largest response body, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Items per list when the request does not say.
pub const DEFAULT_LIMIT: usize = 50;

/// Most items per list.
pub const MAX_LIMIT: usize = 500;

/// Bytes kept free after each item for closing a list: the brackets, `truncated` and `next`.
const TAIL: usize = 128;

/// Share of the response (an eighth) the tenants and the certificates may take each, so the apps,
/// the real payload, always have room.
const SMALL_SECTION_SHARE: usize = 8;

/// A part of the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Version, counts and the process identity.
    Summary,
    /// Tenants with their budgets and live usage.
    Tenants,
    /// Apps with routers, revisions, services and middlewares.
    Apps,
    /// The listeners this process bound.
    EntryPoints,
    /// The certificates the snapshot serves.
    Certificates,
}

impl Section {
    const ALL: [Self; 5] = [
        Self::Summary,
        Self::Tenants,
        Self::Apps,
        Self::EntryPoints,
        Self::Certificates,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Tenants => "tenants",
            Self::Apps => "apps",
            Self::EntryPoints => "entry_points",
            Self::Certificates => "certificates",
        }
    }

    /// Reads a comma separated `section` parameter.
    ///
    /// # Errors
    ///
    /// The unknown name, with the names that exist.
    pub fn parse_list(list: &str) -> Result<Vec<Self>, String> {
        list.split(',')
            .map(|word| {
                Self::ALL
                    .into_iter()
                    .find(|section| section.name() == word.trim())
                    .ok_or_else(|| {
                        let names: Vec<&str> = Self::ALL.iter().map(|s| s.name()).collect();
                        format!(
                            "unknown section {word:?}; the sections are {}",
                            names.join(", ")
                        )
                    })
            })
            .collect()
    }
}

/// What to show.
#[derive(Debug, Clone)]
pub struct Query {
    /// Only this tenant's tenant entry and apps.
    pub tenant: Option<String>,
    /// Only the app with this id.
    pub app: Option<String>,
    /// Most items per list, at most [`MAX_LIMIT`].
    pub limit: usize,
    /// Apps after this app id, in id order.
    pub after: Option<String>,
    /// The sections to show; empty means all.
    pub sections: Vec<Section>,
    /// Largest body, in bytes.
    pub max_bytes: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            tenant: None,
            app: None,
            limit: DEFAULT_LIMIT,
            after: None,
            sections: Vec::new(),
            max_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

impl Query {
    fn wants(&self, section: Section) -> bool {
        self.sections.is_empty() || self.sections.contains(&section)
    }
}

/// The runtime registries the overview reads next to the table.
#[derive(Debug, Clone, Copy)]
pub struct Runtime<'a> {
    /// Per-tenant usage.
    pub budgets: &'a Budgets,
    /// Requests in flight per revision.
    pub inflight: &'a Inflight,
    /// Response outcomes over the last minutes.
    pub outcomes: &'a Outcomes,
    /// Identifies this run of the process, as on the event feed.
    pub boot_id: &'a str,
    /// The listeners the process bound.
    pub entry_points: &'a [EntryPoint],
    /// Where the read-only metrics listener serves, when the process has one.
    pub metrics_addr: Option<std::net::SocketAddr>,
    /// The `podgate-writer` that owns the live snapshot, when the owner sent a name.
    pub writer: Option<&'a str>,
}

/// Renders the overview of `table` as a JSON body of at most `query.max_bytes` bytes.
///
/// # Errors
///
/// Fails only when a value cannot be serialized, which the view types never do.
pub fn render(
    table: &RoutingTable,
    runtime: &Runtime<'_>,
    query: &Query,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = vec![b'{'];
    let mut first = true;
    let mut key = |out: &mut Vec<u8>, section: Section| {
        if !first {
            out.push(b',');
        }
        first = false;
        out.extend_from_slice(format!("\"{}\":", section.name()).as_bytes());
    };
    if query.wants(Section::Summary) {
        key(&mut out, Section::Summary);
        serde_json::to_writer(&mut out, &summary(table, runtime))?;
    }
    if query.wants(Section::EntryPoints) {
        key(&mut out, Section::EntryPoints);
        serde_json::to_writer(&mut out, &entry_points(table, runtime))?;
    }
    if query.wants(Section::Tenants) {
        key(&mut out, Section::Tenants);
        tenants(&mut out, table, runtime, query)?;
    }
    if query.wants(Section::Certificates) {
        key(&mut out, Section::Certificates);
        certificates(&mut out, table, query)?;
    }
    if query.wants(Section::Apps) {
        key(&mut out, Section::Apps);
        apps(&mut out, table, runtime, query)?;
    }
    out.push(b'}');
    Ok(out)
}

#[derive(Serialize)]
struct SummaryView<'a> {
    version: u64,
    /// Seconds since the Unix epoch when the table was compiled.
    applied_at: u64,
    boot_id: &'a str,
    /// The read-only metrics listener, when the process has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics_addr: Option<std::net::SocketAddr>,
    /// The writer that owns the snapshot, when it sent a name.
    #[serde(skip_serializing_if = "Option::is_none")]
    writer: Option<&'a str>,
    tenants: usize,
    apps: usize,
    routers: usize,
    services: usize,
    servers: ServerCounts,
}

#[derive(Default, Serialize)]
struct ServerCounts {
    healthy: usize,
    unhealthy: usize,
    ejected: usize,
}

fn summary<'a>(table: &RoutingTable, runtime: &Runtime<'a>) -> SummaryView<'a> {
    let mut view = SummaryView {
        version: table.version(),
        applied_at: table.applied_at(),
        boot_id: runtime.boot_id,
        metrics_addr: runtime.metrics_addr,
        writer: runtime.writer,
        tenants: table.tenant_ids().count(),
        apps: table.apps().len(),
        routers: 0,
        services: 0,
        servers: ServerCounts::default(),
    };
    for app in table.apps() {
        view.routers += app.routers().len();
        for (_, named) in services_of(app) {
            view.services += 1;
            for server in named.service.servers().iter() {
                if outlier::ejected_for(server).is_some() {
                    view.servers.ejected += 1;
                } else if !server
                    .state
                    .healthy
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    view.servers.unhealthy += 1;
                } else {
                    view.servers.healthy += 1;
                }
            }
        }
    }
    view
}

/// Every service of `app` with the revision it belongs to (`None`: shared by all revisions).
fn services_of(app: &CompiledApp) -> impl Iterator<Item = (Option<&str>, &service::Named)> {
    let shared = app.services().iter().map(|named| (None, named));
    let own = app.revisions().iter().flat_map(|revision| {
        revision
            .services()
            .iter()
            .map(move |named| (Some(revision.id()), named))
    });
    shared.chain(own)
}

#[derive(Serialize)]
struct EntryPointView<'a> {
    name: &'a str,
    protocol: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<std::net::SocketAddr>,
    #[serde(skip_serializing_if = "is_false")]
    proxy_protocol: bool,
    /// Whom the entry point believes about the client: `nobody`, `listed_peers` or `everyone`.
    forwarded_headers: &'static str,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(flag: &bool) -> bool {
    !*flag
}

fn entry_points<'a>(table: &'a RoutingTable, runtime: &Runtime<'a>) -> Vec<EntryPointView<'a>> {
    table
        .context()
        .entry_points()
        .map(|(name, protocol)| {
            let bound = runtime
                .entry_points
                .iter()
                .find(|point| &*point.name == name);
            EntryPointView {
                name,
                protocol: protocol.as_str(),
                address: bound.map(|point| point.addr),
                proxy_protocol: bound.is_some_and(|point| point.proxy_protocol),
                forwarded_headers: match table.forwarded_trust(name) {
                    None => "nobody",
                    Some(trust) if trust.is_insecure() => "everyone",
                    Some(_) => "listed_peers",
                },
            }
        })
        .collect()
}

#[derive(Serialize)]
struct TenantView<'a> {
    id: &'a str,
    weight: u32,
    budget: Budget,
    apps: usize,
    inflight: u32,
    buffer_bytes: u64,
}

fn tenants(
    out: &mut Vec<u8>,
    table: &RoutingTable,
    runtime: &Runtime<'_>,
    query: &Query,
) -> Result<(), serde_json::Error> {
    let mut ids: Vec<&str> = table
        .tenant_ids()
        .filter(|id| query.tenant.as_deref().is_none_or(|wanted| wanted == *id))
        .collect();
    ids.sort_unstable();
    let mut app_counts = std::collections::HashMap::<&str, usize>::new();
    for app in table.apps() {
        *app_counts.entry(app.tenant()).or_default() += 1;
    }
    let end = out.len() + query.max_bytes / SMALL_SECTION_SHARE;
    write_page(
        out,
        &ids,
        query.limit,
        end,
        |id| id,
        |id| {
            let used = runtime.budgets.get(id);
            TenantView {
                id,
                weight: table.tenant_weight(id).unwrap_or_default(),
                budget: table.tenant_budget(id).unwrap_or(Budget {
                    max_inflight: 0,
                    max_buffer_bytes: 0,
                }),
                apps: app_counts.get(id).copied().unwrap_or_default(),
                inflight: used.as_ref().map_or(0, |budget| budget.inflight()),
                buffer_bytes: used.as_ref().map_or(0, |budget| budget.buffered()),
            }
        },
        |_| None,
    )
}

#[derive(Serialize)]
struct CertificateView<'a> {
    hosts: &'a [Box<str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<&'a str>,
    /// Seconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<i64>,
    /// `acme` when the issuer renews it, `snapshot` when the control plane supplies it.
    source: &'static str,
    /// Served for names no certificate covers; absent otherwise.
    #[serde(skip_serializing_if = "is_false")]
    default: bool,
}

fn certificates(
    out: &mut Vec<u8>,
    table: &RoutingTable,
    query: &Query,
) -> Result<(), serde_json::Error> {
    let shown: Vec<&CertSummary> = table
        .certificates()
        .summaries()
        .iter()
        .filter(|cert| {
            query.tenant.is_none()
                || table
                    .apps()
                    .iter()
                    .filter(|app| Some(app.tenant()) == query.tenant.as_deref())
                    .flat_map(|app| app.hosts())
                    .any(|host| cert.hosts.contains(host))
        })
        .collect();
    let end = out.len() + query.max_bytes / SMALL_SECTION_SHARE;
    write_page(
        out,
        &shown,
        query.limit,
        end,
        |cert| cert.hosts.first().map_or("", AsRef::as_ref),
        |cert| CertificateView {
            hosts: &cert.hosts,
            issuer: cert.issuer.as_deref(),
            not_after: cert.not_after,
            default: cert.default,
            source: if table
                .acme()
                .certs()
                .iter()
                .find(|info| info.hosts == cert.hosts)
                .is_some_and(|info| table.acme().renewable(info))
            {
                "acme"
            } else {
                "snapshot"
            },
        },
        |_| None,
    )
}

#[derive(Serialize)]
struct AppView<'a> {
    id: &'a str,
    tenant: &'a str,
    declared_by: &'a str,
    tls: TlsView,
    hosts: &'a [Box<str>],
    allow_domain_fronting: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scale_to_zero: Option<ScaleToZero>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canary: Option<canary::Status<'a>>,
    routers: Vec<RouterView<'a>>,
    revisions: Vec<RevisionView<'a>>,
    services: Vec<ServiceView<'a>>,
    middlewares: Vec<MiddlewareView<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp: Option<TcpView<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp: Option<UdpView<'a>>,
    recent: Recent,
}

/// The app's TCP routers and services.
#[derive(Serialize)]
struct TcpView<'a> {
    routers: Vec<TcpRouterView<'a>>,
    services: Vec<TcpServiceView<'a>>,
}

#[derive(Serialize)]
struct TcpRouterView<'a> {
    name: &'a str,
    entry_points: &'a [Box<str>],
    service: &'a str,
    #[serde(rename = "match", skip_serializing_if = "Option::is_none")]
    matcher: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<crate::l4::tcp::Tls>,
}

#[derive(Serialize)]
struct TcpServiceView<'a> {
    name: &'a str,
    algorithm: Option<&'static str>,
    /// The addresses the servers stand for now: a name is expanded into what it resolves to.
    servers: Vec<std::net::SocketAddr>,
    /// The DNS names among the servers.
    names: Vec<&'a str>,
    idle_timeout_secs: u64,
}

/// The app's UDP routers and services.
#[derive(Serialize)]
struct UdpView<'a> {
    routers: Vec<UdpRouterView<'a>>,
    services: Vec<UdpServiceView<'a>>,
}

#[derive(Serialize)]
struct UdpRouterView<'a> {
    name: &'a str,
    entry_points: &'a [Box<str>],
    service: &'a str,
    max_sessions: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_reply_ratio: Option<u32>,
}

#[derive(Serialize)]
struct UdpServiceView<'a> {
    name: &'a str,
    servers: &'a [std::net::SocketAddr],
    session_timeout_secs: u64,
}

/// The TLS policy without any certificate or CA bytes.
#[derive(Serialize)]
struct TlsView {
    mode: TlsMode,
    challenge: ChallengeKind,
    client_auth: bool,
}

#[derive(Serialize)]
struct RouterView<'a> {
    name: &'a str,
    declared_by: &'a str,
    /// Absent: every HTTP and HTTPS entry point.
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_points: Option<&'a [Box<str>]>,
    #[serde(rename = "match")]
    matcher: Value,
    priority: i32,
    chain: Vec<&'a str>,
    service: &'a str,
}

#[derive(Serialize)]
struct RevisionView<'a> {
    id: &'a str,
    state: RevisionState,
    weight: u16,
    effective_weight: u16,
    inflight: usize,
    recent: Recent,
}

#[derive(Serialize)]
struct ServiceView<'a> {
    name: &'a str,
    /// Absent for a service every revision shares.
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<&'a str>,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<&'static str>,
    #[serde(skip_serializing_if = "is_false")]
    health_check: bool,
    #[serde(skip_serializing_if = "is_false")]
    outlier_detection: bool,
    servers: Vec<ServerView>,
}

#[derive(Serialize)]
struct ServerView {
    url: Box<str>,
    weight: u32,
    /// Healthy and not ejected: whether a new request may go there.
    available: bool,
    /// Requests in flight to the server.
    active: u32,
    /// The active health check's verdict; absent without a `health_check`.
    #[serde(skip_serializing_if = "Option::is_none")]
    healthy: Option<bool>,
    /// Milliseconds until an ejection by outlier detection ends; absent when not ejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    ejected_for_ms: Option<u64>,
}

#[derive(Serialize)]
struct MiddlewareView<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    /// What the kind chooses to show about itself; absent when it shows nothing.
    #[serde(skip_serializing_if = "Value::is_null")]
    config: Value,
}

/// Requests answered over the last [`RING_SECS`] seconds.
#[derive(Serialize)]
struct Recent {
    window_secs: u64,
    requests: u64,
    errors_5xx: u64,
}

impl From<Counts> for Recent {
    fn from(counts: Counts) -> Self {
        Self {
            window_secs: RING_SECS,
            requests: counts.total,
            errors_5xx: counts.errors_5xx,
        }
    }
}

fn recent(runtime: &Runtime<'_>, app: &str, revision: Option<&str>) -> Recent {
    runtime
        .outcomes
        .window(app, revision, Duration::from_secs(RING_SECS))
        .into()
}

fn apps(
    out: &mut Vec<u8>,
    table: &RoutingTable,
    runtime: &Runtime<'_>,
    query: &Query,
) -> Result<(), serde_json::Error> {
    let mut selected: Vec<&CompiledApp> = table
        .apps()
        .iter()
        .filter(|app| query.tenant.as_deref().is_none_or(|t| t == app.tenant()))
        .filter(|app| query.app.as_deref().is_none_or(|id| id == app.id()))
        .collect();
    selected.sort_unstable_by_key(|app| app.id());
    let start = query
        .after
        .as_deref()
        .map_or(0, |after| selected.partition_point(|app| app.id() <= after));
    // `total` counts the apps the filters select, wherever the cursor is.
    write_page_from(
        out,
        &selected,
        start,
        query.limit,
        query.max_bytes,
        |app| app.id(),
        |app| app_view(app, runtime),
        |view| {
            serde_json::to_vec(&serde_json::json!({
                "id": view.id,
                "tenant": view.tenant,
                "too_large": true,
                "routers": view.routers.len(),
                "revisions": view.revisions.len(),
                "services": view.services.len(),
                "middlewares": view.middlewares.len(),
            }))
            .ok()
        },
    )
}

fn app_view<'a>(app: &'a CompiledApp, runtime: &Runtime<'_>) -> AppView<'a> {
    AppView {
        id: app.id(),
        tenant: app.tenant(),
        declared_by: app.declared_by(),
        tls: TlsView {
            mode: app.tls().mode,
            challenge: app.tls().challenge,
            client_auth: app.client_auth().is_some(),
        },
        hosts: app.hosts(),
        allow_domain_fronting: app.allow_domain_fronting(),
        scale_to_zero: app.scale_to_zero(),
        canary: app.canary(),
        routers: app
            .routers()
            .iter()
            .map(|router| router_view(app, router))
            .collect(),
        revisions: app
            .revisions()
            .iter()
            .map(|revision| revision_view(app, revision, runtime))
            .collect(),
        services: services_of(app)
            .map(|(revision, named)| service_view(revision, named))
            .collect(),
        middlewares: app
            .stages()
            .iter()
            .map(|named| MiddlewareView {
                name: &named.name,
                kind: named.stage.kind(),
                config: named.stage.describe(),
            })
            .collect(),
        tcp: tcp_view(app),
        udp: udp_view(app),
        recent: recent(runtime, app.id(), None),
    }
}

/// The TCP side of `app`, `None` when it declares none.
fn tcp_view(app: &CompiledApp) -> Option<TcpView<'_>> {
    let tcp = app.l4().tcp();
    if tcp.routers().is_empty() && tcp.services().is_empty() {
        return None;
    }
    Some(TcpView {
        routers: (0..tcp.routers().len())
            .filter_map(|at| {
                let (router, service) = tcp.route(at)?;
                Some(TcpRouterView {
                    name: router.name(),
                    entry_points: router.entry_points(),
                    service: service.name(),
                    matcher: router.match_json(),
                    tls: router.tls(),
                })
            })
            .collect(),
        services: tcp
            .services()
            .iter()
            .map(|service| TcpServiceView {
                name: service.name(),
                algorithm: service.balancer().algorithm(),
                servers: service
                    .balancer()
                    .servers()
                    .iter()
                    .map(|server| server.addr)
                    .collect(),
                names: service.balancer().dns_names().collect(),
                idle_timeout_secs: service.idle().as_secs(),
            })
            .collect(),
    })
}

/// The UDP side of `app`, `None` when it declares none.
fn udp_view(app: &CompiledApp) -> Option<UdpView<'_>> {
    let udp = app.l4().udp();
    if udp.routers().is_empty() && udp.services().is_empty() {
        return None;
    }
    Some(UdpView {
        routers: (0..udp.routers().len())
            .filter_map(|at| {
                let (router, service) = udp.route(at)?;
                Some(UdpRouterView {
                    name: router.name(),
                    entry_points: router.entry_points(),
                    service: service.name(),
                    max_sessions: router.max_sessions(),
                    max_reply_ratio: router.max_reply_ratio(),
                })
            })
            .collect(),
        services: udp
            .services()
            .iter()
            .map(|service| UdpServiceView {
                name: service.name(),
                servers: service.servers(),
                session_timeout_secs: service.timeout().as_secs(),
            })
            .collect(),
    })
}

fn router_view<'a>(app: &'a CompiledApp, router: &'a CompiledRouter) -> RouterView<'a> {
    RouterView {
        name: router.name(),
        declared_by: router.declared_by(),
        entry_points: router.entry_points(),
        matcher: shown_matcher(router.matcher_json()),
        priority: router.priority(),
        chain: router
            .chain()
            .iter()
            .filter_map(|index| app.stages().get(*index))
            .map(|named| &*named.name)
            .collect(),
        service: router.service(),
    }
}

fn revision_view<'a>(
    app: &CompiledApp,
    revision: &'a CompiledRevision,
    runtime: &Runtime<'_>,
) -> RevisionView<'a> {
    RevisionView {
        id: revision.id(),
        state: revision.state(),
        weight: revision.weight(),
        effective_weight: revision.effective_weight(),
        inflight: runtime.inflight.count(app.id(), revision.id()),
        recent: recent(runtime, app.id(), Some(revision.id())),
    }
}

fn service_view<'a>(revision: Option<&'a str>, named: &'a service::Named) -> ServiceView<'a> {
    let service = &named.service;
    let checked = service.has_health_check();
    ServiceView {
        name: &named.name,
        revision,
        kind: service.kind(),
        algorithm: service.algorithm(),
        health_check: checked,
        outlier_detection: service.has_outlier_detection(),
        servers: service
            .servers()
            .iter()
            .map(|server| ServerView {
                url: server.url.clone(),
                weight: server.weight,
                available: server.available(),
                active: server
                    .state
                    .active
                    .load(std::sync::atomic::Ordering::Relaxed),
                healthy: checked.then(|| {
                    server
                        .state
                        .healthy
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                ejected_for_ms: outlier::ejected_for(server)
                    .map(|left| u64::try_from(left.as_millis()).unwrap_or(u64::MAX)),
            })
            .collect(),
    }
}

/// A matcher tree as declared, except that the value or regular expression of a `header` or
/// `query` leaf is `[value]` whatever the name: such a value is what a client sends, and a router
/// may match on a credential. The names stay.
fn shown_matcher(value: &Value) -> Value {
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(key, child)| {
                let shown = match key.as_str() {
                    "header" | "header_regexp" | "query" | "query_regexp" => shown_leaf(child),
                    _ => shown_matcher(child),
                };
                (key.clone(), shown)
            })
            .collect(),
        Value::Array(list) => list.iter().map(shown_matcher).collect(),
        other => other.clone(),
    }
}

fn shown_leaf(leaf: &Value) -> Value {
    let Some(map) = leaf.as_object() else {
        return leaf.clone();
    };
    map.iter()
        .map(|(key, value)| {
            let shown = if key == "value" || key == "regex" {
                Value::from("[value]")
            } else {
                value.clone()
            };
            (key.clone(), shown)
        })
        .collect()
}

/// [`write_page_from`] from the first item.
fn write_page<'a, X: Copy, T: Serialize>(
    out: &mut Vec<u8>,
    items: &[X],
    limit: usize,
    end: usize,
    id_of: impl Fn(X) -> &'a str,
    view_of: impl Fn(X) -> T,
    stub_of: impl Fn(&T) -> Option<Vec<u8>>,
) -> Result<(), serde_json::Error> {
    write_page_from(out, items, 0, limit, end, id_of, view_of, stub_of)
}

/// Writes `{"total": n, "items": [...]}` for `items[start..]`: at most `limit` items, and no byte
/// past `end` in `out`. An item that does not fit becomes `stub_of(view)` when that fits, else
/// ends the list. A list that stopped early carries `truncated: true`, and `next` (the id of the
/// last item shown) when it showed any.
#[allow(
    clippy::too_many_arguments,
    reason = "one page writer serves tenants, certificates and apps, which differ in exactly these"
)]
fn write_page_from<'a, X: Copy, T: Serialize>(
    out: &mut Vec<u8>,
    items: &[X],
    start: usize,
    limit: usize,
    end: usize,
    id_of: impl Fn(X) -> &'a str,
    view_of: impl Fn(X) -> T,
    stub_of: impl Fn(&T) -> Option<Vec<u8>>,
) -> Result<(), serde_json::Error> {
    // Writing to a `Vec` cannot fail.
    let _ = write!(out, "{{\"total\":{},\"items\":[", items.len());
    let mut last: Option<&str> = None;
    let mut stopped = false;
    // Every pass of the loop either writes an item or ends it, so the index is the count shown.
    for (shown, item) in items.iter().skip(start).copied().enumerate() {
        if shown == limit {
            stopped = true;
            break;
        }
        let id = id_of(item);
        let view = view_of(item);
        let room = |out: &Vec<u8>, len: usize| {
            out.len() + usize::from(shown > 0) + len + TAIL + id.len() <= end
        };
        let mut bytes = serde_json::to_vec(&view)?;
        if !room(out, bytes.len()) {
            bytes = stub_of(&view).unwrap_or_default();
            if bytes.is_empty() || !room(out, bytes.len()) {
                stopped = true;
                break;
            }
        }
        if shown > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&bytes);
        last = Some(id);
    }
    out.push(b']');
    if stopped {
        out.extend_from_slice(b",\"truncated\":true");
        if let Some(id) = last {
            out.extend_from_slice(b",\"next\":");
            serde_json::to_writer(&mut *out, id)?;
        }
    }
    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::events::EventFeed;

    fn table_of(snapshot: &Value) -> RoutingTable {
        let snapshot = serde_json::from_value(snapshot.clone()).expect("snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn rendered(table: &RoutingTable, query: &Query) -> Value {
        rendered_by(table, query, None)
    }

    fn rendered_by(table: &RoutingTable, query: &Query, writer: Option<&str>) -> Value {
        let budgets = Budgets::new();
        let events = EventFeed::new();
        let inflight = Inflight::new(events.clone());
        let outcomes = Outcomes::new();
        let runtime = Runtime {
            budgets: &budgets,
            inflight: &inflight,
            outcomes: &outcomes,
            boot_id: events.boot_id(),
            entry_points: &[],
            metrics_addr: None,
            writer,
        };
        let body = render(table, &runtime, query).expect("renders");
        assert!(body.len() <= query.max_bytes, "{} bytes", body.len());
        serde_json::from_slice(&body).expect("valid JSON")
    }

    fn app(id: &str) -> Value {
        json!({
            "id": id, "tenant": "t", "declared_by": "unit", "tls": {"mode": "acme"},
            "routers": [{"name": "r", "match": {"host": format!("{id}.test")}, "service": "web"}],
            "revisions": [{"id": "r1", "weight": 1, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9"}]}]}],
        })
    }

    fn snapshot(apps: &[Value]) -> Value {
        json!({
            "version": 1,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": apps,
        })
    }

    #[test]
    fn summary_names_the_writer_when_there_is_one() {
        let table = table_of(&snapshot(&[app("a")]));
        let query = Query {
            sections: vec![Section::Summary],
            ..Query::default()
        };
        let named = rendered_by(&table, &query, Some("podkit-agent"));
        assert_eq!(named["summary"]["writer"], "podkit-agent");
        let unnamed = rendered_by(&table, &query, None);
        assert!(
            unnamed["summary"].get("writer").is_none(),
            "no writer, no field: {unnamed}"
        );
    }

    #[test]
    fn overview_size_bounded() {
        let apps: Vec<Value> = (0..200).map(|index| app(&format!("a{index:03}"))).collect();
        let table = table_of(&snapshot(&apps));
        let query = Query {
            limit: MAX_LIMIT,
            max_bytes: 12_000,
            sections: vec![Section::Apps],
            ..Query::default()
        };
        let mut seen = Vec::new();
        let mut after = None;
        for _ in 0..200 {
            let page = rendered(
                &table,
                &Query {
                    after,
                    ..query.clone()
                },
            );
            let items = page["apps"]["items"].as_array().expect("items");
            assert!(!items.is_empty(), "a page made no progress: {page}");
            seen.extend(
                items
                    .iter()
                    .map(|item| item["id"].as_str().expect("id").to_owned()),
            );
            match page["apps"]["next"].as_str() {
                Some(next) => after = Some(next.to_owned()),
                None => {
                    assert!(page["apps"].get("truncated").is_none());
                    break;
                }
            }
        }
        let expected: Vec<String> = (0..200).map(|index| format!("a{index:03}")).collect();
        assert_eq!(seen, expected, "every app exactly once, in id order");
    }

    #[test]
    fn an_app_bigger_than_the_room_becomes_a_stub() {
        let table = table_of(&snapshot(&[app("a")]));
        let page = rendered(
            &table,
            &Query {
                max_bytes: 600,
                sections: vec![Section::Apps],
                ..Query::default()
            },
        );
        assert_eq!(
            page["apps"]["items"][0],
            json!({"id": "a", "tenant": "t", "too_large": true, "routers": 1,
                   "revisions": 1, "services": 1, "middlewares": 0})
        );
    }

    #[test]
    fn matcher_values_are_never_shown() {
        let shown = shown_matcher(&json!({"all": [
            {"header": {"name": "X-Api-Key", "value": "hunter2"}},
            {"header": {"name": "x-env", "value": "canary"}},
            {"header_regexp": {"name": "x-id", "regex": "^abc"}},
            {"query": {"name": "page", "value": "1"}},
            {"query_regexp": {"name": "token", "regex": "^abc"}},
            {"not": {"header": {"name": "x-flag"}}},
            {"path_prefix": "/api"},
        ]}));
        assert_eq!(
            shown,
            json!({"all": [
                {"header": {"name": "X-Api-Key", "value": "[value]"}},
                {"header": {"name": "x-env", "value": "[value]"}},
                {"header_regexp": {"name": "x-id", "regex": "[value]"}},
                {"query": {"name": "page", "value": "[value]"}},
                {"query_regexp": {"name": "token", "regex": "[value]"}},
                {"not": {"header": {"name": "x-flag"}}},
                {"path_prefix": "/api"},
            ]})
        );
    }
}
