//! Services that name other services: what `weighted` and `failover` share. Reference:
//! `docs/ref/svc-weighted-failover.md`.
//!
//! A `weighted` or `failover` service lists children by name, `name` (in the revision the
//! request picked, else the app) or `name@revision`. The names are resolved once per revision when
//! the snapshot compiles, into [`Link`]s that the revision keeps next to its services; a graph
//! service that the whole app shares therefore resolves differently in each revision. A
//! [`Node`] is a service in the scope of one revision: the unit a [`Link`] points at.
//!
//! # Compile
//!
//! `resolve` turns the names into links (`unknown_service`, or `invalid_service` for a child
//! that is not a `loadbalancer`, `weighted` or `failover`: a `static` service answers from disk
//! and a `mirroring` service would hide its copies from the posture checks). `validate` then
//! walks every graph from every node: a node met twice on one path is `service_cycle`, more than
//! [`MAX_DEPTH`] services on one path or more than [`MAX_NODES`] services in the unfolded graph is
//! `invalid_service` (the pick scans the unfolded graph, so it has a bound), and a sticky cookie
//! name used twice on one path is `invalid_service`.
//!
//! # Pick
//!
//! [`pick`] descends from the router's service. Every step reads atomics only and allocates
//! nothing (`tests/lb_alloc.rs`). A child is *eligible* when [`readiness`] says
//! [`Readiness::Ready`]: some server below it [`PickCx::allows`] the request and has a weight.
//! [`Readiness::Asleep`] is a service with no server anywhere below it (`scale_to_zero` wakes the
//! app for it), [`Readiness::Down`] one whose servers all refuse. The path taken is kept as the
//! child index at each graph service ([`Path`]), so the proxy can find the service of the
//! server that took the request ([`Trail`]).

use std::net::SocketAddr;

use serde::Serialize;

use super::mirroring::Scopes;
use super::{Lease, NO_SERVER, Named, PickCx, Service};
use crate::compile::Invalid;
use crate::table::ServiceRef;

/// Most services on one path from a router's service to a server: a `weighted` that holds a
/// `failover` that holds a `weighted` that holds a `loadbalancer` is the deepest graph.
pub const MAX_DEPTH: usize = 4;
/// Most services one router's service reaches, counting a service once per way to reach it.
pub const MAX_NODES: usize = 128;

/// A service in the scope of one revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    /// Index of the revision whose scope holds the service.
    pub(crate) revision: usize,
    /// The service in that scope.
    pub(crate) service: ServiceRef,
}

/// A resolved child of a graph service.
#[derive(Debug, Clone, Copy)]
pub struct Link {
    /// The child.
    pub(crate) node: Node,
    /// Its weight: as declared for a `weighted` child, `1` for the two of a `failover`.
    pub(crate) weight: u16,
}

/// The child index chosen at each graph service on the way to a server, root first. It is
/// `Copy` so that a [`crate::route::Selected`] stays so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Path {
    len: u8,
    at: [u8; MAX_DEPTH],
}

impl Path {
    /// Appends a choice; `false` when the path is full (never for a validated graph).
    fn push(&mut self, index: usize) -> bool {
        let (Some(slot), Ok(index)) = (self.at.get_mut(usize::from(self.len)), u8::try_from(index))
        else {
            return false;
        };
        *slot = index;
        self.len += 1;
        true
    }

    /// The choices, root first.
    #[must_use]
    pub fn indices(&self) -> &[u8] {
        self.at.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// How a service can take a request right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Some server below it may take the request.
    Ready,
    /// It has servers and none may take the request: unhealthy, ejected, already tried, or
    /// without weight.
    Down,
    /// It has no server at all: its app is asleep.
    Asleep,
}

impl Readiness {
    fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Down => "down",
            Self::Asleep => "asleep",
        }
    }
}

/// A child as declared: `name` or `name@revision`, and its weight.
#[derive(Debug)]
pub struct ChildRef {
    /// The service name.
    pub(crate) name: Box<str>,
    /// The revision named by `name@revision`; `None` follows the revision of the request.
    pub(crate) revision: Option<Box<str>>,
    /// The text as declared, which a sticky cookie of the parent is keyed on.
    pub(crate) label: Box<str>,
    /// The weight.
    pub(crate) weight: u16,
}

impl ChildRef {
    /// Parses `text` for a service of type `kind`.
    pub(super) fn parse(kind: &str, text: &str, weight: u16) -> Result<Self, Invalid> {
        let (name, revision) = match text.split_once('@') {
            Some((name, revision)) => (name, Some(revision)),
            None => (text, None),
        };
        if name.is_empty() || revision.is_some_and(|rev| rev.is_empty() || rev.contains('@')) {
            return Err(Invalid::new(
                "invalid_service",
                format!("{kind}: service {text:?} is a service name or name@revision"),
            ));
        }
        Ok(Self {
            name: name.into(),
            revision: revision.map(Into::into),
            label: text.into(),
            weight,
        })
    }
}

/// Where the services of a table are, for the pick and the compile pass alike.
pub trait Graph {
    /// The service at `node`.
    fn named(&self, node: Node) -> Option<&Named>;
    /// The children of the service at `node`, in declaration order; empty for any other type and
    /// for a graph service its revision could not resolve (a `draining` revision may lack one).
    fn links(&self, node: Node) -> &[Link];

    /// The service at `node`.
    fn service(&self, node: Node) -> Option<&Service> {
        self.named(node).map(|named| &named.service)
    }
}

/// The links of one revision: for each of its own services, then for each of the app's.
#[derive(Debug, Default)]
pub struct Links {
    own: Box<[Box<[Link]>]>,
    app: Box<[Box<[Link]>]>,
}

impl Links {
    /// The links of `service`, empty for a service without any.
    pub(crate) fn get(&self, service: ServiceRef) -> &[Link] {
        match service {
            ServiceRef::Own(index) => self.own.get(index),
            ServiceRef::App(index) => self.app.get(index),
        }
        .map_or(&[][..], |links| &**links)
    }
}

/// The services of an app while it compiles, with the links resolved so far.
pub(crate) struct Compiling<'a> {
    pub(crate) scopes: &'a Scopes<'a>,
    pub(crate) links: &'a [Links],
}

impl Graph for Compiling<'_> {
    fn named(&self, node: Node) -> Option<&Named> {
        self.scopes.get(node.revision, node.service)
    }

    fn links(&self, node: Node) -> &[Link] {
        self.links
            .get(node.revision)
            .map_or(&[][..], |links| links.get(node.service))
    }
}

fn unknown(message: impl Into<String>) -> Invalid {
    Invalid::new("unknown_service", message)
}

/// Resolves the children of every graph service of every revision of `scopes`. A problem is
/// returned with where it is (`at`, as the compile pass words it) and leaves that service
/// without links.
pub(crate) fn resolve(scopes: &Scopes<'_>) -> (Vec<Links>, Vec<(String, Invalid)>) {
    let mut problems = Vec::new();
    let links = scopes
        .revisions
        .iter()
        .enumerate()
        .map(|(at, scope)| {
            let own = scope
                .own
                .iter()
                .map(|named| {
                    resolve_one(scopes, at, named).unwrap_or_else(|invalid| {
                        let place = format!("revision {} service {}", scope.id, named.name);
                        problems.push((place, invalid));
                        Box::default()
                    })
                })
                .collect();
            let app = scopes
                .shared
                .iter()
                .map(|named| {
                    resolve_one(scopes, at, named).unwrap_or_else(|invalid| {
                        let place = format!("service {} revision {}", named.name, scope.id);
                        problems.push((place, invalid));
                        Box::default()
                    })
                })
                .collect();
            Links { own, app }
        })
        .collect();
    (links, problems)
}

fn resolve_one(scopes: &Scopes<'_>, at: usize, named: &Named) -> Result<Box<[Link]>, Invalid> {
    let children = named.service.children();
    let draining = scopes.revisions.get(at).is_none_or(|scope| scope.draining);
    let mut links = Vec::with_capacity(children.len());
    for child in children {
        let revision = match &child.revision {
            Some(id) => scopes
                .revisions
                .iter()
                .position(|scope| scope.id == &**id)
                .ok_or_else(|| unknown(format!("the app has no revision {id}")))?,
            None => at,
        };
        let Some(service) = scopes.find(revision, &child.name) else {
            if child.revision.is_none() && draining {
                return Ok(Box::default());
            }
            return Err(unknown(format!(
                "{}: revision {} has no service {}",
                named.service.kind(),
                scopes.revisions.get(revision).map_or("", |scope| scope.id),
                child.name
            )));
        };
        match scopes.get(revision, service).map(|found| &found.service) {
            Some(Service::LoadBalancer(_) | Service::Weighted(_) | Service::Failover(_)) => {}
            Some(other) => {
                return Err(Invalid::new(
                    "invalid_service",
                    format!(
                        "{}: service {} is a {} service; only a loadbalancer, weighted or failover service can be a child",
                        named.service.kind(),
                        child.label,
                        other.kind()
                    ),
                ));
            }
            None => return Err(unknown(format!("service {} is gone", child.label))),
        }
        links.push(Link {
            node: Node { revision, service },
            weight: child.weight,
        });
    }
    Ok(links.into_boxed_slice())
}

struct Walk<'a> {
    stack: Vec<Node>,
    cookies: Vec<&'a str>,
    nodes: usize,
}

/// Checks the graph below `start`: no cycle, at most [`MAX_DEPTH`] services on a path, at most
/// [`MAX_NODES`] in all, and no sticky cookie name twice on a path.
///
/// # Errors
///
/// `service_cycle` or `invalid_service`.
pub(crate) fn validate(graph: &dyn Graph, start: Node) -> Result<(), Invalid> {
    visit(
        graph,
        start,
        &mut Walk {
            stack: Vec::new(),
            cookies: Vec::new(),
            nodes: 0,
        },
    )
}

fn visit<'a>(graph: &'a dyn Graph, node: Node, walk: &mut Walk<'a>) -> Result<(), Invalid> {
    let Some(named) = graph.named(node) else {
        return Ok(());
    };
    if walk.stack.contains(&node) {
        return Err(Invalid::new(
            "service_cycle",
            format!("service {} reaches itself", named.name),
        ));
    }
    if walk.stack.len() >= MAX_DEPTH {
        return Err(Invalid::new(
            "invalid_service",
            format!(
                "service {} is more than {MAX_DEPTH} services deep: weighted and failover nest at most {MAX_DEPTH} levels",
                named.name
            ),
        ));
    }
    walk.nodes += 1;
    if walk.nodes > MAX_NODES {
        return Err(Invalid::new(
            "invalid_service",
            format!(
                "the services reach more than {MAX_NODES} services in all, counting each way to reach one"
            ),
        ));
    }
    let cookie = named.service.sticky().map(super::Sticky::name);
    if let Some(cookie) = cookie {
        if walk.cookies.contains(&cookie) {
            return Err(Invalid::new(
                "invalid_service",
                format!(
                    "sticky cookie {cookie} is set twice on the path to service {}: give the services different cookie names",
                    named.name
                ),
            ));
        }
        walk.cookies.push(cookie);
    }
    walk.stack.push(node);
    for link in graph.links(node) {
        visit(graph, link.node, walk)?;
    }
    walk.stack.pop();
    if cookie.is_some() {
        walk.cookies.pop();
    }
    Ok(())
}

/// The first service reachable from `node` that cannot carry gRPC, with its name and why: every
/// leaf below a `weighted` or `failover` service counts (both of a `failover`'s, the children of
/// a `weighted` that have weight; a child of weight `0` is never chosen). `None` when every
/// reachable leaf speaks HTTP/2.
pub(crate) fn http2_refusal(graph: &dyn Graph, node: Node, depth: usize) -> Option<(&str, String)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let named = graph.named(node)?;
    if named.service.is_graph() {
        return graph
            .links(node)
            .iter()
            .filter(|link| link.weight > 0)
            .find_map(|link| http2_refusal(graph, link.node, depth + 1));
    }
    named
        .service
        .http2_refusal()
        .map(|reason| (&*named.name, reason))
}

/// Whether the service at `node` can ever take a request: it has a server, or is a `static`
/// service. A `weighted` service needs a child with weight that is backed, a `failover` its
/// primary: a primary without servers is asleep, and the fallback must not hide that.
pub(crate) fn backed(graph: &dyn Graph, node: Node, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    match graph.service(node) {
        Some(Service::LoadBalancer(balancer)) => balancer.is_backed(),
        Some(Service::Static(_)) => true,
        Some(Service::Fastcgi(_)) => true,
        Some(Service::Weighted(_)) => graph
            .links(node)
            .iter()
            .any(|link| link.weight > 0 && backed(graph, link.node, depth + 1)),
        Some(Service::Failover(_)) => graph
            .links(node)
            .first()
            .is_some_and(|link| backed(graph, link.node, depth + 1)),
        Some(Service::Mirroring(_)) | None => false,
    }
}

/// How the service at `node` can take `cx` now; `now` is [`super::state::now_ms`].
pub fn readiness(
    graph: &dyn Graph,
    node: Node,
    cx: PickCx<'_>,
    now: u64,
    depth: usize,
) -> Readiness {
    if depth >= MAX_DEPTH {
        return Readiness::Down;
    }
    match graph.service(node) {
        Some(Service::LoadBalancer(balancer)) => balancer.readiness(cx),
        Some(Service::Static(_)) => Readiness::Ready,
        Some(Service::Fastcgi(_)) => Readiness::Ready,
        Some(Service::Weighted(weighted)) => weighted.readiness(graph, node, cx, now, depth),
        Some(Service::Failover(failover)) => failover.readiness(graph, node, cx, now, depth),
        Some(Service::Mirroring(_)) | None => Readiness::Down,
    }
}

/// The server a new request goes to and the service path that led there, from the service at
/// `node`; `None` when nothing below it is ready.
pub fn pick(
    graph: &dyn Graph,
    node: Node,
    cx: PickCx<'_>,
    now: u64,
    path: &mut Path,
    depth: usize,
) -> Option<(SocketAddr, Lease)> {
    if depth >= MAX_DEPTH {
        return None;
    }
    match graph.service(node)? {
        Service::LoadBalancer(balancer) => balancer.pick(cx),
        Service::Static(site) => Some((NO_SERVER, site.lease())),
        Service::Fastcgi(site) => Some((NO_SERVER, site.lease())),
        Service::Weighted(weighted) => weighted.pick(graph, node, cx, now, path, depth),
        Service::Failover(failover) => failover.pick(graph, node, cx, now, path, depth),
        Service::Mirroring(_) => None,
    }
}

/// [`pick`] through child `index` of the service whose links are `links`, recording the choice
/// in `path` when it succeeds.
pub(super) fn enter(
    graph: &dyn Graph,
    links: &[Link],
    index: usize,
    cx: PickCx<'_>,
    now: u64,
    path: &mut Path,
    depth: usize,
) -> Option<(SocketAddr, Lease)> {
    let link = links.get(index)?;
    let saved = *path;
    if !path.push(index) {
        return None;
    }
    let picked = pick(graph, link.node, cx, now, path, depth + 1);
    if picked.is_none() {
        *path = saved;
    }
    picked
}

/// The services a request went through, from the router's service to the one whose server took
/// it, each with the child it chose when it is a graph service.
pub struct Trail<'a> {
    pub(crate) graph: &'a dyn Graph,
    pub(crate) node: Option<Node>,
    pub(crate) path: Path,
    pub(crate) at: usize,
}

impl<'a> Iterator for Trail<'a> {
    type Item = (&'a Named, Option<usize>);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;
        let named = self.graph.named(node)?;
        if named.service.is_graph()
            && let Some(first) = self.path.indices().get(self.at)
        {
            let index = usize::from(*first);
            self.node = self.graph.links(node).get(index).map(|link| link.node);
            self.at += 1;
            return Some((named, Some(index)));
        }
        Some((named, None))
    }
}

/// One service of a graph as `GET /v1/explain` shows it.
#[derive(Debug, Serialize)]
pub struct View<'a> {
    /// The name the service is declared under.
    service: &'a str,
    /// Its type.
    kind: &'static str,
    /// What the parent gave it as declared; absent for the first service.
    #[serde(skip_serializing_if = "Option::is_none")]
    weight: Option<u16>,
    /// What the parent's pick gives it right now: the weight while the service is ready, `0`
    /// while it is not. Absent for the first service.
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_weight: Option<u16>,
    /// `primary` or `fallback` for the children of a `failover`.
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    /// `ready`, `down` (it has servers and none can take a request) or `asleep` (it has none).
    state: &'static str,
    /// Whether a request would go through this service now: the path of [`Described::path`].
    on_path: bool,
    /// The children of a `weighted` or `failover` service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<View<'a>>,
}

/// A graph as `GET /v1/explain` shows it.
#[derive(Debug, Serialize)]
pub struct Described<'a> {
    /// The services a request would go through now, `weighted -> failover -> web-v2`: at a
    /// `weighted` service the ready child with the largest weight, at a `failover` the side that
    /// would serve.
    path: String,
    /// The graph, from the router's service.
    root: View<'a>,
}

/// Describes the graph below `node`, or `None` when it is not a graph service.
#[must_use]
pub fn describe<'a>(
    graph: &'a dyn Graph,
    node: Node,
    cx: PickCx<'_>,
    now: u64,
) -> Option<Described<'a>> {
    if !graph.service(node)?.is_graph() {
        return None;
    }
    let root = view(graph, node, cx, now, 0, None, None, true);
    let mut names = Vec::new();
    let mut at = Some(&root);
    while let Some(current) = at {
        names.push(current.service);
        at = current.children.iter().find(|child| child.on_path);
    }
    Some(Described {
        path: names.join(" -> "),
        root,
    })
}

#[allow(clippy::too_many_arguments, reason = "a recursive walk of one graph")]
fn view<'a>(
    graph: &'a dyn Graph,
    node: Node,
    cx: PickCx<'_>,
    now: u64,
    depth: usize,
    link: Option<&Link>,
    role: Option<&'static str>,
    on_path: bool,
) -> View<'a> {
    let named = graph.named(node);
    let state = readiness(graph, node, cx, now, depth);
    let likely = named.and_then(|named| match &named.service {
        Service::Weighted(weighted) => weighted.likely(graph, node, cx, now, depth),
        Service::Failover(failover) => failover.likely(graph, node, cx, now, depth),
        _ => None,
    });
    let children = graph
        .links(node)
        .iter()
        .enumerate()
        .map(|(index, child)| {
            let role = match (named.map(|named| &named.service), index) {
                (Some(Service::Failover(_)), 0) => Some("primary"),
                (Some(Service::Failover(_)), _) => Some("fallback"),
                _ => None,
            };
            view(
                graph,
                child.node,
                cx,
                now,
                depth + 1,
                Some(child),
                role,
                on_path && likely == Some(index),
            )
        })
        .collect();
    View {
        service: named.map_or("", |named| &named.name),
        kind: named.map_or("", |named| named.service.kind()),
        weight: link.map(|link| link.weight),
        effective_weight: link.map(|link| {
            if state == Readiness::Ready {
                link.weight
            } else {
                0
            }
        }),
        role,
        state: state.name(),
        on_path,
        children,
    }
}

#[cfg(test)]
mod test {
    #![allow(
        clippy::needless_pass_by_value,
        reason = "builders of snapshots take literals"
    )]

    use std::collections::BTreeMap;
    use std::sync::atomic::Ordering;

    use pingora::http::RequestHeader;
    use serde_json::{Value, json};

    use super::*;
    use crate::compile::Rejected;
    use crate::route::{self, RouteError};
    use crate::table::{CompileError, RoutingTable};
    use podgate_model::Snapshot;

    fn lb(name: &str, ports: &[u16]) -> Value {
        let servers: Vec<Value> = ports
            .iter()
            .map(|port| json!({ "url": format!("http://127.0.0.1:{port}") }))
            .collect();
        json!({ "name": name, "type": "loadbalancer", "servers": servers })
    }

    fn weighted(name: &str, children: &[(&str, u16)]) -> Value {
        let services: Vec<Value> = children
            .iter()
            .map(|(service, weight)| json!({ "service": service, "weight": weight }))
            .collect();
        json!({ "name": name, "type": "weighted", "services": services })
    }

    fn failover(name: &str, primary: &str, fallback: &str, hold_secs: u64) -> Value {
        json!({ "name": name, "type": "failover", "service": primary, "fallback": fallback,
                "fallback_hold_secs": hold_secs })
    }

    fn revision(id: &str, weight: u16, state: &str, services: Vec<Value>) -> Value {
        json!({ "id": id, "weight": weight, "state": state, "services": services })
    }

    fn serving(services: Vec<Value>) -> Value {
        revision("r1", 100, "serving", services)
    }

    /// App `a` (host `a.test`, one router to service `top`) with `revisions`.
    fn compile(revisions: Vec<Value>) -> Result<RoutingTable, CompileError> {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{ "id": "t", "weight": 1,
                          "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } }],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
                "routers": [{ "name": "default", "match": { "host": "a.test" }, "service": "top" }],
                "revisions": revisions,
            }],
        }))
        .expect("snapshot");
        RoutingTable::compile(&snapshot)
    }

    fn table(revisions: Vec<Value>) -> RoutingTable {
        compile(revisions).expect("compiles")
    }

    fn codes(result: Result<RoutingTable, CompileError>) -> Vec<&'static str> {
        match result.expect_err("refused") {
            CompileError::Rejected(list) => list.iter().map(Rejected::code).collect(),
            other => panic!("not a rejection: {other:?}"),
        }
    }

    fn request() -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        request.insert_header("host", "a.test").expect("host");
        request
    }

    /// How 5,000 picks of the app spread over the ports of the servers.
    fn spread(table: &RoutingTable) -> BTreeMap<u16, usize> {
        let app = table.app(0).expect("app");
        let request = request();
        let mut seen = BTreeMap::new();
        for _ in 0..5000 {
            let Some(pick) = app.pick(0, PickCx::new(&request)) else {
                *seen.entry(0).or_default() += 1;
                continue;
            };
            *seen.entry(pick.upstream.port()).or_default() += 1;
        }
        seen
    }

    /// Marks every server of service `name` (in revision `revision`) healthy or not.
    fn set_up(table: &RoutingTable, revision: usize, name: &str, up: bool) {
        let app = table.app(0).expect("app");
        let named = app.revisions()[revision]
            .services()
            .iter()
            .find(|named| &*named.name == name)
            .expect("service");
        for server in &named.service.servers() {
            server.state.healthy.store(up, Ordering::Relaxed);
        }
    }

    fn picked_at(table: &RoutingTable, now: u64) -> Option<u16> {
        let app = table.app(0).expect("app");
        let root = app.root(0, 0).expect("root");
        let request = request();
        let mut path = Path::default();
        pick(app, root, PickCx::new(&request), now, &mut path, 0).map(|(addr, _lease)| addr.port())
    }

    #[test]
    fn weighted_split_follows_weights() {
        let table = table(vec![serving(vec![
            weighted("top", &[("a", 90), ("b", 10)]),
            lb("a", &[9001]),
            lb("b", &[9002]),
        ])]);
        let seen = spread(&table);
        assert_eq!(seen.keys().copied().collect::<Vec<_>>(), [9001, 9002]);
        assert!(
            (4450..=4550).contains(&seen[&9001]),
            "90% of 5000 is 4500: {seen:?}"
        );
        let skewed = table_of_three(&[("a", 1), ("b", 2), ("c", 7)]);
        let seen = spread(&skewed);
        assert!((450..=550).contains(&seen[&9001]), "{seen:?}");
        assert!((950..=1050).contains(&seen[&9002]), "{seen:?}");
        assert!((3450..=3550).contains(&seen[&9003]), "{seen:?}");
    }

    fn table_of_three(weights: &[(&str, u16)]) -> RoutingTable {
        table(vec![serving(vec![
            weighted("top", weights),
            lb("a", &[9001]),
            lb("b", &[9002]),
            lb("c", &[9003]),
        ])])
    }

    #[test]
    fn weighted_skips_dead_child() {
        let table = table_of_three(&[("a", 1), ("b", 1), ("c", 1)]);
        set_up(&table, 0, "c", false);
        let seen = spread(&table);
        assert_eq!(
            seen.get(&9003),
            None,
            "the dead child gets nothing: {seen:?}"
        );
        assert!((2450..=2550).contains(&seen[&9001]), "{seen:?}");
        assert!((2450..=2550).contains(&seen[&9002]), "{seen:?}");

        // A child with weight 0 is never chosen, a child without a server is skipped too.
        let table = table_of_three(&[("a", 1), ("b", 0), ("c", 1)]);
        set_up(&table, 0, "c", false);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 5000)]));

        set_up(&table, 0, "a", false);
        let request = request();
        let err = route::resolve(&table, &request, "web", false, None).expect_err("all down");
        assert_eq!(err, RouteError::AllUnhealthy);
    }

    /// A `loadbalancer` whose only server is named by DNS and has never resolved.
    fn unresolved(name: &str) -> Value {
        json!({ "name": name, "type": "loadbalancer",
                "servers": [{ "url": "http://never-resolved.invalid:9002" }] })
    }

    #[test]
    fn weighted_skips_unresolved_dns_child() {
        // A name that has not resolved yet is a declared server nobody can take: the child is
        // down, so the others take its share.
        let table = table(vec![serving(vec![
            weighted("top", &[("a", 1), ("named", 1)]),
            lb("a", &[9001]),
            unresolved("named"),
        ])]);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 5000)]));

        // Alone it answers 503 and wakes nothing: down, not asleep.
        let alone = self::table(vec![serving(vec![
            weighted("top", &[("named", 1)]),
            unresolved("named"),
        ])]);
        let request = request();
        let err = route::resolve(&alone, &request, "web", false, None).expect_err("unresolved");
        assert_eq!(err, RouteError::AllUnhealthy);

        // A failover primary that has not resolved is down: the fallback takes over, where a
        // primary with no server at all would wake the app.
        let failing = self::table(vec![serving(vec![
            failover("top", "named", "f", 10),
            unresolved("named"),
            lb("f", &[9003]),
        ])]);
        assert_eq!(spread(&failing), BTreeMap::from([(9003, 5000)]));
    }

    #[test]
    fn weighted_skips_asleep_child_and_wakes_when_all_sleep() {
        let table = table(vec![serving(vec![
            weighted("top", &[("a", 1), ("b", 1)]),
            lb("a", &[9001]),
            lb("b", &[]),
        ])]);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 5000)]));

        let asleep = table_asleep();
        let request = request();
        let err = route::resolve(&asleep, &request, "web", false, None).expect_err("asleep");
        assert_eq!(
            err,
            RouteError::NoUpstream,
            "nothing to start is not a failure"
        );
    }

    fn table_asleep() -> RoutingTable {
        table(vec![serving(vec![
            weighted("top", &[("a", 1), ("b", 1)]),
            lb("a", &[]),
            lb("b", &[]),
        ])])
    }

    #[test]
    fn failover_to_fallback() {
        let table = table(vec![serving(vec![
            failover("top", "p", "f", 10),
            lb("p", &[9001]),
            lb("f", &[9002]),
        ])]);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 5000)]));
        set_up(&table, 0, "p", false);
        assert_eq!(spread(&table), BTreeMap::from([(9002, 5000)]));
        set_up(&table, 0, "f", false);
        let request = request();
        let err = route::resolve(&table, &request, "web", false, None).expect_err("both down");
        assert_eq!(err, RouteError::AllUnhealthy);
    }

    #[test]
    fn failover_returns_after_hold() {
        let table = table(vec![serving(vec![
            failover("top", "p", "f", 10),
            lb("p", &[9001]),
            lb("f", &[9002]),
        ])]);
        let (primary, fallback) = (Some(9001), Some(9002));
        assert_eq!(picked_at(&table, 1_000), primary);
        set_up(&table, 0, "p", false);
        assert_eq!(picked_at(&table, 2_000), fallback);
        set_up(&table, 0, "p", true);
        assert_eq!(
            picked_at(&table, 3_000),
            fallback,
            "the primary is back, the hold runs"
        );
        assert_eq!(picked_at(&table, 11_999), fallback);
        assert_eq!(
            picked_at(&table, 12_000),
            primary,
            "10 s after the last failure seen"
        );

        // A request that sees the primary down again extends the hold.
        set_up(&table, 0, "p", false);
        assert_eq!(picked_at(&table, 20_000), fallback);
        set_up(&table, 0, "p", true);
        assert_eq!(picked_at(&table, 29_999), fallback);
        assert_eq!(picked_at(&table, 30_000), primary);
    }

    #[test]
    fn failover_does_not_hide_sleeping_app() {
        let table = table(vec![serving(vec![
            failover("top", "p", "f", 10),
            lb("p", &[]),
            lb("f", &[9002]),
        ])]);
        let request = request();
        let err = route::resolve(&table, &request, "web", false, None).expect_err("asleep");
        assert_eq!(
            err,
            RouteError::NoUpstream,
            "the fallback must not hide the sleeping primary"
        );
        assert_eq!(
            table.app(0).expect("app").revisions()[0].effective_weight(),
            0
        );
    }

    #[test]
    fn service_graph_depth_limit() {
        let chain = |levels: usize| {
            let mut services = vec![lb("leaf", &[9001]), lb("spare", &[9002])];
            for level in (1..levels).rev() {
                let name = if level == 1 {
                    "top".to_owned()
                } else {
                    format!("n{level}")
                };
                let child = if level == levels - 1 {
                    "leaf".to_owned()
                } else {
                    format!("n{}", level + 1)
                };
                services.push(if level % 2 == 0 {
                    failover(&name, &child, "spare", 1)
                } else {
                    weighted(&name, &[(&child, 1)])
                });
            }
            compile(vec![serving(services)])
        };
        // weighted -> failover -> weighted -> loadbalancer: four services on one path.
        assert!(chain(4).is_ok(), "four levels are allowed");
        for levels in [5, 6] {
            let found = codes(chain(levels));
            assert!(
                !found.is_empty() && found.iter().all(|code| *code == "invalid_service"),
                "{levels} levels: {found:?}"
            );
        }
    }

    #[test]
    fn graph_with_too_many_paths_is_refused() {
        // 32 services that each reach `leaf` 32 times: 1,057 services below the top, in
        // three levels, so only the count refuses it.
        let mut wide = vec![lb("leaf", &[9001])];
        let names: Vec<String> = (0..32).map(|index| format!("w{index}")).collect();
        for name in &names {
            wide.push(weighted(name, &[("leaf", 1); 32]));
        }
        let children: Vec<(&str, u16)> = names.iter().map(|name| (name.as_str(), 1)).collect();
        wide.push(weighted("top", &children));
        assert_eq!(codes(compile(vec![serving(wide)])), ["invalid_service"]);
    }

    #[test]
    fn service_cycle_rejected() {
        let two = vec![serving(vec![
            weighted("top", &[("b", 1)]),
            failover("b", "top", "x", 1),
            lb("x", &[9001]),
        ])];
        assert!(codes(compile(two)).contains(&"service_cycle"));
        let itself = vec![serving(vec![weighted("top", &[("top", 1)])])];
        assert!(codes(compile(itself)).contains(&"service_cycle"));
        // Across revisions: `top` of r1 reaches `top` of r2, which reaches `top` of r1.
        let across = vec![
            revision(
                "r1",
                100,
                "serving",
                vec![weighted("top", &[("top@r2", 1)])],
            ),
            revision("r2", 0, "serving", vec![weighted("top", &[("top@r1", 1)])]),
        ];
        assert!(codes(compile(across)).contains(&"service_cycle"));
    }

    #[test]
    fn weighted_cross_revision_child() {
        let table = table(vec![
            revision(
                "r1",
                100,
                "serving",
                vec![
                    weighted("top", &[("web", 1), ("web@r2", 1)]),
                    lb("web", &[9001]),
                ],
            ),
            revision("r2", 0, "draining", vec![lb("web", &[9002])]),
        ]);
        let seen = spread(&table);
        assert_eq!(seen, BTreeMap::from([(9001, 2500), (9002, 2500)]));
        assert_eq!(
            codes(compile(vec![serving(vec![
                weighted("top", &[("web@nope", 1)]),
                lb("web", &[9001]),
            ])])),
            ["unknown_service"]
        );
    }

    fn table_shared_graph() -> RoutingTable {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": 1,
            "tenants": [{ "id": "t", "weight": 1,
                          "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } }],
            "apps": [{
                "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
                "routers": [{ "name": "default", "match": { "host": "a.test" }, "service": "top" }],
                "services": [weighted("top", &[("web", 1)])],
                "revisions": [
                    revision("r1", 50, "serving", vec![lb("web", &[9001])]),
                    revision("r2", 50, "serving", vec![lb("web", &[9002])]),
                ],
            }],
        }))
        .expect("snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    #[test]
    fn shared_graph_resolves_in_each_revision() {
        let table = table_shared_graph();
        assert_eq!(spread(&table), BTreeMap::from([(9001, 2500), (9002, 2500)]));
    }

    #[test]
    fn revision_split_skips_unhealthy_revision() {
        let table = table(vec![
            revision("r1", 50, "serving", vec![lb("top", &[9001])]),
            revision("r2", 50, "serving", vec![lb("top", &[9002])]),
        ]);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 2500), (9002, 2500)]));
        set_up(&table, 0, "top", false);
        assert_eq!(spread(&table), BTreeMap::from([(9002, 5000)]));
        let request = request();
        let selected = route::resolve(&table, &request, "web", false, None).expect("routes");
        assert_eq!(selected.revision, 1, "the revision with a server takes it");

        set_up(&table, 0, "top", true);
        set_up(&table, 1, "top", false);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 5000)]));

        set_up(&table, 0, "top", false);
        let err = route::resolve(&table, &request, "web", false, None).expect_err("none left");
        assert_eq!(err, RouteError::AllUnhealthy);
    }

    #[test]
    fn mirroring_child_refused() {
        let mirror = json!({ "name": "m", "type": "mirroring", "service": "a",
                             "mirrors": [{ "service": "b", "percent": 10 }] });
        let weighted_child = vec![serving(vec![
            weighted("top", &[("m", 1)]),
            mirror.clone(),
            lb("a", &[9001]),
            lb("b", &[9002]),
        ])];
        assert_eq!(codes(compile(weighted_child)), ["invalid_service"]);
        let failover_child = vec![serving(vec![
            failover("top", "a", "m", 1),
            mirror,
            lb("a", &[9001]),
            lb("b", &[9002]),
        ])];
        assert_eq!(codes(compile(failover_child)), ["invalid_service"]);

        // The other direction is allowed: the router names the mirroring service itself, so the
        // posture checks of `mirroring::exposure` see it. Copies still go to one loadbalancer.
        let main = json!({ "name": "top", "type": "mirroring", "service": "split",
                           "mirrors": [{ "service": "b", "percent": 10 }] });
        let table = table(vec![serving(vec![
            main.clone(),
            weighted("split", &[("a", 1), ("c", 1)]),
            lb("a", &[9001]),
            lb("b", &[9002]),
            lb("c", &[9003]),
        ])]);
        assert_eq!(spread(&table), BTreeMap::from([(9001, 2500), (9003, 2500)]));
        let as_mirror = json!({ "name": "top", "type": "mirroring", "service": "a",
                                "mirrors": [{ "service": "split", "percent": 10 }] });
        assert_eq!(
            codes(compile(vec![serving(vec![
                as_mirror,
                weighted("split", &[("a", 1)]),
                lb("a", &[9001]),
            ])])),
            ["invalid_service"]
        );
    }

    #[test]
    fn weighted_and_failover_configuration_is_checked() {
        let one = |declared: Value| compile(vec![serving(vec![declared, lb("a", &[9001])])]);
        for (what, declared) in [
            ("no children", weighted("top", &[])),
            ("all weights zero", weighted("top", &[("a", 0)])),
            ("a bad name", weighted("top", &[("a@", 1)])),
            ("too many children", weighted("top", &[("a", 1); 33])),
            ("hold too long", failover("top", "a", "a2", 4000)),
            ("same service twice", failover("top", "a", "a", 1)),
            (
                "unknown field",
                json!({ "name": "top", "type": "weighted", "servers": [], "services": [{"service": "a", "weight": 1}] }),
            ),
            (
                "weight over u16",
                json!({ "name": "top", "type": "weighted", "services": [{"service": "a", "weight": 65536}] }),
            ),
            (
                "weight is required",
                json!({ "name": "top", "type": "weighted", "services": [{"service": "a"}] }),
            ),
        ] {
            assert!(codes(one(declared)).contains(&"invalid_service"), "{what}");
        }
        assert_eq!(
            codes(one(weighted("top", &[("missing", 1)]))),
            ["unknown_service"]
        );
        assert!(one(weighted("top", &[("a", 65535)])).is_ok());
    }

    #[test]
    fn retry_across_weighted_children() {
        let table = table(vec![serving(vec![
            weighted("top", &[("a", 1), ("b", 1)]),
            lb("a", &[9001, 9002]),
            lb("b", &[9003]),
        ])]);
        let request = request();
        let matched = route::matching(&table, &request, "web", false, None).expect("matched");
        let (selected, _lease) = route::select(&table, matched, &request, None).expect("selected");
        let mut tried = vec![selected.upstream];
        let mut seen = vec![selected.upstream.port()];
        // Every retry skips what was tried, whichever child the next server is in.
        while let Some((next, _lease)) = route::reselect(&table, &selected, &request, None, &tried)
        {
            assert!(!tried.contains(&next.upstream), "{tried:?} {next:?}");
            tried.push(next.upstream);
            seen.push(next.upstream.port());
        }
        seen.sort_unstable();
        assert_eq!(seen, [9001, 9002, 9003], "all three servers, then none");

        // One server per child: after the first child's, the retry moves to the other child.
        let table = self::table(vec![serving(vec![
            weighted("top", &[("a", 1), ("b", 1000)]),
            lb("a", &[9001]),
            lb("b", &[9003]),
        ])]);
        let matched = route::matching(&table, &request, "web", false, None).expect("matched");
        let (selected, _lease) = route::select(&table, matched, &request, None).expect("selected");
        let (next, _lease) =
            route::reselect(&table, &selected, &request, None, &[selected.upstream]).expect("next");
        assert_ne!(next.upstream, selected.upstream);
        assert_ne!(next.path, selected.path, "another child");
    }

    #[test]
    fn retry_under_failover_reaches_fallback() {
        let table = table(vec![serving(vec![
            failover("top", "p", "f", 10),
            lb("p", &[9001, 9002]),
            lb("f", &[9003]),
        ])]);
        let request = request();
        let matched = route::matching(&table, &request, "web", false, None).expect("matched");
        let (selected, _lease) = route::select(&table, matched, &request, None).expect("selected");
        assert!([9001, 9002].contains(&selected.upstream.port()));
        let mut tried = vec![selected.upstream];
        let (second, _lease) =
            route::reselect(&table, &selected, &request, None, &tried).expect("the other primary");
        assert!([9001, 9002].contains(&second.upstream.port()));
        assert_ne!(second.upstream, selected.upstream);
        tried.push(second.upstream);
        let (third, _lease) =
            route::reselect(&table, &selected, &request, None, &tried).expect("the fallback");
        assert_eq!(third.upstream.port(), 9003);
        tried.push(third.upstream);
        assert!(route::reselect(&table, &selected, &request, None, &tried).is_none());

        // The retry only skipped the primary's servers: no hold, new requests still use it.
        assert_eq!(
            spread(&table).keys().copied().collect::<Vec<_>>(),
            [9001, 9002]
        );
    }
}
