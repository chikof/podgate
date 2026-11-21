//! What `TLSRoute`, `TCPRoute` and `UDPRoute` share: their listeners, the one
//! service every kind builds from `backendRefs`, the app section that carries them, conflicts
//! between routes, and the watchers that tolerate a cluster without these experimental CRDs.
//!
//! | Listener protocol | Route | podgate |
//! |---|---|---|
//! | `TLS`, mode `Passthrough` | `TLSRoute` | a `tcp` router with `match {sni}` and `tls {passthrough: true}` |
//! | `TLS`, mode `Terminate` | `TLSRoute` | the same router with `tls {}` and the listener's certificates |
//! | `TCP` | `TCPRoute` | a `tcp` router with no `match`: the catch-all of its entry point |
//! | `UDP` | `UDPRoute` | the one `udp` router of its entry point |
//!
//! The port of a listener maps to an entry point as for HTTP (`listener_entry_points`). Every
//! kind uses one rule: a rule of these routes has no match, so two rules could not be told
//! apart. `backendRefs` become one `loadbalancer` service over the endpoints of every backend
//! that has a weight and a ready endpoint. The daemon has no weighted L4 service, so a backend's
//! weight becomes the weight of each of its servers (`weighted_round_robin`, TCP only) in the
//! proportions the API asks for, whatever the number of endpoints of each backend.

use std::collections::{BTreeMap, BTreeSet};

use podgate_model::{Declared, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::sleep;

use super::backend::{Backends, Resolved};
use super::listener::Attachment;
use super::precedence::Rank;
use super::route::{Built, Draft};
use super::status::Target;
use super::types::{BackendRef, Gateway, Listener};
use super::{Cache, Kind, Pending, Rejection, reject};
use crate::kubernetes::Tagged;
use crate::kubernetes::client::{ApiClient, Event, ObjectMeta, Query, Resource, Store, Watcher};
use crate::kubernetes::endpoints::Wire;
use crate::trust::HostPattern;

/// The name of the one service of an L4 route's app.
const SERVICE: &str = "backends";

/// The most servers the daemon accepts in one L4 service.
const MAX_SERVERS: usize = 256;

/// Which L4 section of an app a route fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// `App.tcp`.
    Tcp,
    /// `App.udp`.
    Udp,
}

impl Proto {
    /// The section's key in an app.
    fn section(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// The rule of a `TLSRoute`, `TCPRoute` or `UDPRoute`: backends only, there is nothing to match.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamRule {
    /// Where the connections go.
    #[serde(default)]
    pub backend_refs: Vec<BackendRef>,
}

/// One router a route wants, before the daemon's JSON is made of it.
#[derive(Debug)]
pub struct RouterDraft {
    /// The entry points it listens on, sorted.
    pub entry_points: Vec<Box<str>>,
    /// The server names it takes; `None` takes every connection (`TCPRoute`, `UDPRoute`, and a
    /// `TLSRoute` that names none).
    pub hosts: Option<Vec<HostPattern>>,
    /// `Some(true)` forwards TLS untouched, `Some(false)` terminates it; `None` is not TLS.
    pub passthrough: Option<bool>,
}

/// The entry points of `attachments`, sorted and once each.
#[must_use]
pub fn entry_points(attachments: &[Attachment]) -> Vec<Box<str>> {
    let mut points: Vec<Box<str>> = attachments
        .iter()
        .map(|attachment| attachment.entry_point.clone())
        .collect();
    points.sort();
    points.dedup();
    points
}

/// What an L4 route puts into its app: its routers, as the daemon reads them, and the service
/// they use.
#[derive(Debug)]
pub struct Payload {
    proto: Proto,
    routers: Vec<Item>,
    service: Option<Declared>,
}

/// One router, with what it takes from the entry point it listens on.
#[derive(Debug)]
struct Item {
    name: String,
    json: Value,
    /// `(key, what)`: two routes that hold the same key are in conflict.
    claims: Vec<(String, String)>,
}

impl Payload {
    /// The app section (`tcp` or `udp`) of the routers named in `kept`, `None` when none is.
    pub(super) fn section(&self, kept: &BTreeSet<&str>) -> Option<(&'static str, Value)> {
        let routers: Vec<&Value> = self
            .routers
            .iter()
            .filter(|item| kept.contains(item.name.as_str()))
            .map(|item| &item.json)
            .collect();
        let service = self.service.as_ref().filter(|_| !routers.is_empty())?;
        Some((
            self.proto.section(),
            json!({ "routers": routers, "services": [service] }),
        ))
    }
}

fn proto(kind: Kind) -> Proto {
    match kind {
        Kind::Udp => Proto::Udp,
        _ => Proto::Tcp,
    }
}

fn wire(kind: Kind) -> Wire {
    match kind {
        Kind::Udp => Wire::Udp,
        Kind::Http | Kind::Grpc | Kind::Tls | Kind::Tcp => Wire::Tcp,
    }
}

fn claims(kind: Kind, router: &RouterDraft) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for point in &router.entry_points {
        match (&router.hosts, kind) {
            (Some(hosts), _) => out.extend(hosts.iter().map(|host| {
                (
                    format!("tls:{point}:{host}"),
                    format!("the server name {host} of entry point {point}"),
                )
            })),
            (None, Kind::Tls) => out.push((
                format!("tls:{point}:*"),
                format!("every server name of entry point {point}"),
            )),
            (None, _) => out.push((
                format!("{}:{point}", proto(kind).section()),
                format!("entry point {point}"),
            )),
        }
    }
    out
}

/// The draft of a route of `kind` with `routers`: stand-ins for the tenant rules (an HTTP router
/// that claims the same names), and the daemon's JSON in [`Draft::l4`].
///
/// # Errors
///
/// A [`Rejection`] when the rules or backends cannot be honoured.
pub fn draft(
    kind: Kind,
    namespace: &str,
    rules: &[StreamRule],
    routers: Vec<RouterDraft>,
    backends: &Backends<'_>,
) -> Result<Draft, Rejection> {
    let service = service(kind, namespace, rules, backends)?;
    let mut draft = Draft::default();
    let mut items = Vec::new();
    for (index, router) in routers.into_iter().enumerate() {
        let name = format!("r{index}");
        let matcher = match &router.hosts {
            Some(hosts) => {
                let names: Vec<String> = hosts.iter().map(ToString::to_string).collect();
                json!({ "host": names })
            }
            None => json!({ "path_prefix": "/" }),
        };
        let stand_in: Router = serde_json::from_value(json!({
            "name": name,
            "match": matcher,
            "service": SERVICE,
            "entry_points": router.entry_points,
        }))
        .map_err(|err| reject("UnsupportedValue", err.to_string()))?;
        draft.routers.push(Built {
            router: stand_in,
            rank: Rank::default(),
            rule: 0,
            matched: 0,
        });
        let mut json = json!({
            "name": name,
            "entry_points": router.entry_points,
            "service": SERVICE,
        });
        if let Some(hosts) = &router.hosts {
            let names: Vec<String> = hosts.iter().map(ToString::to_string).collect();
            json["match"] = match names.as_slice() {
                [one] => json!({ "sni": one }),
                _ => json!({ "sni": names }),
            };
        }
        match router.passthrough {
            Some(true) => json["tls"] = json!({ "passthrough": true }),
            Some(false) => json["tls"] = json!({}),
            None => {}
        }
        items.push(Item {
            name,
            json,
            claims: claims(kind, &router),
        });
    }
    draft.l4 = Some(Payload {
        proto: proto(kind),
        routers: items,
        service,
    });
    Ok(draft)
}

/// The one service of a route, or `None` when no backend has a weight and a ready endpoint: the
/// route then has no router, and the daemon closes the connections it gets no route for.
fn service(
    kind: Kind,
    namespace: &str,
    rules: &[StreamRule],
    backends: &Backends<'_>,
) -> Result<Option<Declared>, Rejection> {
    if rules.len() > 1 {
        return Err(reject(
            "UnsupportedValue",
            format!(
                "{} rules: a {kind} has no match to tell rules apart, so podgate takes one rule per route",
                rules.len()
            ),
        ));
    }
    let refs = rules
        .first()
        .map_or(&[][..], |rule| rule.backend_refs.as_slice());
    let mut live: Vec<Resolved> = Vec::new();
    for backend in refs {
        let resolved = backends
            .resolve_stream(kind, namespace, backend, wire(kind))
            .map_err(|why| prefixed("rules[0]", why))?;
        if resolved.weight > 0 && !resolved.servers.is_empty() {
            live.push(resolved);
        }
    }
    if live.is_empty() {
        return Ok(None);
    }
    let weights = server_weights(&live)?;
    let equal = weights
        .values()
        .all(|weight| Some(weight) == weights.values().next());
    if !equal && proto(kind) == Proto::Udp {
        return Err(reject(
            "UnsupportedValue",
            "the backends' weights need a different share per server, and a UDP service has no weights: give the backends equal weight per endpoint",
        ));
    }
    let servers: Vec<Value> = weights
        .iter()
        .map(|(address, weight)| {
            if equal {
                json!({ "address": &**address })
            } else {
                json!({ "address": &**address, "weight": weight })
            }
        })
        .collect();
    let mut value = json!({ "name": SERVICE, "type": "loadbalancer", "servers": servers });
    if !equal {
        value["algorithm"] = json!("weighted_round_robin");
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(|err| reject("UnsupportedValue", err.to_string()))
}

fn prefixed(place: &str, mut rejection: Rejection) -> Rejection {
    rejection.message = format!("{place}: {}", rejection.message);
    rejection
}

fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// The weight of every server of `live`, so that each backend gets the share its weight says
/// however many endpoints it has: a backend of weight `w` and `n` servers gives each `w / n`,
/// scaled to whole numbers and reduced.
///
/// # Errors
///
/// `UnsupportedValue` when the numbers do not fit the daemon's weights, or there are more
/// servers than a service holds.
fn server_weights(live: &[Resolved]) -> Result<BTreeMap<Box<str>, u32>, Rejection> {
    let too_big = || {
        reject(
            "UnsupportedValue",
            "the backends' weights and endpoint counts cannot be expressed as server weights",
        )
    };
    let mut common: u64 = 1;
    for backend in live {
        let count = u64::try_from(backend.servers.len()).map_err(|_| too_big())?;
        common = (common / gcd(common, count))
            .checked_mul(count)
            .ok_or_else(too_big)?;
    }
    let mut units: BTreeMap<Box<str>, u64> = BTreeMap::new();
    for backend in live {
        let count = u64::try_from(backend.servers.len()).map_err(|_| too_big())?;
        let each = u64::from(backend.weight)
            .checked_mul(common / count)
            .ok_or_else(too_big)?;
        for server in &backend.servers {
            let unit = units.entry(server.clone()).or_default();
            *unit = unit.checked_add(each).ok_or_else(too_big)?;
        }
    }
    if units.len() > MAX_SERVERS {
        return Err(reject(
            "UnsupportedValue",
            format!(
                "{} servers: a service holds at most {MAX_SERVERS}",
                units.len()
            ),
        ));
    }
    let divisor = units.values().fold(0, |acc, unit| gcd(acc, *unit));
    units
        .into_iter()
        .map(|(server, unit)| {
            u32::try_from(unit / divisor)
                .map(|weight| (server, weight))
                .map_err(|_| too_big())
        })
        .collect()
}

/// The routes that lose a conflict, by index in `pending`, each with its reason.
///
/// One entry point carries one TCP router without a name to tell it apart (a `TCPRoute`), one
/// UDP router, and one TLS router per server name; the daemon refuses a second one
/// (`route_ambiguity`), and which of two it would keep is not the one the Gateway API keeps. The
/// oldest route wins (then the first `namespace/name`), as for every conflict of the API; the
/// others are not served.
pub(super) fn conflicts(pending: &[Pending]) -> Vec<(usize, Rejection)> {
    let mut order: Vec<usize> = (0..pending.len())
        .filter(|index| pending[*index].l4.is_some())
        .collect();
    order.sort_by(|a, b| {
        let (a, b) = (&pending[*a], &pending[*b]);
        (a.first_seen, &a.namespace, &a.name).cmp(&(b.first_seen, &b.namespace, &b.name))
    });
    let mut taken: BTreeMap<&str, usize> = BTreeMap::new();
    let mut lost = Vec::new();
    for index in order {
        let route = &pending[index];
        let Some(payload) = &route.l4 else { continue };
        let kept: BTreeSet<&str> = route
            .built
            .iter()
            .map(|built| &*built.router.name)
            .collect();
        let claims: Vec<&(String, String)> = payload
            .routers
            .iter()
            .filter(|item| kept.contains(item.name.as_str()))
            .flat_map(|item| &item.claims)
            .collect();
        let held = claims
            .iter()
            .find_map(|(key, what)| taken.get(key.as_str()).map(|owner| (what, *owner)));
        if let Some((what, owner)) = held {
            let owner = &pending[owner];
            lost.push((
                index,
                reject(
                    "NotAllowedByListeners",
                    format!(
                        "route_ambiguity: {what} already has a {} ({}/{}, older): a listener serves one route there, and the oldest one wins",
                        owner.kind, owner.namespace, owner.name
                    ),
                ),
            ));
            continue;
        }
        for (key, _) in claims {
            taken.insert(key, index);
        }
    }
    lost
}

// ---- listeners ---------------------------------------------------------------------------------

/// The route kinds a listener of `protocol` carries, as `supportedKinds` lists them.
#[must_use]
pub fn supported_kinds(protocol: &str) -> &'static [&'static str] {
    match protocol {
        "HTTP" | "HTTPS" => &["HTTPRoute", "GRPCRoute"],
        "TLS" => &["TLSRoute"],
        "TCP" => &["TCPRoute"],
        "UDP" => &["UDPRoute"],
        _ => &[],
    }
}

/// Why a route of `kind` cannot attach to a listener of `protocol`, when it cannot.
#[must_use]
pub fn mismatch(kind: Kind, protocol: &str) -> Option<String> {
    if supported_kinds(protocol).contains(&kind.name()) {
        return None;
    }
    Some(match kind {
        Kind::Http | Kind::Grpc => {
            format!("the protocol {protocol:?} carries no HTTP route (only HTTP and HTTPS do)")
        }
        Kind::Tls => format!("the protocol {protocol:?} carries no TLSRoute (a TLS listener does)"),
        Kind::Tcp => format!("the protocol {protocol:?} carries no TCPRoute (a TCP listener does)"),
        Kind::Udp => format!("the protocol {protocol:?} carries no UDPRoute (a UDP listener does)"),
    })
}

/// Whether a listener holds certificates: an `HTTPS` listener, and a `TLS` one that terminates.
#[must_use]
pub fn terminates(listener: &Listener) -> bool {
    listener.protocol == "HTTPS" || (listener.protocol == "TLS" && !passthrough(listener))
}

/// Whether a `TLS` listener forwards the TLS stream untouched.
#[must_use]
pub fn passthrough(listener: &Listener) -> bool {
    listener.protocol == "TLS"
        && listener
            .tls
            .as_ref()
            .and_then(|tls| tls.mode.as_deref())
            .is_some_and(|mode| mode == "Passthrough")
}

/// The entry points that carry HTTP routes: those of the ports of the `HTTP` and `HTTPS`
/// listeners of `gateways`.
#[must_use]
pub fn http_entry_points<'a>(
    gateways: impl Iterator<Item = &'a Gateway>,
    ports: &BTreeMap<u16, Box<str>>,
) -> BTreeSet<Box<str>> {
    gateways
        .flat_map(|gateway| &gateway.spec.listeners)
        .filter(|listener| matches!(listener.protocol.as_str(), "HTTP" | "HTTPS"))
        .filter_map(|listener| ports.get(&listener.port).cloned())
        .collect()
}

/// Why a `TLS`, `TCP` or `UDP` listener cannot use `entry_point`, when it cannot: the port is
/// shared with an HTTP or HTTPS listener (change 0060 measured a front that shares a port and
/// refused it: TLS routers, TCP routers and UDP routers use an entry point of their own), or a
/// `TLS` listener has a mode that is neither `Terminate` nor `Passthrough`.
///
/// # Errors
///
/// `PortUnavailable` or `UnsupportedProtocol`, the reasons of a listener's `Accepted` condition.
pub fn check(
    listener: &Listener,
    entry_point: &str,
    http: &BTreeSet<Box<str>>,
) -> Result<(), Rejection> {
    if !matches!(listener.protocol.as_str(), "TLS" | "TCP" | "UDP") {
        return Ok(());
    }
    if let Some(mode) = listener
        .tls
        .as_ref()
        .and_then(|tls| tls.mode.as_deref())
        .filter(|mode| listener.protocol == "TLS" && !matches!(*mode, "Terminate" | "Passthrough"))
    {
        return Err(reject(
            "UnsupportedProtocol",
            format!("tls.mode {mode:?} is neither Terminate nor Passthrough"),
        ));
    }
    if http.contains(entry_point) {
        return Err(reject(
            "PortUnavailable",
            format!(
                "port {} is shared with an HTTP or HTTPS listener (entry point {entry_point}), and a {} listener needs an entry point of its own: podgate does not share a port between HTTP routers and TLS, TCP or UDP routers; give it another port in listener_entry_points",
                listener.port, listener.protocol
            ),
        ));
    }
    Ok(())
}

// ---- the cluster ------------------------------------------------------------------------------

impl Cache {
    /// Every `TLSRoute`, `TCPRoute` and `UDPRoute` the source holds, with its status.
    pub(super) fn l4_routes(&self) -> Vec<(Kind, &ObjectMeta, Option<&Value>)> {
        let mut out = Vec::new();
        out.extend(
            self.tls
                .iter()
                .flat_map(Store::values)
                .map(|route| (Kind::Tls, &route.metadata, route.status.as_ref())),
        );
        out.extend(
            self.tcp
                .iter()
                .flat_map(Store::values)
                .map(|route| (Kind::Tcp, &route.metadata, route.status.as_ref())),
        );
        out.extend(
            self.udp
                .iter()
                .flat_map(Store::values)
                .map(|route| (Kind::Udp, &route.metadata, route.status.as_ref())),
        );
        out
    }
}

impl Target {
    /// The status target of an L4 route.
    pub(super) fn l4(kind: Kind, key: String) -> Self {
        match kind {
            Kind::Tls => Self::Tls(key),
            Kind::Udp => Self::Udp(key),
            Kind::Http | Kind::Grpc | Kind::Tcp => Self::Tcp(key),
        }
    }
}

/// Watches `R`, a kind whose CRD may not be installed: while the API server answers `404` to its
/// list, the kind counts as empty (the source is not held back, and nothing is reported), and
/// the list is tried again after the client's longest retry delay. Once it answers, the kind is
/// watched as any other, and when it goes away again its objects are dropped.
pub(super) fn watch_optional<R: Resource>(
    tasks: &mut JoinSet<()>,
    client: &ApiClient,
    query: Query,
    scope: usize,
    tx: &Sender<Tagged>,
    wrap: fn(Event<R>) -> crate::kubernetes::Change,
) {
    let client = client.clone();
    let tx = tx.clone();
    tasks.spawn(async move {
        async fn missing<R: Resource>(client: &ApiClient, query: &Query) -> bool {
            matches!(client.list::<R>(query).await, Err(err) if err.http_status() == Some(404))
        }
        let mut watcher: Option<Watcher<R>> = None;
        let mut told = false;
        loop {
            let event = match watcher.as_mut() {
                Some(watcher) => watcher.next().await,
                None if missing::<R>(&client, &query).await => {
                    // Nothing to watch: say so once, so the kind is in sync and holds nothing.
                    let event = (!told).then(|| Event::Reset(Vec::new()));
                    told = true;
                    match event {
                        Some(event) => event,
                        None => {
                            sleep(client.tuning().backoff_max).await;
                            continue;
                        }
                    }
                }
                None => {
                    told = false;
                    watcher = Some(Watcher::new(client.clone(), query.clone()));
                    continue;
                }
            };
            let outage = matches!(event, Event::Outage(_));
            let change = wrap(event);
            if tx.send(Tagged { scope, change }).await.is_err() {
                return;
            }
            if outage && missing::<R>(&client, &query).await {
                watcher = None;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend(servers: &[&str], weight: u32) -> Resolved {
        Resolved {
            key: "k".into(),
            servers: servers.iter().map(|server| (*server).into()).collect(),
            weight,
        }
    }

    fn weights(live: &[Resolved]) -> Vec<(String, u32)> {
        server_weights(live)
            .expect("weights")
            .into_iter()
            .map(|(server, weight)| (server.to_string(), weight))
            .collect()
    }

    #[test]
    fn equal_backends_share_equally() {
        assert_eq!(
            weights(&[backend(&["a:1"], 1), backend(&["b:1"], 1)]),
            [("a:1".to_owned(), 1), ("b:1".to_owned(), 1)]
        );
    }

    #[test]
    fn weight_is_per_backend_not_per_endpoint() {
        // Weight 3 over three servers is 1 each; weight 3 over one server is 3 for it.
        assert_eq!(
            weights(&[backend(&["a:1", "a:2", "a:3"], 3), backend(&["b:1"], 3)]),
            [
                ("a:1".to_owned(), 1),
                ("a:2".to_owned(), 1),
                ("a:3".to_owned(), 1),
                ("b:1".to_owned(), 3)
            ]
        );
        assert_eq!(
            weights(&[backend(&["a:1", "a:2"], 1), backend(&["b:1"], 1)]),
            [
                ("a:1".to_owned(), 1),
                ("a:2".to_owned(), 1),
                ("b:1".to_owned(), 2)
            ]
        );
    }

    #[test]
    fn weights_are_reduced() {
        assert_eq!(
            weights(&[backend(&["a:1"], 50), backend(&["b:1"], 100)]),
            [("a:1".to_owned(), 1), ("b:1".to_owned(), 2)]
        );
    }

    #[test]
    fn a_repeated_address_adds_up() {
        assert_eq!(
            weights(&[backend(&["a:1"], 1), backend(&["a:1"], 2)]),
            [("a:1".to_owned(), 1)]
        );
    }
}
