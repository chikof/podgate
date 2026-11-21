//! The `podgate.*` labels: what a deployer may say about a container, and the app that follows.
//!
//! Nothing in this file knows Docker. [`parse`] takes plain `(key, value)` pairs, so any source
//! whose objects carry key-value metadata (Nomad service tags, Kubernetes annotations) reads the
//! same keys with the same strictness, and [`assemble`] turns the parsed labels of all the
//! containers (allocations, pods) of one app into the [`App`].
//!
//! # Keys
//!
//! | Key | Meaning |
//! |---|---|
//! | `podgate.enable` | `true` or `false` |
//! | `podgate.app`, `podgate.tenant` | the app id and the tenant the object names for itself |
//! | `podgate.host` | comma separated hosts: a router named `default` matching them |
//! | `podgate.port` | the port the container listens on |
//! | `podgate.revision`, `podgate.revision.state` | revision id (default `default`) and `serving`, `retiring` or `draining` (default `serving`) |
//! | `podgate.tls` | `acme` (default) or `on_demand` |
//! | `podgate.router.<name>.{match,priority,entry_points,chain,service}` | a router; `match` is a matcher as JSON |
//! | `podgate.middleware.<name>.{type,config}` | a middleware; `config` is JSON |
//! | `podgate.service.<name>.config` | a service of the revision, JSON; `type` defaults to `loadbalancer` |
//! | `podgate.transport.<name>.config` | a `servers_transport` of the app, JSON |
//!
//! Any other `podgate.*` key rejects the container, like the daemon rejects an unknown field.
//! Keys that do not start with `podgate.` are not this file's.
//!
//! # The address rule
//!
//! Labels describe routing, never destinations. The servers of a service are added by
//! [`assemble`] from the addresses the runtime assigned to the containers that carry the labels,
//! and a label cannot say otherwise: a scalar that is an address, a URL or a `host:port`
//! ([`Rejection::Address`]), a JSON key named like an address (`servers`, `url`, `address`,
//! `endpoint`, `upstream`, `container`, ...) or a JSON value that is `ip:port` is rejected. Names
//! (`service`, `chain`, a transport) resolve inside the container's own app, so a name that is
//! not defined by the same labels, or that names another app (`other/web`), is rejected too
//! ([`Rejection::Foreign`]): a label cannot reach another tenant's container.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

use podgate_model::{App, Declared, RevisionState, Router, TlsMode};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::source::TenantClaim;

const PREFIX: &str = "podgate.";

/// The service a router uses when it names none, and the one that exists without a label.
const DEFAULT_SERVICE: &str = "web";

const DEFAULT_REVISION: &str = "default";

/// The router that `podgate.host` stands for.
const HOST_ROUTER: &str = "default";

const MAX_NAME: usize = 63;

/// Why a container (allocation, pod) is not used. Each variant has a stable [`code`](Self::code).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Rejection {
    /// A `podgate.*` key this parser does not know.
    #[error("unknown label {key}: see docs/ref/provider-docker.md for the keys")]
    UnknownKey {
        /// The label key.
        key: Box<str>,
    },
    /// A value that is not acceptable for its key.
    #[error("{key}: {reason}")]
    Invalid {
        /// The label key.
        key: Box<str>,
        /// What is wrong.
        reason: Box<str>,
    },
    /// A label that names an address, a URL or a container instead of leaving that to the
    /// runtime.
    #[error(
        "{key}: {what} names an address, a URL or a container; a server is the container's own network address and the port label, nothing else"
    )]
    Address {
        /// The label key.
        key: Box<str>,
        /// The JSON path or the value that did.
        what: Box<str>,
    },
    /// A name that is not defined by this container's own labels.
    #[error(
        "{key}: {name:?} is not defined in this app; names resolve inside the app that carries the label"
    )]
    Foreign {
        /// The label key.
        key: Box<str>,
        /// The name.
        name: Box<str>,
    },
    /// No router: nothing would ever reach the container.
    #[error("no router: set podgate.host or podgate.router.<name>.match")]
    NoRouter,
    /// The containers of one app disagree.
    #[error("{reason}")]
    Conflict {
        /// What differs.
        reason: Box<str>,
    },
}

impl Rejection {
    /// A stable, lowercase code for reports and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownKey { .. } => "unknown_label",
            Self::Invalid { .. } => "invalid_label",
            Self::Address { .. } => "address_label",
            Self::Foreign { .. } => "foreign_reference",
            Self::NoRouter => "no_router",
            Self::Conflict { .. } => "app_conflict",
        }
    }

    fn invalid(key: &str, reason: impl Into<Box<str>>) -> Self {
        Self::Invalid {
            key: key.into(),
            reason: reason.into(),
        }
    }

    fn address(key: &str, what: &str) -> Self {
        Self::Address {
            key: key.into(),
            what: what.into(),
        }
    }

    fn foreign(key: &str, name: &str) -> Self {
        Self::Foreign {
            key: key.into(),
            name: name.into(),
        }
    }
}

/// What every container of one revision of an app must say the same way: the routing of the
/// app, taken from the newest serving revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definition {
    /// Where certificates come from.
    pub tls: TlsMode,
    /// The routers, by name.
    pub routers: Vec<Router>,
    /// The middlewares, by name.
    pub middlewares: Vec<Declared>,
    /// The transports, by name.
    pub transports: Vec<Declared>,
}

/// The `podgate.*` labels of one container, checked on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Labels {
    /// `podgate.app`.
    pub app: Option<Box<str>>,
    /// `podgate.tenant`: the tenant the container names for itself, not yet trusted.
    pub tenant: Option<Box<str>>,
    /// `podgate.port`.
    pub port: Option<u16>,
    /// `podgate.revision`, `default` when absent.
    pub revision: Box<str>,
    /// `podgate.revision.state`, `serving` when absent.
    pub state: RevisionState,
    /// The routing of the app.
    pub definition: Definition,
    /// The services of this container's revision, without servers.
    pub services: Vec<Declared>,
}

#[derive(Default)]
struct RouterDraft {
    matcher: Option<Value>,
    priority: Option<i32>,
    entry_points: Option<Vec<Box<str>>>,
    chain: Vec<Box<str>>,
    service: Option<Box<str>>,
}

#[derive(Default)]
struct MiddlewareDraft {
    kind: Option<Box<str>>,
    config: Map<String, Value>,
}

/// The names a JSON configuration refers to.
#[derive(Default)]
struct Refs {
    services: BTreeSet<Box<str>>,
    transports: BTreeSet<Box<str>>,
}

#[derive(Default)]
struct Draft {
    app: Option<Box<str>>,
    tenant: Option<Box<str>>,
    port: Option<u16>,
    revision: Option<Box<str>>,
    state: Option<RevisionState>,
    tls: Option<TlsMode>,
    hosts: Option<Vec<Box<str>>>,
    routers: BTreeMap<String, RouterDraft>,
    middlewares: BTreeMap<String, MiddlewareDraft>,
    services: BTreeMap<String, (Box<str>, Map<String, Value>)>,
    transports: BTreeMap<String, Map<String, Value>>,
    refs: Refs,
}

/// Reads the `podgate.*` pairs of one container.
///
/// Pairs whose key does not start with `podgate.` are skipped.
///
/// # Errors
///
/// A [`Rejection`] for the first label that is unknown, malformed, names an address, or refers
/// to something this container does not define, and [`Rejection::NoRouter`] when no router
/// remains.
pub fn parse<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<Labels, Rejection> {
    let mut draft = Draft::default();
    for (key, value) in pairs {
        if let Some(rest) = key.strip_prefix(PREFIX) {
            draft.accept(key, rest, value)?;
        }
    }
    draft.finish()
}

impl Draft {
    fn accept(&mut self, key: &str, rest: &str, value: &str) -> Result<(), Rejection> {
        let parts: Vec<&str> = rest.split('.').collect();
        match parts.as_slice() {
            ["enable"] => {
                if !matches!(value, "true" | "false") {
                    return Err(Rejection::invalid(key, "must be true or false"));
                }
            }
            ["app"] => self.app = Some(identifier(key, value)?),
            ["tenant"] => self.tenant = Some(identifier(key, value)?),
            ["host"] => self.hosts = Some(hosts(key, value)?),
            ["port"] => self.port = Some(port(key, value)?),
            ["revision"] => self.revision = Some(identifier(key, value)?),
            ["revision", "state"] => self.state = Some(state(key, value)?),
            ["tls"] => self.tls = Some(tls(key, value)?),
            ["router", name, field] => {
                let name = sub_name(key, name)?;
                self.router_field(key, name, field, value)?;
            }
            ["middleware", name, field @ ("type" | "config")] => {
                let name = sub_name(key, name)?;
                let draft = self.middlewares.entry(name.to_owned()).or_default();
                if *field == "type" {
                    draft.kind = Some(kind_name(key, value)?);
                } else {
                    let config = object(key, value, &mut self.refs)?;
                    if config.contains_key("type") {
                        return Err(Rejection::invalid(
                            key,
                            "the type is in `.type`, not in the JSON",
                        ));
                    }
                    draft.config = config;
                }
            }
            ["service", name, "config"] => {
                let name = sub_name(key, name)?;
                let mut config = object(key, value, &mut self.refs)?;
                let kind = take_kind(key, &mut config, "loadbalancer")?;
                self.services.insert(name.to_owned(), (kind, config));
            }
            ["transport", name, "config"] => {
                let name = sub_name(key, name)?;
                let config = object(key, value, &mut self.refs)?;
                if config.contains_key("type") {
                    return Err(Rejection::invalid(key, "a transport has no type to choose"));
                }
                self.transports.insert(name.to_owned(), config);
            }
            _ => {
                return Err(Rejection::UnknownKey { key: key.into() });
            }
        }
        Ok(())
    }

    fn router_field(
        &mut self,
        key: &str,
        name: &str,
        field: &str,
        value: &str,
    ) -> Result<(), Rejection> {
        let router = self.routers.entry(name.to_owned()).or_default();
        match field {
            "match" => {
                let parsed: Value = serde_json::from_str(value)
                    .map_err(|err| Rejection::invalid(key, format!("not JSON: {err}")))?;
                if !parsed.is_object() {
                    return Err(Rejection::invalid(key, "must be a JSON object"));
                }
                router.matcher = Some(parsed);
            }
            "priority" => {
                let priority = value
                    .trim()
                    .parse()
                    .map_err(|_| Rejection::invalid(key, "must be a whole number"))?;
                router.priority = Some(priority);
            }
            "entry_points" => {
                router.entry_points = Some(
                    list(key, value)?
                        .into_iter()
                        .map(|entry| sub_name(key, entry).map(Into::into))
                        .collect::<Result<_, _>>()?,
                );
            }
            "chain" => {
                router.chain = list(key, value)?
                    .into_iter()
                    .map(|entry| local_name(key, entry))
                    .collect::<Result<_, _>>()?;
            }
            "service" => router.service = Some(local_name(key, value)?),
            _ => return Err(Rejection::UnknownKey { key: key.into() }),
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Labels, Rejection> {
        if let Some(hosts) = self.hosts.take() {
            let router = RouterDraft {
                matcher: Some(json!({ "host": hosts })),
                ..RouterDraft::default()
            };
            if self
                .routers
                .insert(HOST_ROUTER.to_owned(), router)
                .is_some()
            {
                return Err(Rejection::invalid(
                    "podgate.host",
                    format!("is the router {HOST_ROUTER:?}; name your own router differently"),
                ));
            }
        }
        if self.routers.is_empty() {
            return Err(Rejection::NoRouter);
        }
        let mut routers = Vec::new();
        for (name, draft) in self.routers {
            let key = format!("podgate.router.{name}.match");
            let matcher = draft
                .matcher
                .ok_or_else(|| Rejection::invalid(&key, "every router needs a match"))?;
            let service = draft.service.unwrap_or_else(|| DEFAULT_SERVICE.into());
            self.refs.services.insert(service.clone());
            for middleware in &draft.chain {
                if !self.middlewares.contains_key(&**middleware) {
                    return Err(Rejection::foreign(
                        &format!("podgate.router.{name}.chain"),
                        middleware,
                    ));
                }
            }
            routers.push(Router {
                name: name.into(),
                entry_points: draft.entry_points,
                matcher,
                priority: draft.priority,
                chain: draft.chain,
                service,
                observability: None,
                declared_by: None,
            });
        }
        let mut middlewares = Vec::new();
        for (name, draft) in self.middlewares {
            let kind = draft.kind.ok_or_else(|| {
                Rejection::invalid(&format!("podgate.middleware.{name}.type"), "is required")
            })?;
            middlewares.push(Declared {
                name: name.into(),
                kind,
                config: draft.config,
            });
        }
        let mut services: Vec<Declared> = Vec::new();
        for (name, (kind, config)) in self.services {
            services.push(Declared {
                name: name.into(),
                kind,
                config,
            });
        }
        // `web` exists without a label so the shorthand needs nothing else.
        if self.refs.services.contains(DEFAULT_SERVICE)
            && !services
                .iter()
                .any(|service| &*service.name == DEFAULT_SERVICE)
        {
            services.push(Declared {
                name: DEFAULT_SERVICE.into(),
                kind: "loadbalancer".into(),
                config: Map::new(),
            });
            services.sort_by(|a, b| a.name.cmp(&b.name));
        }
        for name in &self.refs.services {
            if !services.iter().any(|service| service.name == *name) {
                return Err(Rejection::foreign("podgate.service", name));
            }
        }
        let transports: Vec<Declared> = self
            .transports
            .into_iter()
            .map(|(name, config)| Declared {
                name: name.into(),
                kind: "servers_transport".into(),
                config,
            })
            .collect();
        for name in &self.refs.transports {
            if !transports.iter().any(|transport| transport.name == *name) {
                return Err(Rejection::foreign("podgate.service", name));
            }
        }
        Ok(Labels {
            app: self.app,
            tenant: self.tenant,
            port: self.port,
            revision: self.revision.unwrap_or_else(|| DEFAULT_REVISION.into()),
            state: self.state.unwrap_or(RevisionState::Serving),
            definition: Definition {
                tls: self.tls.unwrap_or(TlsMode::Acme),
                routers,
                middlewares,
                transports,
            },
            services,
        })
    }
}

/// Whether `value` is an address, a URL or a `host:port` in any of the usual spellings.
fn looks_like_address(value: &str) -> bool {
    value.contains("://")
        || value.starts_with("unix:")
        || value.parse::<IpAddr>().is_ok()
        || value.parse::<SocketAddr>().is_ok()
        || value.rsplit_once(':').is_some_and(|(host, port)| {
            !host.is_empty() && !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// The JSON keys that name a destination, by their ending: `servers`, `server_url`, `jwks_uri`,
/// `address`, `endpoint`, `issuer`, `upstream`, `container`.
fn names_a_destination(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "url",
        "urls",
        "uri",
        "uris",
        "address",
        "addresses",
        "addr",
        "endpoint",
        "endpoints",
        "issuer",
        "server",
        "servers",
        "upstream",
        "upstreams",
        "container",
        "containers",
    ]
    .iter()
    .any(|ending| key.ends_with(ending))
}

fn valid_name(name: &str, dots: bool) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') || (dots && byte == b'.')
        })
}

/// An app, tenant or revision id.
pub(super) fn identifier(key: &str, value: &str) -> Result<Box<str>, Rejection> {
    let value = value.trim();
    if looks_like_address(value) {
        return Err(Rejection::address(key, value));
    }
    if !valid_name(value, true) {
        return Err(Rejection::invalid(
            key,
            format!("must be 1 to {MAX_NAME} letters, digits, `-`, `_` or `.`"),
        ));
    }
    Ok(value.into())
}

/// The `<name>` in `podgate.router.<name>.match`.
fn sub_name<'a>(key: &str, name: &'a str) -> Result<&'a str, Rejection> {
    let name = name.trim();
    if looks_like_address(name) {
        return Err(Rejection::address(key, name));
    }
    if !valid_name(name, false) {
        return Err(Rejection::invalid(
            key,
            format!("{name:?} must be 1 to {MAX_NAME} letters, digits, `-` or `_`"),
        ));
    }
    Ok(name)
}

/// A name that must be defined by this container's own labels.
fn local_name(key: &str, value: &str) -> Result<Box<str>, Rejection> {
    let value = value.trim();
    if looks_like_address(value) {
        return Err(Rejection::address(key, value));
    }
    if value.contains('/') {
        return Err(Rejection::foreign(key, value));
    }
    sub_name(key, value).map(Into::into)
}

fn kind_name(key: &str, value: &str) -> Result<Box<str>, Rejection> {
    let value = value.trim();
    if !valid_name(value, false) {
        return Err(Rejection::invalid(key, "must be a middleware type name"));
    }
    Ok(value.into())
}

fn list<'a>(key: &str, value: &'a str) -> Result<Vec<&'a str>, Rejection> {
    let items: Vec<&str> = value.split(',').map(str::trim).collect();
    if items.iter().any(|item| item.is_empty()) {
        return Err(Rejection::invalid(key, "has an empty entry"));
    }
    Ok(items)
}

fn hosts(key: &str, value: &str) -> Result<Vec<Box<str>>, Rejection> {
    list(key, value)?
        .into_iter()
        .map(|host| {
            if looks_like_address(host) {
                return Err(Rejection::address(key, host));
            }
            let name = host.strip_prefix("*.").unwrap_or(host);
            let valid = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
            if valid {
                Ok(host.into())
            } else {
                Err(Rejection::invalid(
                    key,
                    format!("{host:?} is not a host name or a `*.` wildcard"),
                ))
            }
        })
        .collect()
}

fn port(key: &str, value: &str) -> Result<u16, Rejection> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| Rejection::invalid(key, "must be a port number, 1 to 65535"))
}

fn state(key: &str, value: &str) -> Result<RevisionState, Rejection> {
    match value.trim() {
        "serving" => Ok(RevisionState::Serving),
        "retiring" => Ok(RevisionState::Retiring),
        "draining" => Ok(RevisionState::Draining),
        _ => Err(Rejection::invalid(
            key,
            "must be serving, retiring or draining",
        )),
    }
}

fn tls(key: &str, value: &str) -> Result<TlsMode, Rejection> {
    match value.trim() {
        "acme" => Ok(TlsMode::Acme),
        "on_demand" => Ok(TlsMode::OnDemand),
        _ => Err(Rejection::invalid(key, "must be acme or on_demand")),
    }
}

/// A JSON object, checked against the address rule, with the names it refers to collected.
fn object(key: &str, value: &str, refs: &mut Refs) -> Result<Map<String, Value>, Rejection> {
    let parsed: Value = serde_json::from_str(value)
        .map_err(|err| Rejection::invalid(key, format!("not JSON: {err}")))?;
    let Value::Object(map) = parsed else {
        return Err(Rejection::invalid(key, "must be a JSON object"));
    };
    for (name, nested) in &map {
        walk(key, name, nested, refs)?;
    }
    if map.contains_key("name") {
        return Err(Rejection::invalid(
            key,
            "the name is in the key, not in the JSON",
        ));
    }
    Ok(map)
}

fn walk(label: &str, path: &str, value: &Value, refs: &mut Refs) -> Result<(), Rejection> {
    let leaf = path.rsplit('.').next().unwrap_or(path);
    if names_a_destination(leaf) {
        return Err(Rejection::address(label, path));
    }
    match value {
        Value::Object(map) => {
            for (name, nested) in map {
                walk(label, &format!("{path}.{name}"), nested, refs)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(label, path, item, refs)?;
            }
        }
        Value::String(text) => {
            if text.parse::<SocketAddr>().is_ok() || text.starts_with("unix:") {
                return Err(Rejection::address(label, path));
            }
            match leaf {
                "service" | "fallback" => {
                    refs.services.insert(service_ref(label, text)?);
                }
                "transport" => {
                    refs.transports.insert(local_name(label, text)?);
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

/// A reference to a service of the app: `name`, or `name@revision` for a service of another
/// revision of the same app. Only the name has to be defined here.
fn service_ref(label: &str, text: &str) -> Result<Box<str>, Rejection> {
    let name = text.split_once('@').map_or(text, |(name, _)| name);
    local_name(label, name)
}

/// The `type` of a service, removed from its configuration.
fn take_kind(
    key: &str,
    config: &mut Map<String, Value>,
    default: &str,
) -> Result<Box<str>, Rejection> {
    match config.remove("type") {
        None => Ok(default.into()),
        Some(Value::String(kind)) => kind_name(key, &kind),
        Some(_) => Err(Rejection::invalid(key, "type must be text")),
    }
}

// ---- assembling an app --------------------------------------------------------------------

/// One container (allocation, pod) that carries labels for an app, for [`assemble`].
#[derive(Debug, Clone)]
pub struct Member<'a> {
    /// What reports call it: the container name.
    pub name: &'a str,
    /// Its labels.
    pub labels: &'a Labels,
    /// Its server: the address the runtime assigned plus the port label.
    pub server: SocketAddr,
    /// Who it says it belongs to.
    pub claim: &'a TenantClaim,
    /// When it was created, a number that orders the members of an app; `0` if unknown.
    pub created: u64,
}

/// The app of one group of members, and the members that were left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    /// The app. Its `tenant` and `declared_by` are placeholders: the core sets them.
    pub app: App,
    /// The tenant claim of the members that were used.
    pub claim: TenantClaim,
    /// The indexes (into the members given) that were left out, with the reason.
    pub rejected: Vec<(usize, Rejection)>,
}

/// Builds the app `id` from the members that carry its labels.
///
/// Every revision becomes a [`podgate_model::Revision`] whose services hold the servers of its
/// members, in address order. The routing of the app (routers, middlewares, transports, TLS)
/// comes from the newest serving revision, or the newest revision when none serves, and the
/// other revisions only add their own services: during a rolling deploy the old containers may
/// carry older labels. A member is left out when it contradicts its revision's first member (the
/// oldest), names another tenant than the app's, or sits in a revision that lacks a service or
/// transport the routing needs, since a pinned session must never meet a revision without its
/// route.
///
/// # Errors
///
/// [`Rejection::Invalid`] when the assembled app is not a valid model object, which no parsed
/// labels should cause, and [`Rejection::Conflict`] when `members` is empty.
pub fn assemble(id: &str, members: &[Member<'_>]) -> Result<Assembled, Rejection> {
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by_key(|&index| (members[index].created, members[index].name));
    let mut rejected: Vec<(usize, Rejection)> = Vec::new();

    let mut by_revision: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for &index in &order {
        by_revision
            .entry(&members[index].labels.revision)
            .or_default()
            .push(index);
    }
    for indexes in by_revision.values_mut() {
        let first = &members[indexes[0]];
        let mut kept = vec![indexes[0]];
        for &index in &indexes[1..] {
            let member = &members[index];
            let differs = if member.labels.state != first.labels.state {
                Some("revision.state")
            } else if member.labels.definition != first.labels.definition {
                Some("routers, middlewares, transports or tls")
            } else if member.labels.services != first.labels.services {
                Some("services")
            } else {
                None
            };
            match differs {
                Some(what) => rejected.push((
                    index,
                    Rejection::Conflict {
                        reason: format!(
                            "its {what} differ from {} of the same app and revision {}",
                            first.name, first.labels.revision
                        )
                        .into(),
                    },
                )),
                None => kept.push(index),
            }
        }
        *indexes = kept;
    }

    let born = |indexes: &[usize]| {
        indexes
            .iter()
            .map(|&i| members[i].created)
            .min()
            .unwrap_or(0)
    };
    let serving = |indexes: &[usize]| members[indexes[0]].labels.state == RevisionState::Serving;
    let mut primary: Option<((bool, u64, &str), usize)> = None;
    for (revision, indexes) in &by_revision {
        let rank = (serving(indexes), born(indexes), *revision);
        if primary.as_ref().is_none_or(|(best, _)| rank > *best) {
            primary = Some((rank, indexes[0]));
        }
    }
    let primary = primary.map(|((_, _, revision), member)| (revision, member));
    let Some((primary_revision, primary_member)) = primary else {
        return Err(Rejection::Conflict {
            reason: "the app has no containers".into(),
        });
    };
    let claim = members[primary_member].claim.clone();
    let definition = members[primary_member].labels.definition.clone();

    let needed_services: BTreeSet<&str> = definition
        .routers
        .iter()
        .map(|router| &*router.service)
        .collect();
    let known_transports: BTreeSet<&str> = definition
        .transports
        .iter()
        .map(|transport| &*transport.name)
        .collect();

    let mut revisions = Vec::new();
    for (revision, indexes) in &by_revision {
        let first = &members[indexes[0]].labels;
        let mut kept = Vec::new();
        for &index in indexes {
            let member = &members[index];
            let why = if *member.claim != claim {
                Some(format!(
                    "it names another tenant than {} of the same app",
                    members[primary_member].name
                ))
            } else if *revision != primary_revision && first.state != RevisionState::Draining {
                lacks(&member.labels.services, &needed_services, &known_transports)
            } else {
                None
            };
            match why {
                Some(reason) => rejected.push((
                    index,
                    Rejection::Conflict {
                        reason: reason.into(),
                    },
                )),
                None => kept.push(index),
            }
        }
        if kept.is_empty() {
            continue;
        }
        let mut servers: Vec<SocketAddr> = kept.iter().map(|&i| members[i].server).collect();
        servers.sort();
        servers.dedup();
        let urls: Vec<Value> = servers
            .iter()
            .map(|server| json!({ "url": format!("http://{server}") }))
            .collect();
        let services: Vec<Value> = first
            .services
            .iter()
            .map(|service| {
                let mut config = service.config.clone();
                if &*service.kind == "loadbalancer" {
                    config.insert("servers".into(), Value::Array(urls.clone()));
                }
                let mut object = Map::new();
                object.insert("name".into(), Value::String(service.name.to_string()));
                object.insert("type".into(), Value::String(service.kind.to_string()));
                object.extend(config);
                Value::Object(object)
            })
            .collect();
        revisions.push(json!({
            "id": revision,
            "state": state_name(first.state),
            "weight": 1,
            "services": services,
        }));
    }

    fn to_value<T: serde::Serialize>(what: &str, value: &T) -> Result<Value, Rejection> {
        serde_json::to_value(value).map_err(|err| Rejection::invalid(what, err.to_string()))
    }
    let tenant = claim.mapped.as_deref().unwrap_or("default");
    let app: App = serde_json::from_value(json!({
        "id": id,
        "tenant": tenant,
        "declared_by": "docker",
        "tls": { "mode": tls_name(definition.tls) },
        "routers": to_value("routers", &definition.routers)?,
        "middlewares": to_value("middlewares", &definition.middlewares)?,
        "transports": to_value("transports", &definition.transports)?,
        "revisions": revisions,
    }))
    .map_err(|err| Rejection::invalid("podgate", err.to_string()))?;
    rejected.sort_by_key(|(index, _)| *index);
    Ok(Assembled {
        app,
        claim,
        rejected,
    })
}

/// Why a revision cannot stand next to the primary one, if it cannot.
fn lacks(
    services: &[Declared],
    needed: &BTreeSet<&str>,
    transports: &BTreeSet<&str>,
) -> Option<String> {
    for name in needed {
        if !services.iter().any(|service| &*service.name == *name) {
            return Some(format!(
                "its revision defines no service {name:?}, which a router of the app names"
            ));
        }
    }
    for service in services {
        if let Some(Value::String(transport)) = service.config.get("transport")
            && !transports.contains(transport.as_str())
        {
            return Some(format!(
                "service {:?} names transport {transport:?}, which the app does not define",
                service.name
            ));
        }
    }
    None
}

fn state_name(state: RevisionState) -> &'static str {
    match state {
        RevisionState::Serving => "serving",
        RevisionState::Retiring => "retiring",
        RevisionState::Draining => "draining",
    }
}

fn tls_name(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::Acme => "acme",
        TlsMode::OnDemand => "on_demand",
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parsed(pairs: &[(&str, &str)]) -> Result<Labels, Rejection> {
        parse(pairs.iter().copied())
    }

    #[test]
    fn non_podgate_keys_are_not_ours() {
        let labels = parsed(&[
            ("podgate.host", "a.test"),
            ("com.docker.compose.service", "web"),
        ])
        .expect("labels");
        assert_eq!(labels.definition.routers.len(), 1);
    }

    #[test]
    fn address_shapes() {
        for value in [
            "10.0.0.1",
            "10.0.0.1:80",
            "http://x",
            "[::1]:80",
            "db:5432",
            "unix:/x",
        ] {
            assert!(looks_like_address(value), "{value}");
        }
        for value in ["web", "a.test", "web-1", "v1.2"] {
            assert!(!looks_like_address(value), "{value}");
        }
    }

    #[test]
    fn destination_keys() {
        for key in [
            "servers", "url", "jwks_url", "Address", "issuer", "upstream",
        ] {
            assert!(names_a_destination(key), "{key}");
        }
        for key in ["hostname", "server_name", "path", "port", "algorithm"] {
            assert!(!names_a_destination(key), "{key}");
        }
    }

    #[test]
    fn every_rejection_has_a_code() {
        assert_eq!(
            parsed(&[("podgate.bogus", "1")])
                .expect_err("unknown")
                .code(),
            "unknown_label"
        );
        assert_eq!(
            parsed(&[("podgate.host", "10.0.0.5")])
                .expect_err("address")
                .code(),
            "address_label"
        );
        assert_eq!(
            parsed(&[("podgate.enable", "true")])
                .expect_err("no router")
                .code(),
            "no_router"
        );
    }
}
