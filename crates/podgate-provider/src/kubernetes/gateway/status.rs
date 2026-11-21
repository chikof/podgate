//! What the status of Gateway API objects says.
//!
//! [`plan`] is a pure function from what the source read ([`Cache`]), what the translation made
//! of it ([`Translation`]) and what podgate said of the pushed snapshot ([`Verdicts`]) to the
//! status patches that are still to be written. It writes nothing: [`super::writer`] does, and
//! only on the leader replica.
//!
//! | Object | Conditions |
//! |---|---|
//! | `GatewayClass` | `Accepted` |
//! | `Gateway` | `Accepted`, `Programmed` |
//! | listener | `Accepted`, `Conflicted`, `ResolvedRefs`, `Programmed`, and `attachedRoutes`, `supportedKinds` |
//! | route parent | `Accepted`, `ResolvedRefs`, with the reasons the translation found |
//!
//! `Programmed` is true only once podgate accepted the snapshot that holds what the object
//! orders. It is false, with the daemon's own reason, when podgate refused the snapshot or
//! quarantined a certificate of the listener; it stays as it was (`Unknown`, `Pending` for a new
//! object) while the push is still to happen, so a restart of the provider does not flap every
//! Gateway. A route podgate quarantined has `Accepted` false (`UnsupportedValue`).
//!
//! Every condition carries `observedGeneration`. A condition keeps its `lastTransitionTime`
//! until its `status` changes. Route status entries are written only for `parentRefs` that name
//! a Gateway of our class and only with our `controllerName`: another controller's entries are
//! copied through untouched, and our entries of a `parentRef` that is gone (or whose Gateway is
//! not ours any more) are removed.
//!
//! A patch is a JSON merge patch of `status`, carrying the object's `metadata.resourceVersion`
//! as a precondition: an array in a merge patch replaces the whole array, so the patch must be
//! computed from the version it replaces, and the server refuses it (`409`) when another
//! writer got in between. The watch then delivers the newer version and the plan is made again.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::listener::{GatewayReport, ListenerReport};
use super::types::{CONTROLLER, GROUP};
use super::{Cache, ClassReport, Kind, RouteReport, Translation, is_unresolved_reference};
use crate::kubernetes::client::{ObjectMeta, Store};

/// What the daemon did with the snapshot that holds this source's objects, as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Whole {
    /// Podgate accepted a snapshot with the source's current objects (or quarantined what it
    /// would not take).
    Pushed,
    /// Podgate refused the snapshot, or the push failed, with this reason.
    Refused(String),
    /// The push is still to happen.
    Waiting,
}

/// What the daemon said about the source's objects.
pub struct Verdicts<'a> {
    /// Why podgate left out the object whose `Origin::object` is given (a quarantined or
    /// dropped one), `None` for any other.
    pub rejected: &'a dyn Fn(&str) -> Option<String>,
    /// The snapshot as a whole.
    pub whole: Whole,
}

/// The object a status patch is for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    /// A `GatewayClass`, by name.
    Class(String),
    /// A `Gateway`, by `namespace/name`.
    Gateway(String),
    /// An `HTTPRoute`, by `namespace/name`.
    Http(String),
    /// A `GRPCRoute`, by `namespace/name`.
    Grpc(String),
}

impl Target {
    /// `namespace/name`, or the name of a cluster-scoped object.
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Class(key) | Self::Gateway(key) | Self::Http(key) | Self::Grpc(key) => key,
        }
    }

    /// The kind, for messages.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Class(_) => "GatewayClass",
            Self::Gateway(_) => "Gateway",
            Self::Http(_) => "HTTPRoute",
            Self::Grpc(_) => "GRPCRoute",
        }
    }

    /// The namespace and the name.
    #[must_use]
    pub fn parts(&self) -> (Option<&str>, &str) {
        match self.key().split_once('/') {
            Some((namespace, name)) => (Some(namespace), name),
            None => (None, self.key()),
        }
    }
}

/// One status patch to write.
#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// The object.
    pub target: Target,
    /// The merge patch: `{"metadata": {"resourceVersion": ...}, "status": {...}}`.
    pub body: Value,
}

/// One condition as the plan wants it.
struct Cond {
    kind: &'static str,
    status: &'static str,
    reason: &'static str,
    message: String,
    /// Leave the existing condition of this type alone when there is one (`Programmed` while
    /// the push is still to happen).
    keep: bool,
}

fn cond(kind: &'static str, ok: bool, reason: &'static str, message: impl Into<String>) -> Cond {
    Cond {
        kind,
        status: if ok { "True" } else { "False" },
        reason,
        message: message.into(),
        keep: false,
    }
}

/// Merges `desired` into `existing`: each desired condition keeps the `lastTransitionTime` of
/// the existing one of its type while its `status` is the same. With `keep_others`, existing
/// conditions of types not desired stay, after the desired ones.
fn merge_conditions(
    existing: &[Value],
    desired: Vec<Cond>,
    generation: Option<i64>,
    now: &str,
    keep_others: bool,
) -> Vec<Value> {
    let find = |kind: &str| existing.iter().find(|c| c["type"].as_str() == Some(kind));
    let mut out = Vec::new();
    let mut types = BTreeSet::new();
    for want in desired {
        types.insert(want.kind);
        let before = find(want.kind);
        if want.keep
            && let Some(before) = before
        {
            out.push(before.clone());
            continue;
        }
        let time = before
            .filter(|before| before["status"].as_str() == Some(want.status))
            .and_then(|before| before["lastTransitionTime"].as_str())
            .unwrap_or(now);
        let mut value = json!({
            "type": want.kind,
            "status": want.status,
            "reason": want.reason,
            "message": want.message,
            "lastTransitionTime": time,
        });
        if let Some(generation) = generation {
            value["observedGeneration"] = json!(generation);
        }
        out.push(value);
    }
    if keep_others {
        out.extend(
            existing
                .iter()
                .filter(|c| c["type"].as_str().is_none_or(|kind| !types.contains(kind)))
                .cloned(),
        );
    }
    out
}

fn array<'a>(value: Option<&'a Value>, field: &str) -> &'a [Value] {
    value
        .and_then(|value| value.get(field))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// A condition that waits for the push: `Unknown` and `Pending` unless there is one already.
fn pending(kind: &'static str) -> Cond {
    Cond {
        kind,
        status: "Unknown",
        reason: "Pending",
        message: "waiting for podgate to accept the snapshot".to_owned(),
        keep: true,
    }
}

/// Whether a listener or Gateway is programmed in podgate.
enum Programmed {
    Yes,
    No(String),
    Waiting,
}

impl Programmed {
    fn condition(self) -> Cond {
        match self {
            Self::Yes => cond("Programmed", true, "Programmed", "programmed in podgate"),
            Self::No(why) => cond("Programmed", false, "Invalid", why),
            Self::Waiting => pending("Programmed"),
        }
    }
}

fn whole(verdicts: &Verdicts<'_>) -> Programmed {
    match &verdicts.whole {
        Whole::Pushed => Programmed::Yes,
        Whole::Refused(why) => Programmed::No(why.clone()),
        Whole::Waiting => Programmed::Waiting,
    }
}

fn listener_programmed(listener: &ListenerReport, verdicts: &Verdicts<'_>) -> Programmed {
    let unused = |why: String| Programmed::No(format!("the listener is not used: {why}"));
    if let Err(rejection) = &listener.accepted {
        return unused(rejection.message.clone());
    }
    if let Some(conflict) = &listener.conflict {
        return unused(format!("{}: {}", conflict.reason, conflict.message));
    }
    if let Err(rejection) = &listener.resolved_refs {
        return unused(rejection.message.clone());
    }
    for certificate in &listener.certificates {
        if let Some(why) = (verdicts.rejected)(certificate) {
            return Programmed::No(format!("podgate rejected the certificate: {why}"));
        }
    }
    whole(verdicts)
}

fn listener_status(
    report: &ListenerReport,
    generation: Option<i64>,
    existing: Option<&Value>,
    verdicts: &Verdicts<'_>,
    now: &str,
) -> Value {
    let accepted = match &report.accepted {
        Ok(()) => cond("Accepted", true, "Accepted", "the listener is accepted"),
        Err(why) => cond("Accepted", false, why.reason, why.message.clone()),
    };
    let conflicted = match &report.conflict {
        Some(why) => cond("Conflicted", true, why.reason, why.message.clone()),
        None => cond(
            "Conflicted",
            false,
            "NoConflicts",
            "no other listener of the Gateway conflicts with this one",
        ),
    };
    let resolved = match &report.resolved_refs {
        Ok(()) => cond(
            "ResolvedRefs",
            true,
            "ResolvedRefs",
            "the references of the listener are resolved",
        ),
        Err(why) => cond("ResolvedRefs", false, why.reason, why.message.clone()),
    };
    let programmed = listener_programmed(report, verdicts).condition();
    let conditions = merge_conditions(
        array(existing, "conditions"),
        vec![accepted, conflicted, resolved, programmed],
        generation,
        now,
        false,
    );
    json!({
        "name": report.name,
        "supportedKinds": report
            .supported_kinds
            .iter()
            .map(|kind| json!({ "group": GROUP, "kind": kind }))
            .collect::<Vec<_>>(),
        "attachedRoutes": report.attached_routes,
        "conditions": conditions,
    })
}

/// The `status` of a Gateway: its conditions and its listeners'.
fn gateway_status(
    report: &GatewayReport,
    existing: Option<&Value>,
    verdicts: &Verdicts<'_>,
    now: &str,
) -> Value {
    let generation = report.generation;
    let total = report.listeners.len();
    let usable = report.listeners.iter().filter(|l| l.usable()).count();
    let accepted = if usable == total {
        cond("Accepted", true, "Accepted", "the Gateway is accepted")
    } else {
        let invalid: Vec<&str> = report
            .listeners
            .iter()
            .filter(|l| !l.usable())
            .map(|l| l.name.as_str())
            .collect();
        cond(
            "Accepted",
            usable > 0,
            "ListenersNotValid",
            format!("the listeners {} are not valid", invalid.join(", ")),
        )
    };
    let programs: Vec<Programmed> = report
        .listeners
        .iter()
        .map(|listener| listener_programmed(listener, verdicts))
        .collect();
    let programmed = if programs.is_empty() {
        whole(verdicts)
    } else if programs.iter().any(|p| matches!(p, Programmed::Yes)) {
        Programmed::Yes
    } else if let Some(Programmed::No(why)) = programs
        .iter()
        .find(|p| matches!(p, Programmed::No(_)))
        .filter(|_| programs.iter().all(|p| matches!(p, Programmed::No(_))))
    {
        Programmed::No(why.clone())
    } else {
        Programmed::Waiting
    };
    let known: BTreeMap<&str, &Value> = array(existing, "listeners")
        .iter()
        .filter_map(|listener| Some((listener["name"].as_str()?, listener)))
        .collect();
    let listeners: Vec<Value> = report
        .listeners
        .iter()
        .map(|listener| {
            listener_status(
                listener,
                generation,
                known.get(listener.name.as_str()).copied(),
                verdicts,
                now,
            )
        })
        .collect();
    json!({
        "conditions": merge_conditions(
            array(existing, "conditions"),
            vec![accepted, programmed.condition()],
            generation,
            now,
            true,
        ),
        "listeners": listeners,
    })
}

/// The identity of a `parentRef`, with the API's defaults filled in.
fn parent_key(parent_ref: &Value) -> String {
    let text = |field: &str, default: &'static str| {
        parent_ref[field].as_str().unwrap_or(default).to_owned()
    };
    format!(
        "{}|{}|{}|{}|{}|{}",
        text("group", GROUP),
        text("kind", "Gateway"),
        text("namespace", ""),
        text("name", ""),
        text("sectionName", ""),
        parent_ref["port"].as_u64().unwrap_or(0)
    )
}

/// The parents of a route's status: another controller's entries as they are, ours as the
/// report says (an entry of a `parentRef` the route no longer names is dropped).
fn route_parents(
    route: Option<&RouteReport>,
    daemon: Option<&str>,
    existing: &[Value],
    now: &str,
) -> Vec<Value> {
    let ours = |entry: &Value| entry["controllerName"].as_str() == Some(CONTROLLER);
    let before: BTreeMap<String, &Value> = existing
        .iter()
        .filter(|entry| ours(entry))
        .map(|entry| (parent_key(&entry["parentRef"]), entry))
        .collect();
    let mut wanted: Vec<(String, Value)> = Vec::new();
    let reports = route
        .into_iter()
        .flat_map(|route| route.parents.iter().map(move |parent| (route, parent)));
    for (route, parent) in reports {
        let (namespace, name) = parent
            .gateway
            .split_once('/')
            .unwrap_or(("", parent.gateway.as_str()));
        let mut parent_ref = json!({
            "group": GROUP,
            "kind": "Gateway",
            "namespace": namespace,
            "name": name,
        });
        if let Some(section) = &parent.section {
            parent_ref["sectionName"] = json!(section);
        }
        if let Some(port) = parent.port {
            parent_ref["port"] = json!(port);
        }
        let key = parent_key(&parent_ref);
        if wanted.iter().any(|(known, _)| *known == key) {
            continue;
        }
        let unresolved = route
            .rejected
            .as_ref()
            .filter(|rejection| is_unresolved_reference(rejection.reason));
        let accepted = if !parent.accepted {
            cond("Accepted", false, parent.reason, parent.message.clone())
        } else if let Some(rejection) = route
            .rejected
            .as_ref()
            .filter(|rejection| !is_unresolved_reference(rejection.reason))
        {
            cond(
                "Accepted",
                false,
                rejection.reason,
                rejection.message.clone(),
            )
        } else if let Some(why) = daemon {
            cond(
                "Accepted",
                false,
                "UnsupportedValue",
                format!("podgate rejected this route: {why}"),
            )
        } else {
            cond(
                "Accepted",
                true,
                "Accepted",
                "the route is attached to the Gateway",
            )
        };
        let resolved = match unresolved {
            Some(rejection) if parent.accepted => cond(
                "ResolvedRefs",
                false,
                rejection.reason,
                rejection.message.clone(),
            ),
            _ => cond(
                "ResolvedRefs",
                true,
                "ResolvedRefs",
                "all references of the route are resolved",
            ),
        };
        let conditions = merge_conditions(
            array(before.get(&key).copied(), "conditions"),
            vec![accepted, resolved],
            route.generation,
            now,
            false,
        );
        wanted.push((
            key,
            json!({
                "parentRef": parent_ref,
                "controllerName": CONTROLLER,
                "conditions": conditions,
            }),
        ));
    }
    let mut out = Vec::new();
    let mut placed = BTreeSet::new();
    for entry in existing {
        if !ours(entry) {
            out.push(entry.clone());
            continue;
        }
        let key = parent_key(&entry["parentRef"]);
        if let Some((_, desired)) = wanted.iter().find(|(known, _)| *known == key)
            && placed.insert(key)
        {
            out.push(desired.clone());
        }
    }
    out.extend(
        wanted
            .into_iter()
            .filter(|(key, _)| !placed.contains(key))
            .map(|(_, entry)| entry),
    );
    out
}

fn patch(meta: &ObjectMeta, status: Value) -> Value {
    let mut body = json!({ "status": status });
    if let Some(version) = &meta.resource_version {
        body["metadata"] = json!({ "resourceVersion": version });
    }
    body
}

/// Whether every field `wanted` writes is already what `existing` holds.
fn current(existing: Option<&Value>, wanted: &Value) -> bool {
    wanted.as_object().is_some_and(|fields| {
        fields
            .iter()
            .all(|(field, value)| existing.and_then(|e| e.get(field)) == Some(value))
    })
}

/// The status patches that are still to be written.
///
/// `now` is the time a changed condition gets as `lastTransitionTime`, RFC 3339.
#[must_use]
pub fn plan(
    cache: &Cache,
    translation: &Translation,
    verdicts: &Verdicts<'_>,
    now: &str,
) -> Vec<Write> {
    let mut writes = Vec::new();
    if let Some(ClassReport { name, generation }) = &translation.class
        && let Some(class) = cache.classes.get("", name)
    {
        let existing = class.status.as_ref();
        let conditions = merge_conditions(
            array(existing, "conditions"),
            vec![cond(
                "Accepted",
                true,
                "Accepted",
                "podgate serves this class",
            )],
            *generation,
            now,
            true,
        );
        let status = json!({ "conditions": conditions });
        if !current(existing, &status) {
            writes.push(Write {
                target: Target::Class(name.clone()),
                body: patch(&class.metadata, status),
            });
        }
    }
    for report in &translation.gateways {
        let Some((namespace, name)) = report.key.split_once('/') else {
            continue;
        };
        let Some(gateway) = cache
            .gateways
            .iter()
            .find_map(|store| store.get(namespace, name))
        else {
            continue;
        };
        let status = gateway_status(report, gateway.status.as_ref(), verdicts, now);
        if !current(gateway.status.as_ref(), &status) {
            writes.push(Write {
                target: Target::Gateway(report.key.clone()),
                body: patch(&gateway.metadata, status),
            });
        }
    }
    let route_status = |kind: Kind, meta: &ObjectMeta, status: Option<&Value>| {
        let key = meta.key();
        let report = translation
            .routes
            .iter()
            .find(|report| report.kind == kind && report.key == key);
        let daemon = report
            .filter(|report| report.rejected.is_none())
            .and_then(|_| (verdicts.rejected)(&format!("{kind}/{key}")));
        let existing = array(status, "parents");
        let parents = route_parents(report, daemon.as_deref(), existing, now);
        (parents != existing).then(|| json!({ "parents": parents }))
    };
    for route in cache.http.iter().flat_map(Store::values) {
        if let Some(status) = route_status(Kind::Http, &route.metadata, route.status.as_ref()) {
            writes.push(Write {
                target: Target::Http(route.metadata.key()),
                body: patch(&route.metadata, status),
            });
        }
    }
    for route in cache.grpc.iter().flat_map(Store::values) {
        if let Some(status) = route_status(Kind::Grpc, &route.metadata, route.status.as_ref()) {
            writes.push(Write {
                target: Target::Grpc(route.metadata.key()),
                body: patch(&route.metadata, status),
            });
        }
    }
    writes
}
