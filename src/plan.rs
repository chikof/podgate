//! What a snapshot would change: the diff of the live table against a candidate compiled by the
//! same compiler (`POST /v1/snapshot/plan`), and which apps a swap touched (for auto-revert).
//!
//! Hosts are compared as declared patterns (`a.test`, `*.a.test`). A host is *added* when only
//! the candidate answers for it, *removed* when only the live table does, and *changed* when
//! both do but what answers differs: the app, its tenant, its TLS policy, domain fronting, or
//! any revision's id, upstreams, weight or state. `declared_by` is free text and never counts.
//!
//! A *posture change* is a host that exists on both sides and got less strict. The kinds are
//! [`PostureKind`]. A new host is not a relaxation of anything, and tightening is not listed.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::snapshot::TlsMode;
use crate::table::{CompiledApp, RoutingTable};

/// How a host's security got weaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureKind {
    /// The host required client certificates and no longer does.
    ClientCaRemoved,
    /// The CA that signs client certificates is a different one: whoever it trusts changed.
    ClientCaChanged,
    /// TLS requests whose `Host` differs from the SNI are now served.
    DomainFrontingEnabled,
    /// Certificates for the host are now issued at the first handshake instead of in advance.
    OnDemandTlsEnabled,
    /// The app runs fewer WASM filters than before: a check some filter made is gone.
    FiltersRemoved,
    /// The app had filters and they differ now (a module or a limit) without fewer running: what they check
    /// may have loosened, which a diff of compiled modules cannot tell. Adding filters to an app that had none is a tightening and is not listed.
    FiltersChanged,
}

/// One relaxation, for one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PostureChange {
    /// The host pattern.
    pub host: Box<str>,
    /// The app that answers for the host in the candidate.
    pub app: Box<str>,
    /// What got weaker.
    pub kind: PostureKind,
}

/// The difference between the live table and a candidate. Every list is sorted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Version of the live table.
    pub from_version: u64,
    /// Version of the candidate.
    pub to_version: u64,
    /// Hosts only the candidate answers for.
    pub added: Vec<Box<str>>,
    /// Hosts only the live table answers for.
    pub removed: Vec<Box<str>>,
    /// Hosts both answer for, served differently.
    pub changed: Vec<Box<str>>,
    /// Hosts whose security got weaker.
    pub posture_changes: Vec<PostureChange>,
}

fn by_host(table: &RoutingTable) -> BTreeMap<&str, &CompiledApp> {
    (0..)
        .map_while(|index| table.app(index))
        .flat_map(|app| app.hosts().iter().map(move |host| (&**host, app)))
        .collect()
}

/// Whether two apps serve the same way: everything but the hosts they declare and `declared_by`.
fn same_serving(live: &CompiledApp, candidate: &CompiledApp) -> bool {
    live.id() == candidate.id()
        && live.tenant() == candidate.tenant()
        && live.tls() == candidate.tls()
        && live.allow_domain_fronting() == candidate.allow_domain_fronting()
        && live.filters_digest() == candidate.filters_digest()
        && live.canary_policy() == candidate.canary_policy()
        && live.revisions().len() == candidate.revisions().len()
        && live
            .revisions()
            .iter()
            .zip(candidate.revisions())
            .all(|(old, new)| {
                old.id() == new.id()
                    && old.upstreams() == new.upstreams()
                    && old.weight() == new.weight()
                    && old.state() == new.state()
            })
}

fn relaxations(live: &CompiledApp, candidate: &CompiledApp) -> Vec<PostureKind> {
    let mut kinds = Vec::new();
    match (&live.tls().client_ca_pem, &candidate.tls().client_ca_pem) {
        (Some(_), None) => kinds.push(PostureKind::ClientCaRemoved),
        (Some(old), Some(new)) if old != new => kinds.push(PostureKind::ClientCaChanged),
        _ => {}
    }
    if candidate.allow_domain_fronting() && !live.allow_domain_fronting() {
        kinds.push(PostureKind::DomainFrontingEnabled);
    }
    if candidate.tls().mode == TlsMode::OnDemand && live.tls().mode != TlsMode::OnDemand {
        kinds.push(PostureKind::OnDemandTlsEnabled);
    }
    if candidate.filters().len() < live.filters().len() {
        kinds.push(PostureKind::FiltersRemoved);
    } else if !live.filters().is_empty() && live.filters_digest() != candidate.filters_digest() {
        kinds.push(PostureKind::FiltersChanged);
    }
    kinds
}

/// Diffs `candidate` against `live`.
#[must_use]
pub fn diff(live: &RoutingTable, candidate: &RoutingTable) -> Plan {
    let old = by_host(live);
    let new = by_host(candidate);
    let mut plan = Plan {
        from_version: live.version(),
        to_version: candidate.version(),
        added: Vec::new(),
        removed: old
            .keys()
            .filter(|host| !new.contains_key(*host))
            .map(|host| (*host).into())
            .collect(),
        changed: Vec::new(),
        posture_changes: Vec::new(),
    };
    for (host, app) in &new {
        let Some(previous) = old.get(host) else {
            plan.added.push((*host).into());
            continue;
        };
        if !same_serving(previous, app) {
            plan.changed.push((*host).into());
        }
        plan.posture_changes
            .extend(
                relaxations(previous, app)
                    .into_iter()
                    .map(|kind| PostureChange {
                        host: (*host).into(),
                        app: app.id().into(),
                        kind,
                    }),
            );
    }
    plan
}

/// The ids of the apps `current` serves differently from `previous`: new apps, apps whose
/// serving config changed (see the module docs) and apps that gained or lost a host.
#[must_use]
pub fn changed_apps(previous: &RoutingTable, current: &RoutingTable) -> Vec<Box<str>> {
    let old: HashMap<&str, &CompiledApp> = (0..)
        .map_while(|index| previous.app(index))
        .map(|app| (app.id(), app))
        .collect();
    (0..)
        .map_while(|index| current.app(index))
        .filter(|app| {
            old.get(app.id())
                .is_none_or(|before| !same_serving(before, app) || before.hosts() != app.hosts())
        })
        .map(|app| app.id().into())
        .collect()
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::snapshot::Snapshot;

    fn app(id: &str, hosts: &[&str], port: u16, extra: &Value) -> Value {
        let mut app = json!({
            "id": id, "tenant": "t", "declared_by": format!("test/{id}"), "hosts": hosts,
            "tls": {"mode": "acme"},
            "revisions": [{"id": "r1", "upstreams": [format!("127.0.0.1:{port}")], "weight": 100, "state": "serving"}],
        });
        if let (Some(base), Some(extra)) = (app.as_object_mut(), extra.as_object()) {
            base.extend(extra.clone());
        }
        app
    }

    fn table(version: u64, apps: &[Value]) -> RoutingTable {
        let snapshot: Snapshot = serde_json::from_value(json!({
            "version": version,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": apps,
        }))
        .expect("valid snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    #[test]
    fn diff_lists_added_removed_and_changed_hosts() {
        let none = json!({});
        let live = table(
            1,
            &[
                app("keep", &["keep.test"], 1, &none),
                app("move", &["move.test", "*.move.test"], 2, &none),
                app("gone", &["gone.test"], 3, &none),
            ],
        );
        let candidate = table(
            2,
            &[
                app("keep", &["keep.test"], 1, &none),
                app("move", &["move.test", "*.move.test"], 22, &none),
                app("new", &["new.test"], 4, &none),
            ],
        );
        let plan = diff(&live, &candidate);
        assert_eq!(plan.from_version, 1);
        assert_eq!(plan.to_version, 2);
        assert_eq!(plan.added, ["new.test".into()] as [Box<str>; 1]);
        assert_eq!(plan.removed, ["gone.test".into()] as [Box<str>; 1]);
        assert_eq!(
            plan.changed,
            ["*.move.test".into(), "move.test".into()] as [Box<str>; 2]
        );
        assert!(plan.posture_changes.is_empty());
        assert_eq!(
            changed_apps(&live, &candidate),
            ["move".into(), "new".into()] as [Box<str>; 2]
        );
    }

    #[test]
    fn declared_by_alone_changes_nothing() {
        let live = table(1, &[app("a", &["a.test"], 1, &json!({}))]);
        let candidate = table(
            2,
            &[app(
                "a",
                &["a.test"],
                1,
                &json!({"declared_by": "elsewhere"}),
            )],
        );
        let plan = diff(&live, &candidate);
        assert!(plan.changed.is_empty());
        assert!(changed_apps(&live, &candidate).is_empty());
    }

    #[test]
    fn posture_lists_only_relaxations_of_existing_hosts() {
        let ca = |pem: &str| json!({"tls": {"mode": "acme", "client_ca_pem": pem}});
        let (ca1, ca2) = (
            crate::clientauth::test_ca_pem("ca1"),
            crate::clientauth::test_ca_pem("ca2"),
        );
        let live = table(
            1,
            &[
                app("drop", &["drop.test"], 1, &ca(&ca1)),
                app("swap", &["swap.test"], 2, &ca(&ca1)),
                app("front", &["front.test"], 3, &json!({})),
                app("lazy", &["lazy.test"], 4, &json!({})),
                app(
                    "tight",
                    &["tight.test"],
                    5,
                    &json!({"allow_domain_fronting": true}),
                ),
            ],
        );
        let candidate = table(
            2,
            &[
                app("drop", &["drop.test"], 1, &json!({})),
                app("swap", &["swap.test"], 2, &ca(&ca2)),
                app(
                    "front",
                    &["front.test"],
                    3,
                    &json!({"allow_domain_fronting": true}),
                ),
                app(
                    "lazy",
                    &["lazy.test"],
                    4,
                    &json!({"tls": {"mode": "on_demand"}}),
                ),
                app("tight", &["tight.test"], 5, &ca(&ca1)),
                app(
                    "fresh",
                    &["fresh.test"],
                    6,
                    &json!({"allow_domain_fronting": true}),
                ),
            ],
        );
        let plan = diff(&live, &candidate);
        let listed: Vec<(String, PostureKind)> = plan
            .posture_changes
            .iter()
            .map(|change| (change.host.to_string(), change.kind))
            .collect();
        assert_eq!(
            listed,
            [
                ("drop.test".to_owned(), PostureKind::ClientCaRemoved),
                ("front.test".to_owned(), PostureKind::DomainFrontingEnabled),
                ("lazy.test".to_owned(), PostureKind::OnDemandTlsEnabled),
                ("swap.test".to_owned(), PostureKind::ClientCaChanged),
            ]
        );
    }
}
