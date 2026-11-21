//! What a snapshot would change: the diff of the live table against a candidate compiled by the
//! same compiler (`POST /v1/snapshot/plan`), and which apps a swap touched (for auto-revert).
//!
//! Hosts are compared as declared patterns (`a.test`, `*.a.test`), the literal hosts the routers
//! of an app claim. A host is *added* when only the candidate answers for it, *removed* when only
//! the live table does, and *changed* when both do but what answers differs: the app's
//! fingerprint (everything it declares except `declared_by`: routers, middlewares, services,
//! revisions, TLS, canary) is not the same. So a change to any router marks every host of its
//! app as changed.
//!
//! A *posture change* is a host that exists on both sides and got less strict. The built-in
//! kinds are in [`kind`]; every security middleware reports its own through
//! [`crate::middleware::Kind::posture`], and the plan only asks. A new host is not a relaxation
//! of anything, and tightening is not listed.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::clientauth;
use crate::table::{CompiledApp, RoutingTable};
use crate::tls::Options;
use podgate_model::TlsMode;

/// The `kind` strings of the built-in posture changes. Middleware kinds add their own, such as
/// `filters_removed` and `filters_changed` from the `wasm` middleware.
pub mod kind {
    /// The host required client certificates and no longer does.
    pub const CLIENT_CA_REMOVED: &str = "client_ca_removed";
    /// The CA that signs client certificates is a different one: whoever it trusts changed.
    pub const CLIENT_CA_CHANGED: &str = "client_ca_changed";
    /// TLS requests whose `Host` differs from the SNI are now served.
    pub const DOMAIN_FRONTING_ENABLED: &str = "domain_fronting_enabled";
    /// Certificates for the host are now issued at the first handshake instead of in advance.
    pub const ON_DEMAND_TLS_ENABLED: &str = "on_demand_tls_enabled";
    /// An `https://` upstream is now reached without verifying its certificate
    /// (`insecure_skip_verify` of a `servers_transport`).
    pub const UPSTREAM_TLS_VERIFICATION_DISABLED: &str = "upstream_tls_verification_disabled";
    /// The host's clients may now negotiate an older TLS version.
    pub const TLS_MIN_VERSION_LOWERED: &str = "tls_min_version_lowered";
    /// The host's clients may now negotiate a cipher suite they could not before.
    pub const TLS_CIPHER_SUITES_WIDENED: &str = "tls_cipher_suites_widened";
    /// A name of the host without a certificate is now served the default certificate instead of
    /// failing the handshake.
    pub const SNI_STRICT_DISABLED: &str = "sni_strict_disabled";
    /// The host still asks for client certificates but judges them less.
    pub const CLIENT_AUTH_RELAXED: &str = "client_auth_relaxed";
}

/// What stands in the `host` of a [`PostureChange`] that is about an entry point, followed by its
/// name (`entry_point:web`); its `app` is empty.
pub const ENTRY_POINT_PREFIX: &str = "entry_point:";

/// What stands in the `host` of a [`PostureChange`] that is about the TCP routers of an app,
/// followed by the app's id (`tcp:db`): a TCP router has no host. Its `app` is that app.
pub const TCP_PREFIX: &str = "tcp:";

/// One relaxation, for one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PostureChange {
    /// The host pattern.
    pub host: Box<str>,
    /// The app that answers for the host in the candidate.
    pub app: Box<str>,
    /// What got weaker: one of [`kind`], or a middleware's own.
    pub kind: &'static str,
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
    table
        .apps()
        .iter()
        .flat_map(|app| app.hosts().iter().map(move |host| (&**host, app)))
        .collect()
}

/// Whether two apps serve the same way: everything but `declared_by`.
fn same_serving(live: &CompiledApp, candidate: &CompiledApp) -> bool {
    live.fingerprint() == candidate.fingerprint()
}

/// The names of the middlewares some router of `app` actually runs.
fn used_stages(app: &CompiledApp) -> HashSet<usize> {
    app.routers()
        .iter()
        .flat_map(|router| router.chain().iter().copied())
        .collect()
}

fn relaxations(live: &CompiledApp, candidate: &CompiledApp) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    match (&live.tls().client_ca_pem, &candidate.tls().client_ca_pem) {
        (Some(_), None) => kinds.push(kind::CLIENT_CA_REMOVED),
        (Some(old), Some(new)) if old != new => kinds.push(kind::CLIENT_CA_CHANGED),
        _ => {}
    }
    if let Some(old) = live.client_auth().map(|auth| auth.mode())
        && !kinds.contains(&kind::CLIENT_CA_REMOVED)
        && clientauth::relaxes(old, candidate.client_auth().map(|auth| auth.mode()))
    {
        kinds.push(kind::CLIENT_AUTH_RELAXED);
    }
    kinds.extend(Options::relaxations(
        live.tls_options(),
        candidate.tls_options(),
    ));
    if candidate.allow_domain_fronting() && !live.allow_domain_fronting() {
        kinds.push(kind::DOMAIN_FRONTING_ENABLED);
    }
    if candidate.tls().mode == TlsMode::OnDemand && live.tls().mode != TlsMode::OnDemand {
        kinds.push(kind::ON_DEMAND_TLS_ENABLED);
    }
    let unverified = live.unverified_services();
    if candidate
        .unverified_services()
        .iter()
        .any(|name| !unverified.contains(name))
    {
        kinds.push(kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
    }
    kinds.extend(crate::service::mirroring::relaxations(live, candidate));
    let used_now = used_stages(candidate);
    for index in used_stages(live) {
        let Some(old) = live.stages().get(index) else {
            continue;
        };
        let new = candidate
            .stages()
            .iter()
            .enumerate()
            .find(|(at, stage)| stage.name == old.name && used_now.contains(at))
            .map(|(_, stage)| &stage.stage);
        for posture in old.stage.posture(new) {
            if !kinds.contains(&posture) {
                kinds.push(posture);
            }
        }
    }
    kinds
}

/// What got weaker in the TCP routers of an app: a TCP middleware removed or loosened,
/// or a TCP service that no longer verifies its servers' certificates. A TCP router has no host,
/// so these are listed under [`TCP_PREFIX`] and the app, not per host.
fn l4_relaxations(live: &CompiledApp, candidate: &CompiledApp) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let unverified = live.unverified_tcp_services();
    if candidate
        .unverified_tcp_services()
        .iter()
        .any(|name| !unverified.contains(name))
    {
        kinds.push(kind::UPSTREAM_TLS_VERIFICATION_DISABLED);
    }
    kinds.extend(crate::l4::middleware::relaxations(
        live.l4().tcp(),
        candidate.l4().tcp(),
    ));
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
    let live_apps: HashMap<&str, &CompiledApp> =
        live.apps().iter().map(|app| (app.id(), app)).collect();
    for app in candidate.apps() {
        if let Some(previous) = live_apps.get(app.id()) {
            plan.posture_changes
                .extend(
                    l4_relaxations(previous, app)
                        .into_iter()
                        .map(|kind| PostureChange {
                            host: format!("{TCP_PREFIX}{}", app.id()).into(),
                            app: app.id().into(),
                            kind,
                        }),
                );
        }
    }
    let mut entry_points: Vec<_> = candidate.forwarded_trusts().collect();
    entry_points.sort_unstable_by_key(|(name, _)| *name);
    for (name, trust) in entry_points {
        if let Some(kind) = trust.relaxation(live.forwarded_trust(name)) {
            plan.posture_changes.push(PostureChange {
                host: format!("{ENTRY_POINT_PREFIX}{name}").into(),
                app: "".into(),
                kind,
            });
        }
    }
    for (name, kind) in crate::entry::policy::relaxations(live, candidate) {
        plan.posture_changes.push(PostureChange {
            host: format!("{ENTRY_POINT_PREFIX}{name}").into(),
            app: "".into(),
            kind,
        });
    }
    plan
}

/// The ids of the apps `current` serves differently from `previous`: new apps and apps whose
/// declaration changed in any way but `declared_by` (see the module docs).
#[must_use]
pub fn changed_apps(previous: &RoutingTable, current: &RoutingTable) -> Vec<Box<str>> {
    let old: HashMap<&str, &CompiledApp> =
        previous.apps().iter().map(|app| (app.id(), app)).collect();
    current
        .apps()
        .iter()
        .filter(|app| {
            old.get(app.id())
                .is_none_or(|before| !same_serving(before, app))
        })
        .map(|app| app.id().into())
        .collect()
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use podgate_model::Snapshot;

    fn app(id: &str, hosts: &[&str], port: u16, extra: &Value) -> Value {
        let mut app = json!({
            "id": id, "tenant": "t", "declared_by": format!("test/{id}"),
            "tls": {"mode": "acme"},
            "routers": [{"name": "all", "match": {"host": hosts}, "service": "web"}],
            "revisions": [{"id": "r1", "weight": 100, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "servers": [{"url": format!("http://127.0.0.1:{port}")}]}]}],
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
        let listed: Vec<(String, &str)> = plan
            .posture_changes
            .iter()
            .map(|change| (change.host.to_string(), change.kind))
            .collect();
        assert_eq!(
            listed,
            [
                ("drop.test".to_owned(), kind::CLIENT_CA_REMOVED),
                ("front.test".to_owned(), kind::DOMAIN_FRONTING_ENABLED),
                ("lazy.test".to_owned(), kind::ON_DEMAND_TLS_ENABLED),
                ("swap.test".to_owned(), kind::CLIENT_CA_CHANGED),
            ]
        );
    }
}
