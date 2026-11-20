//! Security conflicts between the declarations of one snapshot.
//!
//! Declarations that disagree are never merged: the compiler collects every [`Conflict`] and
//! refuses the whole snapshot, so no declaration silently wins over another. Each conflict names
//! both apps and both `declared_by` sources, in the order documented on its variant.
//!
//! Rules, over every literal host pattern a router claims (an exact name, or a `*.` wildcard
//! that covers one extra label; see [`crate::router::CompiledRouter::patterns`]):
//!
//! - Two tenants claiming the same pattern: [`Conflict::Host`], whatever else their routers
//!   match. Priority therefore only ever orders the routers of one tenant for a host.
//! - Two routers of one tenant claiming the same pattern with the same priority and
//!   specificity, unless provably disjoint: [`Conflict::RouteAmbiguity`] within one app,
//!   [`Conflict::Host`] across apps. Routers of one tenant that differ (by path, say) may share
//!   a host. A router repeating its own host is not a conflict.
//! - A claim is *under* a wildcard when the claimed name (the host itself, or the base name of a
//!   wildcard) is one label below the wildcard's base: `x.a.test` and `*.x.a.test` are under
//!   `*.a.test`; `a.test` and `*.y.a.test` are not.
//! - A claim under another tenant's wildcard: [`Conflict::CrossTenantWildcard`].
//! - A claim under a wildcard of the same tenant, in another app, or a pattern two apps of one
//!   tenant share, with a different `tls.client_ca_pem` (compared as written, `None` against
//!   `Some` included): [`Conflict::TlsPolicy`]. TLS is decided per host at the handshake, before
//!   any path is known, and exact beats wildcard when routing, so without this rule an app could
//!   drop or swap the client-certificate requirement of its neighbour.
//! - Routers with no literal host (a `host_regexp`, or no host constraint) of two tenants on a
//!   common entry point: [`Conflict::CrossTenantCatchAll`], because no order between them would
//!   be fair; and two of one tenant that are ambiguous: [`Conflict::RouteAmbiguity`] without a
//!   host.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};
use thiserror::Error;

use crate::host::HostPattern;
use crate::router::{CompiledRouter, Tier};
use podgate_model::App;

fn describe_ambiguity(
    host: Option<&str>,
    apps: &[Box<str>; 2],
    routers: &[Box<str>; 2],
    declared_by: &[Box<str>; 2],
) -> String {
    let on = host.map_or_else(String::new, |host| format!(" for host {host}"));
    format!(
        "routers {} (app {}, {}) and {} (app {}, {}) can match the same request with the same priority{on}",
        routers[0], apps[0], declared_by[0], routers[1], apps[1], declared_by[1]
    )
}

/// One reason a snapshot is refused. [`Self::code`] is the stable identifier in the `422` body.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Conflict {
    /// Two apps claim the same exact host or the same wildcard, as different tenants or with
    /// routers that are ambiguous.
    #[error(
        "host {host} is claimed by app {} ({}) and app {} ({})",
        .apps[0], .declared_by[0], .apps[1], .declared_by[1]
    )]
    Host {
        /// The contested pattern, as `a.test` or `*.a.test`.
        host: Box<str>,
        /// The apps, first claimant first.
        apps: [Box<str>; 2],
        /// Their `declared_by` values, in the order of `apps`.
        declared_by: [Box<str>; 2],
    },
    /// Two routers of one tenant can match the same request and nothing orders them.
    #[error("{}", describe_ambiguity(.host.as_deref(), .apps, .routers, .declared_by))]
    RouteAmbiguity {
        /// The shared host pattern; `None` for routers with no literal host.
        host: Option<Box<str>>,
        /// The apps of the routers, in the order of `routers`.
        apps: [Box<str>; 2],
        /// The routers, first declared first.
        routers: [Box<str>; 2],
        /// Their `declared_by` values: the router's own, else its app's.
        declared_by: [Box<str>; 2],
    },
    /// A claim and the wildcard above it, both of one tenant, disagree on `client_ca_pem`.
    #[error(
        "host {host} of app {} ({}) and wildcard {wildcard} of app {} ({}) disagree on client_ca_pem",
        .apps[0], .declared_by[0], .apps[1], .declared_by[1]
    )]
    TlsPolicy {
        /// The claim under the wildcard.
        host: Box<str>,
        /// The wildcard above it (the same pattern again when two apps share one).
        wildcard: Box<str>,
        /// The app of `host` first, then the app of `wildcard`.
        apps: [Box<str>; 2],
        /// Their `declared_by` values, in the order of `apps`.
        declared_by: [Box<str>; 2],
    },
    /// A tenant claims a host under another tenant's wildcard.
    #[error(
        "host {host} of tenant {} (app {}, {}) lies under wildcard {wildcard} of tenant {} (app {}, {})",
        .tenants[0], .apps[0], .declared_by[0], .tenants[1], .apps[1], .declared_by[1]
    )]
    CrossTenantWildcard {
        /// The claim under the wildcard.
        host: Box<str>,
        /// The wildcard above it.
        wildcard: Box<str>,
        /// The tenant of `host` first, then the tenant of `wildcard`.
        tenants: [Box<str>; 2],
        /// The app of `host` first, then the app of `wildcard`.
        apps: [Box<str>; 2],
        /// Their `declared_by` values, in the order of `apps`.
        declared_by: [Box<str>; 2],
    },
    /// Routers of two tenants with no literal host share an entry point.
    #[error(
        "router {} (tenant {}, app {}, {}) and router {} (tenant {}, app {}, {}) both match hosts without a literal host on a shared entry point; only one tenant may",
        .routers[0], .tenants[0], .apps[0], .declared_by[0],
        .routers[1], .tenants[1], .apps[1], .declared_by[1]
    )]
    CrossTenantCatchAll {
        /// The tenants, in the order of `routers`.
        tenants: [Box<str>; 2],
        /// The apps, in the order of `routers`.
        apps: [Box<str>; 2],
        /// The routers.
        routers: [Box<str>; 2],
        /// Their `declared_by` values.
        declared_by: [Box<str>; 2],
    },
}

impl Conflict {
    /// The stable code: `host_conflict`, `route_ambiguity`, `tls_policy_conflict`,
    /// `cross_tenant_wildcard` or `cross_tenant_catch_all`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Host { .. } => "host_conflict",
            Self::RouteAmbiguity { .. } => "route_ambiguity",
            Self::TlsPolicy { .. } => "tls_policy_conflict",
            Self::CrossTenantWildcard { .. } => "cross_tenant_wildcard",
            Self::CrossTenantCatchAll { .. } => "cross_tenant_catch_all",
        }
    }

    /// The object in the `conflicts` list of a `422` body: `code`, `message` and the fields of
    /// the variant (`host`, `apps`, `declared_by`, plus `wildcard`, `tenants` and `routers`
    /// where present).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let (code, message) = (self.code(), self.to_string());
        match self {
            Self::Host {
                host,
                apps,
                declared_by,
            } => json!({
                "code": code, "message": message,
                "host": host, "apps": apps, "declared_by": declared_by,
            }),
            Self::RouteAmbiguity {
                host,
                apps,
                routers,
                declared_by,
            } => json!({
                "code": code, "message": message,
                "host": host, "apps": apps, "routers": routers, "declared_by": declared_by,
            }),
            Self::TlsPolicy {
                host,
                wildcard,
                apps,
                declared_by,
            } => json!({
                "code": code, "message": message,
                "host": host, "wildcard": wildcard, "apps": apps, "declared_by": declared_by,
            }),
            Self::CrossTenantWildcard {
                host,
                wildcard,
                tenants,
                apps,
                declared_by,
            } => json!({
                "code": code, "message": message,
                "host": host, "wildcard": wildcard, "tenants": tenants,
                "apps": apps, "declared_by": declared_by,
            }),
            Self::CrossTenantCatchAll {
                tenants,
                apps,
                routers,
                declared_by,
            } => json!({
                "code": code, "message": message,
                "tenants": tenants, "apps": apps, "routers": routers, "declared_by": declared_by,
            }),
        }
    }
}

/// How a pattern reads in a message: `a.test` or `*.a.test`.
fn show(pattern: &HostPattern) -> Box<str> {
    match pattern {
        HostPattern::Exact(name) => name.clone(),
        HostPattern::Wildcard(base) => format!("*.{base}").into(),
    }
}

/// The name a claim is about: the host itself, or the base of a wildcard.
fn anchor(pattern: &HostPattern) -> &str {
    match pattern {
        HostPattern::Exact(name) | HostPattern::Wildcard(name) => name,
    }
}

fn pair(first: &str, second: &str) -> [Box<str>; 2] {
    [first.into(), second.into()]
}

/// One literal host a router claims.
struct Claim<'a> {
    pattern: &'a HostPattern,
    app: usize,
    router: usize,
}

/// The apps and routers of a snapshot, for looking things up by position.
struct World<'a> {
    apps: &'a [App],
    routers: &'a [Vec<CompiledRouter>],
}

impl<'a> World<'a> {
    fn app(&self, index: usize) -> Option<&'a App> {
        self.apps.get(index)
    }

    fn router(&self, app: usize, router: usize) -> Option<&'a CompiledRouter> {
        self.routers.get(app)?.get(router)
    }

    fn router_name(&self, app: usize, router: usize) -> &'a str {
        self.router(app, router).map_or("", CompiledRouter::name)
    }

    fn router_source(&self, app: usize, router: usize) -> &'a str {
        self.router(app, router)
            .map_or("", CompiledRouter::declared_by)
    }

    fn same_tenant(&self, a: usize, b: usize) -> bool {
        matches!((self.app(a), self.app(b)), (Some(a), Some(b)) if a.tenant == b.tenant)
    }

    fn ambiguity(&self, host: Option<Box<str>>, a: (usize, usize), b: (usize, usize)) -> Conflict {
        Conflict::RouteAmbiguity {
            host,
            apps: pair(
                self.app(a.0).map_or("", |app| &app.id),
                self.app(b.0).map_or("", |app| &app.id),
            ),
            routers: pair(self.router_name(a.0, a.1), self.router_name(b.0, b.1)),
            declared_by: pair(self.router_source(a.0, a.1), self.router_source(b.0, b.1)),
        }
    }
}

/// Finds every conflict among the routers of `apps` (`routers[i]` are the compiled routers of
/// `apps[i]`). Returns them in claim order; empty means the snapshot is clean.
pub(crate) fn detect(apps: &[App], routers: &[Vec<CompiledRouter>]) -> Vec<Conflict> {
    let world = World { apps, routers };
    let mut found = Vec::new();

    let mut claims = Vec::new();
    for (app, list) in routers.iter().enumerate() {
        for (router, compiled) in list.iter().enumerate() {
            claims.extend(compiled.patterns().map(|pattern| Claim {
                pattern,
                app,
                router,
            }));
        }
    }

    // The same pattern claimed more than once.
    let mut order: Vec<Vec<&Claim<'_>>> = Vec::new();
    let mut by_pattern: HashMap<(bool, &str), usize> = HashMap::new();
    for claim in &claims {
        let key = (
            matches!(claim.pattern, HostPattern::Wildcard(_)),
            anchor(claim.pattern),
        );
        let slot = *by_pattern.entry(key).or_insert_with(|| {
            order.push(Vec::new());
            order.len() - 1
        });
        if let Some(members) = order.get_mut(slot)
            && !members
                .iter()
                .any(|member| (member.app, member.router) == (claim.app, claim.router))
        {
            members.push(claim);
        }
    }
    for members in &order {
        let Some(first) = members.first() else {
            continue;
        };
        let host = show(first.pattern);
        let mut other_tenants = HashSet::new();
        for member in members.iter().skip(1) {
            if !world.same_tenant(first.app, member.app) && other_tenants.insert(member.app) {
                found.push(Conflict::Host {
                    host: host.clone(),
                    apps: pair(
                        world.app(first.app).map_or("", |app| &app.id),
                        world.app(member.app).map_or("", |app| &app.id),
                    ),
                    declared_by: pair(
                        world.app(first.app).map_or("", |app| &app.declared_by),
                        world.app(member.app).map_or("", |app| &app.declared_by),
                    ),
                });
            }
        }
        let mut settled: HashSet<(usize, usize)> = HashSet::new();
        for (index, a) in members.iter().enumerate() {
            for b in members.iter().skip(index + 1) {
                if !world.same_tenant(a.app, b.app) {
                    continue;
                }
                let (Some(left), Some(right)) =
                    (world.router(a.app, a.router), world.router(b.app, b.router))
                else {
                    continue;
                };
                if left.same_order_as(right) && !left.disjoint(right) {
                    if a.app == b.app {
                        found.push(world.ambiguity(
                            Some(host.clone()),
                            (a.app, a.router),
                            (b.app, b.router),
                        ));
                    } else if settled.insert((a.app.min(b.app), a.app.max(b.app))) {
                        found.push(Conflict::Host {
                            host: host.clone(),
                            apps: pair(
                                world.app(a.app).map_or("", |app| &app.id),
                                world.app(b.app).map_or("", |app| &app.id),
                            ),
                            declared_by: pair(
                                world.app(a.app).map_or("", |app| &app.declared_by),
                                world.app(b.app).map_or("", |app| &app.declared_by),
                            ),
                        });
                    }
                } else if a.app != b.app
                    && settled.insert((a.app.min(b.app), a.app.max(b.app)))
                    && let (Some(one), Some(two)) = (world.app(a.app), world.app(b.app))
                    && one.tls.client_ca_pem != two.tls.client_ca_pem
                {
                    found.push(Conflict::TlsPolicy {
                        host: host.clone(),
                        wildcard: host.clone(),
                        apps: pair(&one.id, &two.id),
                        declared_by: pair(&one.declared_by, &two.declared_by),
                    });
                }
            }
        }
    }

    // A claim under a wildcard of another app.
    let mut unique: Vec<(&HostPattern, usize)> = Vec::with_capacity(claims.len());
    let mut seen: HashSet<(bool, &str, usize)> = HashSet::new();
    for claim in &claims {
        let key = (
            matches!(claim.pattern, HostPattern::Wildcard(_)),
            anchor(claim.pattern),
            claim.app,
        );
        if seen.insert(key) {
            unique.push((claim.pattern, claim.app));
        }
    }
    let mut wildcards: HashMap<&str, Vec<(usize, &HostPattern)>> = HashMap::new();
    for &(pattern, index) in &unique {
        if let HostPattern::Wildcard(base) = pattern {
            wildcards.entry(base).or_default().push((index, pattern));
        }
    }
    for &(pattern, index) in &unique {
        let Some((_label, parent)) = anchor(pattern).split_once('.') else {
            continue;
        };
        let Some(above) = wildcards.get(parent) else {
            continue;
        };
        let Some(app) = world.app(index) else {
            continue;
        };
        for &(wildcard_index, wildcard) in above {
            let Some(owner) = world
                .app(wildcard_index)
                .filter(|_| wildcard_index != index)
            else {
                continue;
            };
            let (host, wildcard) = (show(pattern), show(wildcard));
            let (apps, declared_by) = (
                pair(&app.id, &owner.id),
                pair(&app.declared_by, &owner.declared_by),
            );
            if app.tenant != owner.tenant {
                found.push(Conflict::CrossTenantWildcard {
                    host,
                    wildcard,
                    tenants: pair(&app.tenant, &owner.tenant),
                    apps,
                    declared_by,
                });
            } else if app.tls.client_ca_pem != owner.tls.client_ca_pem {
                found.push(Conflict::TlsPolicy {
                    host,
                    wildcard,
                    apps,
                    declared_by,
                });
            }
        }
    }

    found.extend(fallbacks(&world));
    found
}

/// The conflicts among routers with no literal host.
fn fallbacks(world: &World<'_>) -> Vec<Conflict> {
    let mut found = Vec::new();
    let mut all: Vec<(usize, usize, &CompiledRouter)> = Vec::new();
    for (app, list) in world.routers.iter().enumerate() {
        for (router, compiled) in list.iter().enumerate() {
            if compiled.is_fallback() {
                all.push((app, router, compiled));
            }
        }
    }
    let mut tenants_done: HashSet<(&str, &str)> = HashSet::new();
    for (index, &(app_a, router_a, a)) in all.iter().enumerate() {
        for &(app_b, router_b, b) in all.iter().skip(index + 1) {
            let (Some(one), Some(two)) = (world.app(app_a), world.app(app_b)) else {
                continue;
            };
            let shares_entry = match (a.entry_points(), b.entry_points()) {
                (Some(x), Some(y)) => x.iter().any(|name| y.contains(name)),
                _ => true,
            };
            if one.tenant != two.tenant {
                let tenants = if one.tenant <= two.tenant {
                    (&*one.tenant, &*two.tenant)
                } else {
                    (&*two.tenant, &*one.tenant)
                };
                if shares_entry && !a.is_unrestricted() && tenants_done.insert(tenants) {
                    found.push(Conflict::CrossTenantCatchAll {
                        tenants: pair(&one.tenant, &two.tenant),
                        apps: pair(&one.id, &two.id),
                        routers: pair(a.name(), b.name()),
                        declared_by: pair(a.declared_by(), b.declared_by()),
                    });
                }
            } else if a.tier() == b.tier() && a.same_order_as(b) && !a.disjoint(b) {
                found.push(world.ambiguity(None, (app_a, router_a), (app_b, router_b)));
            }
        }
    }
    found
}

/// The messages of `conflicts`, separated by `; `.
pub(crate) fn join(conflicts: &[Conflict]) -> String {
    conflicts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether `tier` is one that has no literal host.
#[must_use]
pub fn is_fallback_tier(tier: Tier) -> bool {
    tier != Tier::Literal
}

#[cfg(test)]
#[allow(clippy::type_complexity, reason = "test fixtures are tuples")]
mod test {
    use super::*;
    use crate::table::{CompileError, RoutingTable};

    /// A snapshot of two tenants whose apps each have one router built from `routers`
    /// (`(app, tenant, ca, match, priority)`), all answering from one service.
    fn conflicts(apps: &[(&str, &str, Option<&str>, Value, Option<i32>)]) -> Vec<Conflict> {
        let tenant = |id: &str| json!({ "id": id, "weight": 1, "budget": { "max_inflight": 1, "max_buffer_bytes": 1 } });
        let apps: Vec<Value> = apps
            .iter()
            .map(|(id, tenant, ca, matcher, priority)| {
                let mut tls = json!({ "mode": "acme" });
                if let Some(ca) = ca {
                    tls["client_ca_pem"] = json!(ca);
                }
                json!({
                    "id": id, "tenant": tenant, "declared_by": format!("src/{id}"), "tls": tls,
                    "routers": [{ "name": "r", "match": matcher, "service": "web", "priority": priority }],
                    "revisions": [{ "id": "r1", "state": "serving", "weight": 1, "services": [
                        { "name": "web", "type": "loadbalancer", "servers": [{ "url": "http://127.0.0.1:1" }] }
                    ]}],
                })
            })
            .collect();
        let snapshot = serde_json::from_value(json!({
            "version": 1, "tenants": [tenant("t1"), tenant("t2")], "apps": apps,
        }))
        .expect("snapshot");
        let context = crate::entry::CompileContext::default().with_catch_all_tenants(["t1", "t2"]);
        match RoutingTable::compile_with(&snapshot, &context) {
            Ok(_) => Vec::new(),
            Err(CompileError::Conflicts(found)) => found,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    fn hosts(names: &[&str]) -> Value {
        json!({ "host": names })
    }

    fn app<'a>(
        id: &'a str,
        tenant: &'a str,
        names: &[&str],
        ca: Option<&'a str>,
    ) -> (&'a str, &'a str, Option<&'a str>, Value, Option<i32>) {
        (id, tenant, ca, hosts(names), None)
    }

    #[test]
    fn host_conflict_for_exact_hosts_and_wildcards_across_tenants() {
        let found = conflicts(&[
            app("a", "t1", &["x.test", "*.w.test"], None),
            app("b", "t2", &["X.test", "*.w.test"], None),
        ]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found[0],
            Conflict::Host {
                host: "x.test".into(),
                apps: pair("a", "b"),
                declared_by: pair("src/a", "src/b"),
            }
        );
        assert!(matches!(&found[1], Conflict::Host { host, .. } if &**host == "*.w.test"));
    }

    #[test]
    fn a_router_repeating_its_own_host_is_not_a_conflict() {
        assert!(
            conflicts(&[app(
                "a",
                "t1",
                &["x.test", "x.test", "*.w.test", "*.w.test"],
                None
            )])
            .is_empty()
        );
    }

    #[test]
    fn tls_policy_conflict_when_an_exact_host_drops_the_wildcards_client_ca() {
        let found = conflicts(&[
            app("wild", "t1", &["*.a.test"], Some("CA")),
            app("exact", "t1", &["x.a.test"], None),
            app("same", "t1", &["y.a.test"], Some("CA")),
            app("nested", "t1", &["*.z.a.test"], Some("OTHER")),
        ]);
        assert_eq!(
            found,
            vec![
                Conflict::TlsPolicy {
                    host: "x.a.test".into(),
                    wildcard: "*.a.test".into(),
                    apps: pair("exact", "wild"),
                    declared_by: pair("src/exact", "src/wild"),
                },
                Conflict::TlsPolicy {
                    host: "*.z.a.test".into(),
                    wildcard: "*.a.test".into(),
                    apps: pair("nested", "wild"),
                    declared_by: pair("src/nested", "src/wild"),
                },
            ]
        );
    }

    #[test]
    fn cross_tenant_wildcard_for_hosts_and_nested_wildcards() {
        let found = conflicts(&[
            app("wild", "t1", &["*.a.test"], None),
            app("exact", "t2", &["x.a.test"], None),
            app("nested", "t2", &["*.y.a.test"], None),
            app("deep", "t2", &["p.q.a.test", "a.test"], None),
        ]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            found[0],
            Conflict::CrossTenantWildcard {
                host: "x.a.test".into(),
                wildcard: "*.a.test".into(),
                tenants: pair("t2", "t1"),
                apps: pair("exact", "wild"),
                declared_by: pair("src/exact", "src/wild"),
            }
        );
        assert!(
            matches!(&found[1], Conflict::CrossTenantWildcard { host, .. } if &**host == "*.y.a.test")
        );
    }

    #[test]
    fn all_conflicts_are_collected_and_json_is_flat() {
        let found = conflicts(&[
            app("a", "t1", &["x.test", "*.a.test"], None),
            app("b", "t1", &["x.test", "y.a.test"], Some("CA")),
            app("c", "t2", &["z.a.test"], None),
        ]);
        let codes: Vec<_> = found.iter().map(Conflict::code).collect();
        assert_eq!(
            codes,
            [
                "host_conflict",
                "tls_policy_conflict",
                "cross_tenant_wildcard"
            ]
        );
        assert_eq!(
            found[0].to_json(),
            json!({
                "code": "host_conflict",
                "message": "host x.test is claimed by app a (src/a) and app b (src/b)",
                "host": "x.test",
                "apps": ["a", "b"],
                "declared_by": ["src/a", "src/b"],
            })
        );
    }

    fn at(
        id: &'static str,
        tenant: &'static str,
        matcher: Value,
        priority: Option<i32>,
    ) -> (
        &'static str,
        &'static str,
        Option<&'static str>,
        Value,
        Option<i32>,
    ) {
        (id, tenant, None, matcher, priority)
    }

    #[test]
    fn apps_of_one_tenant_may_share_a_host_when_their_routers_differ() {
        let found = conflicts(&[
            at(
                "api",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}),
                None,
            ),
            at(
                "web",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path_prefix": "/"}]}),
                None,
            ),
            at(
                "other",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}),
                Some(5),
            ),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn equal_routers_of_one_tenant_on_a_host_are_ambiguous() {
        let same = json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]});
        let found = conflicts(&[
            at("one", "t1", same.clone(), None),
            at("two", "t1", same, None),
        ]);
        assert_eq!(
            found.iter().map(Conflict::code).collect::<Vec<_>>(),
            ["host_conflict"]
        );
        let disjoint = conflicts(&[
            at(
                "one",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path": "/a"}]}),
                None,
            ),
            at(
                "two",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path": "/b"}]}),
                None,
            ),
        ]);
        assert!(disjoint.is_empty(), "{disjoint:?}");
    }

    #[test]
    fn two_tenants_never_share_a_host_whatever_the_path_or_priority() {
        let found = conflicts(&[
            at(
                "one",
                "t1",
                json!({"all": [{"host": "a.test"}, {"path": "/a"}]}),
                None,
            ),
            at(
                "two",
                "t2",
                json!({"all": [{"host": "a.test"}, {"path": "/b"}]}),
                Some(i32::MAX),
            ),
        ]);
        assert_eq!(
            found.iter().map(Conflict::code).collect::<Vec<_>>(),
            ["host_conflict"]
        );
    }

    #[test]
    fn routers_without_a_literal_host_belong_to_one_tenant() {
        let found = conflicts(&[
            at("one", "t1", json!({"host_regexp": "^a"}), None),
            at("two", "t2", json!({"path_prefix": "/"}), Some(i32::MAX)),
        ]);
        assert_eq!(
            found.iter().map(Conflict::code).collect::<Vec<_>>(),
            ["cross_tenant_catch_all"]
        );
        let alone = conflicts(&[
            at("one", "t1", json!({"host_regexp": "^a"}), None),
            at("two", "t1", json!({"host_regexp": "^b"}), None),
        ]);
        assert_eq!(
            alone.iter().map(Conflict::code).collect::<Vec<_>>(),
            ["route_ambiguity"]
        );
    }
}
