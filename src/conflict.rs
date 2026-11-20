//! Security conflicts between the declarations of one snapshot.
//!
//! Declarations that disagree are never merged: the compiler collects every [`Conflict`] and
//! refuses the whole snapshot, so no declaration silently wins over another. Each conflict names
//! both apps and both `declared_by` sources, in the order documented on its variant.
//!
//! Rules, over every host pattern an app claims (an exact name, or a `*.` wildcard that covers
//! one extra label):
//!
//! - Two different apps claiming the same pattern: [`Conflict::Host`], whatever their
//!   tenants. An app repeating its own host is not a conflict.
//! - A claim is *under* a wildcard when the claimed name (the host itself, or the base name of a
//!   wildcard) is one label below the wildcard's base: `x.a.test` and `*.x.a.test` are under
//!   `*.a.test`; `a.test` and `*.y.a.test` are not.
//! - A claim under another tenant's wildcard: [`Conflict::CrossTenantWildcard`].
//! - A claim under a wildcard of the same tenant, in another app, with a different
//!   `tls.client_ca_pem` (compared as written, `None` against `Some` included):
//!   [`Conflict::TlsPolicy`]. Exact beats wildcard when routing, so without this rule an
//!   app could drop or swap the client-certificate requirement its wildcard sibling declares.

use std::collections::HashMap;

use serde_json::{Value, json};
use thiserror::Error;

use crate::host::HostPattern;
use crate::snapshot::App;

/// One reason a snapshot is refused. [`Self::code`] is the stable identifier in the `422` body.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Conflict {
    /// Two apps claim the same exact host or the same wildcard.
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
    /// A claim and the wildcard above it, both of one tenant, disagree on `client_ca_pem`.
    #[error(
        "host {host} of app {} ({}) and wildcard {wildcard} of app {} ({}) disagree on client_ca_pem",
        .apps[0], .declared_by[0], .apps[1], .declared_by[1]
    )]
    TlsPolicy {
        /// The claim under the wildcard.
        host: Box<str>,
        /// The wildcard above it.
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
}

impl Conflict {
    /// The stable code: `host_conflict`, `tls_policy_conflict` or `cross_tenant_wildcard`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Host { .. } => "host_conflict",
            Self::TlsPolicy { .. } => "tls_policy_conflict",
            Self::CrossTenantWildcard { .. } => "cross_tenant_wildcard",
        }
    }

    /// The object in the `conflicts` list of a `422` body: `code`, `message` and the fields of
    /// the variant (`host`, `apps`, `declared_by`, plus `wildcard` and `tenants` where present).
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

/// Finds every conflict among `claims`, each a parsed host pattern and the index into `apps` of
/// the app that declares it. Returns them in claim order; empty means the snapshot is clean.
pub(crate) fn detect(apps: &[App], claims: &[(HostPattern, usize)]) -> Vec<Conflict> {
    let mut found = Vec::new();

    // Same pattern, different apps. An app repeating its own host counts once.
    let mut unique: Vec<(&HostPattern, usize)> = Vec::with_capacity(claims.len());
    let mut claimants: HashMap<(bool, &str), Vec<usize>> = HashMap::new();
    for (pattern, index) in claims {
        let key = (matches!(pattern, HostPattern::Wildcard(_)), anchor(pattern));
        let seen = claimants.entry(key).or_default();
        if seen.contains(index) {
            continue;
        }
        if let Some(&first) = seen.first()
            && let (Some(other), Some(second)) = (apps.get(first), apps.get(*index))
        {
            found.push(Conflict::Host {
                host: show(pattern),
                apps: pair(&other.id, &second.id),
                declared_by: pair(&other.declared_by, &second.declared_by),
            });
        }
        seen.push(*index);
        unique.push((pattern, *index));
    }

    // A claim under a wildcard of another app.
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
        let Some(app) = apps.get(index) else {
            continue;
        };
        for &(wildcard_index, wildcard) in above {
            let Some(owner) = apps.get(wildcard_index).filter(|_| wildcard_index != index) else {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::snapshot::{Budget, Snapshot, Tenant, TlsMode, TlsPolicy};
    use crate::table::{CompileError, RoutingTable};

    fn app(id: &str, tenant: &str, hosts: &[&str], ca: Option<&str>) -> App {
        App {
            id: id.into(),
            tenant: tenant.into(),
            declared_by: format!("src/{id}").into(),
            hosts: hosts.iter().map(|host| (*host).into()).collect(),
            tls: TlsPolicy {
                mode: TlsMode::Acme,
                client_ca_pem: ca.map(Into::into),
            },
            revisions: Vec::new(),
            allow_domain_fronting: false,
            record_bodies: false,
        }
    }

    fn conflicts(apps: Vec<App>) -> Vec<Conflict> {
        let tenant = |id: &str| Tenant {
            id: id.into(),
            weight: 1,
            budget: Budget {
                max_inflight: 1,
                max_buffer_bytes: 1,
            },
        };
        let snapshot = Snapshot {
            version: 1,
            tenants: vec![tenant("t1"), tenant("t2")],
            apps,
            certificates: Vec::new(),
            skew_secret: None,
        };
        match RoutingTable::compile(&snapshot) {
            Ok(_) => Vec::new(),
            Err(CompileError::Conflicts(found)) => found,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn host_conflict_for_exact_hosts_and_wildcards_across_tenants() {
        let found = conflicts(vec![
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
    fn an_app_repeating_its_own_host_is_not_a_conflict() {
        assert!(
            conflicts(vec![app(
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
        let found = conflicts(vec![
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
        let found = conflicts(vec![
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
        let found = conflicts(vec![
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
}
