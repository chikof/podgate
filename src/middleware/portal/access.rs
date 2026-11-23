//! Who sees what: the only code of the portal that reads the catalog.
//!
//! A [`Viewer`] is a tenant, read from the verified claims of the login stage in front of the
//! portal and from nothing else. [`Visible`] is a catalog entry that viewer may see; every list,
//! detail and document function takes a `Visible`, never the compiled entry, so code that renders
//! an entry cannot be handed a foreign one. The rule, in order: the viewer is a tenant, the
//! entry's tenant is that tenant, the entry is published, and its lifecycle is `preview`,
//! `stable` or `deprecated`. There is no operator view and no cross-tenant view.
//!
//! The test `portal_reads_catalog_only_through_access` fails when another file of the portal
//! names `.apis()`, `.apps()` or the compiled entry type.

use std::ops::Deref;

use serde_json::{Map, Value};

use crate::catalog::Api;
use crate::table::RoutingTable;
use podgate_model::Lifecycle;

/// Longest tenant id the portal accepts from a claim.
const MAX_TENANT: usize = 128;

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Viewer {
    /// A request the login stage did not give a tenant: sees nothing.
    Anonymous,
    /// A person of this tenant.
    Tenant(Box<str>),
}

impl Viewer {
    /// The viewer the verified `claims` name through the string claim `claim`: 1 to 128 bytes of
    /// visible ASCII, no whitespace. A missing claim, another type (a number, a list, an object),
    /// a blank or oversized string, and no claims at all are [`Self::Anonymous`].
    pub(super) fn from_claims(claims: Option<&Map<String, Value>>, claim: &str) -> Self {
        match claims.and_then(|claims| claims.get(claim)) {
            Some(Value::String(tenant))
                if !tenant.is_empty()
                    && tenant.len() <= MAX_TENANT
                    && tenant.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                Self::Tenant(tenant.as_str().into())
            }
            _ => Self::Anonymous,
        }
    }

    /// Whether the viewer is a tenant.
    pub(super) fn is_known(&self) -> bool {
        matches!(self, Self::Tenant(_))
    }

    /// The tenant, when the viewer is one.
    pub(super) fn tenant(&self) -> Option<&str> {
        match self {
            Self::Tenant(tenant) => Some(tenant),
            Self::Anonymous => None,
        }
    }
}

/// A catalog entry the viewer may see.
#[derive(Debug, Clone, Copy)]
pub(super) struct Visible<'a> {
    api: &'a Api,
}

impl Deref for Visible<'_> {
    type Target = Api;

    fn deref(&self) -> &Api {
        self.api
    }
}

/// Whether the lifecycle is one the portal shows.
fn shown(lifecycle: Lifecycle) -> bool {
    matches!(
        lifecycle,
        Lifecycle::Preview | Lifecycle::Stable | Lifecycle::Deprecated
    )
}

/// The entries `viewer` may see, unsorted. An app of another tenant is skipped before any of its
/// entries is read.
fn each<'a>(table: &'a RoutingTable, viewer: &Viewer) -> impl Iterator<Item = Visible<'a>> {
    let tenant = viewer.tenant().map(str::to_owned);
    table
        .apps()
        .iter()
        .filter(move |app| tenant.as_deref() == Some(app.tenant()))
        .flat_map(|app| app.apis())
        .filter(|api| api.published() && shown(api.lifecycle()))
        .map(|api| Visible { api })
}

/// The entries `viewer` may see, sorted by `(id, version)` as text.
pub(super) fn visible<'a>(table: &'a RoutingTable, viewer: &Viewer) -> Vec<Visible<'a>> {
    let mut entries: Vec<Visible<'a>> = each(table, viewer).collect();
    entries.sort_unstable_by(|a, b| (a.id(), a.version()).cmp(&(b.id(), b.version())));
    entries
}

/// The entry `(id, version)` among the entries `viewer` may see. An entry of another tenant, an
/// unpublished one, a draft, a retired one and a missing one are the same `None`.
pub(super) fn find<'a>(
    table: &'a RoutingTable,
    viewer: &Viewer,
    id: &str,
    version: &str,
) -> Option<Visible<'a>> {
    each(table, viewer).find(|entry| entry.id() == id && entry.version() == version)
}

/// The successor of `entry`, when the viewer may see it too: naming an unpublished entry would
/// tell the viewer it exists.
pub(super) fn shown_successor<'a>(
    table: &'a RoutingTable,
    viewer: &Viewer,
    entry: Visible<'_>,
) -> Option<Visible<'a>> {
    let successor = entry.successor()?;
    find(table, viewer, &successor.id, &successor.version)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    fn claims(value: &Value) -> Option<Map<String, Value>> {
        value.as_object().cloned()
    }

    #[test]
    fn viewer_comes_only_from_a_string_tenant_claim() {
        let named = |value: Value| {
            Viewer::from_claims(claims(&json!({"tenant": value})).as_ref(), "tenant")
        };
        assert_eq!(named(json!("acme")), Viewer::Tenant("acme".into()));
        assert_eq!(named(json!("a/b")), Viewer::Tenant("a/b".into()));
        for bad in [
            json!(""),
            json!(" "),
            json!("a b"),
            json!("a, b"),
            json!("a\tb"),
            json!("na\u{ef}ve"),
            json!(7),
            json!(true),
            json!(null),
            json!(["acme"]),
            json!({"id": "acme"}),
            json!("x".repeat(MAX_TENANT + 1)),
        ] {
            assert_eq!(named(bad.clone()), Viewer::Anonymous, "{bad}");
        }
        assert_eq!(
            named(json!("x".repeat(MAX_TENANT))),
            Viewer::Tenant("x".repeat(MAX_TENANT).into())
        );
        assert_eq!(Viewer::from_claims(None, "tenant"), Viewer::Anonymous);
        let other = claims(&json!({"team": "acme"}));
        assert_eq!(
            Viewer::from_claims(other.as_ref(), "tenant"),
            Viewer::Anonymous
        );
        assert_eq!(
            Viewer::from_claims(other.as_ref(), "team"),
            Viewer::Tenant("acme".into())
        );
    }

    /// A table of apps `(tenant, id, [(api id, version, lifecycle, published)])`.
    type Entry<'a> = (&'a str, &'a str, &'a str, bool);
    type AppSpec<'a> = (&'a str, &'a str, &'a [Entry<'a>]);

    fn table(apps: &[AppSpec<'_>]) -> RoutingTable {
        let tenants: Vec<Value> = apps
            .iter()
            .map(|(tenant, _, _)| tenant)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|tenant| {
                json!({"id": tenant, "weight": 1,
                       "budget": {"max_inflight": 10, "max_buffer_bytes": 1_048_576}})
            })
            .collect();
        let apps: Vec<Value> = apps
            .iter()
            .map(|(tenant, id, apis)| {
                let host = format!("{id}.test");
                let routers: Vec<Value> = apis
                    .iter()
                    .enumerate()
                    .map(|(at, _)| {
                        json!({"name": format!("r{at}"), "service": "web",
                               "match": {"all": [{"host": host}, {"path_prefix": format!("/r{at}")}]}})
                    })
                    .collect();
                let apis: Vec<Value> = apis
                    .iter()
                    .enumerate()
                    .map(|(at, (api, version, lifecycle, published))| {
                        let mut entry = json!({
                            "id": api, "version": version, "lifecycle": lifecycle,
                            "routers": [format!("r{at}")], "published": published,
                            "title": format!("{tenant}/{api}/{version}"),
                        });
                        if *lifecycle == "deprecated" {
                            entry["sunset"] = json!("2027-01-01");
                        }
                        entry
                    })
                    .collect();
                json!({
                    "id": id, "tenant": tenant, "declared_by": "test", "tls": {"mode": "acme"},
                    "routers": routers, "apis": apis,
                    "revisions": [{"id": "r1", "state": "serving", "weight": 100, "services": [
                        {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://10.0.0.1:80"}]}
                    ]}],
                })
            })
            .collect();
        let snapshot =
            serde_json::from_value(json!({"version": 1, "tenants": tenants, "apps": apps}))
                .expect("a snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn fleet() -> RoutingTable {
        table(&[
            (
                "acme",
                "a",
                &[
                    ("p", "1", "stable", true),
                    ("p", "2", "preview", true),
                    ("p", "3", "deprecated", true),
                    ("d", "1", "draft", true),
                    ("r", "1", "retired", true),
                    ("u", "1", "stable", false),
                ],
            ),
            (
                "globex",
                "g",
                &[("p", "1", "stable", true), ("q", "1", "stable", true)],
            ),
        ])
    }

    fn ids(entries: &[Visible<'_>]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| format!("{}/{}", entry.id(), entry.version()))
            .collect()
    }

    #[test]
    fn visible_needs_tenant_published_and_shown_lifecycle() {
        let table = fleet();
        let tenant = |name: &str| Viewer::Tenant(name.into());
        assert_eq!(
            ids(&visible(&table, &tenant("acme"))),
            ["p/1", "p/2", "p/3"]
        );
        assert_eq!(ids(&visible(&table, &tenant("globex"))), ["p/1", "q/1"]);
        assert!(visible(&table, &Viewer::Anonymous).is_empty());
        // A tenant is matched whole and exactly.
        for other in ["ACME", "acm", "acme ", "", "globex/acme"] {
            assert!(visible(&table, &tenant(other)).is_empty(), "{other:?}");
        }
    }

    #[test]
    fn find_compares_only_own_entries() {
        let table = fleet();
        let acme = Viewer::Tenant("acme".into());
        let globex = Viewer::Tenant("globex".into());
        // The same `(id, version)` is each tenant's own.
        let mine = find(&table, &acme, "p", "1").expect("acme's p/1");
        let theirs = find(&table, &globex, "p", "1").expect("globex's p/1");
        assert_eq!(mine.title(), Some("acme/p/1"));
        assert_eq!(theirs.title(), Some("globex/p/1"));
        // What another tenant has, what is unpublished, a draft and a retired entry: none.
        assert!(find(&table, &acme, "q", "1").is_none());
        assert!(find(&table, &globex, "u", "1").is_none());
        for hidden in [("u", "1"), ("d", "1"), ("r", "1"), ("p", "9")] {
            assert!(
                find(&table, &acme, hidden.0, hidden.1).is_none(),
                "{hidden:?}"
            );
        }
        assert!(find(&table, &Viewer::Anonymous, "p", "1").is_none());
    }
}
