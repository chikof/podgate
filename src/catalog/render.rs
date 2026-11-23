//! The body of `GET /v1/catalog`: every catalog entry the live table holds.
//!
//! [`render`] reads the compiled [`RoutingTable`], never a snapshot, and the item type lists the
//! fields it shows, so no secret and no OpenAPI document can reach the answer. The list is sorted
//! by `(tenant, id, version)`, which is unique, so that key is the cursor (`next` and `after`):
//! a table swap between two pages never repeats or skips an entry that stays. The body never
//! exceeds `max_bytes` (4 MiB); the page ends early, with `truncated` and `next`, when an entry
//! does not fit.

use serde::Serialize;
use serde_json::json;

use super::Api;
use crate::overview::{self, write_page_from};
use crate::table::{CompiledApp, RoutingTable};
use podgate_model::{ApiRef, Lifecycle};

/// Largest response body, in bytes: the overview's.
pub const MAX_RESPONSE_BYTES: usize = overview::MAX_RESPONSE_BYTES;

/// Entries per page when the request does not say.
pub const DEFAULT_LIMIT: usize = 50;

/// Most entries per page.
pub const MAX_LIMIT: usize = 500;

/// Bytes kept free for the `version` member written before the page.
const PREFIX_ROOM: usize = 48;

/// Where a page starts: after the entry `tenant/id/version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    tenant: String,
    id: String,
    version: String,
}

impl Cursor {
    /// Reads `<tenant>/<id>/<version>`. An id and a version never hold `/`, so the text is split
    /// from the right and the tenant keeps any it has.
    ///
    /// # Errors
    ///
    /// The cursor is not three non-empty parts.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parts = text.rsplitn(3, '/');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(version), Some(id), Some(tenant))
                if !version.is_empty() && !id.is_empty() && !tenant.is_empty() =>
            {
                Ok(Self {
                    tenant: tenant.to_owned(),
                    id: id.to_owned(),
                    version: version.to_owned(),
                })
            }
            _ => Err("after is the next of a previous page: <tenant>/<id>/<version>".to_owned()),
        }
    }
}

/// What to list.
#[derive(Debug, Clone)]
pub struct Query {
    /// Only this tenant's entries.
    pub tenant: Option<String>,
    /// Only the entries of the app with this id.
    pub app: Option<String>,
    /// Only entries at this lifecycle.
    pub lifecycle: Option<Lifecycle>,
    /// Most entries in the page, at most [`MAX_LIMIT`].
    pub limit: usize,
    /// Entries after this one.
    pub after: Option<Cursor>,
    /// Largest body, in bytes.
    pub max_bytes: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            tenant: None,
            app: None,
            lifecycle: None,
            limit: DEFAULT_LIMIT,
            after: None,
            max_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

/// One entry and where it lives.
struct Row<'a> {
    tenant: &'a str,
    app: &'a CompiledApp,
    api: &'a Api,
    cursor: String,
}

impl Row<'_> {
    fn key(&self) -> (&str, &str, &str) {
        (self.tenant, self.api.id(), self.api.version())
    }
}

/// An entry as the catalog shows it. Optional fields are absent, never `null`.
#[derive(Serialize)]
struct Item<'a> {
    tenant: &'a str,
    app: &'a str,
    declared_by: &'a str,
    id: &'a str,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    lifecycle: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sunset: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    successor: Option<&'a ApiRef>,
    routers: &'a [Box<str>],
    hosts: &'a [Box<str>],
    published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    openapi: Option<OpenapiItem<'a>>,
}

/// The OpenAPI document of an entry: what identifies it, never what is in it.
#[derive(Serialize)]
struct OpenapiItem<'a> {
    name: &'a str,
    title: &'a str,
    version: &'a str,
    dialect: &'static str,
    operations: usize,
}

fn item<'a>(row: &Row<'a>) -> Item<'a> {
    let api = row.api;
    Item {
        tenant: row.tenant,
        app: row.app.id(),
        declared_by: row.app.declared_by(),
        id: api.id(),
        version: api.version(),
        title: api.title(),
        description: api.description(),
        lifecycle: api.lifecycle().name(),
        sunset: api.sunset().map(super::Sunset::day),
        successor: api.successor(),
        routers: api.routers(),
        hosts: api.hosts(),
        published: api.published(),
        openapi: api.openapi().map(|description| OpenapiItem {
            name: description.name(),
            title: description.document().title(),
            version: description.document().version(),
            dialect: description.dialect(),
            operations: description.document().operation_count(),
        }),
    }
}

/// Renders the catalog of `table` as a JSON body of at most `query.max_bytes` bytes:
/// `{"version", "total", "items", "truncated"?, "next"?}`.
///
/// # Errors
///
/// Fails only when a value cannot be serialized, which the item types never do.
pub fn render(table: &RoutingTable, query: &Query) -> Result<Vec<u8>, serde_json::Error> {
    let mut rows: Vec<Row<'_>> = table
        .apps()
        .iter()
        .filter(|app| {
            query
                .tenant
                .as_deref()
                .is_none_or(|tenant| tenant == app.tenant())
        })
        .filter(|app| query.app.as_deref().is_none_or(|id| id == app.id()))
        .flat_map(|app| {
            app.apis()
                .iter()
                .filter(|api| query.lifecycle.is_none_or(|stage| stage == api.lifecycle()))
                .map(move |api| Row {
                    tenant: app.tenant(),
                    app,
                    api,
                    cursor: format!("{}/{}/{}", app.tenant(), api.id(), api.version()),
                })
        })
        .collect();
    rows.sort_unstable_by(|a, b| a.key().cmp(&b.key()));
    let start = query.after.as_ref().map_or(0, |after| {
        let after = (&*after.tenant, &*after.id, &*after.version);
        rows.partition_point(|row| row.key() <= after)
    });
    let listed: Vec<&Row<'_>> = rows.iter().collect();
    let mut page = Vec::new();
    write_page_from(
        &mut page,
        &listed,
        start,
        query.limit,
        query.max_bytes.saturating_sub(PREFIX_ROOM),
        |row| row.cursor.as_str(),
        item,
        |view| {
            serde_json::to_vec(&json!({
                "tenant": view.tenant, "app": view.app, "id": view.id,
                "version": view.version, "lifecycle": view.lifecycle, "too_large": true,
            }))
            .ok()
        },
    )?;
    // The page is an object that starts with `{`; `version` goes in front of its members.
    let mut body = format!("{{\"version\":{},", table.version()).into_bytes();
    body.extend_from_slice(page.get(1..).unwrap_or_default());
    Ok(body)
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;

    fn app(id: &str, count: usize, lifecycle: &str) -> Value {
        let routers: Vec<Value> = (0..count)
            .map(|at| json!({"name": format!("r{at}"), "match": {"host": format!("{id}-{at}.test")}, "service": "web"}))
            .collect();
        let apis: Vec<Value> = (0..count)
            .map(|at| {
                json!({
                    "id": format!("{id}-api{at:02}"), "version": "1", "lifecycle": lifecycle,
                    "routers": [format!("r{at}")], "title": "t".repeat(40),
                })
            })
            .collect();
        json!({
            "id": id, "tenant": "t", "declared_by": "unit", "tls": {"mode": "acme"},
            "routers": routers, "apis": apis,
            "revisions": [{"id": "r1", "weight": 1, "state": "serving", "services": [
                {"name": "web", "type": "loadbalancer", "servers": [{"url": "http://127.0.0.1:9"}]}]}],
        })
    }

    fn table(apps: &[Value]) -> RoutingTable {
        let snapshot = serde_json::from_value(json!({
            "version": 7,
            "tenants": [{"id": "t", "weight": 1, "budget": {"max_inflight": 1, "max_buffer_bytes": 1}}],
            "apps": apps,
        }))
        .expect("a snapshot");
        RoutingTable::compile(&snapshot).expect("compiles")
    }

    fn page(table: &RoutingTable, query: &Query) -> Value {
        let body = render(table, query).expect("renders");
        assert!(body.len() <= query.max_bytes, "{} bytes", body.len());
        serde_json::from_slice(&body).expect("valid JSON")
    }

    #[test]
    fn catalog_respects_cap() {
        assert_eq!(MAX_RESPONSE_BYTES, 4 * 1024 * 1024);
        assert_eq!(Query::default().max_bytes, MAX_RESPONSE_BYTES);
        let table = table(&[app("a", 20, "stable")]);
        let mut seen = Vec::new();
        let mut query = Query {
            max_bytes: 1500,
            ..Query::default()
        };
        let mut pages = 0;
        loop {
            let answer = page(&table, &query);
            assert_eq!(answer["version"], 7);
            assert_eq!(answer["total"], 20);
            let items = answer["items"].as_array().expect("items");
            assert!(!items.is_empty(), "a page always makes progress: {answer}");
            seen.extend(
                items
                    .iter()
                    .map(|entry| entry["id"].as_str().expect("id").to_owned()),
            );
            pages += 1;
            let Some(next) = answer["next"].as_str() else {
                assert!(answer.get("truncated").is_none(), "{answer}");
                break;
            };
            assert_eq!(answer["truncated"], true);
            query.after = Some(Cursor::parse(next).expect("a cursor"));
        }
        assert!(pages > 1, "1500 bytes hold fewer than 20 entries");
        let expected: Vec<String> = (0..20).map(|at| format!("a-api{at:02}")).collect();
        assert_eq!(seen, expected, "no entry skipped or repeated");
    }

    #[test]
    fn catalog_cursor_round_trips() {
        let cursor = Cursor::parse("acme/team/pets/2026-05-01").expect("a cursor");
        assert_eq!(cursor.tenant, "acme/team");
        assert_eq!(cursor.id, "pets");
        assert_eq!(cursor.version, "2026-05-01");
        for bad in ["", "a", "a/b", "/b/c", "a//c", "a/b/"] {
            assert!(Cursor::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn filters_select_by_tenant_app_and_lifecycle() {
        let table = table(&[app("a", 3, "stable"), app("b", 2, "retired")]);
        let ids = |query: &Query| page(&table, query)["total"].as_u64().expect("total");
        assert_eq!(ids(&Query::default()), 5);
        assert_eq!(
            ids(&Query {
                app: Some("b".into()),
                ..Query::default()
            }),
            2
        );
        assert_eq!(
            ids(&Query {
                lifecycle: Some(Lifecycle::Retired),
                ..Query::default()
            }),
            2
        );
        assert_eq!(
            ids(&Query {
                tenant: Some("other".into()),
                ..Query::default()
            }),
            0
        );
    }
}
