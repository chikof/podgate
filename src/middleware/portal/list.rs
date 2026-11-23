//! The portal's list of APIs: the entries one viewer may see, in bounded pages.
//!
//! The entries come from [`super::access`] and nothing else. Every text of a tenant is cut to a
//! fixed size, a page holds at most [`MAX_LIMIT`] entries and [`MAX_PAGE_BYTES`] bytes, and the
//! cursor, the search and the query string are bounded, so the cost of a page does not depend on
//! what a tenant wrote.

use serde::Serialize;

use super::access::{Viewer, Visible, shown_successor, visible};
use crate::table::RoutingTable;

/// Entries per page when the request does not say.
pub(super) const DEFAULT_LIMIT: usize = 25;
/// Most entries per page.
pub(super) const MAX_LIMIT: usize = 100;
/// Largest page, in bytes.
pub(super) const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Longest query string.
pub(super) const MAX_QUERY_BYTES: usize = 2048;
/// Longest cursor.
const MAX_CURSOR: usize = 512;
/// Longest search text.
const MAX_SEARCH: usize = 64;
/// Longest title shown.
const MAX_TITLE: usize = 256;
/// Longest description shown.
const MAX_DESCRIPTION: usize = 4096;
/// Most hosts shown for one entry.
const MAX_HOSTS: usize = 16;
/// Bytes the closing of a page needs.
const TAIL: usize = 128;

/// What a list request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Query {
    limit: usize,
    after: Option<(Box<str>, Box<str>)>,
    search: Option<Box<str>>,
}

impl Query {
    /// Reads the query string: `limit` (1 to 100), `after` (`<id>/<version>`) and `q` (up to 64
    /// bytes). Any other parameter, a repeated one, a bad value or an oversized query is `None`.
    pub(super) fn parse(raw: Option<&str>) -> Option<Self> {
        let raw = raw.unwrap_or_default();
        if raw.len() > MAX_QUERY_BYTES {
            return None;
        }
        let mut query = Self {
            limit: DEFAULT_LIMIT,
            after: None,
            search: None,
        };
        let mut seen = [false; 3];
        for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
            let slot = match &*name {
                "limit" => 0,
                "after" => 1,
                "q" => 2,
                _ => return None,
            };
            if std::mem::replace(&mut seen[slot], true) {
                return None;
            }
            match slot {
                0 => {
                    let limit: usize = value.parse().ok()?;
                    if limit == 0 {
                        return None;
                    }
                    query.limit = limit.min(MAX_LIMIT);
                }
                1 => {
                    if value.len() > MAX_CURSOR {
                        return None;
                    }
                    let (id, version) = value.split_once('/')?;
                    if id.is_empty() || version.is_empty() || version.contains('/') {
                        return None;
                    }
                    query.after = Some((id.into(), version.into()));
                }
                _ => {
                    if value.len() > MAX_SEARCH {
                        return None;
                    }
                    if !value.is_empty() {
                        query.search = Some(value.to_lowercase().into());
                    }
                }
            }
        }
        Some(query)
    }

    /// Whether `entry` matches the search: a case-insensitive part of its id, title or
    /// description.
    fn matches(&self, entry: Visible<'_>) -> bool {
        let Some(search) = &self.search else {
            return true;
        };
        let has = |text: &str| text.to_lowercase().contains(&**search);
        has(entry.id()) || entry.title().is_some_and(has) || entry.description().is_some_and(has)
    }
}

/// The cut of `text` to at most `max` bytes, on a character boundary, and whether it was cut.
fn cut(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

#[derive(Serialize)]
struct Successor<'a> {
    id: &'a str,
    version: &'a str,
}

#[derive(Serialize)]
struct Summary<'a> {
    title: &'a str,
    version: &'a str,
    dialect: &'static str,
    operations: usize,
}

/// One entry as the portal shows it. The fields are the whole list of what a viewer learns about
/// an entry: no app, no declaring source, no router or middleware name, no `published`.
#[derive(Serialize)]
struct Item<'a> {
    tenant: &'a str,
    id: &'a str,
    version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    description_cut: bool,
    lifecycle: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    sunset: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    successor: Option<Successor<'a>>,
    hosts: Vec<&'a str>,
    #[serde(skip_serializing_if = "is_zero")]
    hosts_more: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    openapi: Option<Summary<'a>>,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's `skip_serializing_if` passes a reference"
)]
fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// The page for `viewer`: `{"total", "items", "truncated"?, "next"?}`. `total` counts the
/// viewer's own entries that match the search. A page ends early, with `truncated` and `next`,
/// at the limit or when the next entry would pass [`MAX_PAGE_BYTES`].
pub(super) fn render(table: &RoutingTable, viewer: &Viewer, query: &Query) -> Vec<u8> {
    let Some(tenant) = viewer.tenant() else {
        return br#"{"total":0,"items":[]}"#.to_vec();
    };
    let entries: Vec<Visible<'_>> = visible(table, viewer)
        .into_iter()
        .filter(|entry| query.matches(*entry))
        .collect();
    let mut out = format!("{{\"total\":{},\"items\":[", entries.len()).into_bytes();
    let mut shown = 0_usize;
    let mut last: Option<(&str, &str)> = None;
    let mut more = false;
    let after = query
        .after
        .as_ref()
        .map(|(id, version)| (&**id, &**version));
    for entry in &entries {
        if after.is_some_and(|after| (entry.id(), entry.version()) <= after) {
            continue;
        }
        let bytes = item_bytes(table, viewer, tenant, *entry);
        if shown == query.limit || out.len() + 1 + bytes.len() + TAIL > MAX_PAGE_BYTES {
            more = true;
            break;
        }
        if shown > 0 {
            out.push(b',');
        }
        out.extend_from_slice(&bytes);
        shown += 1;
        last = Some((entry.id(), entry.version()));
    }
    out.push(b']');
    if more && let Some((id, version)) = last {
        out.extend_from_slice(b",\"truncated\":true,\"next\":");
        out.extend_from_slice(
            serde_json::to_string(&format!("{id}/{version}"))
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    out.push(b'}');
    out
}

/// The bytes of one entry's JSON.
fn item_bytes(table: &RoutingTable, viewer: &Viewer, tenant: &str, entry: Visible<'_>) -> Vec<u8> {
    let (description, description_cut) = entry.description().map_or((None, false), |text| {
        let (text, cut) = cut(text, MAX_DESCRIPTION);
        (Some(text), cut)
    });
    let successor = shown_successor(table, viewer, entry);
    let item = Item {
        tenant,
        id: entry.id(),
        version: entry.version(),
        title: entry.title().map(|text| cut(text, MAX_TITLE).0),
        description,
        description_cut,
        lifecycle: entry.lifecycle().name(),
        sunset: entry.sunset().map(|sunset| sunset.day()),
        successor: successor.as_ref().map(|found| Successor {
            id: found.id(),
            version: found.version(),
        }),
        hosts: entry
            .hosts()
            .iter()
            .take(MAX_HOSTS)
            .map(|host| &**host)
            .collect(),
        hosts_more: entry.hosts().len().saturating_sub(MAX_HOSTS),
        openapi: entry.openapi().map(|description| Summary {
            title: cut(description.document().title(), MAX_TITLE).0,
            version: cut(description.document().version(), MAX_TITLE).0,
            dialect: description.dialect(),
            operations: description.document().operation_count(),
        }),
    };
    serde_json::to_vec(&item).unwrap_or_default()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let query = Query::parse(Some("after=pets%2F2&limit=7&q=Pet")).expect("parses");
        assert_eq!(query.limit, 7);
        assert_eq!(
            query.after,
            Some(("pets".into(), "2".into())),
            "the cursor is the next of the previous page"
        );
        assert_eq!(query.search.as_deref(), Some("pet"));
    }

    #[test]
    fn query_is_bounded_and_strict() {
        for bad in [
            "limit=0",
            "limit=x",
            "limit=-1",
            "limit=1&limit=2",
            "tenant=acme",
            "after=nowhere",
            "after=a%2F",
            "after=%2Fb",
            "after=a%2Fb%2Fc",
            "q=a&q=b",
        ] {
            assert!(Query::parse(Some(bad)).is_none(), "{bad}");
        }
        let long_cursor = format!("after={}%2F1", "a".repeat(MAX_CURSOR));
        assert!(Query::parse(Some(&long_cursor)).is_none());
        let long_search = format!("q={}", "a".repeat(MAX_SEARCH + 1));
        assert!(Query::parse(Some(&long_search)).is_none());
        let long_query = format!("q=a&{}", "x".repeat(MAX_QUERY_BYTES));
        assert!(Query::parse(Some(&long_query)).is_none());
        assert_eq!(
            Query::parse(Some("limit=9999")).map(|q| q.limit),
            Some(MAX_LIMIT)
        );
        assert_eq!(Query::parse(None).map(|q| q.limit), Some(DEFAULT_LIMIT));
        assert_eq!(Query::parse(Some("q=")).and_then(|q| q.search), None);
    }

    #[test]
    fn cut_keeps_characters_whole() {
        assert_eq!(cut("abc", 3), ("abc", false));
        assert_eq!(cut("abcd", 3), ("abc", true));
        assert_eq!(cut("\u{e9}\u{e9}", 3), ("\u{e9}", true));
        assert_eq!(cut("", 0), ("", false));
    }

    /// The worst case of one entry stays inside the budget a page of [`MAX_LIMIT`] needs.
    #[test]
    fn list_item_bounds_hold_the_page_under_the_cap() {
        let item = Item {
            tenant: "t",
            id: &"i".repeat(128),
            version: &"v".repeat(64),
            title: Some(&"t".repeat(MAX_TITLE)),
            description: Some(&"d".repeat(MAX_DESCRIPTION)),
            description_cut: true,
            lifecycle: "deprecated",
            sunset: Some("2027-03-01"),
            successor: Some(Successor {
                id: &"s".repeat(128),
                version: &"v".repeat(64),
            }),
            hosts: vec!["h".repeat(253).leak() as &str; MAX_HOSTS],
            hosts_more: 1000,
            openapi: Some(Summary {
                title: &"t".repeat(MAX_TITLE),
                version: &"v".repeat(MAX_TITLE),
                dialect: "3.1",
                operations: 4000,
            }),
        };
        let bytes = serde_json::to_vec(&item).expect("serializes").len();
        assert!(bytes < 10_000, "one entry is {bytes} bytes");
        assert!(
            MAX_LIMIT * (bytes + 1) + TAIL < MAX_PAGE_BYTES,
            "a full page of worst-case entries fits"
        );
    }
}
