//! The combined view: pure functions over the fleet. They filter and page local data and send
//! nothing to any peer.
//!
//! Entries are sorted by `(cluster, tenant, id, version)` as text. The cursor is that key, so a
//! swap between two pages never repeats or skips an entry that stays.

use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::ClusterName;
use crate::failure::ErrorClass;
use crate::fleet::{Cluster, Freshness};
use crate::serve::{Params, Reply};
use crate::wire::{Counts, Cursor, Item, Key, Lifecycle};

/// Entries in a page unless `limit` says otherwise.
pub const DEFAULT_LIMIT: usize = 50;
/// The most entries in a page.
pub const MAX_LIMIT: usize = 500;
/// The most bytes of a page.
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// What a reader asked for.
#[derive(Debug, Clone)]
pub struct Query {
    cluster: Option<ClusterName>,
    tenant: Option<Box<str>>,
    lifecycle: Option<Lifecycle>,
    limit: usize,
    after: Option<(ClusterName, Key)>,
}

fn bad(message: &str) -> Reply {
    Reply::bad_request(message)
}

impl Query {
    /// Reads `cluster`, `tenant`, `lifecycle`, `limit` and `after`.
    ///
    /// # Errors
    ///
    /// The `400` to send.
    pub fn parse(query: Option<&str>) -> Result<Self, Reply> {
        let params = Params::parse(query, &["cluster", "tenant", "lifecycle", "limit", "after"])?;
        let cluster = params
            .get("cluster")
            .map(|name| ClusterName::parse(name).map_err(|_| bad("cluster is not a cluster name")))
            .transpose()?;
        let lifecycle = params
            .get("lifecycle")
            .map(|word| match Lifecycle::from_word(word) {
                Lifecycle::Other if word != "unknown" => Err(bad("unknown lifecycle")),
                found => Ok(found),
            })
            .transpose()?;
        let limit = match params.get("limit") {
            None => DEFAULT_LIMIT,
            Some(text) => match text.parse::<usize>() {
                Ok(0) | Err(_) => return Err(bad("limit must be a number of at least 1")),
                Ok(limit) => limit.min(MAX_LIMIT),
            },
        };
        let after = params
            .get("after")
            .map(|text| {
                let (name, rest) = text.split_once('/').ok_or_else(|| bad("bad cursor"))?;
                let name = ClusterName::parse(name).map_err(|_| bad("bad cursor"))?;
                let cursor = Cursor::parse(rest).map_err(|_| bad("bad cursor"))?;
                Ok::<_, Reply>((name, cursor.key()))
            })
            .transpose()?;
        Ok(Self {
            cluster,
            tenant: params.get("tenant").map(Into::into),
            lifecycle,
            limit,
            after,
        })
    }

    fn selects(&self, item: &Item) -> bool {
        self.tenant
            .as_deref()
            .is_none_or(|tenant| tenant == &*item.tenant)
            && self.lifecycle.is_none_or(|stage| stage == item.lifecycle)
    }
}

#[derive(Serialize)]
struct ViewItem<'a> {
    cluster: &'a str,
    stale: bool,
    #[serde(flatten)]
    item: &'a Item,
}

fn unix(time: Option<SystemTime>) -> Option<u64> {
    time?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// The page of the combined catalog `query` asks for.
#[must_use]
pub fn catalog(
    fleet: &[Arc<Cluster>],
    query: &Query,
    now: SystemTime,
    stale_after: Duration,
) -> Vec<u8> {
    let mut selected: Vec<&Arc<Cluster>> = fleet
        .iter()
        .filter(|cluster| {
            query
                .cluster
                .as_ref()
                .is_none_or(|name| *name == cluster.name)
        })
        .collect();
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    let total: usize = selected
        .iter()
        .map(|cluster| {
            cluster
                .entries
                .iter()
                .filter(|item| query.selects(item))
                .count()
        })
        .sum();
    let mut out = format!(r#"{{"total":{total},"items":["#).into_bytes();
    let mut count = 0_usize;
    let mut last: Option<(&str, Key)> = None;
    let mut truncated = false;
    'clusters: for cluster in &selected {
        let stale = cluster.freshness(now, stale_after) == Freshness::Stale;
        for item in cluster.entries.iter().filter(|item| query.selects(item)) {
            if let Some((name, key)) = &query.after {
                let past = match cluster.name.cmp(name) {
                    Ordering::Less => false,
                    Ordering::Equal => {
                        (&*item.tenant, &*item.id, &*item.version)
                            > (&*key.tenant, &*key.id, &*key.version)
                    }
                    Ordering::Greater => true,
                };
                if !past {
                    continue;
                }
            }
            // The entries are capped, so an item is far below the cap and a page always has one.
            let Ok(bytes) = serde_json::to_vec(&ViewItem {
                cluster: cluster.name.as_str(),
                stale,
                item,
            }) else {
                continue;
            };
            if count == query.limit || (count > 0 && out.len() + bytes.len() + 1 > MAX_BODY) {
                truncated = true;
                break 'clusters;
            }
            if count > 0 {
                out.push(b',');
            }
            out.extend_from_slice(&bytes);
            count += 1;
            last = Some((cluster.name.as_str(), Key::of(item)));
        }
    }
    out.extend_from_slice(br#"],"stale_clusters":"#);
    let stale: Vec<&str> = selected
        .iter()
        .filter(|cluster| cluster.freshness(now, stale_after) == Freshness::Stale)
        .map(|cluster| cluster.name.as_str())
        .collect();
    out.extend_from_slice(&serde_json::to_vec(&stale).unwrap_or_else(|_| b"[]".to_vec()));
    if let (true, Some((name, key))) = (truncated, last) {
        let next = format!("{name}/{}", Cursor::after(&key).as_str());
        out.extend_from_slice(br#","truncated":true,"next":"#);
        out.extend_from_slice(&serde_json::to_vec(&next).unwrap_or_else(|_| b"\"\"".to_vec()));
    }
    out.push(b'}');
    out
}

#[derive(Serialize)]
struct ErrorRow {
    class: ErrorClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
}

#[derive(Serialize)]
struct Row<'a> {
    name: &'a str,
    state: &'static str,
    last_success: Option<u64>,
    last_attempt: Option<u64>,
    error: Option<ErrorRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    writer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_format_version: Option<u32>,
    entries: usize,
    dropped: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    counts: Option<&'a Counts>,
}

/// Every cluster with its state, stale or not.
#[must_use]
pub fn clusters(fleet: &[Arc<Cluster>], now: SystemTime, stale_after: Duration) -> Vec<u8> {
    let mut sorted: Vec<&Arc<Cluster>> = fleet.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let rows: Vec<Row<'_>> = sorted
        .iter()
        .map(|cluster| Row {
            name: cluster.name.as_str(),
            state: match cluster.freshness(now, stale_after) {
                Freshness::Fresh => "fresh",
                Freshness::Stale => "stale",
            },
            last_success: unix(cluster.last_success),
            last_attempt: unix(cluster.last_attempt),
            error: cluster.error.map(|failure| ErrorRow {
                class: failure.class,
                status: failure.http_status,
            }),
            snapshot_version: cluster.status.as_ref().map(|s| s.snapshot_version),
            boot_id: cluster.status.as_ref().map(|s| &*s.boot_id),
            applied_at: cluster.status.as_ref().map(|s| s.applied_at),
            writer: cluster.status.as_ref().and_then(|s| s.writer.as_deref()),
            peer_format_version: cluster.peer_format,
            entries: cluster.entries.len(),
            dropped: cluster.dropped,
            counts: cluster.status.as_ref().map(|s| &s.counts),
        })
        .collect();
    serde_json::to_vec(&serde_json::json!({ "now": unix(Some(now)), "items": rows }))
        .unwrap_or_else(|_| b"{}".to_vec())
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;
    use crate::failure::Failure;
    use crate::fleet::Fleet;
    use crate::pull::Pulled;
    use crate::wire::{Counts, Status};

    fn item(tenant: &str, id: &str, lifecycle: &str) -> Item {
        Item::parse(json!({
            "tenant": tenant, "app": "a", "declared_by": "d", "id": id, "version": "1",
            "lifecycle": lifecycle, "routers": ["r"], "hosts": ["h.test"], "published": true
        }))
        .expect("an item")
    }

    fn fleet(parts: &[(&str, Vec<Item>)]) -> Vec<Arc<Cluster>> {
        let names: Vec<ClusterName> = parts
            .iter()
            .map(|(name, _)| ClusterName::parse(name).expect("name"))
            .collect();
        let fleet = Fleet::new(names);
        for (index, (_, items)) in parts.iter().enumerate() {
            fleet.succeed(
                index,
                Pulled {
                    status: Status {
                        snapshot_version: 7,
                        applied_at: 0,
                        boot_id: "b".into(),
                        writer: None,
                        counts: Counts::default(),
                    },
                    entries: items.clone().into(),
                    dropped: 0,
                    snapshot_version: 7,
                },
                UNIX_EPOCH + Duration::from_secs(100),
            );
        }
        fleet.snapshot()
    }

    const NOW: Duration = Duration::from_secs(101);

    fn run(clusters: &[Arc<Cluster>], query: &str) -> Value {
        let query = Query::parse(Some(query)).expect("a query");
        let body = catalog(clusters, &query, UNIX_EPOCH + NOW, Duration::from_secs(90));
        serde_json::from_slice(&body).expect("json")
    }

    #[test]
    fn federation_view_cursor_round_trips() {
        let clusters = fleet(&[
            ("us", vec![item("acme", "b", "stable")]),
            (
                "eu",
                vec![
                    item("acme", "a", "stable"),
                    item("acme", "b", "stable"),
                    item("zed", "a", "stable"),
                ],
            ),
        ]);
        let mut seen = Vec::new();
        let mut after = String::new();
        loop {
            let query = if after.is_empty() {
                "limit=2".to_owned()
            } else {
                format!("limit=2&after={}", crate::wire::percent_encode(&after))
            };
            let page = run(&clusters, &query);
            for entry in page["items"].as_array().expect("items") {
                seen.push(format!(
                    "{}/{}/{}",
                    entry["cluster"], entry["tenant"], entry["id"]
                ));
            }
            if page["truncated"] != json!(true) {
                break;
            }
            after = page["next"].as_str().expect("next").to_owned();
        }
        assert_eq!(seen.len(), 4, "{seen:?}");
        assert!(
            seen[0].contains("eu") && seen[3].contains("us"),
            "sorted by cluster first: {seen:?}"
        );
    }

    #[test]
    fn federation_view_page_cap() {
        let big: Vec<Item> = (0..40)
            .map(|n| {
                Item::parse(json!({
                    "tenant": "t", "app": "a", "id": format!("{n:03}"), "version": "1",
                    "lifecycle": "stable", "description": "d".repeat(crate::wire::MAX_DESCRIPTION)
                }))
                .expect("item")
            })
            .collect();
        let clusters = fleet(&[("eu", big)]);
        let query = Query::parse(Some("limit=500")).expect("query");
        let body = catalog(&clusters, &query, UNIX_EPOCH + NOW, Duration::from_secs(90));
        assert!(body.len() <= MAX_BODY);
        assert_eq!(MAX_BODY, 4 * 1024 * 1024);
        assert_eq!(MAX_LIMIT, 500);
    }

    #[test]
    fn federation_view_filters_and_marks_stale() {
        let mut clusters = fleet(&[
            (
                "eu",
                vec![item("acme", "a", "stable"), item("acme", "b", "deprecated")],
            ),
            ("us", vec![item("zed", "a", "stable")]),
        ]);
        let failed = Cluster {
            error: Some(Failure::status(500)),
            ..Cluster::clone(&clusters[1])
        };
        clusters[1] = Arc::new(failed);
        let all = run(&clusters, "limit=10");
        assert_eq!(all["total"], 3);
        assert_eq!(all["stale_clusters"], json!(["us"]));
        let stale: Vec<bool> = all["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|e| e["stale"] == json!(true))
            .collect();
        assert_eq!(stale, [false, false, true]);
        assert_eq!(run(&clusters, "cluster=us")["total"], 1);
        assert_eq!(
            run(&clusters, "tenant=acme&lifecycle=deprecated")["total"],
            1
        );
        assert_eq!(run(&clusters, "cluster=nowhere")["total"], 0);
        assert!(Query::parse(Some("lifecycle=nonsense")).is_err());
        assert!(Query::parse(Some("limit=0")).is_err());
        assert!(Query::parse(Some("after=nocluster")).is_err());
        assert!(Query::parse(Some("tenant=a&tenant=b")).is_err());
        assert!(Query::parse(Some("other=1")).is_err());
    }
}
