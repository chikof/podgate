//! The parts of Consul's catalog and health answers that the source reads.
//!
//! Every field is optional and a field the source does not read is never an error: Consul
//! sends `null` where a list or map is empty, and Enterprise adds fields CE does not have.

use std::collections::BTreeMap;

use serde::Deserialize;

/// The most instances of one service the source uses.
pub(super) const MAX_INSTANCES: usize = 256;

/// `GET /v1/catalog/services`: service name to the union of the tags of its instances.
pub(super) type Catalog = BTreeMap<Box<str>, Option<Vec<String>>>;

/// One entry of `GET /v1/health/service/<name>`.
#[derive(Debug, Deserialize)]
pub(super) struct Entry {
    #[serde(rename = "Node", default)]
    node: NodeBody,
    #[serde(rename = "Service", default)]
    service: ServiceBody,
    #[serde(rename = "Checks", default)]
    checks: Option<Vec<CheckBody>>,
}

#[derive(Debug, Default, Deserialize)]
struct NodeBody {
    #[serde(rename = "Node", default)]
    name: String,
    #[serde(rename = "Address", default)]
    address: String,
}

#[derive(Debug, Default, Deserialize)]
struct ServiceBody {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Tags", default)]
    tags: Option<Vec<String>>,
    #[serde(rename = "Address", default)]
    address: String,
    #[serde(rename = "Port", default)]
    port: u16,
    #[serde(rename = "Meta", default)]
    meta: Option<BTreeMap<String, String>>,
    #[serde(rename = "Kind", default)]
    kind: String,
    #[serde(rename = "CreateIndex", default)]
    create_index: u64,
}

#[derive(Debug, Default, Deserialize)]
struct CheckBody {
    #[serde(rename = "Status", default)]
    status: String,
}

/// One instance of a service that can serve, as the source needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Instance {
    /// The node it runs on.
    pub(super) node: Box<str>,
    /// The service id, unique on its node.
    pub(super) id: Box<str>,
    /// The address its server has: the service's own, else its node's. Not yet checked to be an
    /// IP address.
    pub(super) address: Box<str>,
    /// The port the service registered; `0` when it registered none.
    pub(super) port: u16,
    pub(super) tags: Vec<String>,
    pub(super) meta: BTreeMap<String, String>,
    /// `""` for an ordinary service, `connect-proxy` for a sidecar, a gateway kind otherwise.
    pub(super) kind: Box<str>,
    /// The raft index of its registration: a number that orders the instances of a service by
    /// age.
    pub(super) create_index: u64,
}

/// The instances of one service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Instances {
    /// At most [`MAX_INSTANCES`], in address order.
    pub(super) list: Vec<Instance>,
    /// How many more than [`MAX_INSTANCES`] there were.
    pub(super) beyond_cap: usize,
}

impl Instances {
    /// The instances of `entries` whose checks all pass, however the query was filtered: the
    /// source does not rely on the server's `passing` filter alone.
    pub(super) fn from_entries(entries: Vec<Entry>) -> Self {
        let mut list: Vec<Instance> = entries
            .into_iter()
            .filter(|entry| {
                entry
                    .checks
                    .iter()
                    .flatten()
                    .all(|check| check.status == "passing")
            })
            .map(|entry| {
                let service = entry.service;
                let address = if service.address.is_empty() {
                    entry.node.address
                } else {
                    service.address
                };
                Instance {
                    node: entry.node.name.into(),
                    id: service.id.into(),
                    address: address.into(),
                    port: service.port,
                    tags: service.tags.unwrap_or_default(),
                    meta: service.meta.unwrap_or_default(),
                    kind: service.kind.into(),
                    create_index: service.create_index,
                }
            })
            .collect();
        list.sort_by(|a, b| {
            (&a.address, a.port, &a.node, &a.id).cmp(&(&b.address, b.port, &b.node, &b.id))
        });
        let beyond_cap = list.len().saturating_sub(MAX_INSTANCES);
        list.truncate(MAX_INSTANCES);
        Self { list, beyond_cap }
    }
}
