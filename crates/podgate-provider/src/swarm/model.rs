//! The parts of the Docker Engine's Swarm API that the source reads: services, tasks, nodes and
//! networks.
//!
//! Every field is optional or defaulted, and a field the source does not read is never an error:
//! the engine adds fields between versions, and a socket proxy or another implementation may
//! leave some out.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Deserialize;

use crate::docker::model::parse_time;

/// One entry of `GET /services`.
#[derive(Debug, Deserialize)]
pub(crate) struct ServiceEntry {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "CreatedAt", default)]
    created_at: String,
    #[serde(rename = "Spec", default)]
    spec: ServiceSpec,
    #[serde(rename = "Endpoint", default)]
    endpoint: EndpointEntry,
}

#[derive(Debug, Default, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "Name", default)]
    name: String,
    /// The service's own labels: a stack's `deploy.labels`. The container labels live under
    /// `TaskTemplate.ContainerSpec.Labels` and are not read at all.
    #[serde(rename = "Labels", default)]
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Default, Deserialize)]
struct EndpointEntry {
    #[serde(rename = "VirtualIPs", default)]
    virtual_ips: Option<Vec<VirtualIp>>,
}

#[derive(Debug, Deserialize)]
struct VirtualIp {
    #[serde(rename = "NetworkID", default)]
    network_id: String,
    /// `10.0.1.2/24`.
    #[serde(rename = "Addr", default)]
    addr: String,
}

/// One entry of `GET /tasks`.
#[derive(Debug, Deserialize)]
pub(crate) struct TaskEntry {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "ServiceID", default)]
    service_id: String,
    #[serde(rename = "NodeID", default)]
    node_id: String,
    #[serde(rename = "Slot", default)]
    slot: Option<u64>,
    #[serde(rename = "Status", default)]
    status: TaskStatus,
    #[serde(rename = "NetworksAttachments", default)]
    attachments: Option<Vec<Attachment>>,
}

#[derive(Debug, Default, Deserialize)]
struct TaskStatus {
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "ContainerStatus", default)]
    container: Option<ContainerStatus>,
}

#[derive(Debug, Default, Deserialize)]
struct ContainerStatus {
    #[serde(rename = "Health", default)]
    health: Option<Health>,
}

#[derive(Debug, Default, Deserialize)]
struct Health {
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Debug, Deserialize)]
struct Attachment {
    #[serde(rename = "Network", default)]
    network: AttachedNetwork,
    /// `10.0.1.5/24`, one per address family.
    #[serde(rename = "Addresses", default)]
    addresses: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
struct AttachedNetwork {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Spec", default)]
    spec: NetworkSpec,
}

#[derive(Debug, Default, Deserialize)]
struct NetworkSpec {
    #[serde(rename = "Name", default)]
    name: String,
}

/// One entry of `GET /nodes`.
#[derive(Debug, Deserialize)]
pub(crate) struct NodeEntry {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Status", default)]
    status: NodeStatus,
}

#[derive(Debug, Default, Deserialize)]
struct NodeStatus {
    #[serde(rename = "State", default)]
    state: String,
}

/// One entry of `GET /networks`.
#[derive(Debug, Deserialize)]
pub(crate) struct NetworkEntry {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Name", default)]
    name: String,
}

/// A service as the source needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Service {
    pub(super) id: Box<str>,
    pub(super) name: Box<str>,
    /// The service's own creation time, unix seconds; `0` when the engine sent none that parses.
    pub(super) created: u64,
    pub(super) labels: BTreeMap<String, String>,
    /// The service's virtual IP on each network, by network id; `None` for an address that is
    /// not a literal.
    pub(super) virtual_ips: BTreeMap<Box<str>, Option<IpAddr>>,
}

/// Whether a task may serve traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readiness {
    /// Running, and healthy when the engine reports a health status.
    Serving,
    /// Anything else: starting, failed, shut down, or reporting a health status that is not
    /// `healthy`.
    NotServing,
}

/// A task's address on one network it is attached to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attached {
    pub(super) network_id: Box<str>,
    pub(super) network_name: Box<str>,
    /// The IPv4 address, else the IPv6 one; `None` when the task has no literal on the network.
    pub(super) address: Option<IpAddr>,
}

/// A task as the source needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Task {
    pub(super) id: Box<str>,
    pub(super) service_id: Box<str>,
    pub(super) node_id: Box<str>,
    /// `<service>.<slot>` is the name a task is known by on the command line; `None` for a
    /// global service's task.
    pub(super) slot: Option<u64>,
    pub(super) readiness: Readiness,
    pub(super) attachments: Vec<Attached>,
}

/// The state of a node, reduced to whether tasks on it can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(super) id: Box<str>,
    pub(super) ready: bool,
}

/// A network of the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Network {
    pub(super) id: Box<str>,
    pub(super) name: Box<str>,
}

impl ServiceEntry {
    pub(crate) fn into_service(self) -> Service {
        let virtual_ips = self
            .endpoint
            .virtual_ips
            .unwrap_or_default()
            .into_iter()
            .map(|vip| (Box::from(vip.network_id), literal(&vip.addr)))
            .collect();
        Service {
            id: self.id.into(),
            name: self.spec.name.into(),
            created: parse_time(&self.created_at).unwrap_or(0),
            labels: self.spec.labels.unwrap_or_default(),
            virtual_ips,
        }
    }
}

impl TaskEntry {
    pub(crate) fn into_task(self) -> Task {
        let reported_health = self
            .status
            .container
            .and_then(|container| container.health)
            .map(|health| health.status)
            .filter(|status| !status.is_empty());
        let serving = self.status.state == "running"
            && reported_health.is_none_or(|status| status == "healthy");
        let attachments = self
            .attachments
            .unwrap_or_default()
            .into_iter()
            .map(|attachment| Attached {
                network_id: attachment.network.id.into(),
                network_name: attachment.network.spec.name.into(),
                address: attachment
                    .addresses
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|text| literal(text))
                    .min_by_key(IpAddr::is_ipv6),
            })
            .collect();
        Task {
            id: self.id.into(),
            service_id: self.service_id.into(),
            node_id: self.node_id.into(),
            slot: self.slot,
            readiness: if serving {
                Readiness::Serving
            } else {
                Readiness::NotServing
            },
            attachments,
        }
    }
}

impl NodeEntry {
    pub(crate) fn into_node(self) -> Node {
        Node {
            id: self.id.into(),
            ready: self.status.state == "ready",
        }
    }
}

impl NetworkEntry {
    pub(crate) fn into_network(self) -> Network {
        Network {
            id: self.id.into(),
            name: self.name.into(),
        }
    }
}

/// The IP address of `10.0.1.5/24` or `10.0.1.5`. Only literals count.
fn literal(text: &str) -> Option<IpAddr> {
    text.split('/').next().and_then(|ip| ip.parse().ok())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn literals_drop_the_prefix_length() {
        assert_eq!(literal("10.0.1.5/24"), "10.0.1.5".parse().ok());
        assert_eq!(literal("fd00::5/64"), "fd00::5".parse().ok());
        assert_eq!(literal("10.0.1.5"), "10.0.1.5".parse().ok());
        assert_eq!(literal("db.internal/24"), None);
        assert_eq!(literal(""), None);
    }
}
