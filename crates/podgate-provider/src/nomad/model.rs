//! The parts of Nomad's service registration API the source reads.

use serde::Deserialize;

/// One element of `GET /v1/services`: the services of a namespace.
#[derive(Debug, Deserialize)]
pub(super) struct Listing {
    #[serde(rename = "Namespace")]
    pub(super) namespace: String,
    #[serde(rename = "Services", default)]
    pub(super) services: Option<Vec<ServiceStub>>,
}

/// A service name with the tags of all its instances together.
#[derive(Debug, Deserialize)]
pub(super) struct ServiceStub {
    #[serde(rename = "ServiceName")]
    pub(super) name: String,
    #[serde(rename = "Tags", default)]
    pub(super) tags: Option<Vec<String>>,
}

/// One registration of `GET /v1/service/<name>`: an allocation's instance of the service.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct Instance {
    #[serde(rename = "ServiceName")]
    pub(super) service: String,
    #[serde(rename = "Namespace", default)]
    pub(super) namespace: String,
    #[serde(rename = "Address", default)]
    pub(super) address: String,
    #[serde(rename = "Port", default)]
    pub(super) port: u16,
    #[serde(rename = "Tags", default)]
    pub(super) tags: Option<Vec<String>>,
    #[serde(rename = "AllocID", default)]
    pub(super) alloc: String,
    #[serde(rename = "JobID", default)]
    pub(super) job: String,
    /// A raft index: orders the instances of one service against each other, nothing else.
    #[serde(rename = "CreateIndex", default)]
    pub(super) created: u64,
}
