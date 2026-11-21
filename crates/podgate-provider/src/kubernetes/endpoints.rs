//! Services, EndpointSlices and Secrets: where the servers and certificates of an Ingress come
//! from.
//!
//! The only source of an upstream address is the EndpointSlices of the backend Service, in the
//! Ingress's own namespace. An Ingress has no field that names an address, and none is read from
//! an annotation: a namespace member must not be able to aim podgate at any pod of the cluster.
//! EndpointSlices written by hand (a Service without a selector, whose slices anyone with the
//! right can fill with any address) are ignored unless `allow_external_name` is set, and every
//! address that does reach a snapshot still passes the operator's upstream policy in the merge.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::Deserialize;

use super::client::{ObjectMeta, Resource};

/// The label that ties an EndpointSlice to its Service.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// The label the slice controller sets on the slices it writes.
const MANAGED_BY_LABEL: &str = "endpointslice.kubernetes.io/managed-by";

/// The slice controller that follows the Service's selector.
const SLICE_CONTROLLER: &str = "endpointslice-controller.k8s.io";

/// A `v1` Service.
#[derive(Debug, Deserialize)]
pub struct Service {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The Service's settings.
    #[serde(default)]
    pub spec: ServiceSpec,
}

/// The parts of a Service's spec the mapping reads.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// `ClusterIP`, `NodePort`, `LoadBalancer` or `ExternalName`.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// The DNS name of an `ExternalName` Service.
    #[serde(default)]
    pub external_name: Option<String>,
    /// The ports the Service exposes.
    #[serde(default)]
    pub ports: Vec<ServicePort>,
}

/// One port of a Service.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePort {
    /// The port's name; required when the Service has several ports.
    #[serde(default)]
    pub name: Option<String>,
    /// `TCP` (the default), `UDP` or `SCTP`.
    #[serde(default)]
    pub protocol: Option<String>,
    /// The port the Service listens on, which an Ingress backend names.
    pub port: u16,
    /// The application protocol hint: `http` (or unset), `kubernetes.io/h2c`, ...
    #[serde(default)]
    pub app_protocol: Option<String>,
}

impl Resource for Service {
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "services";
    const KIND: &'static str = "Service";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// A `discovery.k8s.io/v1` EndpointSlice.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointSlice {
    /// Name, namespace, labels.
    pub metadata: ObjectMeta,
    /// `IPv4`, `IPv6` or `FQDN`.
    #[serde(default)]
    pub address_type: Option<String>,
    /// The endpoints.
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
    /// The ports, keyed by the Service port's name.
    #[serde(default)]
    pub ports: Vec<SlicePort>,
}

/// One endpoint of a slice.
#[derive(Debug, Deserialize)]
pub struct Endpoint {
    /// The addresses: one of the slice's address type.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The readiness conditions. Absent means ready.
    #[serde(default)]
    pub conditions: Conditions,
}

/// The conditions of an endpoint; an absent one is `None`.
#[derive(Debug, Default, Deserialize)]
pub struct Conditions {
    /// The endpoint can take new traffic. `None` means ready, as the API documents.
    #[serde(default)]
    pub ready: Option<bool>,
    /// The endpoint is shutting down.
    #[serde(default)]
    pub terminating: Option<bool>,
}

/// One port of a slice: the container port behind the Service port of the same name.
#[derive(Debug, Deserialize)]
pub struct SlicePort {
    /// The Service port's name; empty for an unnamed single port.
    #[serde(default)]
    pub name: Option<String>,
    /// `TCP` (the default), `UDP` or `SCTP`.
    #[serde(default)]
    pub protocol: Option<String>,
    /// The port number on the endpoints.
    #[serde(default)]
    pub port: Option<u16>,
}

impl Resource for EndpointSlice {
    const GROUP: &'static str = "discovery.k8s.io";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "endpointslices";
    const KIND: &'static str = "EndpointSlice";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// A `v1` Secret of type `kubernetes.io/tls`.
///
/// The API server only sends these (the watch carries the field selector), so the provider holds
/// no other Secret. The values are never shown by `Debug` and never put in a message.
#[derive(Deserialize)]
pub struct Secret {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// The Secret type.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// base64 values by key: `tls.crt` and `tls.key`.
    #[serde(default)]
    pub data: BTreeMap<String, String>,
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("metadata", &self.metadata)
            .field("type", &self.kind)
            .field("data", &format_args!("[{} keys redacted]", self.data.len()))
            .finish()
    }
}

/// The type a certificate Secret has, and the field selector that asks for exactly those.
pub const TLS_SECRET_TYPE: &str = "kubernetes.io/tls";

impl Resource for Secret {
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "secrets";
    const KIND: &'static str = "Secret";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

/// How a backend is reached: HTTP backends are `scheme://address`, stream backends (Gateway API
/// `TCPRoute`, `TLSRoute` and `UDPRoute`) are `address` alone, from a port of their protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// HTTP requests over a TCP port, with the scheme the port's `appProtocol` says.
    Http,
    /// A TCP stream, whatever the `appProtocol`.
    Tcp,
    /// UDP datagrams to a UDP port.
    Udp,
}

/// A backend port as an Ingress names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRef {
    /// The Service's port number.
    Number(u16),
    /// The Service port's name.
    Name(Box<str>),
}

impl fmt::Display for PortRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) => write!(f, "{number}"),
            Self::Name(name) => f.write_str(name),
        }
    }
}

/// What the cluster says about the Services of one namespace-wide snapshot of the stores.
pub struct ServiceIndex<'a> {
    services: BTreeMap<(&'a str, &'a str), &'a Service>,
    slices: BTreeMap<(&'a str, &'a str), Vec<&'a EndpointSlice>>,
    allow_external_name: bool,
}

impl<'a> ServiceIndex<'a> {
    /// Indexes the Services and EndpointSlices the source holds.
    #[must_use]
    pub fn new(
        services: impl Iterator<Item = &'a Service>,
        slices: impl Iterator<Item = &'a EndpointSlice>,
        allow_external_name: bool,
    ) -> Self {
        let services = services
            .map(|service| {
                (
                    (service.metadata.namespace(), service.metadata.name.as_str()),
                    service,
                )
            })
            .collect();
        let mut by_service: BTreeMap<(&str, &str), Vec<&EndpointSlice>> = BTreeMap::new();
        for slice in slices {
            if let Some(name) = slice.metadata.labels.get(SERVICE_NAME_LABEL) {
                by_service
                    .entry((slice.metadata.namespace(), name.as_str()))
                    .or_default()
                    .push(slice);
            }
        }
        Self {
            services,
            slices: by_service,
            allow_external_name,
        }
    }

    /// The servers (`scheme://address:port`, sorted, without duplicates) behind `port` of the
    /// Service `name` in `namespace`.
    ///
    /// An empty list is a Service whose pods are all unready or gone: that is a normal state,
    /// not an error.
    ///
    /// # Errors
    ///
    /// A message when the Service is missing, is an `ExternalName` Service (unless
    /// `allow_external_name`), has no such port, uses a protocol other than TCP or HTTP, or has
    /// no EndpointSlices at all.
    pub fn servers(
        &self,
        namespace: &str,
        name: &str,
        port: &PortRef,
    ) -> Result<Vec<Box<str>>, String> {
        self.addresses(namespace, name, port, Wire::Http)
    }

    /// [`Self::servers`] for a backend of the given [`Wire`]: a stream backend returns plain
    /// `address:port` entries from a TCP (or, for UDP, a UDP) port, and an `ExternalName` Service
    /// is a host name that only a TCP stream can use.
    ///
    /// # Errors
    ///
    /// As [`Self::servers`], with the port's protocol checked against `wire`.
    pub fn addresses(
        &self,
        namespace: &str,
        name: &str,
        port: &PortRef,
        wire: Wire,
    ) -> Result<Vec<Box<str>>, String> {
        let service = self
            .services
            .get(&(namespace, name))
            .ok_or_else(|| format!("Service {namespace}/{name} does not exist"))?;
        if service.spec.kind.as_deref() == Some("ExternalName") {
            return self.external(service, namespace, name, port, wire);
        }
        let service_port = service
            .spec
            .ports
            .iter()
            .find(|candidate| match port {
                PortRef::Number(number) => candidate.port == *number,
                PortRef::Name(wanted) => candidate.name.as_deref() == Some(&**wanted),
            })
            .ok_or_else(|| format!("Service {namespace}/{name} has no port {port}"))?;
        let protocol = if wire == Wire::Udp { "UDP" } else { "TCP" };
        if service_port
            .protocol
            .as_deref()
            .is_some_and(|found| found != protocol)
        {
            return Err(format!(
                "port {port} of Service {namespace}/{name} is not {protocol}"
            ));
        }
        let scheme = match wire {
            Wire::Http => Some(scheme_of(service_port.app_protocol.as_deref())
                .ok_or_else(|| format!("port {port} of Service {namespace}/{name} has the appProtocol {:?}, which is not supported (http and kubernetes.io/h2c are)", service_port.app_protocol.as_deref().unwrap_or("")))?),
            Wire::Tcp | Wire::Udp => None,
        };
        let slices: Vec<&EndpointSlice> = self
            .slices
            .get(&(namespace, name))
            .into_iter()
            .flatten()
            .copied()
            .filter(|slice| self.allow_external_name || controller_managed(slice))
            .collect();
        if slices.is_empty() && !self.allow_external_name {
            return Err(format!(
                "Service {namespace}/{name} has no EndpointSlices written by the Kubernetes controller; podgate takes pod addresses from those only (a Service without a selector needs allow_external_name)"
            ));
        }
        let wanted = service_port.name.as_deref().unwrap_or("");
        let mut servers = BTreeSet::new();
        for slice in slices {
            let Some(target) = slice_port(slice, wanted, protocol) else {
                continue;
            };
            if !matches!(slice.address_type.as_deref(), Some("IPv4" | "IPv6")) {
                continue;
            }
            for endpoint in &slice.endpoints {
                // `ready` is nil for "unknown", which the API says to read as ready; a
                // terminating endpoint is out at once even before its readiness flips.
                if endpoint.conditions.ready == Some(false)
                    || endpoint.conditions.terminating == Some(true)
                {
                    continue;
                }
                for address in &endpoint.addresses {
                    if let Ok(ip) = address.parse::<IpAddr>() {
                        let address = SocketAddr::new(ip, target);
                        servers.insert(match scheme {
                            Some(scheme) => format!("{scheme}://{address}").into(),
                            None => address.to_string().into(),
                        });
                    }
                }
            }
        }
        Ok(servers.into_iter().collect())
    }

    fn external(
        &self,
        service: &Service,
        namespace: &str,
        name: &str,
        port: &PortRef,
        wire: Wire,
    ) -> Result<Vec<Box<str>>, String> {
        if wire == Wire::Udp {
            return Err(format!(
                "Service {namespace}/{name} is an ExternalName Service, and podgate's UDP servers are IP literals only"
            ));
        }
        if !self.allow_external_name {
            return Err(format!(
                "Service {namespace}/{name} is an ExternalName Service: its target is a DNS name its owner picks; set allow_external_name to serve it"
            ));
        }
        let PortRef::Number(number) = port else {
            return Err(format!(
                "Service {namespace}/{name} is an ExternalName Service, which has no named ports; name the port by number"
            ));
        };
        let target = service.spec.external_name.as_deref().unwrap_or("");
        let valid = !target.is_empty()
            && target.len() <= 253
            && target.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        if !valid {
            return Err(format!(
                "Service {namespace}/{name} has an externalName that is not a host name"
            ));
        }
        Ok(vec![match wire {
            Wire::Http => format!("http://{target}:{number}").into(),
            Wire::Tcp | Wire::Udp => format!("{target}:{number}").into(),
        }])
    }
}

fn controller_managed(slice: &EndpointSlice) -> bool {
    slice
        .metadata
        .labels
        .get(MANAGED_BY_LABEL)
        .map(String::as_str)
        == Some(SLICE_CONTROLLER)
}

fn scheme_of(app_protocol: Option<&str>) -> Option<&'static str> {
    match app_protocol {
        None | Some("" | "http") => Some("http"),
        Some("kubernetes.io/h2c") => Some("h2c"),
        Some(_) => None,
    }
}

/// The container port of the slice's `protocol` port called `name`.
fn slice_port(slice: &EndpointSlice, name: &str, protocol: &str) -> Option<u16> {
    slice
        .ports
        .iter()
        .find(|port| {
            port.name.as_deref().unwrap_or("") == name
                && port
                    .protocol
                    .as_deref()
                    .is_none_or(|found| found == protocol)
        })
        .and_then(|port| port.port)
}
