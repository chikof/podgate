//! `ip_hash`: a client address always goes to the same server (consistent hashing, see
//! [`super::ring`]). The address is the resolved client of the entry point's forwarding policy
//! ([`crate::client_ip`]), never a raw `X-Forwarded-For`: a peer that is not trusted cannot
//! choose its server by forging it. An IPv6 client counts by its `/64`, so a host that rotates
//! the rest of its address keeps its server. A request with no client address (a unix-socket
//! peer) goes to a random available server.

use std::net::IpAddr;

use super::PickCx;
use super::ring::{Ring, fallback};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The client-address hash balancer.
#[derive(Debug)]
pub struct IpHash {
    ring: Ring,
}

/// The keyed hash of a client address: the address, or the `/64` of an IPv6 one.
pub(super) fn digest(client: IpAddr, shared: &ServiceState) -> u64 {
    match client {
        IpAddr::V4(addr) => shared.keyed_hash(addr.octets()),
        IpAddr::V6(addr) => {
            shared.keyed_hash(u64::try_from(u128::from(addr) >> 64).unwrap_or_default())
        }
    }
}

impl IpHash {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        Ring::compile("ip_hash", servers).map(|ring| Self { ring })
    }

    pub(super) fn points(&self) -> u64 {
        self.ring.points()
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        match cx.client {
            Some(client) => self.ring.pick(digest(client, shared), cx, servers),
            None => fallback(cx, servers, shared),
        }
    }
}
