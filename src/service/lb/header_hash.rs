//! `header_hash`: the value of one request header always goes to the same server (consistent
//! hashing, see [`super::ring`]). `{"type": "header_hash", "header": "x-tenant"}`; the header
//! is required. A header that is repeated is hashed with all its values, in order. A request
//! without the header goes to a random available server instead of failing.

use http::HeaderName;

use super::PickCx;
use super::ring::{Ring, fallback};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The header hash balancer.
#[derive(Debug)]
pub struct HeaderHash {
    ring: Ring,
    header: HeaderName,
}

impl HeaderHash {
    pub(super) fn compile(servers: &[Server], header: Option<&str>) -> Result<Self, Invalid> {
        let header = header.ok_or_else(|| {
            Invalid::new(
                "invalid_service",
                "header_hash needs the header to hash: \
                 {\"type\": \"header_hash\", \"header\": \"x-tenant\"}",
            )
        })?;
        let header = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            Invalid::new(
                "invalid_service",
                format!("header_hash: {header:?} is not a header name"),
            )
        })?;
        Ring::compile("header_hash", servers).map(|ring| Self { ring, header })
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
        let mut values = cx.request.headers.get_all(&self.header).iter().peekable();
        if values.peek().is_none() {
            return fallback(cx, servers, shared);
        }
        let digest = values.fold(0_u64, |digest, value| {
            shared.keyed_hash((digest, value.as_bytes()))
        });
        self.ring.pick(digest, cx, servers)
    }
}
