//! Upstream connection pool isolation.
//!
//! Pingora keeps idle upstream connections in one pool and hands one out when a new peer has the
//! same `reuse_hash`. That hash covers the upstream address and TLS settings but nothing about
//! who is asking, so two tenants behind one address would share connections. Traefik's pool had
//! the same shape and leaked NTLM and Negotiate identities between clients (GHSA-hrpp-p4fc-wwf8,
//! GHSA-53qr-784g-cj35, GHSA-xv5x-242w-7hf7, GHSA-p956-6gvv-mxqp).
//!
//! [`isolate`] sets `HttpPeer::group_key`, which Pingora mixes into the reuse hash next to the
//! upstream address. The key is `(tenant, app, revision, transport)`, so the pool key is
//! `(tenant, app, revision, transport, upstream addr)`. The transport is the fingerprint of the
//! service's `servers_transport` (every field, client certificate and key included) and whether
//! the connection is TLS, so TLS and plain connections, or connections with different client
//! certificates, never mix. Pingora's own hash names a client certificate by its serial number
//! alone.
//!
//! # NTLM and Negotiate
//!
//! These schemes authenticate the TCP connection, not the request: after the handshake the
//! upstream treats every later request on that connection as the same user, usually without an
//! `Authorization` header. A request that carries either scheme therefore pins its upstream
//! connection to its downstream connection: the group key also holds the downstream socket's
//! kernel cookie (`SO_COOKIE`, unique per socket for the life of the host, never reused), so no
//! other downstream connection can ever draw that upstream connection from the pool. Once a
//! downstream connection has sent such a header, every later request on it is pinned too, so the
//! authenticated upstream connection stays reachable for it ([`State`] rides along with HTTP/1.x
//! keepalive through `persist_connection_context`).
//!
//! Pingora cannot close an idle pooled connection on demand, so "closed with the downstream
//! connection" is enforced by a short idle timeout: after the downstream connection is gone
//! nothing can reach the pinned connection and the pool drops it after [`PINNED_IDLE_TIMEOUT`].
//!
//! Fail closed: where the kernel cookie is unavailable (non-Linux, or the call fails) the pin is
//! a fresh number per request, so the connection is never shared but a multi-leg handshake
//! cannot finish.
//!
//! Limit: an HTTP/2 downstream connection has no per-connection state in Pingora's callbacks, so
//! only the requests that carry the header are pinned. HTTP/2 forbids connection-based
//! authentication, so this is the protocol's own rule, not a gap.
//!
//! # PROXY protocol
//!
//! A transport with `proxy_protocol` writes a header naming the client at the start of each
//! upstream connection, so such a connection belongs to one client address (ip and
//! port): `isolate` adds it to the group key, and the connection is closed by the same short
//! idle timeout once its client has gone.

use std::any::Any;
use std::hash::{BuildHasher, RandomState};
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{AUTHORIZATION, HeaderName, PROXY_AUTHORIZATION};
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use pingora::upstreams::peer::HttpPeer;

use crate::route::Selected;
use crate::table::RoutingTable;

/// How long a pinned upstream connection may sit idle in the pool. Matches Pingora's HTTP/1.x
/// downstream keepalive, so it outlives the downstream connection it belongs to by at most that.
pub const PINNED_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The request headers that can carry a connection-based authentication scheme. Header name
/// constants, so a lookup does not parse a name per request.
const AUTH_HEADERS: [HeaderName; 2] = [AUTHORIZATION, PROXY_AUTHORIZATION];

/// Keys the group hash per process, so a group key cannot be predicted or collided on purpose.
static KEYS: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Source of pins for requests whose downstream socket has no kernel cookie.
static NEXT_REQUEST_PIN: AtomicU64 = AtomicU64::new(0);

/// What the pool needs to know about a downstream connection across its requests.
///
/// Lives on [`crate::Ctx`]; carried to the next request of an HTTP/1.x keepalive connection by
/// [`persist`] and [`restore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    /// A request on this downstream connection used NTLM or Negotiate.
    pinned: bool,
}

/// Who a pooled upstream connection belongs to.
#[derive(Debug, Clone, Copy)]
pub struct Identity {
    /// [`scope`] of the owning tenant, app and revision, computed when the table was compiled.
    pub scope: u64,
    /// The transport the connection is made with: its fingerprint and whether it is TLS.
    pub transport: u64,
}

/// What a pooled connection is shared with, beyond its [`Identity`].
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum Pin {
    /// Any request of the same identity.
    Shared,
    /// Only requests of the downstream connection with this kernel socket cookie.
    Connection(u64),
    /// One request only: the connection could not be tied to a downstream connection.
    Request(u64),
}

/// The one number that stands for a tenant, an app and a revision, keyed per process like the
/// group key it goes into. The table computes it once per revision, so a request does not hash
/// three strings.
#[must_use]
pub fn scope(tenant: &str, app: &str, revision: &str) -> u64 {
    KEYS.hash_one((tenant, app, revision))
}

impl Identity {
    /// The identity of the app and revision `selected` points at in `table`, reached through the
    /// transport with pool key `transport` ([`crate::service::Upstream::pool_key`]), or `None`
    /// when it points outside the table.
    #[must_use]
    pub fn of(table: &RoutingTable, selected: &Selected, transport: u64) -> Option<Self> {
        let revision = table
            .app(selected.app)?
            .revisions()
            .get(selected.revision)?;
        Some(Self {
            scope: revision.pool_scope(),
            transport,
        })
    }
}

/// Whether `value`, the value of an `Authorization` or `Proxy-Authorization` header, uses a
/// connection-based scheme: `NTLM` or `Negotiate`, compared case-insensitively on the first token.
#[must_use]
pub fn is_connection_scheme(value: &[u8]) -> bool {
    let value = value.trim_ascii_start();
    let end = value
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(value.len());
    let scheme = &value[..end];
    scheme.eq_ignore_ascii_case(b"ntlm") || scheme.eq_ignore_ascii_case(b"negotiate")
}

/// Whether `request` carries NTLM or Negotiate credentials in any header value.
#[must_use]
pub fn carries_connection_auth(request: &RequestHeader) -> bool {
    AUTH_HEADERS.iter().any(|name| {
        request
            .headers
            .get_all(name)
            .iter()
            .any(|value| is_connection_scheme(value.as_bytes()))
    })
}

/// Records what `request` shows about its downstream connection. Call for every request.
pub fn observe(state: &mut State, request: &RequestHeader) {
    state.pinned |= carries_connection_auth(request);
}

/// The state to carry to the next request of this downstream connection, if there is any.
#[must_use]
pub fn persist(state: State) -> Option<Box<dyn Any + Send + Sync>> {
    state.pinned.then(|| Box::new(state) as _)
}

/// Takes the state [`persist`] returned for the previous request into `state`.
pub fn restore(state: &mut State, previous: Box<dyn Any + Send + Sync>) {
    if let Ok(previous) = previous.downcast::<State>() {
        state.pinned |= previous.pinned;
    }
}

/// Makes `peer` draw only from, and return only to, the pool partition of `identity` (and of the
/// downstream connection of `session` when `state` is pinned, and of `client` when the transport
/// writes a PROXY protocol header, which names its client). Call after every other peer
/// setting, before returning the peer.
pub fn isolate(
    peer: &mut HttpPeer,
    identity: Identity,
    state: State,
    session: &Session,
    client: Option<SocketAddr>,
) {
    // A connection bound to one downstream connection or one client address has no use once
    // that one is gone: it is closed by a short idle timeout, and a transport's shorter one
    // still wins.
    if state.pinned || client.is_some() {
        peer.options.idle_timeout = Some(
            peer.options
                .idle_timeout
                .map_or(PINNED_IDLE_TIMEOUT, |idle| idle.min(PINNED_IDLE_TIMEOUT)),
        );
    }
    let pin = if state.pinned {
        pin_for(session)
    } else {
        Pin::Shared
    };
    peer.group_key = group_key(identity, pin, client);
}

fn group_key(identity: Identity, pin: Pin, client: Option<SocketAddr>) -> u64 {
    KEYS.hash_one((identity.scope, identity.transport, pin, client))
}

fn pin_for(session: &Session) -> Pin {
    let cookie = session
        .digest()
        .and_then(|digest| digest.socket_digest.as_ref())
        .and_then(|socket| socket.socket_cookie().ok())
        .filter(|cookie| *cookie != 0);
    match cookie {
        Some(cookie) => Pin::Connection(cookie),
        None => Pin::Request(NEXT_REQUEST_PIN.fetch_add(1, Ordering::Relaxed)),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in headers {
            request
                .append_header(name.to_string(), *value)
                .expect("header");
        }
        request
    }

    fn peer(addr: &str, identity: Identity, pin: Pin) -> HttpPeer {
        let mut peer = HttpPeer::new(addr, false, String::new());
        peer.group_key = group_key(identity, pin, None);
        peer
    }

    fn identity(tenant: &str, app: &str, revision: &str) -> Identity {
        Identity {
            scope: scope(tenant, app, revision),
            transport: 0,
        }
    }

    fn base() -> Identity {
        identity("t1", "a", "r1")
    }

    #[test]
    fn auth_scheme_detect() {
        for value in [
            "NTLM TlRMTVNTUAAB",
            "ntlm abc",
            "NtLm",
            "Negotiate YIIB",
            "NEGOTIATE",
            "  negotiate x",
        ] {
            assert!(is_connection_scheme(value.as_bytes()), "{value}");
        }
        for value in [
            "Bearer ntlm",
            "Basic dXNlcjpwYXNz",
            "NTLMX abc",
            "Negotiated",
            "",
            "Digest username=\"ntlm\"",
        ] {
            assert!(!is_connection_scheme(value.as_bytes()), "{value}");
        }
        assert!(carries_connection_auth(&request(&[(
            "Authorization",
            "NTLM abc"
        )])));
        assert!(carries_connection_auth(&request(&[
            ("Authorization", "Bearer x"),
            ("authorization", "Negotiate y"),
        ])));
        assert!(carries_connection_auth(&request(&[(
            "Proxy-Authorization",
            "NTLM abc"
        )])));
        assert!(!carries_connection_auth(&request(&[
            ("Authorization", "Bearer x"),
            ("X-Auth", "NTLM abc"),
        ])));
        assert!(!carries_connection_auth(&request(&[])));
    }

    #[test]
    fn state_pins_from_first_ntlm_request_and_persists() {
        let mut state = State::default();
        observe(&mut state, &request(&[("Authorization", "Bearer x")]));
        assert_eq!(state, State::default());
        assert!(persist(state).is_none());

        observe(&mut state, &request(&[("Authorization", "NTLM abc")]));
        let carried = persist(state).expect("a pinned connection carries its state");

        let mut next = State::default();
        restore(&mut next, carried);
        assert_eq!(next, state);
        observe(&mut next, &request(&[]));
        assert!(next.pinned, "later requests stay pinned");
    }

    #[test]
    fn reuse_hash_separates_tenant_app_revision_and_address() {
        use pingora::upstreams::peer::Peer;
        let reference = peer("127.0.0.1:9000", base(), Pin::Shared);
        let same = peer("127.0.0.1:9000", base(), Pin::Shared);
        assert_eq!(reference.reuse_hash(), same.reuse_hash());

        let other = |identity| peer("127.0.0.1:9000", identity, Pin::Shared).reuse_hash();
        assert_ne!(reference.reuse_hash(), other(identity("t2", "a", "r1")));
        assert_ne!(reference.reuse_hash(), other(identity("t1", "b", "r1")));
        assert_ne!(reference.reuse_hash(), other(identity("t1", "a", "r2")));
        assert_ne!(
            reference.reuse_hash(),
            peer("127.0.0.1:9001", base(), Pin::Shared).reuse_hash()
        );
        // Field boundaries count: ("ab", "c") is not ("a", "bc").
        assert_ne!(
            other(identity("ab", "c", "r1")),
            other(identity("a", "bc", "r1"))
        );
    }

    #[test]
    fn pins_never_share_with_each_other_or_the_shared_pool() {
        use pingora::upstreams::peer::Peer;
        let hash = |pin| peer("127.0.0.1:9000", base(), pin).reuse_hash();
        let all = [
            hash(Pin::Shared),
            hash(Pin::Connection(1)),
            hash(Pin::Connection(2)),
            hash(Pin::Request(1)),
        ];
        for (index, left) in all.iter().enumerate() {
            for right in &all[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn reuse_hash_separates_transports_even_for_equal_peers() {
        use pingora::upstreams::peer::Peer;
        let hash = |transport| {
            peer(
                "127.0.0.1:9000",
                Identity {
                    transport,
                    ..base()
                },
                Pin::Shared,
            )
            .reuse_hash()
        };
        assert_eq!(hash(1), hash(1));
        assert_ne!(hash(1), hash(2));
        assert_ne!(hash(0), hash(1));
    }

    #[test]
    fn reuse_hash_separates_client_addresses() {
        use pingora::upstreams::peer::Peer;
        let hash = |client: Option<&str>| {
            let mut peer = HttpPeer::new("127.0.0.1:9000", false, String::new());
            peer.group_key = group_key(
                base(),
                Pin::Shared,
                client.map(|text| text.parse().expect("address")),
            );
            peer.reuse_hash()
        };
        assert_eq!(hash(Some("192.0.2.1:5000")), hash(Some("192.0.2.1:5000")));
        assert_ne!(hash(Some("192.0.2.1:5000")), hash(Some("192.0.2.1:5001")));
        assert_ne!(hash(Some("192.0.2.1:5000")), hash(Some("192.0.2.2:5000")));
        assert_ne!(hash(Some("192.0.2.1:5000")), hash(None));
    }
}
