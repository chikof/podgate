//! Upstream transports: `servers_transport` objects (SNI, CA, client certificate,
//! `insecure_skip_verify`, HTTP/2 and h2c, timeouts, keep-alive pool size) that a `loadbalancer`
//! names with `transport`.
//!
//! Not built: until its spec lands every upstream is plain HTTP/1.1 with the proxy-wide
//! timeouts, and a snapshot that declares a transport is refused with `transport_not_built`.
//! The pool key of `crate::pool` gains the transport's fingerprint there.
