//! DNS upstreams: servers named by host name, resolved on a TTL by a background service.
//!
//! Not built: the `loadbalancer` accepts IP literals only and refuses a host name with
//! `dns_upstream_not_built`. The resolver spec owns this file and the upstream address policy
//! (the allowlist of addresses a tenant may point servers at), which must also be checked on
//! every resolution before a connection is made.
