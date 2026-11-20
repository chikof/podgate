//! Active health checks: `health_check {path, method, interval_secs, timeout_secs,
//! expect_status, headers, hostname, scheme}` probes the servers of a `loadbalancer` from a
//! background service and writes [`super::ServerState::healthy`].
//!
//! Not built: the `loadbalancer` refuses a `health_check` setting with `service_not_built`
//! until its spec lands.
