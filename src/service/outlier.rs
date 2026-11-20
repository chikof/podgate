//! Passive outlier ejection: `passive {consecutive_failures, ejection_secs,
//! max_ejection_percent}` ejects servers that fail real requests by writing
//! [`super::ServerState::ejected_until_ms`].
//!
//! Not built: the `loadbalancer` refuses a `passive` setting with `service_not_built` until its
//! spec lands.
