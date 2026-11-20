//! Sticky sessions: a cookie that keeps a client on one server of a `loadbalancer`. The value is
//! an HMAC of the server URL under the snapshot's `skew_secret` with its own domain label.
//!
//! Not built: the `loadbalancer` refuses a `sticky` setting with `service_not_built` until its
//! spec lands.
