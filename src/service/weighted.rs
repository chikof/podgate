//! The `weighted` service: a weighted choice among other services, optionally sticky.
//!
//! Planned, not built: a snapshot that names the type is refused with `service_not_built`.
//! Its spec fills this file, adds a variant to [`super::Service`] and removes the type from
//! `UNBUILT` in `service.rs`.
