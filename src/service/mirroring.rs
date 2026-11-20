//! The `mirroring` service: send every request to one service and a copy of a percentage of
//! them to others, ignoring the copies' answers.
//!
//! Planned, not built: a snapshot that names the type is refused with `service_not_built`.
//! Mirrors call services of the same app only, never an address derived from the request.
