//! OCSP stapling: verified responses stapled to the certificates the TLS listener
//! serves. Reference for operators: `docs/ref/ocsp.md`.
//!
//! - [`Identity`]: what a certificate must be answered for, from the certificate itself: serial,
//!   issuer hashes, the responder URL of its Authority Information Access, the request.
//! - [`verify`]: the checks a response passes before it may be stapled.
//! - [`Responder`], [`AllowedHosts`]: the responder URL parsed strictly, and `OCSP_ALLOWED_HOSTS`.
//! - [`Scope`]: whose upstream address policy a certificate's fetches are held to.
//! - [`Runner`]: one fetch, through the upstream address policy, with its caps.
//! - [`Staples`]: the registry keyed by certificate fingerprint and the lock-free view the
//!   handshake reads; [`schedule`]: when to refresh and how to back off.
//! - [`OcspService`]: the background service that starts due fetches, eight at a time.
//! - [`render`]: the `podgate_ocsp_*` series.
//!
//! Nothing in a snapshot sets the responder URL or turns verification off: the URL is read from
//! the certificate and the only knob a snapshot has is the `ocsp` mode.

mod identity;
mod metrics;
mod reason;
mod responder;
mod runner;
pub mod schedule;
mod scope;
mod service;
mod staples;
mod verify;

pub use identity::{Fingerprint, Identity};
pub use metrics::render;
pub use reason::Reason;
pub use responder::{AllowedHosts, Responder};
pub use runner::{Runner, TIMEOUT};
pub use scope::Scope;
pub use service::{MAX_CONCURRENT, OcspService};
pub use staples::{Candidate, Job, Outcome, Staples};
pub use verify::{MAX_RESPONSE, Verified, verify};
