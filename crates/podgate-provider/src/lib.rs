//! `podgate-provider`: merges the declarations of many sources into one podgate snapshot and
//! pushes it over the admin socket.
//!
//! podgate itself never merges: conflicting declarations reject the whole snapshot.
//! Merging, trust and quarantine therefore live here, in a separate program that podgate does not
//! depend on (and that does not depend on podgate; both speak the `podgate-model` types and the
//! admin API of `docs/ref/admin-tools.md`).
//!
//! - [`source`]: what a source sends ([`source::Update`]) and the [`source::Source`] trait.
//! - [`merge`]: the pure merge of all sources' states into one canonical snapshot.
//! - [`trust`]: who may claim which host, and which label may name which tenant.
//! - [`policy`]: the operator's upstream address policy, checked before the push.
//! - [`push`]: the admin socket client, the debounce and the retry delays.
//! - [`quarantine`]: leaving out the objects podgate rejects, found by `declared_by` or by
//!   bisection.
//! - [`file`]: the source that reads YAML, TOML and JSON files and watches them.
//! - [`engine`]: the loop that joins them. [`config`] is the TOML file that configures it.
//!
//! The reference is `docs/ref/provider.md`.

pub mod config;
pub mod engine;
pub mod file;
pub mod merge;
pub mod policy;
pub mod push;
pub mod quarantine;
pub mod source;
pub mod trust;

pub use config::{Config, ConfigError};
pub use engine::{Engine, RunError, Status};
pub use merge::{Finding, Merged, Merger};
pub use policy::UpstreamPolicy;
pub use source::{Origin, Source, SourceApp, SourceCertificate, TenantClaim, Update};
