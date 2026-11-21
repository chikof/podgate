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
//! - [`mod@file`]: the source that reads YAML, TOML and JSON files and watches them.
//! - [`docker`]: the source that turns Docker and Podman containers into apps through their
//!   `podgate.*` labels.
//! - [`kubernetes`]: the source that turns Ingresses and EndpointSlices into routers and servers.
//! - [`traefik`]: the translator of `traefik.*` labels and tags (rules, services, middlewares),
//!   called by the sources next to their own labels.
//! - [`engine`]: the loop that joins them. [`config`] is the TOML file that configures it.
//! - [`acme`]: the ACME broker, which answers podgate's ACME events from a state directory.
//!
//! The references are `docs/ref/provider.md` and, for the ACME broker, `docs/ref/provider-acme.md`.

pub mod acme;
pub mod config;
pub mod docker;
pub mod engine;
pub mod file;
pub mod kubernetes;
pub mod merge;
pub mod policy;
pub mod push;
pub mod quarantine;
pub mod source;
pub mod traefik;
pub mod trust;

pub use config::{Config, ConfigError};
pub use engine::{Engine, RunError, Status};
pub use merge::{Finding, Merged, Merger};
pub use policy::UpstreamPolicy;
pub use source::{Origin, Source, SourceApp, SourceCertificate, TenantClaim, Update};
