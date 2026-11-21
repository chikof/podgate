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
//! - [`ecs`]: the source that turns running Amazon ECS tasks into apps through the `podgate.*`
//!   labels of their task definitions.
//! - [`kubernetes`]: the source that turns Ingresses and EndpointSlices into routers and servers.
//! - [`traefik`]: the translator of `traefik.*` labels and tags (rules, services, middlewares),
//!   called by the sources next to their own labels.
//! - [`nomad`]: the source that turns Nomad service registrations into apps through their
//!   `podgate.*` tags.
//! - [`swarm`]: the source that turns Docker Swarm services into apps through their `podgate.*`
//!   service labels, taking servers from task addresses or the service's virtual IP.
//! - [`traefik_file`]: the converter of Traefik dynamic configuration files (YAML or TOML), also the
//!   `convert-traefik` command.
//! - [`kv`]: the layer the key-value sources share: layouts, tenant mapping, the allowlist
//!   requirement and limits.
//! - [`etcd`]: the source that reads a key prefix per tenant from etcd and follows it with a watch.
//! - [`mod@http`]: the source that polls an HTTP(S) endpoint for apps or a Traefik configuration.
//! - [`engine`]: the loop that joins them. [`config`] is the TOML file that configures it.
//! - [`acme`]: the ACME broker, which answers podgate's ACME events from a state directory.
//! - [`ca`]: the internal CA, which issues leaves for `tls.mode = "internal"` apps from a name-constrained
//!   intermediate (`docs/ref/internal-ca.md`).
//!
//! The references are `docs/ref/provider.md` and, for the ACME broker, `docs/ref/provider-acme.md`.

mod abort;
pub mod acme;
pub mod ca;
pub mod config;
pub mod consul;
pub mod docker;
pub mod ecs;
pub mod engine;
pub mod etcd;
pub mod file;
pub mod http;
pub mod kubernetes;
pub mod kv;
pub mod merge;
pub mod nomad;
pub mod policy;
pub mod push;
pub mod quarantine;
pub mod source;
pub mod swarm;
mod tags;
mod tls_client;
pub mod traefik;
pub mod traefik_file;
pub mod trust;

pub use config::{Config, ConfigError};
pub use engine::{Engine, RunError, Status};
pub use merge::{Finding, Merged, Merger};
pub use policy::UpstreamPolicy;
pub use source::{Origin, Source, SourceApp, SourceCertificate, TenantClaim, Update};
