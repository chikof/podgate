//! `podgate-federation`: a read-only view of several podgate clusters.
//!
//! Two roles, one crate, and no dependency on any podgate crate: this program holds text that
//! peers wrote, so it must have no way to build a snapshot (`docs/ref/federation.md`).
//!
//! - [`export`] runs beside a cluster's podgate. It reads the daemon's read socket
//!   (`ADMIN_READ_SOCKET`) through [`admin_get`] and serves two routes over mutual TLS.
//! - [`hub`] pulls every peer the operator listed ([`config::PeersFile`]) and serves the
//!   combined view ([`view`]) over mutual TLS.
//!
//! The shared parts are [`wire`] (the documents and every cap on them), [`tls`] and [`serve`].
//! [`client`], [`pull`] and [`fleet`] are the hub's: one pinned connection that only sends `GET`,
//! one pull under one deadline, and the per-peer state with its freshness rules.

pub mod admin_get;
pub mod client;
pub mod config;
pub mod export;
pub mod failure;
pub mod fleet;
pub mod hub;
pub mod pull;
pub mod serve;
pub mod tls;
pub mod view;
pub mod wire;
