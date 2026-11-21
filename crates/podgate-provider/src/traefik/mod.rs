//! Traefik v3 labels, translated: `traefik.*` pairs become podgate routers, services and
//! middlewares, with the priorities that reproduce Traefik's ordering.
//!
//! The one entry point is [`translate`]. It takes plain `(key, value)` pairs, so the Docker
//! source calls it next to the `podgate.*` parser and a Nomad source calls it with service tags
//! split at the first `=`. The rule grammar is the `podgate-rule` crate. Translate or reject,
//! never approximate: what podgate cannot express exactly is a [`Problem`] naming the label, and
//! the router it would have changed is left out.
//!
//! The reference is `docs/ref/provider-traefik.md`.

mod labels;
mod middlewares;
mod problem;
mod reader;
mod services;

pub use labels::{Translation, translate};
pub use problem::{Code, Problem};
