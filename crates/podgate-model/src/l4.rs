//! TCP and UDP routers and services of an app.
//!
//! The model exists so a snapshot can carry them; `src/l4/` compiles them. Routers and services
//! are [`Declared`] objects like the HTTP ones; their kind modules own their configuration.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Declared;

/// The TCP side of an app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Tcp {
    /// Routers: `name`, `entry_points`, `match`, `tls`, `chain` and `service`, kept raw.
    #[serde(default)]
    pub routers: Vec<Value>,
    /// Services.
    #[serde(default)]
    pub services: Vec<Declared>,
    /// Middlewares.
    #[serde(default)]
    pub middlewares: Vec<Declared>,
}

/// The UDP side of an app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Udp {
    /// Routers: `name`, `entry_points`, `service`, `max_sessions?` and `max_reply_ratio?`, kept raw.
    #[serde(default)]
    pub routers: Vec<Value>,
    /// Services.
    #[serde(default)]
    pub services: Vec<Declared>,
}
