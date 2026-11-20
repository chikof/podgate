//! Request-time policy of an entry point (listener).
//!
//! Where an entry point listens is process configuration (Pingora binds sockets before it runs);
//! what it allows is snapshot data. The entry point spec (`src/entry.rs`) owns the semantics of
//! every field but `name` and `tenants`; until it lands, a policy that sets one of them is
//! refused with `unsupported_setting`, never ignored.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The policy for the entry point called `name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct EntryPointPolicy {
    /// The entry point this policy is for; the process must have bound it.
    pub name: Box<str>,
    /// Tenants that may attach routers to the entry point. Absent: every tenant. A router with
    /// no literal host that lists an entry point whose `tenants` names only its own tenant may
    /// match any host there.
    #[serde(default)]
    pub tenants: Option<Vec<Box<str>>>,
    /// Peers whose `X-Forwarded-*` headers are trusted. Not built yet.
    #[serde(default)]
    pub forwarded_headers: Option<Value>,
    /// PROXY protocol acceptance. Not built yet.
    #[serde(default)]
    pub proxy_protocol: Option<Value>,
    /// Read, write, idle and header timeouts. Not built yet.
    #[serde(default)]
    pub timeouts: Option<Value>,
    /// HTTP/2 settings. Not built yet.
    #[serde(default)]
    pub http2: Option<Value>,
    /// Redirect every request to another entry point. Not built yet.
    #[serde(default)]
    pub redirect: Option<Value>,
    /// Accept an encoded `/` in the path. Not built yet.
    #[serde(default)]
    pub allow_encoded_slash: Option<bool>,
}
