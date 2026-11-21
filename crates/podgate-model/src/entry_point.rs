//! Request-time policy of an entry point (listener).
//!
//! Where an entry point listens is process configuration (Pingora binds sockets before it runs);
//! what it allows is snapshot data. The daemon owns the semantics of every field: the kind
//! configuration held as [`Value`] is parsed strictly by the module that applies it (a misspelt
//! option is refused, never ignored), and a knob the proxy cannot apply is refused with
//! `unsupported_setting`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What an entry point does with a request header whose name holds an underscore (`X_Forwarded_For`),
/// which a CGI-style upstream may read as `X-Forwarded-For`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum UnderscoreHeaders {
    /// Pass the header on. What an entry point with no policy does.
    #[default]
    Keep,
    /// Remove the header and serve the request.
    Delete,
    /// Answer `400` and serve nothing.
    Reject,
}

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
    /// Peers whose `X-Forwarded-*` headers are trusted.
    #[serde(default)]
    pub forwarded_headers: Option<Value>,
    /// `{trusted_ips, insecure}`: the peers allowed to send a PROXY protocol header to an entry
    /// point started with `;proxy_protocol` (`docs/ref/proxy-protocol.md`). Neither field set
    /// trusts nobody. `insecure: true` trusts every peer and is a posture change in a plan.
    #[serde(default)]
    pub proxy_protocol: Option<Value>,
    /// `{read_secs, write_secs, idle_secs, header_secs}`: each is applied or refused with
    /// `unsupported_setting` (`docs/ref/entry-policy.md`).
    #[serde(default)]
    pub timeouts: Option<Value>,
    /// `{max_concurrent_streams}` of HTTP/2 connections.
    #[serde(default)]
    pub http2: Option<Value>,
    /// `{to, permanent}`: answer every request with a redirect to the entry point `to`.
    #[serde(default)]
    pub redirect: Option<Value>,
    /// Accept an encoded `/` (`%2F`) in the path. It is kept as an escape inside its segment,
    /// never turned into a separator. A posture change in a plan.
    #[serde(default)]
    pub allow_encoded_slash: Option<bool>,
    /// Largest request head (request line and headers) in bytes.
    #[serde(default)]
    pub max_header_bytes: Option<u32>,
    /// What to do with request headers whose name holds an underscore. Absent: `keep`.
    #[serde(default)]
    pub underscore_headers: Option<UnderscoreHeaders>,
}
