//! The `wasm` middleware: a proxy-wasm module that runs on the request head with fuel and
//! memory limits. The engine, the host ABI and the limits are in [`crate::wasm`]; this file is
//! the middleware kind around it.
//!
//! ```json
//! { "name": "check", "type": "wasm", "wasm_base64": "...", "fuel": 1000000, "max_memory_bytes": 1048576 }
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use crate::wasm::{CompiledFilter, Reason, run_filter};
use podgate_model::Declared;

/// The configuration of a `wasm` middleware.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The module in the WebAssembly binary format, standard base64.
    pub wasm_base64: String,
    /// Instructions the filter may execute per request; running out ends the request with `500`.
    pub fuel: u64,
    /// Most bytes of linear memory the filter may hold; growing past it ends the request with
    /// `500`.
    pub max_memory_bytes: u64,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field(
                "wasm_base64",
                &format_args!("{} bytes", self.wasm_base64.len()),
            )
            .field("fuel", &self.fuel)
            .field("max_memory_bytes", &self.max_memory_bytes)
            .finish()
    }
}

/// A compiled `wasm` middleware.
#[derive(Debug)]
pub struct Wasm {
    filter: Arc<CompiledFilter>,
    fuel: u64,
    max_memory_bytes: u64,
    digest: u64,
}

impl Kind for Wasm {
    type State = ();

    fn compile(declared: &Declared, cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_middleware", format!("wasm: {err}")))?;
        let filter = cx
            .engine
            .compile((&cx.app.id, &cx.app.tenant), &config)
            .map_err(Reason::into_invalid)?;
        let mut hasher = std::hash::DefaultHasher::new();
        config.wasm_base64.hash(&mut hasher);
        config.fuel.hash(&mut hasher);
        config.max_memory_bytes.hash(&mut hasher);
        Ok(Self {
            filter: Arc::new(filter),
            fuel: config.fuel,
            max_memory_bytes: config.max_memory_bytes,
            digest: hasher.finish(),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let answered = run_filter(
            cx.session,
            &self.filter,
            cx.tenant,
            cx.executor,
            cx.capacity_refusal,
        )
        .await?;
        Ok(if answered {
            Flow::Respond
        } else {
            Flow::Continue
        })
    }

    /// A filter that is gone is a check that is gone; one whose module or limits differ may check
    /// less than before, which a diff of compiled modules cannot tell.
    fn posture(&self, new: Option<&Self>) -> Vec<&'static str> {
        match new {
            None => vec!["filters_removed"],
            Some(new) if new.digest != self.digest => vec!["filters_changed"],
            Some(_) => Vec::new(),
        }
    }

    fn describe(&self) -> Value {
        json!({ "fuel": self.fuel, "max_memory_bytes": self.max_memory_bytes })
    }
}
