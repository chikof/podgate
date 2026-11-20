//! The `content_type` middleware: Traefik's `contentType`, reduced to the one setting that is
//! safe. Pingora never sniffs a response's content type, so a response without `Content-Type`
//! leaves podgate without one, and `auto_detect: false` (the default) is what already happens.
//! `auto_detect: true` is refused: guessing a type from the body is a vulnerability class, not a
//! feature, and a setting podgate cannot honour is never ignored.
//!
//! ```json
//! { "name": "c", "type": "content_type", "auto_detect": false }
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Kind};
use crate::compile::Invalid;
use podgate_model::Declared;

/// The configuration of a `content_type` middleware.
#[derive(Debug, Clone, Copy, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Only `false` is accepted.
    #[serde(default)]
    pub auto_detect: bool,
}

/// A compiled `content_type` middleware. It has no hook: leaving the header alone is the
/// behaviour.
#[derive(Debug)]
pub struct ContentType;

impl Kind for ContentType {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| Invalid::new("invalid_middleware", format!("content_type: {err}")))?;
        if config.auto_detect {
            return Err(Invalid::new(
                "unsupported_setting",
                "content_type: `auto_detect: true` is not supported: podgate never guesses a content type from the body",
            ));
        }
        Ok(Self)
    }

    fn describe(&self) -> Value {
        json!({ "auto_detect": false })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn compile(config: &Value) -> Result<ContentType, Invalid> {
        let mut declared = json!({ "name": "c", "type": "content_type" });
        if let (Some(object), Some(extra)) = (declared.as_object_mut(), config.as_object()) {
            object.extend(extra.clone());
        }
        let declared: Declared = serde_json::from_value(declared).expect("declared");
        let app: podgate_model::App = serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": { "mode": "acme" },
            "routers": [], "revisions": []
        }))
        .expect("app");
        let mut engine = crate::wasm::Compiler::default();
        ContentType::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    #[test]
    fn sniffing_is_refused_and_everything_else_is_strict() {
        assert!(compile(&json!({})).is_ok());
        assert!(compile(&json!({ "auto_detect": false })).is_ok());
        let sniff = compile(&json!({ "auto_detect": true })).expect_err("sniffing");
        assert_eq!(sniff.code, "unsupported_setting");
        let unknown = compile(&json!({ "detect": true })).expect_err("unknown field");
        assert_eq!(unknown.code, "invalid_middleware");
    }
}
