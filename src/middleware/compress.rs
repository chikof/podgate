//! The `compress` middleware: which response encodings podgate applies (Traefik's `compress`,
//! Caddy's `encode`). Without it a chain gets the platform default, gzip of text-like responses;
//! with it the chain gets exactly this configuration, and `algorithms: []` turns compression off.
//!
//! ```json
//! { "name": "z", "type": "compress", "algorithms": ["zstd", "br", "gzip"], "min_bytes": 1024,
//!   "include_content_types": ["text/*", "application/json"], "exclude_content_types": ["text/css"],
//!   "level": 4 }
//! ```
//!
//! The middleware has no hook of its own: the proxy reads [`Compress::settings`] of the chain
//! ([`super::compression`]) when the upstream's response head arrives, after every
//! `response_head` hook (so a limit judges what the upstream sent) and before the `response`
//! hooks. The encoders, the negotiation and the memory rules are in [`crate::compress`].

use serde::Deserialize;
use serde_json::{Value, json};

use super::{CompileCx, Kind};
use crate::compile::Invalid;
use crate::compress::{
    Algorithm, DEFAULT_LEVEL, DEFAULT_MIN_BYTES, MAX_LEVEL, MediaPattern, Settings,
};
use podgate_model::Declared;

/// The most entries of a content-type list.
const MAX_PATTERNS: usize = 64;

/// The configuration of a `compress` middleware.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "default_algorithms")]
    algorithms: Vec<String>,
    min_bytes: Option<u64>,
    include_content_types: Option<Vec<String>>,
    exclude_content_types: Option<Vec<String>>,
    level: Option<u8>,
}

fn default_algorithms() -> Vec<String> {
    vec!["gzip".to_owned()]
}

/// A compiled `compress` middleware.
#[derive(Debug)]
pub struct Compress {
    settings: Settings,
}

impl Compress {
    /// What the chain compresses with.
    #[must_use]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
}

fn invalid(message: impl std::fmt::Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("compress: {message}"))
}

fn algorithm(name: &str) -> Result<Algorithm, Invalid> {
    match name {
        "gzip" => Ok(Algorithm::Gzip),
        "brotli" | "br" => Ok(Algorithm::Brotli),
        "zstd" => Ok(Algorithm::Zstd),
        other => Err(invalid(format!(
            "unknown algorithm {other:?}: use gzip, brotli or zstd"
        ))),
    }
}

fn patterns(name: &str, list: Option<Vec<String>>) -> Result<Option<Vec<MediaPattern>>, Invalid> {
    let Some(list) = list else {
        return Ok(None);
    };
    if list.len() > MAX_PATTERNS {
        return Err(invalid(format!(
            "{name} has more than {MAX_PATTERNS} entries"
        )));
    }
    list.iter()
        .map(|text| {
            MediaPattern::parse(text).map_err(|why| invalid(format!("{name}: {text:?}: {why}")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

impl Kind for Compress {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(Value::Object(declared.config.clone())).map_err(invalid)?;
        let mut algorithms = Vec::new();
        for name in &config.algorithms {
            let next = algorithm(name)?;
            if algorithms.contains(&next) {
                return Err(invalid(format!("algorithm {name:?} is listed twice")));
            }
            algorithms.push(next);
        }
        let level = config.level.unwrap_or(DEFAULT_LEVEL);
        if !(1..=MAX_LEVEL).contains(&level) {
            return Err(invalid(format!("level is 1 to {MAX_LEVEL}")));
        }
        Ok(Self {
            settings: Settings {
                algorithms,
                min_bytes: config.min_bytes.unwrap_or(DEFAULT_MIN_BYTES),
                include: patterns("include_content_types", config.include_content_types)?,
                exclude: patterns("exclude_content_types", config.exclude_content_types)?
                    .unwrap_or_default(),
                level,
            },
        })
    }

    fn describe(&self) -> Value {
        let settings = &self.settings;
        json!({
            "algorithms": settings.algorithms.iter().map(|a| a.token()).collect::<Vec<_>>(),
            "min_bytes": settings.min_bytes,
            "include_content_types": settings.include.as_ref().map(|list| {
                list.iter().map(MediaPattern::render).collect::<Vec<_>>()
            }),
            "exclude_content_types": settings.exclude.iter().map(MediaPattern::render).collect::<Vec<_>>(),
            "level": settings.level,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn compile(config: &Value) -> Result<Compress, Invalid> {
        let mut declared = json!({ "name": "z", "type": "compress" });
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
        Compress::compile(
            &declared,
            &mut CompileCx {
                app: &app,
                engine: &mut engine,
            },
        )
    }

    #[test]
    fn defaults_are_the_platform_default() {
        let compress = compile(&json!({})).expect("compiles");
        let settings = compress.settings();
        assert_eq!(settings.algorithms, [Algorithm::Gzip]);
        assert_eq!(settings.min_bytes, 1024);
        assert_eq!(settings.level, DEFAULT_LEVEL);
        assert!(settings.include.is_none() && settings.exclude.is_empty());
    }

    #[test]
    fn an_empty_algorithm_list_turns_compression_off() {
        let compress = compile(&json!({ "algorithms": [] })).expect("compiles");
        assert!(compress.settings().algorithms.is_empty());
    }

    #[test]
    fn order_and_aliases_are_kept() {
        let compress = compile(&json!({ "algorithms": ["zstd", "br", "gzip"] })).expect("compiles");
        assert_eq!(
            compress.settings().algorithms,
            [Algorithm::Zstd, Algorithm::Brotli, Algorithm::Gzip]
        );
        assert_eq!(
            compress.describe()["algorithms"],
            json!(["zstd", "br", "gzip"])
        );
    }

    #[test]
    fn bad_declarations_are_refused() {
        for config in [
            json!({ "algorithms": ["deflate"] }),
            json!({ "algorithms": ["gzip", "gzip"] }),
            json!({ "level": 0 }),
            json!({ "level": 4 }),
            json!({ "min_bytes": -1 }),
            json!({ "include_content_types": ["text"] }),
            json!({ "exclude_content_types": ["*/*"] }),
            json!({ "windows": 22 }),
        ] {
            let err = compile(&config).expect_err("refused");
            assert_eq!(err.code, "invalid_middleware", "{config}");
        }
    }
}
