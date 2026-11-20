//! The `add_prefix` middleware: puts a fixed prefix in front of the path. Full reference:
//! `docs/ref/mw-rewrite.md`.
//!
//! ```json
//! { "name": "api", "type": "add_prefix", "prefix": "/api" }
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

use super::path_rewrite::{self as rewrite, Refusal};
use super::{CompileCx, Kind};
use crate::compile::Invalid;
use pingora::http::RequestHeader;
use podgate_model::Declared;

const KIND: &str = "add_prefix";

/// The configuration of an `add_prefix` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The prefix, starting with `/`.
    pub prefix: String,
}

/// A compiled `add_prefix` middleware.
#[derive(Debug)]
pub struct AddPrefix {
    name: Box<str>,
    prefix: Box<str>,
}

impl AddPrefix {
    fn rewrite(&self, request: &mut RequestHeader) -> Result<(), Refusal> {
        let Some(path) = rewrite::current(request) else {
            return Ok(());
        };
        let joined = format!("{}{path}", self.prefix);
        rewrite::commit(request, &joined)
    }
}

impl Kind for AddPrefix {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| rewrite::invalid(KIND, err))?;
        let prefix = rewrite::literal(KIND, "prefix", &config.prefix)?;
        Ok(Self {
            name: declared.name.clone(),
            prefix: prefix.into(),
        })
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        _state: &mut Self::State,
    ) -> pingora::Result<()> {
        rewrite::settle(KIND, &self.name, self.rewrite(request))
    }

    fn describe(&self) -> Value {
        json!({ "prefix": &*self.prefix })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn add(prefix: &str, path: &str) -> String {
        let stage = AddPrefix {
            name: "m".into(),
            prefix: rewrite::literal(KIND, "prefix", prefix)
                .expect("prefix")
                .into(),
        };
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        stage.rewrite(&mut request).expect("rewrites");
        request
            .uri
            .path_and_query()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_default()
    }

    #[test]
    fn add_prefix_works() {
        for (prefix, path, expected) in [
            ("/api", "/users", "/api/users"),
            ("/api", "/", "/api/"),
            ("/api/", "/users", "/api/users"),
            ("/api", "/users?x=1", "/api/users?x=1"),
            ("/a/b", "/c/d/", "/a/b/c/d/"),
            ("/a/..", "/c", "/c"),
        ] {
            assert_eq!(add(prefix, path), expected, "{prefix} + {path}");
        }
    }
}
