//! The `replace_path` middleware: replaces the whole path with a fixed one and tells the
//! upstream the original in `X-Replaced-Path`. Full reference: `docs/ref/mw-rewrite.md`.
//!
//! ```json
//! { "name": "to-index", "type": "replace_path", "path": "/index.html" }
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

use super::path_rewrite::{self as rewrite, REPLACED_PATH, Refusal};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use pingora::http::RequestHeader;
use podgate_model::Declared;

const KIND: &str = "replace_path";

/// The configuration of a `replace_path` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The new path, starting with `/`.
    pub path: String,
}

/// A compiled `replace_path` middleware.
#[derive(Debug)]
pub struct ReplacePath {
    name: Box<str>,
    /// Normalized when the snapshot compiles.
    path: Box<str>,
}

/// Per-request state: the path as the client sent it.
#[derive(Debug, Default)]
pub struct State {
    original: Box<str>,
}

impl ReplacePath {
    fn rewrite(&self, request: &mut RequestHeader, original: &str) -> Result<(), Refusal> {
        if rewrite::current(request).is_none() {
            return Ok(());
        }
        rewrite::commit(request, &self.path)?;
        rewrite::keep_replaced_path(request, original)
    }
}

impl Kind for ReplacePath {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| rewrite::invalid(KIND, err))?;
        let path = rewrite::literal(KIND, "path", &config.path)?;
        Ok(Self {
            name: declared.name.clone(),
            path: path.into(),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, state: &mut State) -> pingora::Result<Flow> {
        rewrite::drop_client_copies(cx, &[REPLACED_PATH]);
        state.original = cx.session.req_header().uri.path().into();
        Ok(Flow::Continue)
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        state: &mut State,
    ) -> pingora::Result<()> {
        rewrite::settle(KIND, &self.name, self.rewrite(request, &state.original))
    }

    fn describe(&self) -> Value {
        json!({ "path": &*self.path })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn replace_path_works() {
        for (replacement, path, expected) in [
            ("/new", "/old/thing", "/new"),
            ("/new", "/old?x=1", "/new?x=1"),
            ("/", "/old", "/"),
            ("/a//b/../c", "/old", "/a/c"),
        ] {
            let stage = ReplacePath {
                name: "m".into(),
                path: rewrite::literal(KIND, "path", replacement)
                    .expect("path")
                    .into(),
            };
            let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
            let original = request.uri.path().to_owned();
            stage.rewrite(&mut request, &original).expect("rewrites");
            let target = request.uri.path_and_query().map(|target| target.as_str());
            assert_eq!(target, Some(expected), "{replacement} for {path}");
            let header = request.headers.get(REPLACED_PATH).expect("header");
            assert_eq!(header.to_str().expect("ascii"), original);
        }
    }
}
