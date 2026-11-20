//! The `strip_prefix` middleware: removes the first listed prefix the path starts with, whole
//! segments only, and tells the upstream in `X-Forwarded-Prefix`. Full reference:
//! `docs/ref/mw-rewrite.md`.
//!
//! ```json
//! { "name": "no-api", "type": "strip_prefix", "prefixes": ["/api", "/v1"] }
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

use super::path_rewrite::{self as rewrite, FORWARDED_PREFIX, Refusal};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use pingora::http::RequestHeader;
use podgate_model::Declared;

const KIND: &str = "strip_prefix";

/// The configuration of a `strip_prefix` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Prefixes, each starting with `/`; the first one that matches is removed.
    pub prefixes: Vec<String>,
}

/// A compiled `strip_prefix` middleware.
#[derive(Debug)]
pub struct StripPrefix {
    name: Box<str>,
    /// Normalized, without a trailing slash, never empty.
    prefixes: Box<[Box<str>]>,
}

/// What is left of `path` after `prefix`, when `prefix` is a whole-segment prefix of it.
fn strip<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

impl StripPrefix {
    fn rewrite(&self, request: &mut RequestHeader) -> Result<(), Refusal> {
        let Some(path) = rewrite::current(request) else {
            return Ok(());
        };
        let Some((prefix, rest)) = self
            .prefixes
            .iter()
            .find_map(|prefix| strip(prefix, path).map(|rest| (prefix, rest)))
        else {
            return Ok(());
        };
        let rest = if rest.is_empty() { "/" } else { rest }.to_owned();
        rewrite::commit(request, &rest)?;
        rewrite::add_forwarded_prefix(request, prefix)
    }
}

impl Kind for StripPrefix {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| rewrite::invalid(KIND, err))?;
        if config.prefixes.is_empty() || config.prefixes.len() > rewrite::MAX_ENTRIES {
            return Err(rewrite::invalid(
                KIND,
                format!("`prefixes` needs 1 to {} entries", rewrite::MAX_ENTRIES),
            ));
        }
        let mut prefixes: Vec<Box<str>> = Vec::with_capacity(config.prefixes.len());
        for raw in &config.prefixes {
            let normalized = rewrite::literal(KIND, "prefix", raw)?;
            let prefix = normalized.trim_end_matches('/');
            if prefix.is_empty() {
                return Err(rewrite::invalid(
                    KIND,
                    format!("prefix {raw:?} is the root and strips nothing"),
                ));
            }
            prefixes.push(prefix.into());
        }
        Ok(Self {
            name: declared.name.clone(),
            prefixes: prefixes.into(),
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        rewrite::drop_client_copies(cx, &[FORWARDED_PREFIX]);
        Ok(Flow::Continue)
    }

    fn upstream_request(
        &self,
        request: &mut RequestHeader,
        _state: &mut Self::State,
    ) -> pingora::Result<()> {
        rewrite::settle(KIND, &self.name, self.rewrite(request))
    }

    fn describe(&self) -> Value {
        json!({ "prefixes": self.prefixes })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn stage(prefixes: &[&str]) -> StripPrefix {
        StripPrefix {
            name: "m".into(),
            prefixes: prefixes
                .iter()
                .map(|raw| {
                    rewrite::literal(KIND, "prefix", raw)
                        .expect("prefix")
                        .trim_end_matches('/')
                        .into()
                })
                .collect(),
        }
    }

    fn run(prefixes: &[&str], path: &str) -> (String, Option<String>) {
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        stage(prefixes).rewrite(&mut request).expect("rewrites");
        let target = request
            .uri
            .path_and_query()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_default();
        let header = request
            .headers
            .get(FORWARDED_PREFIX)
            .map(|value| value.to_str().expect("ascii").to_owned());
        (target, header)
    }

    #[test]
    fn strip_prefix_whole_segments() {
        for (prefixes, path, expected, header) in [
            (&["/api"][..], "/api/users", "/users", Some("/api")),
            (&["/api"], "/api/users?x=1", "/users?x=1", Some("/api")),
            (&["/api/"], "/api/users", "/users", Some("/api")),
            (&["/api"], "/apix", "/apix", None),
            (&["/api"], "/apix/users", "/apix/users", None),
            (&["/api"], "/other/api", "/other/api", None),
            (&["/api", "/v1"], "/v1/x", "/x", Some("/v1")),
            (&["/api", "/api/v1"], "/api/v1/x", "/v1/x", Some("/api")),
            (&["/api/v1", "/api"], "/api/v1/x", "/x", Some("/api/v1")),
        ] {
            let (target, forwarded) = run(prefixes, path);
            assert_eq!(target, expected, "{prefixes:?} {path}");
            assert_eq!(forwarded.as_deref(), header, "{prefixes:?} {path}");
        }
    }

    #[test]
    fn strip_prefix_to_root() {
        assert_eq!(run(&["/api"], "/api").0, "/");
        assert_eq!(run(&["/api"], "/api/").0, "/");
        assert_eq!(run(&["/api"], "/api?x=1").0, "/?x=1");
    }
}
