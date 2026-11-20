//! The `strip_prefix_regex` middleware: removes the text a regular expression matches at the
//! start of the path, and tells the upstream in `X-Forwarded-Prefix`. Full reference:
//! `docs/ref/mw-rewrite.md`.
//!
//! ```json
//! { "name": "no-tenant", "type": "strip_prefix_regex", "regexes": ["/t-[a-z0-9]+"] }
//! ```

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{Value, json};

use super::path_rewrite::{self as rewrite, FORWARDED_PREFIX, Refusal};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use pingora::http::RequestHeader;
use podgate_model::Declared;

const KIND: &str = "strip_prefix_regex";

/// The configuration of a `strip_prefix_regex` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Regular expressions (Rust `regex` syntax, unanchored); the first that matches a non-empty
    /// text at the start of the path is removed.
    pub regexes: Vec<String>,
}

/// A compiled `strip_prefix_regex` middleware.
#[derive(Debug)]
pub struct StripPrefixRegex {
    name: Box<str>,
    regexes: Box<[Regex]>,
}

impl StripPrefixRegex {
    fn rewrite(&self, request: &mut RequestHeader) -> Result<(), Refusal> {
        let Some(path) = rewrite::current(request) else {
            return Ok(());
        };
        let Some((prefix, rest)) = self.regexes.iter().find_map(|regex| {
            let found = regex.find(path)?;
            (found.start() == 0 && found.end() > 0)
                .then(|| (found.as_str().to_owned(), path[found.end()..].to_owned()))
        }) else {
            return Ok(());
        };
        rewrite::commit(request, &rest)?;
        rewrite::add_forwarded_prefix(request, &prefix)
    }
}

impl Kind for StripPrefixRegex {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| rewrite::invalid(KIND, err))?;
        if config.regexes.is_empty() || config.regexes.len() > rewrite::MAX_ENTRIES {
            return Err(rewrite::invalid(
                KIND,
                format!("`regexes` needs 1 to {} entries", rewrite::MAX_ENTRIES),
            ));
        }
        let mut regexes = Vec::with_capacity(config.regexes.len());
        for pattern in &config.regexes {
            rewrite::bounded(KIND, "regex", pattern)?;
            if pattern.is_empty() {
                return Err(rewrite::invalid(KIND, "a regex must not be empty"));
            }
            regexes.push(
                RegexBuilder::new(pattern)
                    .size_limit(rewrite::REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|err| rewrite::invalid(KIND, format!("regex {pattern:?}: {err}")))?,
            );
        }
        Ok(Self {
            name: declared.name.clone(),
            regexes: regexes.into(),
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
        let patterns: Vec<&str> = self.regexes.iter().map(Regex::as_str).collect();
        json!({ "regexes": patterns })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn run(patterns: &[&str], path: &str) -> (String, Option<String>) {
        let stage = StripPrefixRegex {
            name: "m".into(),
            regexes: patterns
                .iter()
                .map(|pattern| Regex::new(pattern).expect("regex"))
                .collect(),
        };
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        stage.rewrite(&mut request).expect("rewrites");
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
    fn strip_prefix_regex_works() {
        for (patterns, path, expected, header) in [
            (
                &["^/t-[a-z0-9]+"][..],
                "/t-acme/users",
                "/users",
                Some("/t-acme"),
            ),
            (
                &["/t-[a-z0-9]+"],
                "/t-acme/users?x=1",
                "/users?x=1",
                Some("/t-acme"),
            ),
            (&["^/t-[a-z0-9]+"], "/t-acme", "/", Some("/t-acme")),
            (&["^/api"], "/apix", "/x", Some("/api")),
            (&["^/api"], "/other/api", "/other/api", None),
            (&["/api"], "/other/api", "/other/api", None),
            (&["^/a", "^/b"], "/b/x", "/x", Some("/b")),
            (&["^$"], "/b/x", "/b/x", None),
        ] {
            let (target, forwarded) = run(patterns, path);
            assert_eq!(target, expected, "{patterns:?} {path}");
            assert_eq!(forwarded.as_deref(), header, "{patterns:?} {path}");
        }
    }
}
