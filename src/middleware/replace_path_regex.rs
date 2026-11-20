//! The `replace_path_regex` middleware: replaces what a regular expression matches in the path,
//! and tells the upstream the original in `X-Replaced-Path`. Full reference:
//! `docs/ref/mw-rewrite.md`.
//!
//! ```json
//! { "name": "v1", "type": "replace_path_regex",
//!   "regex": "^/api/(.*)", "replacement": "/v1/$1" }
//! ```

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use serde_json::{Value, json};

use super::path_rewrite::{self as rewrite, REPLACED_PATH, Refusal};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use pingora::http::RequestHeader;
use podgate_model::Declared;

const KIND: &str = "replace_path_regex";

/// The configuration of a `replace_path_regex` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// A regular expression (Rust `regex` syntax, unanchored).
    pub regex: String,
    /// What replaces each match; `$1`, `$name` and `${name}` insert capture groups.
    pub replacement: String,
}

/// A group a replacement template inserts.
#[derive(Debug, PartialEq, Eq)]
enum Reference<'a> {
    Index(usize),
    Name(&'a str),
}

fn is_name_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_')
}

/// The groups `template` inserts, read the way `regex::Captures::expand` reads it: `$$` is a
/// dollar sign, `$name` takes the longest run of letters, digits and `_`, `${name}` takes
/// anything up to the closing brace, and a `$` that starts neither is literal.
fn references(template: &str) -> Vec<Reference<'_>> {
    let bytes = template.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = template[at..].find('$') {
        let start = at + offset + 1;
        at = start;
        let (name, braced) = match bytes.get(start) {
            Some(b'$') => {
                at = start + 1;
                continue;
            }
            Some(b'{') => match template[start + 1..].find('}') {
                Some(close) => {
                    at = start + 1 + close + 1;
                    (&template[start + 1..start + 1 + close], true)
                }
                None => continue,
            },
            _ => {
                let len = bytes[start..]
                    .iter()
                    .take_while(|byte| is_name_byte(**byte))
                    .count();
                at = start + len;
                (&template[start..start + len], false)
            }
        };
        if name.is_empty() && !braced {
            continue;
        }
        found.push(match name.parse() {
            Ok(index) => Reference::Index(index),
            Err(_) => Reference::Name(name),
        });
    }
    found
}

/// A compiled `replace_path_regex` middleware.
#[derive(Debug)]
pub struct ReplacePathRegex {
    name: Box<str>,
    regex: Regex,
    replacement: Box<str>,
    /// How many groups the template inserts: bounds what one match can expand to.
    inserts: usize,
}

/// Per-request state: the path as the client sent it.
#[derive(Debug, Default)]
pub struct State {
    original: Box<str>,
}

impl ReplacePathRegex {
    /// The path after the replacement, or `None` when the regular expression matches nothing.
    fn replaced(&self, path: &str) -> Result<Option<String>, Refusal> {
        let limit = rewrite::limit(path.len());
        let mut out = String::new();
        let mut last = 0;
        for captures in self.regex.captures_iter(path) {
            let Some(whole) = captures.get(0) else {
                continue;
            };
            let worst = self.replacement.len() + self.inserts * whole.len();
            if out.len() + (whole.start() - last) + worst + (path.len() - whole.end()) > limit {
                return Err(Refusal::TooLong);
            }
            out.push_str(&path[last..whole.start()]);
            captures.expand(&self.replacement, &mut out);
            last = whole.end();
        }
        if last == 0 && out.is_empty() {
            return Ok(None);
        }
        out.push_str(&path[last..]);
        Ok(Some(out))
    }

    fn rewrite(&self, request: &mut RequestHeader, original: &str) -> Result<(), Refusal> {
        let Some(path) = rewrite::current(request) else {
            return Ok(());
        };
        let Some(replaced) = self.replaced(path)? else {
            return Ok(());
        };
        rewrite::commit(request, &replaced)?;
        rewrite::keep_replaced_path(request, original)
    }
}

impl Kind for ReplacePathRegex {
    type State = State;

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| rewrite::invalid(KIND, err))?;
        rewrite::bounded(KIND, "regex", &config.regex)?;
        rewrite::bounded(KIND, "replacement", &config.replacement)?;
        if config.regex.is_empty() {
            return Err(rewrite::invalid(KIND, "the regex must not be empty"));
        }
        let regex = RegexBuilder::new(&config.regex)
            .size_limit(rewrite::REGEX_SIZE_LIMIT)
            .build()
            .map_err(|err| rewrite::invalid(KIND, format!("regex {:?}: {err}", config.regex)))?;
        rewrite::template_characters(KIND, &config.replacement)?;
        let inserted = references(&config.replacement);
        for reference in &inserted {
            let known = match reference {
                Reference::Index(index) => *index < regex.captures_len(),
                Reference::Name(name) => {
                    regex.capture_names().flatten().any(|group| group == *name)
                }
            };
            if !known {
                let which = match reference {
                    Reference::Index(index) => format!("${index}"),
                    Reference::Name(name) => format!("${{{name}}}"),
                };
                return Err(rewrite::invalid(
                    KIND,
                    format!(
                        "the replacement uses {which}, which the regex does not define ({} groups besides the whole match)",
                        regex.captures_len() - 1
                    ),
                ));
            }
        }
        Ok(Self {
            name: declared.name.clone(),
            regex,
            inserts: inserted.len(),
            replacement: config.replacement.into(),
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
        json!({ "regex": self.regex.as_str(), "replacement": &*self.replacement })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn stage(pattern: &str, replacement: &str) -> ReplacePathRegex {
        ReplacePathRegex {
            name: "m".into(),
            regex: Regex::new(pattern).expect("regex"),
            replacement: replacement.into(),
            inserts: references(replacement).len(),
        }
    }

    fn run(pattern: &str, replacement: &str, path: &str) -> Result<String, Refusal> {
        let mut request = RequestHeader::build("GET", path.as_bytes(), None).expect("request");
        stage(pattern, replacement).rewrite(&mut request, path)?;
        Ok(request
            .uri
            .path_and_query()
            .map(|target| target.as_str().to_owned())
            .unwrap_or_default())
    }

    #[test]
    fn replace_path_regex_works() {
        for (pattern, replacement, path, expected) in [
            ("^/api/(.*)", "/v1/$1", "/api/users", "/v1/users"),
            ("^/api/(.*)", "/v1/$1", "/api/users?x=1", "/v1/users?x=1"),
            ("^/api/(.*)", "/v1/$1", "/other", "/other"),
            (
                "^/(?<a>[a-z]+)/(?<b>[a-z]+)$",
                "/${b}/${a}",
                "/one/two",
                "/two/one",
            ),
            ("a", "b", "/banana", "/bbnbnb"),
            ("^/old", "", "/old/x", "/x"),
            ("^/old/?", "", "/old/", "/"),
            ("^/x$", "$$", "/x", "/$"),
            ("^/x$", "/$0$0", "/x", "/x/x"),
        ] {
            let got = run(pattern, replacement, path).expect("rewrites");
            assert_eq!(got, expected, "{pattern} {replacement} {path}");
        }
    }

    #[test]
    fn the_template_is_read_like_the_regex_crate_reads_it() {
        use Reference::{Index, Name};
        assert_eq!(
            references("/$1/${name}/$name_2/$$1/$/${open"),
            [Index(1), Name("name"), Name("name_2")]
        );
        assert_eq!(references("$1a ${1} ${}"), [Name("1a"), Index(1), Name("")]);
    }

    #[test]
    fn an_expansion_far_longer_than_the_path_is_refused() {
        let long = format!("/{}", "a".repeat(2000));
        assert_eq!(run(".", &"$0".repeat(100), &long), Err(Refusal::TooLong));
    }
}
