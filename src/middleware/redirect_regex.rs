//! The `redirect_regex` middleware: rewrites the request URL with a regular expression and
//! answers with a redirect to the result.
//!
//! ```json
//! { "name": "moved", "type": "redirect_regex", "regex": "^http://old\\.test/(.*)",
//!   "replacement": "https://new.test/$1", "permanent": true }
//! ```
//!
//! - The regex runs over `scheme://host[:port]/path?query` ([`super::redirect::Origin::url`]):
//!   the connection's real scheme, the normalized host and the normalized path. It is
//!   unanchored, like Traefik's: write `^` and `$` when you mean them. The `regex` crate is
//!   linear time, so a pattern cannot be made to burn CPU; its compiled size is capped.
//! - A request the regex does not match, or whose rewritten URL equals the original, is passed
//!   on, so a rule that rewrites to itself cannot loop.
//! - The replacement is checked at compile time: `$1`, `${1}`, `$name` and `${name}` name groups
//!   the regex has (a missing group is `invalid_middleware`, where Traefik writes nothing), `$$`
//!   is a dollar sign, any other `$` is refused, and a literal control character is refused.
//!   A group that did not take part in the match is empty.
//! - The result goes through [`super::redirect::finish`]: control characters (also as percent
//!   escapes) are `400`, only `http`, `https`, protocol-relative and path targets are sent.
//!
//! A replacement may name another host. Traefik allows it, because a tenant moves domains, and
//! so does podgate; the author owns the target. A group that captures the *path* and is
//! placed in the host position (`https://$1/`) lets a visitor choose where the redirect goes;
//! write the host literally or capture it from the host part of the URL.

use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use super::redirect::{Decision, MAX_LOCATION, Origin, Refused, answer, has_control};
use super::{CompileCx, Flow, Kind, RequestCx};
use crate::compile::Invalid;
use podgate_model::Declared;

/// Compiled size a pattern may have, the same cap `host_regexp` and `path_regexp` use.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The configuration of a `redirect_regex` middleware.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The pattern, over `scheme://host[:port]/path?query`.
    pub regex: String,
    /// The target, with `$1`, `${1}`, `$name` and `${name}` for groups.
    pub replacement: String,
    /// `301` instead of `302`.
    #[serde(default)]
    pub permanent: bool,
}

/// One piece of a parsed replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Group(usize),
}

/// A compiled `redirect_regex` middleware.
#[derive(Debug)]
pub struct RedirectRegex {
    regex: Regex,
    parts: Vec<Part>,
    source: Config,
}

fn name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

/// Splits `replacement` into literals and group references, checking every reference against
/// `regex`.
fn parse_replacement(regex: &Regex, replacement: &str) -> Result<Vec<Part>, String> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut rest = replacement;
    while let Some(at) = rest.find('$') {
        literal.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if let Some(escaped) = after.strip_prefix('$') {
            literal.push('$');
            rest = escaped;
            continue;
        }
        let (name, tail) = match after.strip_prefix('{') {
            Some(braced) => {
                let (name, tail) = braced
                    .split_once('}')
                    .ok_or_else(|| "`${` has no closing `}`".to_owned())?;
                (name, tail)
            }
            None => {
                let end = after.find(|ch| !name_char(ch)).unwrap_or(after.len());
                after.split_at(end)
            }
        };
        if name.is_empty() || !name.chars().all(name_char) {
            return Err("a `$` must start `$name`, `${name}`, `$1` or be written `$$`".to_owned());
        }
        let index = if name.bytes().all(|b| b.is_ascii_digit()) {
            let index: usize = name
                .parse()
                .map_err(|_| format!("group {name} does not exist"))?;
            (index < regex.captures_len()).then_some(index)
        } else {
            regex
                .capture_names()
                .position(|candidate| candidate == Some(name))
        };
        let index = index.ok_or_else(|| format!("the regex has no group {name}"))?;
        if !literal.is_empty() {
            parts.push(Part::Literal(std::mem::take(&mut literal)));
        }
        parts.push(Part::Group(index));
        rest = tail;
    }
    literal.push_str(rest);
    if has_control(&literal) {
        return Err("the replacement has a control character".to_owned());
    }
    if !literal.is_empty() {
        parts.push(Part::Literal(literal));
    }
    Ok(parts)
}

impl RedirectRegex {
    /// The rewritten URL, or `None` when the regex does not match `url`.
    fn rewrite(&self, url: &str) -> Result<Option<String>, Refused> {
        let mut out = String::new();
        let mut copied = 0;
        let mut matched = false;
        for captures in self.regex.captures_iter(url) {
            let Some(whole) = captures.get(0) else {
                continue;
            };
            matched = true;
            out.push_str(&url[copied..whole.start()]);
            for part in &self.parts {
                match part {
                    Part::Literal(text) => out.push_str(text),
                    Part::Group(index) => {
                        if let Some(group) = captures.get(*index) {
                            out.push_str(group.as_str());
                        }
                    }
                }
            }
            copied = whole.end();
            if out.len() > MAX_LOCATION {
                return Err(Refused::TooLong);
            }
        }
        if !matched {
            return Ok(None);
        }
        out.push_str(&url[copied..]);
        Ok(Some(out))
    }

    /// What to do with a request that arrived as `origin`.
    fn decide(&self, origin: &Origin) -> Decision {
        let url = origin.url();
        match self.rewrite(&url) {
            Ok(None) => Decision::Pass,
            Ok(Some(target)) if target == url => Decision::Pass,
            Ok(Some(target)) => Decision::target(&target),
            Err(refused) => Decision::Refuse(refused),
        }
    }
}

impl Kind for RedirectRegex {
    type State = ();

    fn compile(declared: &Declared, _cx: &mut CompileCx<'_>) -> Result<Self, Invalid> {
        let invalid = |message: String| {
            Invalid::new("invalid_middleware", format!("redirect_regex: {message}"))
        };
        let config: Config = serde_json::from_value(Value::Object(declared.config.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        let regex = regex::RegexBuilder::new(&config.regex)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|err| invalid(format!("regex: {err}")))?;
        if config.replacement.is_empty() {
            return Err(invalid("replacement is empty".to_owned()));
        }
        let parts = parse_replacement(&regex, &config.replacement)
            .map_err(|err| invalid(format!("replacement: {err}")))?;
        Ok(Self {
            regex,
            parts,
            source: config,
        })
    }

    async fn request(&self, cx: &mut RequestCx<'_>, _state: &mut ()) -> pingora::Result<Flow> {
        let decision = match Origin::of(cx.session) {
            Ok(origin) => self.decide(&origin),
            Err(refused) => Decision::Refuse(refused),
        };
        answer(cx.session, self.source.permanent, decision).await
    }

    fn describe(&self) -> Value {
        json!({
            "regex": self.source.regex,
            "replacement": self.source.replacement,
            "permanent": self.source.permanent,
        })
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;

    use super::*;

    fn kind(regex: &str, replacement: &str) -> Result<RedirectRegex, String> {
        let regex = Regex::new(regex).map_err(|err| err.to_string())?;
        let parts = parse_replacement(&regex, replacement)?;
        Ok(RedirectRegex {
            regex,
            parts,
            source: Config {
                regex: String::new(),
                replacement: replacement.to_owned(),
                permanent: false,
            },
        })
    }

    fn origin(host: &str, target: &str) -> Origin {
        let mut request = RequestHeader::build("GET", target.as_bytes(), None).expect("request");
        request.insert_header("Host", host).expect("host");
        Origin::from_request(&request, false).expect("origin")
    }

    fn decide(regex: &str, replacement: &str, host: &str, target: &str) -> Decision {
        kind(regex, replacement)
            .expect("compiles")
            .decide(&origin(host, target))
    }

    fn redirect(to: &str) -> Decision {
        Decision::Redirect(to.to_owned())
    }

    #[test]
    fn captures_rewrite_the_full_url() {
        assert_eq!(
            decide(
                r"^http://([^/]+)/old/(.*)$",
                "https://$1/new/$2",
                "a.test",
                "/old/x?q=1"
            ),
            redirect("https://a.test/new/x?q=1")
        );
        assert_eq!(
            decide(
                r"^http://(?P<h>[^/]+)/(?<rest>.*)$",
                "https://${h}/${rest}",
                "a.test",
                "/p"
            ),
            redirect("https://a.test/p")
        );
        assert_eq!(
            decide(r"^http://a\.test/", "https://b.test/$$1/", "a.test", "/"),
            redirect("https://b.test/$1/")
        );
    }

    #[test]
    fn no_match_and_an_identity_rewrite_pass() {
        assert_eq!(decide(r"^https://", "x", "a.test", "/"), Decision::Pass);
        assert_eq!(
            decide(r"^http://", "http://", "a.test", "/"),
            Decision::Pass
        );
    }

    #[test]
    fn an_unmatched_group_is_empty_and_every_match_is_replaced() {
        assert_eq!(
            decide(
                r"^http://a\.test/(x)?",
                "https://b.test/[$1]",
                "a.test",
                "/"
            ),
            redirect("https://b.test/[]")
        );
        assert_eq!(
            decide(r"a", "bb", "a.test", "/a"),
            redirect("http://bb.test/bb")
        );
    }

    #[test]
    fn a_bad_regex_or_replacement_is_refused() {
        for (regex, replacement) in [
            ("(", "x"),
            ("^(a)", "$2"),
            ("^(a)", "${nope}"),
            ("^(a)", "$1x"),
            ("^(a)", "${1"),
            ("^(a)", "$"),
            ("^(a)", "$-"),
            ("^(a)", "/a\r\nb"),
            ("^(a)", "/a%0d%0a"),
            ("^(a)", "/\u{7f}"),
            ("^(a)", "99999999999999999999999$99999999999999999999999"),
        ] {
            assert!(
                kind(regex, replacement).is_err(),
                "{regex} -> {replacement}"
            );
        }
        assert!(kind("^(a)", "${1}x$0").is_ok());
    }

    #[test]
    fn a_capture_with_control_characters_never_becomes_a_location() {
        for target in ["/%0d%0aSet-Cookie:x", "/a?b=%0A"] {
            assert_eq!(
                decide(r"^http://[^/]+(.*)$", "https://b.test$1", "a.test", target),
                Decision::Refuse(Refused::Control),
                "{target}"
            );
        }
    }

    #[test]
    fn a_replacement_that_repeats_a_capture_is_bounded() {
        let decision = decide(
            r"",
            &"x".repeat(1000),
            "a.test",
            &format!("/{}", "a".repeat(2000)),
        );
        assert_eq!(decision, Decision::Refuse(Refused::TooLong));
    }

    #[test]
    fn a_target_with_another_scheme_is_refused() {
        assert_eq!(
            decide(
                r"^http://[^/]+/(.*)$",
                "$1",
                "a.test",
                "/javascript:alert(1)"
            ),
            Decision::Refuse(Refused::Scheme)
        );
    }
}
