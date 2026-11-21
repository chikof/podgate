//! The result of parsing a rule.

use serde_json::Value;

use crate::error::RuleError;
use crate::lex::lex;
use crate::parse::Parser;

/// Which functions a rule may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// A router of HTTP entry points: `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`,
    /// `Method`, `Header`, `HeaderRegexp`, `Query`, `QueryRegexp`, `ClientIP`.
    Http,
    /// A router of TCP entry points: `HostSNI`, `HostSNIRegexp`, `ALPN`, `ClientIP`.
    Tcp,
}

/// A rule translated to podgate's matcher JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    /// The matcher tree of `docs/architecture.md ### Routers and matchers`. `None` when the
    /// rule matches every connection (a TCP `HostSNI(`*`)`), which a TCP router says by having
    /// no `match`.
    pub matcher: Option<Value>,
    /// Every regular expression in the rule, in order. Each one compiled with the `regex`
    /// crate, the same one the daemon compiles with.
    pub regexes: Vec<Box<str>>,
    /// The length of the rule in bytes, as written. Traefik's priority for a router that sets
    /// none.
    pub len: usize,
}

/// Parses a Traefik v3 rule.
///
/// The grammar is the functions of `dialect`, the operators `&&`, `||` and `!`, parentheses, and
/// arguments in backticks or double quotes. Function names are case-insensitive, as in Traefik.
/// `Host`, `Method`, `Path`, `PathPrefix` and `PathRegexp` take several arguments, which mean
/// any of them. `Host(a) || Host(b)` becomes one `host` leaf with both names.
///
/// # Errors
///
/// A [`RuleError`] (code `unsupported_rule`) for anything else: a syntax error, Traefik v2
/// syntax (`Headers()`, `HostHeader()`, `{name:regex}` groups), an unknown function, a function
/// of the other dialect, an argument podgate has no exact matcher for, or a regular expression
/// the `regex` crate does not compile.
///
/// # Examples
///
/// ```
/// use podgate_rule::{Dialect, parse};
///
/// let rule = parse("Host(`a.test`) && !PathPrefix(`/admin`)", Dialect::Http)?;
/// assert_eq!(
///     rule.matcher.expect("a matcher").to_string(),
///     r#"{"all":[{"host":"a.test"},{"not":{"path_prefix":"/admin"}}]}"#
/// );
/// assert_eq!(rule.len, 36);
/// # Ok::<(), podgate_rule::RuleError>(())
/// ```
pub fn parse(rule: &str, dialect: Dialect) -> Result<Rule, RuleError> {
    let tokens = lex(rule)?;
    let mut parser = Parser::new(tokens, rule.len(), dialect);
    let node = parser.rule()?;
    Ok(Rule {
        matcher: node.into_matcher(0)?,
        regexes: parser.regexes,
        len: rule.len(),
    })
}
