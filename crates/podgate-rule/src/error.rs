//! Why a rule is not translated.

use std::error::Error;
use std::fmt;

/// Whether a rule is wrong or only beyond what podgate translates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleErrorKind {
    /// Traefik syntax podgate does not translate: a v2 function, an unknown function, a
    /// `{name:regex}` group, an argument it has no exact matcher for.
    Unsupported,
    /// A rule that is wrong in any dialect: a syntax error, a function of the other dialect, a
    /// wrong number of arguments, a regular expression the `regex` crate rejects.
    Invalid,
}

/// A rule that podgate cannot translate exactly. The code is always `unsupported_rule`: a rule
/// that is malformed, written in Traefik v2 syntax, uses a function podgate has no matcher for,
/// or carries a regular expression the Rust `regex` crate rejects is refused the same way, and
/// the message says which. [`RuleError::kind`] tells a malformed rule from an unsupported one for
/// a reader that wants to code them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    at: usize,
    kind: RuleErrorKind,
    message: Box<str>,
}

impl RuleError {
    pub(crate) fn new(at: usize, message: impl Into<Box<str>>) -> Self {
        Self {
            at,
            kind: RuleErrorKind::Unsupported,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(at: usize, message: impl Into<Box<str>>) -> Self {
        Self {
            at,
            kind: RuleErrorKind::Invalid,
            message: message.into(),
        }
    }

    /// The stable code for reports and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "unsupported_rule"
    }

    /// Whether the rule is malformed or only unsupported.
    #[must_use]
    pub fn kind(&self) -> RuleErrorKind {
        self.kind
    }

    /// The byte offset in the rule where the problem was found.
    #[must_use]
    pub fn at(&self) -> usize {
        self.at
    }

    /// What is wrong, in a sentence.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at byte {})", self.message, self.at)
    }
}

impl Error for RuleError {}

#[cfg(test)]
mod test {
    use crate::{Dialect, RuleErrorKind, parse};

    fn kind(rule: &str, dialect: Dialect) -> RuleErrorKind {
        let err = parse(rule, dialect).expect_err(rule);
        assert_eq!(err.code(), "unsupported_rule", "{rule}");
        err.kind()
    }

    #[test]
    fn malformed_and_unsupported_rules_are_told_apart() {
        use RuleErrorKind::{Invalid, Unsupported};
        for (rule, dialect, want) in [
            ("Host(`a.test`", Dialect::Http, Invalid),
            ("Host(`a.test`) &", Dialect::Http, Invalid),
            ("Host()", Dialect::Http, Invalid),
            ("HostRegexp(`^a(`)", Dialect::Http, Invalid),
            ("HostSNI(`a.test`)", Dialect::Http, Invalid),
            ("Host(`a.test`)", Dialect::Tcp, Invalid),
            ("Headers(`x`, `y`)", Dialect::Http, Unsupported),
            (
                "HostRegexp(`{sub:[a-z]+}.test`)",
                Dialect::Http,
                Unsupported,
            ),
            ("Nope(`x`)", Dialect::Http, Unsupported),
        ] {
            assert_eq!(kind(rule, dialect), want, "{rule}");
        }
    }
}
