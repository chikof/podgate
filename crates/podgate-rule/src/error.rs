//! Why a rule is not translated.

use std::error::Error;
use std::fmt;

/// A rule that podgate cannot translate exactly. The code is always `unsupported_rule`: a rule
/// that is malformed, written in Traefik v2 syntax, uses a function podgate has no matcher for,
/// or carries a regular expression the Rust `regex` crate rejects is refused the same way, and
/// the message says which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    at: usize,
    message: Box<str>,
}

impl RuleError {
    pub(crate) fn new(at: usize, message: impl Into<Box<str>>) -> Self {
        Self {
            at,
            message: message.into(),
        }
    }

    /// The stable code for reports and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "unsupported_rule"
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
