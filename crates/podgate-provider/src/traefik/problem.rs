//! What the translator could not do, and which label said it.

use std::fmt;

/// The stable code of a [`Problem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Code {
    /// A rule or an expression podgate cannot express exactly (`unsupported_rule`).
    UnsupportedRule,
    /// A label that has no podgate equivalent (`unsupported_label`).
    UnsupportedLabel,
    /// A value that does not parse (`invalid_label`).
    InvalidLabel,
    /// A label that names an address, a URL or a container (`address_label`).
    AddressLabel,
    /// A name that the labels of this container do not define (`foreign_reference`).
    ForeignReference,
}

impl Code {
    /// The code as reports and tests write it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedRule => "unsupported_rule",
            Self::UnsupportedLabel => "unsupported_label",
            Self::InvalidLabel => "invalid_label",
            Self::AddressLabel => "address_label",
            Self::ForeignReference => "foreign_reference",
        }
    }
}

/// One thing the translator left out, naming the exact label.
///
/// The router, service or middleware the label belongs to is not emitted, and neither is any
/// router that names it: a router must never lose a middleware silently. Only a problem with
/// `fatal` set takes the whole container with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// What kind of problem.
    pub code: Code,
    /// The label key, exactly as written.
    pub key: Box<str>,
    /// What is wrong and what to do instead.
    pub reason: Box<str>,
    /// Whether the container as a whole cannot be used: a label that names an address, or a
    /// `traefik.enable` that is neither `true` nor `false`.
    pub fatal: bool,
}

impl Problem {
    fn new(code: Code, key: &str, reason: impl Into<Box<str>>) -> Self {
        Self {
            code,
            key: key.into(),
            reason: reason.into(),
            fatal: false,
        }
    }

    pub(super) fn unsupported_rule(key: &str, reason: impl Into<Box<str>>) -> Self {
        Self::new(Code::UnsupportedRule, key, reason)
    }

    pub(super) fn unsupported_label(key: &str, reason: impl Into<Box<str>>) -> Self {
        Self::new(Code::UnsupportedLabel, key, reason)
    }

    pub(super) fn invalid(key: &str, reason: impl Into<Box<str>>) -> Self {
        Self::new(Code::InvalidLabel, key, reason)
    }

    pub(super) fn address(key: &str, what: &str) -> Self {
        let mut problem = Self::new(
            Code::AddressLabel,
            key,
            format!(
                "{what} names an address, a URL or a container; a server is the container's own network address and the port label, nothing else"
            ),
        );
        problem.fatal = true;
        problem
    }

    pub(super) fn foreign(key: &str, name: &str) -> Self {
        Self::new(
            Code::ForeignReference,
            key,
            format!(
                "{name:?} is not defined by this container's labels; names resolve inside the app that carries the label"
            ),
        )
    }

    pub(super) fn fatal(mut self) -> Self {
        self.fatal = true;
        self
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.key, self.reason, self.code.as_str())
    }
}
