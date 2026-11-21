//! `{"sni_regexp": "^.*\\.a\\.test$"}` (TCP routers): a regular expression over the
//! normalized server name of the ClientHello (unanchored: write `^` and `$` when you mean them).
//! A connection that sent no server name never matches it, whatever the expression accepts.
//!
//! Like `host_regexp` it claims no literal name: it only ever narrows a literal `sni` claim next
//! to it, or sits on an entry point the tenant has to itself or the operator allows a catch-all
//! on; see `docs/architecture.md` (`### Priority, ambiguity and conflicts`).

use regex::Regex;
use serde_json::Value;

use super::{Error, Spec, View, regex};

/// A compiled `sni_regexp` leaf.
#[derive(Debug)]
pub struct SniRegexp {
    regex: Regex,
}

impl SniRegexp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let pattern = argument
            .as_str()
            .ok_or_else(|| Error::invalid("sni_regexp: a string"))?;
        Ok(Self {
            regex: regex("sni_regexp", pattern)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.hello
            .server_name
            .is_some_and(|name| self.regex.is_match(name))
    }

    /// Below every `sni` class, above no name constraint at all.
    pub(super) fn spec(&self) -> Spec {
        Spec { path: 1, others: 0 }
    }
}
