//! `{"host_regexp": "..."}`: a regular expression over the normalized host (unanchored: write
//! `^` and `$` when you mean them).
//!
//! A router with a host regular expression claims no literal host. It only ever matches hosts
//! that no other tenant claims, and at most one tenant may have such routers on an entry point;
//! see `docs/architecture.md` (`### Priority, ambiguity and conflicts`).

use regex::Regex;
use serde_json::Value;

use super::{Error, View, regex};

/// A compiled `host_regexp` leaf.
#[derive(Debug)]
pub struct HostRegexp {
    regex: Regex,
}

impl HostRegexp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let pattern = argument
            .as_str()
            .ok_or_else(|| Error::invalid("host_regexp: a string"))?;
        Ok(Self {
            regex: regex("host_regexp", pattern)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        self.regex.is_match(view.host)
    }
}
