//! `{"path_regexp": "^/v[0-9]+/"}`: a regular expression over the normalized path
//! (unanchored: write `^` and `$` when you mean them).

use regex::Regex;
use serde_json::Value;

use super::{Error, Spec, View, regex};

/// Weight of the regexp class in [`Spec::path`].
const CLASS: u32 = 2 << 10;

/// A compiled `path_regexp` leaf.
#[derive(Debug)]
pub struct PathRegexp {
    regex: Regex,
}

impl PathRegexp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let pattern = argument
            .as_str()
            .ok_or_else(|| Error::invalid("path_regexp: a string"))?;
        Ok(Self {
            regex: regex("path_regexp", pattern)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        self.regex.is_match(view.path)
    }

    pub(super) fn spec(&self) -> Spec {
        Spec {
            path: CLASS,
            others: 0,
        }
    }
}
