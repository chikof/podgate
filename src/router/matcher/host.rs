//! `{"host": "a.test"}` and `{"host": ["a.test", "*.b.test"]}`: an exact name or one-label
//! wildcard; a list matches any of its entries. This is the only leaf that claims hosts.

use serde_json::Value;

use super::{Claim, Error, View};
use crate::host::HostPattern;

/// The hosts of a `host` leaf.
#[derive(Debug)]
pub struct Host {
    patterns: Vec<HostPattern>,
}

/// The patterns of the argument of `key` (`host` or `sni`): a name or a list of names, each an
/// exact name or a `*.` wildcard.
pub(super) fn parse_patterns(key: &str, argument: &Value) -> Result<Vec<HostPattern>, Error> {
    let names: Vec<&str> = match argument {
        Value::String(name) => vec![name],
        Value::Array(list) => list
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .ok_or_else(|| Error::invalid(format!("{key}: every entry is a string")))
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(Error::invalid(format!(
                "{key}: a string or a list of strings, like \"a.test\" or \"*.a.test\""
            )));
        }
    };
    if names.is_empty() {
        return Err(Error::invalid(format!("{key}: the list is empty")));
    }
    names
        .into_iter()
        .map(|name| {
            HostPattern::parse(name).map_err(|err| Error {
                code: "invalid_host",
                message: err.to_string(),
            })
        })
        .collect()
}

/// Whether the normalized `name` is the exact name of `pattern`, or one label under its wildcard.
pub(super) fn covers(pattern: &HostPattern, name: &str) -> bool {
    match pattern {
        HostPattern::Exact(exact) => &**exact == name,
        HostPattern::Wildcard(base) => name
            .split_once('.')
            .is_some_and(|(label, parent)| !label.is_empty() && parent == &**base),
    }
}

impl Host {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        Ok(Self {
            patterns: parse_patterns("host", argument)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        self.patterns
            .iter()
            .any(|pattern| covers(pattern, view.host))
    }

    pub(super) fn claims(&self) -> Vec<Claim> {
        self.patterns.iter().cloned().map(Claim::Pattern).collect()
    }
}
