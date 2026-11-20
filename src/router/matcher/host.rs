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

impl Host {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let names: Vec<&str> = match argument {
            Value::String(name) => vec![name],
            Value::Array(list) => list
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .ok_or_else(|| Error::invalid("host: every entry is a string"))
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(Error::invalid(
                    "host: a string or a list of strings, like \"a.test\" or \"*.a.test\"",
                ));
            }
        };
        if names.is_empty() {
            return Err(Error::invalid("host: the list is empty"));
        }
        let patterns = names
            .into_iter()
            .map(|name| {
                HostPattern::parse(name).map_err(|err| Error {
                    code: "invalid_host",
                    message: err.to_string(),
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { patterns })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            HostPattern::Exact(name) => &**name == view.host,
            HostPattern::Wildcard(base) => view
                .host
                .split_once('.')
                .is_some_and(|(label, parent)| !label.is_empty() && parent == &**base),
        })
    }

    pub(super) fn claims(&self) -> Vec<Claim> {
        self.patterns.iter().cloned().map(Claim::Pattern).collect()
    }
}
