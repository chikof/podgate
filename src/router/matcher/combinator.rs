//! `all`, `any` and `not`: boolean combination of matchers.

use serde_json::Value;

use super::{Error, Matcher, parse_at};

/// Parses the list under `all` or `any`: at least one matcher.
pub(super) fn parse_list(key: &str, argument: &Value, depth: usize) -> Result<Vec<Matcher>, Error> {
    let list = argument
        .as_array()
        .filter(|list| !list.is_empty())
        .ok_or_else(|| Error::invalid(format!("{key}: a non-empty list of matchers")))?;
    list.iter()
        .map(|child| parse_at(child, depth + 1))
        .collect()
}
