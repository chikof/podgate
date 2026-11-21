//! The regular expressions of a rule: Go's RE2 in Traefik, the Rust `regex` crate here.

use regex::Regex;

use crate::error::RuleError;

/// Compiles `pattern` and records it. A pattern the Rust crate rejects is refused, never
/// dropped or rewritten: a different expression would route different requests.
pub(crate) fn check(
    pattern: &str,
    at: usize,
    regexes: &mut Vec<Box<str>>,
) -> Result<(), RuleError> {
    check_pattern(pattern)
        .map_err(|why| RuleError::invalid(at, format!("regular expression {pattern:?}: {why}")))?;
    regexes.push(pattern.into());
    Ok(())
}

/// Whether `pattern` compiles with the `regex` crate, which the daemon uses too.
///
/// # Errors
///
/// The crate's own message when it does not.
pub fn check_pattern(pattern: &str) -> Result<(), String> {
    Regex::new(pattern).map(drop).map_err(|err| {
        err.to_string()
            .lines()
            .last()
            .unwrap_or_default()
            .trim()
            .to_owned()
    })
}

/// Whether `pattern` has a Traefik v2 `{name:regex}` group.
pub(crate) fn has_named_group(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    bytes.iter().enumerate().any(|(index, &byte)| {
        byte == b'{'
            && bytes[index + 1..]
                .iter()
                .position(|&next| !(next.is_ascii_alphanumeric() || next == b'_'))
                .is_some_and(|len| {
                    len > 0
                        && bytes[index + 1].is_ascii_alphabetic()
                        && bytes.get(index + 1 + len) == Some(&b':')
                })
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn named_groups_are_v2() {
        assert!(has_named_group("{sub:[a-z]+}.example.com"));
        assert!(has_named_group("^api-{env_1:.*}$"));
        assert!(!has_named_group("^a{2,3}$"));
        assert!(!has_named_group("^a{2}:b$"));
        assert!(!has_named_group("^[a-z]+$"));
    }

    #[test]
    fn rust_only_rejections_are_reported() {
        assert!(check_pattern("^a(").is_err());
        assert!(check_pattern(r"^(?=a)").is_err());
        assert!(check_pattern(r"^(a)\1$").is_err());
        assert!(check_pattern(r"^[a-z]+\.example\.com$").is_ok());
    }
}
