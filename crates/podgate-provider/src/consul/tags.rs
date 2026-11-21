//! Consul tags as `key=value` pairs.
//!
//! A Consul tag is one string. The source reads the tags that are written like the labels of
//! the Docker source (`podgate.host=app.example`), split at the first `=`, so a value may hold
//! `=` itself (a JSON matcher does not, but a regular expression can). Tags that are not
//! `key=value` are the deployer's own business (`v2`, `primary`), unless they start with
//! `podgate.`: that is a misspelt tag, and it rejects the instance like an unknown key would.

use thiserror::Error;

const PODGATE: &str = "podgate.";
const ENABLE: &str = "podgate.enable";

/// A tag the source cannot read.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum TagError {
    /// A `podgate.*` tag with no `=`.
    #[error("tag {tag:?}: a podgate tag is written key=value")]
    NoValue { tag: Box<str> },
    /// The same `podgate.*` key twice: which value counts would depend on tag order.
    #[error("tag {key}: given twice")]
    Duplicate { key: Box<str> },
}

/// Splits `tag` at the first `=`.
fn split(tag: &str) -> Option<(&str, &str)> {
    tag.split_once('=')
}

/// The `key=value` pairs of `tags`, in tag order.
///
/// # Errors
///
/// [`TagError`] for a `podgate.*` tag without `=` and for a `podgate.*` key given twice.
pub(super) fn pairs(tags: &[String]) -> Result<Vec<(&str, &str)>, TagError> {
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(tags.len());
    for tag in tags {
        match split(tag) {
            Some((key, value)) => {
                if key.starts_with(PODGATE) && pairs.iter().any(|(seen, _)| *seen == key) {
                    return Err(TagError::Duplicate { key: key.into() });
                }
                pairs.push((key, value));
            }
            None if tag.starts_with(PODGATE) => {
                return Err(TagError::NoValue {
                    tag: tag.as_str().into(),
                });
            }
            None => {}
        }
    }
    Ok(pairs)
}

/// Whether one instance counts, by its own tags.
///
/// `podgate.enable=false` always excludes (a duplicate counts, the safe way), any other value
/// includes (the label parser rejects a value it does not know, with a report), and with no
/// tag the source's `exposed_by_default` decides.
pub(super) fn exposed(tags: &[String], exposed_by_default: bool) -> bool {
    let mut enabled = None;
    for (key, value) in tags.iter().filter_map(|tag| split(tag)) {
        if key == ENABLE {
            if value == "false" {
                return false;
            }
            enabled = Some(true);
        }
    }
    enabled.unwrap_or(exposed_by_default)
}

/// Whether a service is worth watching, by the union of its instances' tags that the catalog
/// lists: some instance may count. The instances decide for themselves.
pub(super) fn worth_watching(union: &[String], exposed_by_default: bool) -> bool {
    exposed_by_default
        || union
            .iter()
            .filter_map(|tag| split(tag))
            .any(|(key, value)| key == ENABLE && value != "false")
}

#[cfg(test)]
mod test {
    use super::*;

    fn tags(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|tag| (*tag).to_owned()).collect()
    }

    #[test]
    fn splits_at_the_first_equals() {
        let tags = tags(&["v2", "podgate.host=a.test", "x=y=z"]);
        assert_eq!(
            pairs(&tags),
            Ok(vec![("podgate.host", "a.test"), ("x", "y=z")])
        );
    }

    #[test]
    fn podgate_tags_are_strict() {
        assert_eq!(
            pairs(&tags(&["podgate.host"])),
            Err(TagError::NoValue {
                tag: "podgate.host".into()
            })
        );
        assert_eq!(
            pairs(&tags(&["podgate.host=a", "podgate.host=b"])),
            Err(TagError::Duplicate {
                key: "podgate.host".into()
            })
        );
        assert!(
            pairs(&tags(&["other=1", "other=2"])).is_ok(),
            "duplicates of other keys are not this module's business"
        );
    }

    #[test]
    fn exposure_follows_the_enable_tag() {
        assert!(exposed(&tags(&["podgate.enable=true"]), false));
        assert!(!exposed(&tags(&["podgate.enable=false"]), true));
        assert!(!exposed(
            &tags(&["podgate.enable=true", "podgate.enable=false"]),
            false
        ));
        assert!(!exposed(&tags(&["podgate.host=a"]), false));
        assert!(exposed(&tags(&["podgate.host=a"]), true));
        assert!(exposed(&tags(&["podgate.enable=maybe"]), false));
    }

    #[test]
    fn watching_is_permissive() {
        assert!(worth_watching(
            &tags(&["podgate.enable=true", "podgate.enable=false"]),
            false
        ));
        assert!(!worth_watching(&tags(&["podgate.enable=false"]), false));
        assert!(worth_watching(&tags(&[]), true));
    }
}
