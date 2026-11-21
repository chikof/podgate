//! Splitting `key=value` tags, for the sources whose tags are the Docker labels written
//! `key=value` (Consul and Nomad).

/// A tag the pairing refuses. The source words the report, because its own rules decide which
/// tags are governed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unpaired<'a> {
    /// A governed tag with no `=`.
    NoValue(&'a str),
    /// A governed key given twice: which value counts would depend on tag order.
    Duplicate(&'a str),
}

/// The `key=value` pairs of `tags`, in tag order, each tag split at its first `=` so a value may
/// hold more. A tag that `governed` accepts must be a pair and its key may not repeat; any other
/// tag without `=` is the deployer's own business and is skipped.
///
/// # Errors
///
/// [`Unpaired`] for the first governed tag without `=` or governed key given twice.
pub(crate) fn pairs<'a>(
    tags: &'a [String],
    governed: impl Fn(&str) -> bool,
) -> Result<Vec<(&'a str, &'a str)>, Unpaired<'a>> {
    let mut pairs: Vec<(&str, &str)> = Vec::with_capacity(tags.len());
    for tag in tags {
        let governed = governed(tag);
        match tag.split_once('=') {
            Some((key, value)) => {
                if governed && pairs.iter().any(|(seen, _)| *seen == key) {
                    return Err(Unpaired::Duplicate(key));
                }
                pairs.push((key, value));
            }
            None if governed => return Err(Unpaired::NoValue(tag)),
            None => {}
        }
    }
    Ok(pairs)
}

#[cfg(test)]
mod test {
    use super::*;

    fn tags(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|tag| (*tag).to_owned()).collect()
    }

    fn governed(tag: &str) -> bool {
        tag.starts_with("g.")
    }

    #[test]
    fn splits_at_the_first_equals_and_skips_foreign_tags() {
        let tags = tags(&["v2", "g.a=1", "x=y=z", "x=2"]);
        assert_eq!(
            pairs(&tags, governed),
            Ok(vec![("g.a", "1"), ("x", "y=z"), ("x", "2")])
        );
    }

    #[test]
    fn governed_tags_are_strict() {
        assert_eq!(
            pairs(&tags(&["g.a"]), governed),
            Err(Unpaired::NoValue("g.a"))
        );
        assert_eq!(
            pairs(&tags(&["g.a=1", "g.a=2"]), governed),
            Err(Unpaired::Duplicate("g.a"))
        );
    }
}
