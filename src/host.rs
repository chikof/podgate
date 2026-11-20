//! Host names: parsing declared patterns, normalizing request hosts, and lookup by exact or
//! one-label wildcard match.

use std::borrow::Cow;
use std::collections::HashMap;

use thiserror::Error;

/// A declared host that is neither a valid exact name nor a valid `*.` wildcard.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0:?} is not a host name or a `*.` wildcard")]
pub struct InvalidHost(pub Box<str>);

/// A host an app or certificate claims: an exact name or one leading `*.` wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// `app.example.com`, stored lowercase.
    Exact(Box<str>),
    /// `*.example.com`, stored as the suffix `example.com`. Matches exactly one extra label.
    Wildcard(Box<str>),
}

impl HostPattern {
    /// Parses a declared host. Names are lowercased.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHost`] for an empty name, an empty label, a character outside
    /// `a-z 0-9 - _`, or a `*` anywhere but the whole first label.
    pub fn parse(raw: &str) -> Result<Self, InvalidHost> {
        let invalid = || InvalidHost(raw.into());
        let lower = raw.to_ascii_lowercase();
        let (wildcard, name) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                    })
            });
        if !valid {
            return Err(invalid());
        }
        Ok(if wildcard {
            Self::Wildcard(name.into())
        } else {
            Self::Exact(name.into())
        })
    }
}

/// Reduces the value of a `Host` header or `:authority` to a lookup key: port removed,
/// lowercase, no trailing dot. Allocates only when the input has uppercase letters.
#[must_use]
pub fn normalize(raw: &str) -> Cow<'_, str> {
    let name = match raw.strip_prefix('[') {
        // IPv6 literal: `[::1]:8080` keeps everything inside the brackets.
        Some(rest) => rest.split_once(']').map_or(rest, |(inside, _)| inside),
        None => raw.split_once(':').map_or(raw, |(name, _port)| name),
    };
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(name.to_ascii_lowercase())
    } else {
        Cow::Borrowed(name)
    }
}

/// How a host matched a declared pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    /// The host is the declared name.
    Exact,
    /// The host is one label under a declared `*.` wildcard.
    Wildcard,
}

/// A successful [`HostMap::find`]: what matched and the value stored under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matched<'a, V> {
    /// Whether an exact name or a wildcard matched.
    pub kind: MatchKind,
    /// The stored key: the name for [`MatchKind::Exact`], the suffix after `*.` for
    /// [`MatchKind::Wildcard`].
    pub key: &'a str,
    /// The value stored under the pattern.
    pub value: &'a V,
}

impl<V> Matched<'_, V> {
    /// The declared pattern as written in a snapshot: `a.test` or `*.a.test`.
    #[must_use]
    pub fn pattern(&self) -> String {
        match self.kind {
            MatchKind::Exact => self.key.to_owned(),
            MatchKind::Wildcard => format!("*.{}", self.key),
        }
    }
}

/// Maps host patterns to values. An exact name beats a wildcard.
#[derive(Debug)]
pub struct HostMap<V> {
    exact: HashMap<Box<str>, V>,
    wildcard: HashMap<Box<str>, V>,
}

impl<V> Default for HostMap<V> {
    fn default() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: HashMap::new(),
        }
    }
}

impl<V> HostMap<V> {
    /// Adds `value` under `pattern` and returns the value it replaced, if any.
    pub fn insert(&mut self, pattern: HostPattern, value: V) -> Option<V> {
        match pattern {
            HostPattern::Exact(name) => self.exact.insert(name, value),
            HostPattern::Wildcard(suffix) => self.wildcard.insert(suffix, value),
        }
    }

    /// Finds the value for a normalized host: the exact name, else `*.` plus everything after
    /// its first label.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<&V> {
        self.find(host).map(|matched| matched.value)
    }

    /// Like [`Self::lookup`], and says which pattern matched.
    #[must_use]
    pub fn find(&self, host: &str) -> Option<Matched<'_, V>> {
        if let Some((key, value)) = self.exact.get_key_value(host) {
            return Some(Matched {
                kind: MatchKind::Exact,
                key,
                value,
            });
        }
        let (_label, suffix) = host.split_once('.')?;
        let (key, value) = self.wildcard.get_key_value(suffix)?;
        Some(Matched {
            kind: MatchKind::Wildcard,
            key,
            value,
        })
    }

    /// The declared wildcard nearest to `host`, for explaining a miss.
    ///
    /// "Nearest" is the wildcard whose suffix is the longest suffix of `host`, the whole host
    /// counting as a suffix of itself: `p.q.a.test` is nearest to `*.a.test` (one label too
    /// deep), and `a.test` to `*.a.test` (the apex, which a wildcard never matches). Returns the
    /// pattern as declared, `*.a.test`.
    #[must_use]
    pub fn nearest_wildcard(&self, host: &str) -> Option<String> {
        let mut suffix = host;
        loop {
            if self.wildcard.contains_key(suffix) {
                return Some(format!("*.{suffix}"));
            }
            suffix = suffix.split_once('.')?.1;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_exact_and_wildcard() {
        assert_eq!(
            HostPattern::parse("A.Test"),
            Ok(HostPattern::Exact("a.test".into()))
        );
        assert_eq!(
            HostPattern::parse("*.a.test"),
            Ok(HostPattern::Wildcard("a.test".into()))
        );
    }

    #[test]
    fn rejects_bad_patterns() {
        for bad in [
            "", "*", "*.", "a.*.test", "a*.test", "a..test", "a b", "a/b", ".a.test",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn normalizes_request_hosts() {
        assert_eq!(normalize("A.Test:8080"), "a.test");
        assert_eq!(normalize("a.test."), "a.test");
        assert_eq!(normalize("[::1]:8080"), "::1");
        assert!(matches!(normalize("a.test"), Cow::Borrowed(_)));
    }

    #[test]
    fn exact_beats_wildcard_and_wildcard_spans_one_label() {
        let mut map = HostMap::default();
        map.insert(HostPattern::Wildcard("a.test".into()), "wild");
        map.insert(HostPattern::Exact("x.a.test".into()), "exact");
        assert_eq!(map.lookup("x.a.test"), Some(&"exact"));
        assert_eq!(map.lookup("y.a.test"), Some(&"wild"));
        assert_eq!(map.lookup("a.test"), None);
        assert_eq!(map.lookup("p.q.a.test"), None);
    }

    #[test]
    fn find_reports_the_matching_pattern() {
        let mut map = HostMap::default();
        map.insert(HostPattern::Wildcard("a.test".into()), 1);
        map.insert(HostPattern::Exact("x.a.test".into()), 2);
        let exact = map.find("x.a.test").expect("exact");
        assert_eq!(exact.kind, MatchKind::Exact);
        assert_eq!(exact.pattern(), "x.a.test");
        assert_eq!(*exact.value, 2);
        let wild = map.find("y.a.test").expect("wildcard");
        assert_eq!(wild.kind, MatchKind::Wildcard);
        assert_eq!(wild.pattern(), "*.a.test");
        assert_eq!(*wild.value, 1);
        assert!(map.find("a.test").is_none());
    }

    #[test]
    fn nearest_wildcard_is_the_longest_declared_suffix() {
        let mut map = HostMap::default();
        map.insert(HostPattern::Wildcard("a.test".into()), ());
        map.insert(HostPattern::Wildcard("example".into()), ());
        assert_eq!(map.nearest_wildcard("a.test").as_deref(), Some("*.a.test"));
        assert_eq!(
            map.nearest_wildcard("p.q.a.test").as_deref(),
            Some("*.a.test")
        );
        assert_eq!(
            map.nearest_wildcard("b.q.example").as_deref(),
            Some("*.example")
        );
        assert_eq!(map.nearest_wildcard("other.test"), None);
        assert_eq!(map.nearest_wildcard("localhost"), None);
    }
}
