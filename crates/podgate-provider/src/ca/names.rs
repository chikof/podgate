//! Which names the internal CA may certify: the operator's `allowed_suffixes`, the wildcard
//! switch, and the public-suffix check `ca init` runs.
//!
//! The same suffixes go into the intermediate's critical `NameConstraints` extension
//! ([`super::init`]) and into the provider's own refusal ([`Policy`]), so a stolen intermediate key
//! and a confused provider are held to the same list.

use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

use thiserror::Error;

use crate::trust::{HostPattern, Problem};

/// The ICANN section of the public suffix list (publicsuffix.org), one rule per line: `com`,
/// `co.uk`, wildcard rules `*.ck` and exceptions `!www.ck`. ASCII rules only: a name is matched
/// in its punycode form.
const PUBLIC_SUFFIXES: &str = include_str!("public_suffixes.txt");

struct Rules {
    exact: HashSet<&'static str>,
    wildcard: HashSet<&'static str>,
    exception: HashSet<&'static str>,
}

static RULES: LazyLock<Rules> = LazyLock::new(|| {
    let mut rules = Rules {
        exact: HashSet::new(),
        wildcard: HashSet::new(),
        exception: HashSet::new(),
    };
    for line in PUBLIC_SUFFIXES.lines() {
        if let Some(rest) = line.strip_prefix("*.") {
            rules.wildcard.insert(rest);
        } else if let Some(rest) = line.strip_prefix('!') {
            rules.exception.insert(rest);
        } else {
            rules.exact.insert(line);
        }
    }
    rules
});

/// Special-use names for private networks that the list carries only to keep cookies apart:
/// `home.arpa` (RFC 8375) is exactly where a home or lab CA belongs.
const PRIVATE_USE: [&str; 1] = ["home.arpa"];

/// Whether `name` (lowercase, no leading dot) is a public suffix: a TLD or a registry's
/// second-level suffix such as `co.uk`, where anyone can register a name. Names that are not on
/// the list (`internal`, `lan`, `svc.cluster.local`) are not public.
#[must_use]
pub fn is_public_suffix(name: &str) -> bool {
    if PRIVATE_USE.contains(&name) {
        return false;
    }
    let rules = &*RULES;
    if rules.exception.contains(name) {
        return false;
    }
    rules.exact.contains(name)
        || name
            .split_once('.')
            .is_some_and(|(_, parent)| rules.wildcard.contains(parent))
}

/// Why a suffix list is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SuffixError {
    /// No suffix at all: the CA would certify nothing, and an intermediate without a permitted
    /// subtree would be unconstrained.
    #[error("allowed_suffixes is empty")]
    Empty,
    /// Not a DNS name: letters, digits, `-` and `_` in dot-separated labels.
    #[error("{0:?} is not a DNS suffix")]
    Invalid(Box<str>),
    /// A TLD or a registry suffix: the CA could mint names for anyone's domains.
    #[error(
        "{0:?} is a public suffix: a CA for it could certify names anyone can register (pass --allow-public-suffix to override)"
    )]
    Public(Box<str>),
}

/// A DNS suffix the CA may certify names under, lowercase, without a leading dot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Suffix(Box<str>);

impl Suffix {
    /// Reads `raw`: one leading dot is dropped, the name is lowercased.
    ///
    /// # Errors
    ///
    /// [`SuffixError::Invalid`] for an empty name or label, a wildcard, or a character outside
    /// `a-z 0-9 - _`.
    pub fn parse(raw: &str) -> Result<Self, SuffixError> {
        let lower = raw.trim().to_ascii_lowercase();
        let name = lower.strip_prefix('.').unwrap_or(&lower);
        let valid = !name.is_empty()
            && name.len() <= 253
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                    })
            });
        if valid {
            Ok(Self(name.into()))
        } else {
            Err(SuffixError::Invalid(raw.into()))
        }
    }

    /// The suffix text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `name` is the suffix or lies under it, as an X.509 dNSName constraint reads it.
    #[must_use]
    pub fn covers(&self, name: &str) -> bool {
        name.strip_suffix(&*self.0)
            .is_some_and(|head| head.is_empty() || head.ends_with('.'))
    }
}

impl fmt::Display for Suffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reads and checks a suffix list.
///
/// # Errors
///
/// [`SuffixError`] for an empty list, an invalid suffix, or (unless `allow_public`) a public one.
pub fn parse_suffixes<S: AsRef<str>>(
    raw: &[S],
    allow_public: bool,
) -> Result<Vec<Suffix>, SuffixError> {
    if raw.is_empty() {
        return Err(SuffixError::Empty);
    }
    let mut suffixes = Vec::with_capacity(raw.len());
    for text in raw {
        let suffix = Suffix::parse(text.as_ref())?;
        if !allow_public && is_public_suffix(suffix.as_str()) {
            return Err(SuffixError::Public(suffix.as_str().into()));
        }
        if !suffixes.contains(&suffix) {
            suffixes.push(suffix);
        }
    }
    suffixes.sort();
    Ok(suffixes)
}

/// The code of the finding and the refusal for a name the CA will not certify.
pub const NOT_ALLOWED: &str = "internal_name_not_allowed";

/// The names the CA certifies: under one of the suffixes, wildcards only when switched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    suffixes: Vec<Suffix>,
    allow_wildcards: bool,
}

impl Policy {
    /// A policy for `suffixes`.
    #[must_use]
    pub fn new(suffixes: Vec<Suffix>, allow_wildcards: bool) -> Self {
        Self {
            suffixes,
            allow_wildcards,
        }
    }

    /// The suffixes.
    #[must_use]
    pub fn suffixes(&self) -> &[Suffix] {
        &self.suffixes
    }

    /// Whether `*.example.internal` hosts get certificates.
    #[must_use]
    pub fn allow_wildcards(&self) -> bool {
        self.allow_wildcards
    }

    /// Why `host` may not be certified, `None` when it may.
    #[must_use]
    pub fn refusal(&self, host: &HostPattern) -> Option<String> {
        let (name, wildcard) = match host {
            HostPattern::Exact(name) => (name, false),
            HostPattern::Wildcard(base) => (base, true),
        };
        if !self.suffixes.iter().any(|suffix| suffix.covers(name)) {
            let list: Vec<&str> = self.suffixes.iter().map(Suffix::as_str).collect();
            return Some(format!(
                "{host} is outside the CA's allowed_suffixes ({})",
                list.join(", ")
            ));
        }
        if wildcard && !self.allow_wildcards {
            return Some(format!(
                "{host} is a wildcard and the CA's allow_wildcards is off"
            ));
        }
        None
    }

    /// [`Self::refusal`] as the merge's problem, with the stable code.
    #[must_use]
    pub fn problem(&self, host: &HostPattern) -> Option<Problem> {
        self.refusal(host).map(|why| Problem::new(NOT_ALLOWED, why))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn public_suffix_rules() {
        for public in ["com", "co.uk", "uk", "foo.ck", "github.io"] {
            // `github.io` is in the private section, so only the first four are public here.
            assert_eq!(is_public_suffix(public), public != "github.io", "{public}");
        }
        assert!(!is_public_suffix("www.ck"));
        for private in [
            "internal",
            "lan",
            "svc.cluster.local",
            "home.arpa",
            "example.com",
        ] {
            assert!(!is_public_suffix(private), "{private}");
        }
    }

    #[test]
    fn suffix_covers_like_an_x509_dns_constraint() {
        let suffix = Suffix::parse(".Internal").expect("suffix");
        assert!(suffix.covers("a.internal"));
        assert!(suffix.covers("internal"));
        assert!(!suffix.covers("a.notinternal"));
        assert!(!suffix.covers("internal.example.com"));
    }
}
