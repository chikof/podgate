//! `CONTENT_CLASSIFIERS_FILE`: the external text classifiers a `content_guard` may name, parsed
//! and validated once at startup.
//!
//! ```json
//! {"toxicity": {
//!    "url": "http://10.0.0.9:8080/classify",
//!    "timeout_ms": 2000,
//!    "tenants": ["acme"],
//!    "max_concurrent": 64}}
//! ```
//!
//! No model runs in podgate. A classifier is an HTTP service that speaks the guard wire
//! (`docs/ref/mw-llm-guard.md`). Its address is the operator's: a snapshot only names an entry,
//! and only one that lists the app's tenant, so a tenant cannot aim the proxy at an address of
//! its choosing. The address policy still applies to every dial.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::middleware::forward_auth::parse_url;
use crate::middleware::guard::MAX_ADDRESS;

/// The most entries.
const MAX_CLASSIFIERS: usize = 1024;

/// The most tenants one entry may list.
const MAX_TENANTS: usize = 4096;

/// The default deadline of one call.
const DEFAULT_TIMEOUT_MS: u64 = 2000;

/// The longest `timeout_ms`.
const MAX_TIMEOUT_MS: u64 = 10_000;

/// The default `max_concurrent`.
const DEFAULT_MAX_CONCURRENT: u32 = 64;

/// The largest `max_concurrent`.
const MAX_CONCURRENT: u32 = 4096;

/// The longest classifier name.
const MAX_NAME: usize = 64;

/// Why `CONTENT_CLASSIFIERS_FILE` cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// The cause.
        source: std::io::Error,
    },
    /// The file is not a JSON object of entries.
    #[error("{0}")]
    Parse(serde_json::Error),
    /// One entry is wrong.
    #[error("classifier {name:?}: {reason}")]
    Classifier {
        /// The entry's name.
        name: Box<str>,
        /// What is wrong, naming the field.
        reason: Box<str>,
    },
}

fn bad(name: &str, reason: impl Into<Box<str>>) -> LoadError {
    LoadError::Classifier {
        name: name.into(),
        reason: reason.into(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    url: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    tenants: Vec<String>,
    #[serde(default)]
    max_concurrent: Option<u32>,
}

/// One classifier the operator declared.
#[derive(Debug)]
pub(crate) struct Entry {
    url: Box<str>,
    timeout: Duration,
    tenants: Box<[Box<str>]>,
    max_concurrent: u32,
}

impl Entry {
    /// The classifier's URL.
    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    /// The deadline of one call.
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Calls in flight at once, per stage that names this classifier.
    pub(crate) fn max_concurrent(&self) -> u32 {
        self.max_concurrent
    }

    /// Whether `tenant` may name this classifier.
    pub(crate) fn allows(&self, tenant: &str) -> bool {
        self.tenants.iter().any(|listed| &**listed == tenant)
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// The classifiers a `content_guard` may name (`CONTENT_CLASSIFIERS_FILE`). Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct Classifiers(Arc<BTreeMap<Box<str>, Entry>>);

impl Classifiers {
    /// Reads and validates the file at `path`. Nothing is contacted.
    ///
    /// # Errors
    ///
    /// [`LoadError`] when the file cannot be read, is not a JSON object, has more than 1024
    /// entries, or an entry has a bad name, URL, timeout, tenant list or concurrency (the reason
    /// names the field).
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text)
    }

    /// [`Self::load`] over the text of the file.
    ///
    /// # Errors
    ///
    /// As [`Self::load`], but the file.
    pub fn parse(text: &str) -> Result<Self, LoadError> {
        let raw: BTreeMap<String, Value> = serde_json::from_str(text).map_err(LoadError::Parse)?;
        if raw.len() > MAX_CLASSIFIERS {
            return Err(bad("*", format!("more than {MAX_CLASSIFIERS} entries")));
        }
        let mut entries = BTreeMap::new();
        for (name, value) in raw {
            if !valid_name(&name) {
                return Err(bad(
                    &name,
                    format!("the name is 1 to {MAX_NAME} bytes of a-z, 0-9, `_` and `-`"),
                ));
            }
            let file: File =
                serde_json::from_value(value).map_err(|err| bad(&name, err.to_string()))?;
            parse_url(&file.url, "url", MAX_ADDRESS)
                .map_err(|why| bad(&name, format!("`url`: {why}")))?;
            let timeout_ms = file.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
            if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
                return Err(bad(
                    &name,
                    format!("`timeout_ms` is in 1..={MAX_TIMEOUT_MS}"),
                ));
            }
            let max_concurrent = file.max_concurrent.unwrap_or(DEFAULT_MAX_CONCURRENT);
            if !(1..=MAX_CONCURRENT).contains(&max_concurrent) {
                return Err(bad(
                    &name,
                    format!("`max_concurrent` is in 1..={MAX_CONCURRENT}"),
                ));
            }
            if file.tenants.is_empty() || file.tenants.len() > MAX_TENANTS {
                return Err(bad(
                    &name,
                    format!("`tenants` lists 1 to {MAX_TENANTS} tenant ids"),
                ));
            }
            if file.tenants.iter().any(String::is_empty) {
                return Err(bad(&name, "`tenants` has an empty tenant id"));
            }
            entries.insert(
                Box::from(name.as_str()),
                Entry {
                    url: file.url.into(),
                    timeout: Duration::from_millis(timeout_ms),
                    tenants: file.tenants.into_iter().map(Into::into).collect(),
                    max_concurrent,
                },
            );
        }
        Ok(Self(Arc::new(entries)))
    }

    /// The entry called `name`.
    pub(crate) fn get(&self, name: &str) -> Option<&Entry> {
        self.0.get(name)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn reason(text: &str) -> String {
        Classifiers::parse(text).expect_err("refused").to_string()
    }

    #[test]
    fn content_guard_classifier_file_accepts_an_entry() {
        let classifiers = Classifiers::parse(
            r#"{"toxicity": {"url": "https://nlp.internal:8443/c", "tenants": ["acme"]}}"#,
        )
        .expect("parsed");
        let entry = classifiers.get("toxicity").expect("entry");
        assert_eq!(entry.url(), "https://nlp.internal:8443/c");
        assert_eq!(entry.timeout(), Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(entry.max_concurrent(), DEFAULT_MAX_CONCURRENT);
        assert!(entry.allows("acme") && !entry.allows("other"));
        assert!(classifiers.get("missing").is_none());
        assert!(Classifiers::parse("{}").expect("empty").get("x").is_none());
    }

    #[test]
    fn content_guard_classifier_file_rejected() {
        let ok = r#""url": "http://10.0.0.9/c", "tenants": ["a"]"#;
        let cases: [(String, &str); 12] = [
            ("[]".into(), "invalid type"),
            ("not json".into(), "expected"),
            (format!(r#"{{"Bad Name": {{{ok}}}}}"#), "name"),
            (format!(r#"{{"a": {{{ok}, "nope": 1}}}}"#), "nope"),
            (r#"{"a": {"tenants": ["a"]}}"#.into(), "url"),
            (r#"{"a": {"url": "http://10.0.0.9/c"}}"#.into(), "tenants"),
            (
                r#"{"a": {"url": "ftp://x/c", "tenants": ["a"]}}"#.into(),
                "url",
            ),
            (
                r#"{"a": {"url": "http://u:p@x/c", "tenants": ["a"]}}"#.into(),
                "url",
            ),
            (
                format!(r#"{{"a": {{{ok}, "timeout_ms": 0}}}}"#),
                "timeout_ms",
            ),
            (
                format!(r#"{{"a": {{{ok}, "max_concurrent": 4097}}}}"#),
                "max_concurrent",
            ),
            (
                r#"{"a": {"url": "http://10.0.0.9/c", "tenants": []}}"#.into(),
                "tenants",
            ),
            (
                r#"{"a": {"url": "http://10.0.0.9/c", "tenants": [""]}}"#.into(),
                "tenant",
            ),
        ];
        for (text, field) in cases {
            let why = reason(&text);
            assert!(why.contains(field), "{text}: {why}");
        }
        assert!(Classifiers::load(Path::new("/nonexistent/classifiers.json")).is_err());
    }
}
