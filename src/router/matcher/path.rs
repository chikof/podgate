//! `{"path": "/x"}`: the normalized path equals the string.

use serde_json::Value;

use super::{Error, Spec, View};
use crate::router::path as normalize;

/// Weight of the exact-path class in [`Spec::path`]; more segments add to it.
const CLASS: u32 = 4 << 10;

/// An exact path.
#[derive(Debug)]
pub struct Path {
    path: Box<str>,
}

/// Reads a configured path: absolute and already normalized, so it can be compared as written.
pub(super) fn configured(key: &str, argument: &Value) -> Result<Box<str>, Error> {
    let path = argument
        .as_str()
        .ok_or_else(|| Error::invalid(format!("{key}: a string")))?;
    let normalized = normalize::normalize(path)
        .map_err(|_| Error::invalid(format!("{key}: {path:?} is not a clean path")))?;
    if !path.starts_with('/') || normalized != path {
        return Err(Error::invalid(format!(
            "{key}: {path:?} must be absolute and normalized (no `//`, dot segments or escapes of unreserved characters)"
        )));
    }
    Ok(path.into())
}

/// Number of non-empty segments, capped to fit the class.
pub(super) fn segments(path: &str) -> u32 {
    let count = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count();
    u32::try_from(count).unwrap_or(u32::MAX).min((1 << 10) - 1)
}

impl Path {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        Ok(Self {
            path: configured("path", argument)?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.path == &*self.path
    }

    pub(super) fn spec(&self) -> Spec {
        Spec {
            path: CLASS + segments(&self.path),
            others: 0,
        }
    }

    /// The configured path.
    pub(super) fn as_str(&self) -> &str {
        &self.path
    }
}

/// Two exact paths never match the same request unless they are equal.
pub(super) fn exact_disjoint(a: &Path, b: &Path) -> bool {
    a.path != b.path
}
