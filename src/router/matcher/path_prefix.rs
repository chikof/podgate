//! `{"path_prefix": "/api"}`: the normalized path is the prefix or continues it at a segment
//! boundary: `/api` and `/api/x` match, `/apix` does not. A trailing `/` on the prefix is
//! ignored, and `/` matches every path.

use serde_json::Value;

use super::path::{configured, segments};
use super::{Error, Spec, View};

/// Weight of the prefix class in [`Spec::path`]; more segments add to it.
const CLASS: u32 = 3 << 10;

/// A path prefix, without its trailing slash (empty for the root).
#[derive(Debug)]
pub struct PathPrefix {
    prefix: Box<str>,
}

/// Whether `path` is `prefix` or lies under it.
fn under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

impl PathPrefix {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let path = configured("path_prefix", argument)?;
        let prefix = path.strip_suffix('/').unwrap_or(&path);
        Ok(Self {
            prefix: prefix.into(),
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        under(view.path, &self.prefix)
    }

    pub(super) fn spec(&self) -> Spec {
        Spec {
            path: CLASS + segments(&self.prefix),
            others: 0,
        }
    }
}

/// Whether the prefix covers `path`.
pub(super) fn covers(prefix: &PathPrefix, path: &str) -> bool {
    under(path, &prefix.prefix)
}

/// Two prefixes are disjoint unless one lies under the other.
pub(super) fn disjoint(a: &PathPrefix, b: &PathPrefix) -> bool {
    !(under(&a.prefix, &b.prefix) || under(&b.prefix, &a.prefix))
}
