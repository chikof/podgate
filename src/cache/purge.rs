//! What a purge removes: by URL, by prefix, by tag, or everything of one app.
//!
//! A purge is always scoped to one app (the caller names it); a selector only narrows which of
//! that app's entries go. Matching is on the normalized key, so `/a/./b` and `/a/b` are one URL.

use serde::Deserialize;

use crate::cache::key::ResourceKey;
use crate::host;
use crate::router::path;

/// The JSON body of `POST /v1/cache/purge`. Exactly one selector must be set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) app: String,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default)]
    pub(crate) prefix: Option<String>,
    #[serde(default)]
    pub(crate) tag: Option<String>,
    #[serde(default)]
    pub(crate) all: bool,
}

/// A bad purge selector.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum Invalid {
    /// None or several of `url`, `prefix`, `tag` and `all` were given.
    #[error("give exactly one of url, prefix, tag and all")]
    Selectors,
    /// A URL or prefix is neither a path nor an `http(s)` URL.
    #[error("{0} must be an absolute path (`/x`) or an http or https URL")]
    Target(&'static str),
    /// The path cannot be normalized without changing what it names.
    #[error("{0} is not a valid path")]
    Path(&'static str),
    /// A tag is empty.
    #[error("tag must not be empty")]
    Tag,
}

/// Which of an app's entries a purge removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Selector {
    /// The entries of one URL (every variant, revision and scheme); `host` is `None` for a bare
    /// path, which matches under every host of the app.
    Url {
        host: Option<Box<str>>,
        target: Box<str>,
    },
    /// The entries whose path and query start with `prefix`.
    Prefix {
        host: Option<Box<str>>,
        prefix: Box<str>,
    },
    /// The entries whose response named this tag.
    Tag(Box<str>),
    /// Every entry of the app.
    All,
}

impl Selector {
    /// The selector `request` asks for.
    ///
    /// # Errors
    ///
    /// [`Invalid`] when the number of selectors is not one or a value is malformed.
    pub(crate) fn of(request: &Request) -> Result<Self, Invalid> {
        let given = usize::from(request.url.is_some())
            + usize::from(request.prefix.is_some())
            + usize::from(request.tag.is_some())
            + usize::from(request.all);
        if given != 1 {
            return Err(Invalid::Selectors);
        }
        if request.all {
            return Ok(Self::All);
        }
        if let Some(url) = &request.url {
            let (host, target) = split(url, "url")?;
            return Ok(Self::Url { host, target });
        }
        if let Some(prefix) = &request.prefix {
            let (host, prefix) = split(prefix, "prefix")?;
            return Ok(Self::Prefix { host, prefix });
        }
        match request.tag.as_deref() {
            Some(tag) if !tag.is_empty() => Ok(Self::Tag(tag.into())),
            _ => Err(Invalid::Tag),
        }
    }

    /// Whether the resource `key` is selected by everything but a tag. Tags are judged per
    /// entry, see [`Self::tag`].
    #[must_use]
    pub(crate) fn matches_key(&self, key: &ResourceKey) -> bool {
        match self {
            Self::All => true,
            Self::Url { host, target } => {
                host_matches(host.as_deref(), key) && *key.target == **target
            }
            Self::Prefix { host, prefix } => {
                host_matches(host.as_deref(), key) && key.target.starts_with(&**prefix)
            }
            Self::Tag(_) => false,
        }
    }

    /// The tag this selector purges by, if it is a tag selector.
    #[must_use]
    pub(crate) fn tag(&self) -> Option<&str> {
        match self {
            Self::Tag(tag) => Some(tag),
            _ => None,
        }
    }
}

fn host_matches(host: Option<&str>, key: &ResourceKey) -> bool {
    host.is_none_or(|host| *key.host == *host)
}

/// Splits an `http(s)://host[:port]/path?query` URL or a bare `/path?query` into its host and
/// its normalized target.
fn split(value: &str, what: &'static str) -> Result<(Option<Box<str>>, Box<str>), Invalid> {
    let (host, rest) = match value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    {
        Some(after) => {
            let end = after.find(['/', '?']).unwrap_or(after.len());
            let (authority, rest) = after.split_at(end);
            if authority.is_empty() {
                return Err(Invalid::Target(what));
            }
            (Some(Box::from(&*host::normalize(authority))), rest)
        }
        None => (None, value),
    };
    let rest = if rest.is_empty() { "/" } else { rest };
    if !rest.starts_with('/') {
        return Err(Invalid::Target(what));
    }
    let (raw_path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (rest, None),
    };
    let normalized = path::normalize(raw_path).map_err(|_| Invalid::Path(what))?;
    let target = match query {
        Some(query) => format!("{normalized}?{query}"),
        None => normalized.into_owned(),
    };
    Ok((host, target.into()))
}

#[cfg(test)]
mod test {
    use super::*;

    fn request(url: Option<&str>, prefix: Option<&str>, tag: Option<&str>, all: bool) -> Request {
        Request {
            app: "a".into(),
            url: url.map(Into::into),
            prefix: prefix.map(Into::into),
            tag: tag.map(Into::into),
            all,
        }
    }

    #[test]
    fn exactly_one_selector_is_required() {
        assert_eq!(
            Selector::of(&request(None, None, None, false)),
            Err(Invalid::Selectors)
        );
        assert_eq!(
            Selector::of(&request(Some("/a"), None, Some("t"), false)),
            Err(Invalid::Selectors)
        );
        assert_eq!(
            Selector::of(&request(None, None, None, true)),
            Ok(Selector::All)
        );
    }

    #[test]
    fn urls_are_normalized_and_may_carry_a_host() {
        assert_eq!(
            Selector::of(&request(
                Some("https://A.test:8443/x/./y?q=1"),
                None,
                None,
                false
            )),
            Ok(Selector::Url {
                host: Some("a.test".into()),
                target: "/x/y?q=1".into()
            })
        );
        assert_eq!(
            Selector::of(&request(None, Some("/blog/"), None, false)),
            Ok(Selector::Prefix {
                host: None,
                prefix: "/blog/".into()
            })
        );
        assert_eq!(
            Selector::of(&request(Some("ftp://x/"), None, None, false)),
            Err(Invalid::Target("url"))
        );
        assert_eq!(
            Selector::of(&request(Some("relative"), None, None, false)),
            Err(Invalid::Target("url"))
        );
    }

    #[test]
    fn an_empty_tag_is_refused() {
        assert_eq!(
            Selector::of(&request(None, None, Some(""), false)),
            Err(Invalid::Tag)
        );
    }
}
