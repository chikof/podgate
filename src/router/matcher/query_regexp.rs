//! `{"query_regexp": {"name": "id", "regex": "^[0-9]+$"}}`: some decoded value of the query
//! parameter of that name matches the regular expression (unanchored: write `^` and `$` when you
//! mean them). Decoding and repetition work as in `query`.

use regex::Regex;
use serde_json::Value;

use super::{Error, Spec, View, header, query, regex};

/// A compiled `query_regexp` leaf.
#[derive(Debug)]
pub struct QueryRegexp {
    name: Box<str>,
    regex: Regex,
}

impl QueryRegexp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let (name, pattern) = header::fields("query_regexp", argument, "regex", true)?;
        Ok(Self {
            name: name.into(),
            regex: regex("query_regexp", pattern.unwrap_or_default())?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        query::params(view).any(|(name, value)| *name == *self.name && self.regex.is_match(&value))
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// What explain shows for a failed leaf.
    pub(super) fn describe(&self) -> String {
        format!("{:?} ~ {:?}", self.name, self.regex.as_str())
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use super::*;

    fn matches(leaf: &Value, target: &str) -> bool {
        let request = RequestHeader::build("GET", target.as_bytes(), None).expect("request");
        let view = View {
            host: "a.test",
            path: "/",
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: None,
            hello: crate::router::matcher::Hello::NONE,
        };
        QueryRegexp::parse(leaf).expect("parses").matches(&view)
    }

    #[test]
    fn query_regexp_matches() {
        let leaf = json!({"name": "id", "regex": "^[0-9]+$"});
        assert!(matches(&leaf, "/?id=42"));
        assert!(matches(&leaf, "/?id=abc&id=7"), "any occurrence");
        assert!(!matches(&leaf, "/?id=4x"));
        assert!(!matches(&leaf, "/?other=42"));
        let decoded = json!({"name": "q", "regex": "^a b$"});
        assert!(matches(&decoded, "/?q=a+b"));
        assert!(matches(&decoded, "/?q=a%20b"));
    }

    #[test]
    fn query_regexp_arguments_are_checked() {
        for bad in [
            json!({"name": "q"}),
            json!({"name": "q", "regex": "("}),
            json!({"name": "q", "value": "a"}),
        ] {
            let err = QueryRegexp::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}");
        }
    }
}
