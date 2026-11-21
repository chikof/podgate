//! `{"header_regexp": {"name": "user-agent", "regex": "^curl/"}}`: some header of that name has a
//! value the regular expression matches (unanchored: write `^` and `$` when you mean them).
//!
//! The name is case-insensitive. Every occurrence of a repeated header is tried and a value is
//! never split on commas. A value that is not UTF-8 matches nothing. Like `header`, it reads the
//! request as the client sent it.

use http::HeaderName;
use regex::Regex;
use serde_json::Value;

use super::{Error, Spec, View, header, regex};

/// A compiled `header_regexp` leaf.
#[derive(Debug)]
pub struct HeaderRegexp {
    name: HeaderName,
    regex: Regex,
}

impl HeaderRegexp {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let (text, pattern) = header::fields("header_regexp", argument, "regex", true)?;
        Ok(Self {
            name: header::name("header_regexp", text)?,
            regex: regex("header_regexp", pattern.unwrap_or_default())?,
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        view.request
            .headers
            .get_all(&self.name)
            .iter()
            .filter_map(|value| std::str::from_utf8(value.as_bytes()).ok())
            .any(|value| self.regex.is_match(value))
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// What explain shows for a failed leaf.
    pub(super) fn describe(&self) -> String {
        format!("{} ~ {:?}", self.name, self.regex.as_str())
    }
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use super::*;

    fn matches(leaf: &Value, headers: &[(&str, &str)]) -> bool {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in headers {
            request
                .append_header((*name).to_owned(), (*value).to_owned())
                .expect("header");
        }
        let view = View {
            host: "a.test",
            path: "/",
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: None,
            hello: crate::router::matcher::Hello::NONE,
        };
        HeaderRegexp::parse(leaf).expect("parses").matches(&view)
    }

    #[test]
    fn header_regexp_each_value() {
        let leaf = json!({"name": "User-Agent", "regex": "^curl/[0-9]+"});
        assert!(matches(&leaf, &[("user-agent", "curl/8.4")]));
        assert!(!matches(&leaf, &[("user-agent", "wget/1.0")]));
        assert!(
            matches(&leaf, &[("user-agent", "wget"), ("user-agent", "curl/7")]),
            "any occurrence"
        );
        assert!(!matches(&leaf, &[]));
        let unanchored = json!({"name": "x", "regex": "bc"});
        assert!(matches(&unanchored, &[("x", "abcd")]));
        let list = json!({"name": "accept", "regex": "^text/html$"});
        assert!(
            !matches(&list, &[("accept", "text/html, */*")]),
            "no comma split"
        );
    }

    #[test]
    fn header_regexp_arguments_are_checked() {
        for bad in [
            json!({"name": "x"}),
            json!({"name": "x", "regex": "("}),
            json!({"name": "x", "value": "a"}),
            json!({"name": "x", "regex": 1}),
        ] {
            let err = HeaderRegexp::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}");
        }
    }
}
