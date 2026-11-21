//! `{"query": {"name": "debug", "value": "1"}}`: some query parameter of that name has exactly
//! that value, after decoding. Without `value` the leaf matches mere presence (`?debug` counts).
//!
//! Parsing follows `application/x-www-form-urlencoded`: `&` separates parameters, `+` is a space
//! and `%XX` is decoded. A malformed escape is kept literally and is never an error, so a
//! hostile query can only fail to match. The name and the value are case-sensitive. A repeated
//! parameter matches when any occurrence does. It reads the request as the client sent it.

use serde_json::Value;

use super::{Error, Spec, View, header};

/// A `query` leaf.
#[derive(Debug)]
pub struct Query {
    name: Box<str>,
    value: Option<Box<str>>,
}

/// The decoded `(name, value)` pairs of the request's query.
pub(super) fn params<'a>(
    view: &View<'a>,
) -> impl Iterator<Item = (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)> {
    form_urlencoded::parse(view.request.uri.query().unwrap_or_default().as_bytes())
}

impl Query {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let (name, value) = header::fields("query", argument, "value", false)?;
        Ok(Self {
            name: name.into(),
            value: value.map(Box::from),
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        params(view).any(|(name, value)| {
            *name == *self.name && self.value.as_deref().is_none_or(|wanted| *value == *wanted)
        })
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// What explain shows for a failed leaf.
    pub(super) fn describe(&self) -> String {
        match &self.value {
            None => format!("{:?} is present", self.name),
            Some(value) => format!("{:?} = {value:?}", self.name),
        }
    }
}

/// Two query leaves are disjoint when they name the same parameter and want different values. A
/// request that repeats the parameter with both values matches both; the router order decides.
pub(super) fn disjoint(a: &Query, b: &Query) -> bool {
    a.name == b.name && matches!((&a.value, &b.value), (Some(x), Some(y)) if x != y)
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
        Query::parse(leaf).expect("parses").matches(&view)
    }

    #[test]
    fn query_decoded_param() {
        let leaf = json!({"name": "q", "value": "a b&c"});
        assert!(matches(&leaf, "/?q=a+b%26c"));
        assert!(matches(&leaf, "/?q=a%20b%26c"));
        assert!(!matches(&leaf, "/?q=a+b"));
        assert!(!matches(&leaf, "/?Q=a+b%26c"), "names are case-sensitive");
        let decoded_name = json!({"name": "a b", "value": "1"});
        assert!(matches(&decoded_name, "/?a%20b=1"));
        assert!(matches(&decoded_name, "/?a+b=1"));
        assert!(!matches(&leaf, "/"));
        let presence = json!({"name": "debug"});
        assert!(matches(&presence, "/?debug"));
        assert!(matches(&presence, "/?debug="));
        assert!(matches(&presence, "/?x=1&debug=0"));
        assert!(!matches(&presence, "/?debugx=1"));
        let literal = json!({"name": "q", "value": "100%zz"});
        assert!(
            matches(&literal, "/?q=100%zz"),
            "a malformed escape stays literal"
        );
    }

    #[test]
    fn query_repeated_param() {
        let leaf = json!({"name": "tag", "value": "b"});
        assert!(matches(&leaf, "/?tag=a&tag=b&tag=c"));
        assert!(!matches(&leaf, "/?tag=a&tag=c"));
    }

    #[test]
    fn query_arguments_are_checked() {
        for bad in [
            json!("debug"),
            json!({"name": ""}),
            json!({"name": "q", "value": 1}),
        ] {
            let err = Query::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}");
        }
    }
}
