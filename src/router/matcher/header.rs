//! `{"header": {"name": "x-env", "value": "canary"}}`: some header of that name has exactly that
//! value. Without `value` the leaf matches mere presence.
//!
//! The name is case-insensitive, the value is compared byte for byte (case-sensitive). A request
//! that sends the header several times matches when any occurrence does; a value is never split
//! on commas. The matcher reads the request as the client sent it: routing runs before any
//! middleware, so a header a middleware adds later is invisible here.

use http::HeaderName;
use serde_json::Value;

use super::{Error, Spec, View};

/// A `header` leaf.
#[derive(Debug)]
pub struct Header {
    name: HeaderName,
    value: Option<Box<str>>,
}

/// Reads the argument of a header or query leaf: an object with a `name` and the field `value_key`
/// (`value` or `regex`), which `required` makes mandatory. Any other field is refused.
pub(super) fn fields<'a>(
    key: &str,
    argument: &'a Value,
    value_key: &str,
    required: bool,
) -> Result<(&'a str, Option<&'a str>), Error> {
    let object = argument
        .as_object()
        .ok_or_else(|| Error::invalid(format!("{key}: an object with `name` and `{value_key}`")))?;
    if let Some(other) = object
        .keys()
        .find(|field| *field != "name" && *field != value_key)
    {
        return Err(Error::invalid(format!(
            "{key}: unknown field {other:?}; the fields are `name` and `{value_key}`"
        )));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Error::invalid(format!("{key}: `name` is a non-empty string")))?;
    let value = match object.get(value_key) {
        None if required => {
            return Err(Error::invalid(format!("{key}: `{value_key}` is required")));
        }
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(Error::invalid(format!("{key}: `{value_key}` is a string")));
        }
    };
    Ok((name, value))
}

/// Parses a header name; `HeaderName` lowercases it, which makes the comparison case-insensitive.
pub(super) fn name(key: &str, text: &str) -> Result<HeaderName, Error> {
    HeaderName::from_bytes(text.as_bytes())
        .map_err(|_| Error::invalid(format!("{key}: {text:?} is not a header name")))
}

impl Header {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let (text, value) = fields("header", argument, "value", false)?;
        Ok(Self {
            name: name("header", text)?,
            value: value.map(Box::from),
        })
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        let mut values = view.request.headers.get_all(&self.name).iter();
        match &self.value {
            None => values.next().is_some(),
            Some(wanted) => values.any(|value| value.as_bytes() == wanted.as_bytes()),
        }
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// What explain shows for a failed leaf.
    pub(super) fn describe(&self) -> String {
        match &self.value {
            None => format!("{} is present", self.name),
            Some(value) => format!("{} = {value:?}", self.name),
        }
    }
}

/// Two header leaves are disjoint when they name the same header and want different values. A
/// request that repeats the header with both values matches both; the router order then decides.
pub(super) fn disjoint(a: &Header, b: &Header) -> bool {
    a.name == b.name && matches!((&a.value, &b.value), (Some(x), Some(y)) if x != y)
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use super::*;

    fn request(headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build("GET", b"/", None).expect("request");
        for (name, value) in headers {
            request
                .append_header((*name).to_owned(), (*value).to_owned())
                .expect("header");
        }
        request
    }

    fn matches(leaf: &Value, headers: &[(&str, &str)]) -> bool {
        let request = request(headers);
        let view = View {
            host: "a.test",
            path: "/",
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: None,
        };
        Header::parse(leaf).expect("parses").matches(&view)
    }

    #[test]
    fn header_exact_value() {
        let leaf = json!({"name": "x-env", "value": "canary"});
        assert!(matches(&leaf, &[("x-env", "canary")]));
        assert!(!matches(&leaf, &[("x-env", "Canary")]), "case-sensitive");
        assert!(!matches(&leaf, &[("x-env", "canary,prod")]), "never split");
        assert!(!matches(&leaf, &[("x-other", "canary")]));
        assert!(!matches(&leaf, &[]));
        assert!(matches(&leaf, &[("x-env", "prod"), ("x-env", "canary")]));
    }

    #[test]
    fn header_name_case_insensitive() {
        let leaf = json!({"name": "X-Env", "value": "canary"});
        assert!(matches(&leaf, &[("x-ENV", "canary")]));
    }

    #[test]
    fn header_presence() {
        let leaf = json!({"name": "x-env"});
        assert!(matches(&leaf, &[("x-env", "")]));
        assert!(matches(&leaf, &[("X-Env", "anything")]));
        assert!(!matches(&leaf, &[]));
    }

    #[test]
    fn header_arguments_are_checked() {
        for bad in [
            json!("x-env"),
            json!({}),
            json!({"name": ""}),
            json!({"name": "bad name"}),
            json!({"name": "x", "value": 1}),
            json!({"name": "x", "regex": "a"}),
        ] {
            let err = Header::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher", "{bad}");
        }
    }
}
