//! The strict reader of an answer of the OPA Data API.
//!
//! The answer is a verdict, so it is read as strictly as the HTTP framing around it: one JSON
//! object whose `result` is a boolean or an object with a boolean `allow`. A missing `result` is
//! the answer OPA gives for an undefined document, which is a deny. Everything else, a result of
//! another type, a `status` outside `401..=499`, a header the policy may not set, is a
//! [`Malformed`] answer, and a malformed answer closes the door like a failed call does.

use http::{HeaderName, HeaderValue};
use serde_json::{Map, Value};

/// The `status` of a deny that names none.
const DENY_STATUS: u16 = 403;

/// Headers the policy asked to set: lower-case names, each once.
pub(super) type Headers = Vec<(HeaderName, HeaderValue)>;

/// What the policy decided.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    /// The request goes on, with `headers` added to it.
    Allow {
        /// The headers for the request that goes on.
        headers: Headers,
    },
    /// The request is refused with `status`, and `headers` on the refusal.
    Deny {
        /// `403`, or the `status` of the result (`401..=499`).
        status: u16,
        /// The headers for the refusal.
        headers: Headers,
    },
}

/// Why an answer is not one this client accepts.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Malformed(pub(super) &'static str);

/// Reads the body of a `200` answer. `may_set` says whether the policy may set a header.
///
/// # Errors
///
/// [`Malformed`] for a body that is not one JSON object, a `result` that is neither a boolean
/// nor an object with a boolean `allow`, a `status` that is not an integer in `401..=499`,
/// `headers` that is not an object of strings, a header name that is invalid, not allowed or
/// given twice, and an invalid header value.
pub(super) fn parse(
    body: &[u8],
    may_set: impl Fn(&HeaderName) -> bool,
) -> Result<Verdict, Malformed> {
    let Value::Object(mut answer) =
        serde_json::from_slice(body).map_err(|_| Malformed("the answer is not JSON"))?
    else {
        return Err(Malformed("the answer is not a JSON object"));
    };
    match answer.remove("result") {
        None => Ok(Verdict::Deny {
            status: DENY_STATUS,
            headers: Vec::new(),
        }),
        Some(Value::Bool(true)) => Ok(Verdict::Allow {
            headers: Vec::new(),
        }),
        Some(Value::Bool(false)) => Ok(Verdict::Deny {
            status: DENY_STATUS,
            headers: Vec::new(),
        }),
        Some(Value::Object(result)) => object(&result, may_set),
        Some(_) => Err(Malformed("the result is neither a boolean nor an object")),
    }
}

fn object(
    result: &Map<String, Value>,
    may_set: impl Fn(&HeaderName) -> bool,
) -> Result<Verdict, Malformed> {
    let Some(Value::Bool(allow)) = result.get("allow") else {
        return Err(Malformed("the result has no boolean allow"));
    };
    let status = match result.get("status") {
        None => DENY_STATUS,
        Some(value) => value
            .as_u64()
            .filter(|status| (401..=499).contains(status))
            .and_then(|status| u16::try_from(status).ok())
            .ok_or(Malformed("status is not an integer in 401..=499"))?,
    };
    let headers = match result.get("headers") {
        None => Vec::new(),
        Some(Value::Object(listed)) => headers(listed, may_set)?,
        Some(_) => return Err(Malformed("headers is not an object")),
    };
    Ok(if *allow {
        Verdict::Allow { headers }
    } else {
        Verdict::Deny { status, headers }
    })
}

fn headers(
    listed: &Map<String, Value>,
    may_set: impl Fn(&HeaderName) -> bool,
) -> Result<Headers, Malformed> {
    let mut out: Headers = Vec::with_capacity(listed.len());
    for (raw, value) in listed {
        let name = HeaderName::from_bytes(raw.as_bytes())
            .map_err(|_| Malformed("a header name is invalid"))?;
        if !may_set(&name) {
            return Err(Malformed("a header is not in response_headers"));
        }
        if out.iter().any(|(known, _)| *known == name) {
            return Err(Malformed("a header is given twice"));
        }
        let Value::String(text) = value else {
            return Err(Malformed("a header value is not a string"));
        };
        let value =
            HeaderValue::from_str(text).map_err(|_| Malformed("a header value is invalid"))?;
        out.push((name, value));
    }
    Ok(out)
}

#[cfg(test)]
mod test {
    use super::*;

    fn read(body: &str) -> Result<Verdict, Malformed> {
        parse(body.as_bytes(), |name| {
            matches!(name.as_str(), "x-user" | "www-authenticate")
        })
    }

    fn deny(status: u16) -> Verdict {
        Verdict::Deny {
            status,
            headers: Vec::new(),
        }
    }

    #[test]
    fn verdict_booleans() {
        assert_eq!(
            read(r#"{"result": true}"#),
            Ok(Verdict::Allow {
                headers: Vec::new()
            })
        );
        assert_eq!(read(r#"{"result": false}"#), Ok(deny(403)));
    }

    #[test]
    fn verdict_undefined_document_denies() {
        assert_eq!(read("{}"), Ok(deny(403)));
        assert_eq!(read(r#"{"decision_id": "x"}"#), Ok(deny(403)));
    }

    #[test]
    fn verdict_object_result() {
        assert_eq!(
            read(
                r#"{"result": {"allow": false, "status": 401, "headers": {"WWW-Authenticate": "Bearer"}, "why": "x"}}"#
            ),
            Ok(Verdict::Deny {
                status: 401,
                headers: vec![(
                    HeaderName::from_static("www-authenticate"),
                    HeaderValue::from_static("Bearer")
                )],
            })
        );
        assert_eq!(
            read(r#"{"result": {"allow": true, "status": 404, "headers": {"x-user": "ann"}}}"#),
            Ok(Verdict::Allow {
                headers: vec![(
                    HeaderName::from_static("x-user"),
                    HeaderValue::from_static("ann")
                )],
            }),
            "status is validated and ignored on an allow"
        );
        assert_eq!(read(r#"{"result": {"allow": false}}"#), Ok(deny(403)));
    }

    #[test]
    fn verdict_anything_else_is_malformed() {
        for bad in [
            "",
            "{",
            "[]",
            "true",
            r#"{"result": "true"}"#,
            r#"{"result": 1}"#,
            r#"{"result": null}"#,
            r#"{"result": [true]}"#,
            r#"{"result": {}}"#,
            r#"{"result": {"allow": "yes"}}"#,
            r#"{"result": {"allow": null}}"#,
            r#"{"result": {"status": 401}}"#,
            r#"{"result": {"allow": false, "status": 200}}"#,
            r#"{"result": {"allow": false, "status": 400}}"#,
            r#"{"result": {"allow": false, "status": 500}}"#,
            r#"{"result": {"allow": false, "status": "401"}}"#,
            r#"{"result": {"allow": false, "status": 401.5}}"#,
            r#"{"result": {"allow": true, "status": 200}}"#,
            r#"{"result": {"allow": true, "headers": []}}"#,
            r#"{"result": {"allow": true, "headers": {"x-other": "a"}}}"#,
            r#"{"result": {"allow": true, "headers": {"x-user": 1}}}"#,
            r#"{"result": {"allow": true, "headers": {"x-user": ["a"]}}}"#,
            r#"{"result": {"allow": true, "headers": {"x-user": "a\nb"}}}"#,
            r#"{"result": {"allow": true, "headers": {"not a name": "a"}}}"#,
            r#"{"result": {"allow": true, "headers": {"x-user": "a", "X-User": "b"}}}"#,
        ] {
            assert!(read(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn verdict_boundary_statuses() {
        assert_eq!(
            read(r#"{"result": {"allow": false, "status": 401}}"#),
            Ok(deny(401))
        );
        assert_eq!(
            read(r#"{"result": {"allow": false, "status": 499}}"#),
            Ok(deny(499))
        );
    }
}
