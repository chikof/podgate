//! `{"cel": "request.method == 'GET' && request.headers['x-env'] == 'canary'"}`: a
//! [CEL](https://github.com/google/cel-spec) expression over the request, for what the typed
//! leaves cannot say. The argument is the expression, or `{"expression": "...", "max_cost": 200}`
//! to raise the cost limit.
//!
//! The expression is parsed and type-checked against a fixed environment when the snapshot is
//! compiled ([`env`]), so a syntax error, a type error, an unknown name, a comprehension or a
//! regular expression that is not a literal is `invalid_matcher` with the column. Its static
//! cost ([`cost`]) must not exceed `max_cost` (default 100, at most 1000): `cel_cost_exceeded`.
//! At most 2 KiB of source. Evaluation ([`value`]) reads the request in place and is bounded.
//!
//! A `cel` leaf claims no host, so it can never take or widen a host claim: write a `host`
//! leaf next to it. It counts as one constraint beside the path, and two routers with `cel`
//! leaves are never provably disjoint (`route_ambiguity` unless their priorities differ).
//!
//! A leaf is a pure function of the request. An evaluation that fails (a missing header read
//! without `has`, an input over 8 KiB, an address that is not one) is a non-match, counted in
//! `podgate_cel_errors_total{app}`; it is never a failure of the request. It is an HTTP leaf: a
//! TCP router has no request to read.

mod cost;
mod env;
mod parse;
mod value;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;

use super::{Error, Spec, View};
use crate::budget::Escaped;
use crate::table::RoutingTable;

/// Longest expression, in bytes.
const MAX_SOURCE: usize = 2048;

/// The cost limit when the leaf names none.
const DEFAULT_COST: u64 = 100;

/// The most a leaf may raise its cost limit to.
const MAX_COST: u64 = 1000;

/// Errors counted per app, shared by every table (and every snapshot) of the process so a
/// counter never restarts at a push. An app is added when a leaf is bound to it.
static ERRORS: Mutex<BTreeMap<Box<str>, Arc<AtomicU64>>> = Mutex::new(BTreeMap::new());

/// A compiled `cel` leaf.
#[derive(Debug)]
pub struct Cel {
    source: Box<str>,
    program: env::Expr,
    errors: Option<Arc<AtomicU64>>,
}

impl Cel {
    pub(super) fn parse(argument: &Value) -> Result<Self, Error> {
        let (source, max_cost) = arguments(argument)?;
        if source.len() > MAX_SOURCE {
            return Err(Error::invalid(format!(
                "cel: the expression is {} bytes, the limit is {MAX_SOURCE}",
                source.len()
            )));
        }
        let tree = parse::parse(source).map_err(|err| Error::invalid(format!("cel: {err}")))?;
        let program = env::check(&tree).map_err(|err| Error::invalid(format!("cel: {err}")))?;
        let cost = cost::estimate(&program);
        if cost > max_cost {
            return Err(Error::invalid(format!(
                "cel_cost_exceeded: the expression costs {cost}, the limit is {max_cost} (max_cost, at most {MAX_COST})"
            )));
        }
        Ok(Self {
            source: source.into(),
            program,
            errors: None,
        })
    }

    /// Counts this leaf's evaluation errors under `app` from now on.
    pub(super) fn bind(&mut self, app: &str) {
        let mut errors = ERRORS.lock().unwrap_or_else(PoisonError::into_inner);
        let counter = errors.entry(app.into()).or_default();
        self.errors = Some(Arc::clone(counter));
    }

    pub(super) fn matches(&self, view: &View<'_>) -> bool {
        match value::run(&self.program, view) {
            Ok(matched) => matched,
            Err(_) => {
                if let Some(errors) = &self.errors {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                false
            }
        }
    }

    pub(super) fn spec(&self) -> Spec {
        Spec { path: 0, others: 1 }
    }

    /// What explain shows for a failed leaf.
    pub(super) fn describe(&self) -> String {
        self.source.to_string()
    }
}

/// The expression and the cost limit of a leaf's argument.
fn arguments(argument: &Value) -> Result<(&str, u64), Error> {
    match argument {
        Value::String(source) => Ok((source, DEFAULT_COST)),
        Value::Object(fields) => {
            let source = fields
                .get("expression")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::invalid("cel: expression is a string"))?;
            let max_cost = match fields.get("max_cost") {
                None => DEFAULT_COST,
                Some(limit) => limit
                    .as_u64()
                    .filter(|limit| (1..=MAX_COST).contains(limit))
                    .ok_or_else(|| {
                        Error::invalid(format!("cel: max_cost is an integer from 1 to {MAX_COST}"))
                    })?,
            };
            if let Some(other) = fields
                .keys()
                .find(|key| !matches!(key.as_str(), "expression" | "max_cost"))
            {
                return Err(Error::invalid(format!(
                    "cel: unknown field {other}; expression and max_cost only"
                )));
            }
            Ok((source, max_cost))
        }
        _ => Err(Error::invalid(
            "cel: a string, or an object with expression and max_cost",
        )),
    }
}

/// The Prometheus exposition of the evaluation errors of the apps of `live` that have a `cel`
/// leaf: `podgate_cel_errors_total{app}`. Empty when no app has one.
pub(crate) fn render(live: &RoutingTable) -> String {
    use std::fmt::Write as _;

    let errors = ERRORS.lock().unwrap_or_else(PoisonError::into_inner);
    let mut out = String::new();
    for app in live.apps() {
        let Some(counter) = errors.get(app.id()) else {
            continue;
        };
        if out.is_empty() {
            out.push_str(
                "# HELP podgate_cel_errors_total Evaluations of a cel matcher that failed and counted as a non-match.\n# TYPE podgate_cel_errors_total counter\n",
            );
        }
        // Writing to a `String` cannot fail.
        let _ = writeln!(
            out,
            "podgate_cel_errors_total{{app=\"{}\"}} {}",
            Escaped(app.id()),
            counter.load(Ordering::Relaxed)
        );
    }
    out
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use serde_json::json;

    use super::*;
    use crate::router::matcher::{Hello, View};

    struct Request {
        head: RequestHeader,
        client: Option<std::net::IpAddr>,
        tls: bool,
        sni: Option<&'static str>,
    }

    fn request(method: &str, target: &str, headers: &[(&str, &str)]) -> Request {
        let mut head = RequestHeader::build(method, target.as_bytes(), None).expect("request");
        for (name, value) in headers {
            head.append_header((*name).to_owned(), (*value).to_owned())
                .expect("header");
        }
        Request {
            head,
            client: None,
            tls: false,
            sni: None,
        }
    }

    fn eval(expression: &str, request: &Request) -> Result<bool, value::EvalError> {
        let leaf = Cel::parse(&json!(expression)).expect("compiles");
        value::run(
            &leaf.program,
            &View {
                host: "a.test",
                path: request.head.uri.path(),
                entry_point: "web",
                tls: request.tls,
                request: &request.head,
                client_ip: request.client,
                hello: Hello {
                    server_name: request.sni,
                    alpn: &[],
                    version: request.tls.then_some("TLSv1.3"),
                },
            },
        )
    }

    #[test]
    fn evaluates_the_environment() {
        let mut get = request(
            "GET",
            "/api/v1?debug=1&name=a+b&name=c",
            &[("x-env", "canary"), ("User-Agent", "curl/8.4")],
        );
        get.client = Some("10.1.2.3".parse().expect("ip"));
        get.tls = true;
        get.sni = Some("a.test");
        for (expression, wanted) in [
            ("request.method == 'GET'", true),
            ("request.method in ['POST', 'PUT']", false),
            ("request.host == 'a.test' && entry_point == 'web'", true),
            (
                "request.path.startsWith('/api') && request.path.endsWith('v1')",
                true,
            ),
            (
                "request.path.contains('/v1') && !request.path.contains('v2')",
                true,
            ),
            ("request.headers['x-env'] == 'canary'", true),
            ("request.headers['X-Env'] == 'canary' || true", true),
            (
                "request.headers['user-agent'].matches('^curl/[0-9]+')",
                true,
            ),
            ("has(request.headers.etag)", false),
            ("'x-env' in request.headers", true),
            ("request.query['name'] == 'a b'", true),
            ("request.query.debug == '1'", true),
            (
                "size(request.query) == 2 && size(request.headers) == 2",
                true,
            ),
            ("ip(request.client_ip).in_cidr('10.0.0.0/8')", true),
            (
                "ip(request.client_ip).in_cidr(cidr('192.168.0.0/16'))",
                false,
            ),
            ("request.client_ip == '10.1.2.3'", true),
            (
                "tls.sni == 'a.test' && tls.version == 'TLSv1.3' && request.scheme == 'https'",
                true,
            ),
            ("size(request.path) == 7 && request.path.size() == 7", true),
            ("1 + 2 * 3 == 7 && 7 % 4 == 3 && -1 < 0 && 'a' < 'b'", true),
            ("'a' + 'b' == 'ab'", true),
            ("request.method == 'GET' ? true : false", true),
            ("!(request.method == 'GET')", false),
        ] {
            assert_eq!(eval(expression, &get), Ok(wanted), "{expression}");
        }
    }

    #[test]
    fn errors_are_absorbed_like_cel_does() {
        let plain = request("GET", "/", &[]);
        assert_eq!(
            eval("request.headers['x'] == 'a'", &plain),
            Err(value::EvalError::MissingKey)
        );
        assert_eq!(
            eval(
                "request.headers['x'] == 'a' || request.method == 'GET'",
                &plain
            ),
            Ok(true)
        );
        assert_eq!(
            eval(
                "request.method == 'POST' && request.headers['x'] == 'a'",
                &plain
            ),
            Ok(false)
        );
        assert_eq!(
            eval(
                "request.headers['x'] == 'a' && request.method == 'GET'",
                &plain
            ),
            Err(value::EvalError::MissingKey)
        );
        assert_eq!(
            eval("ip(request.client_ip).in_cidr('10.0.0.0/8')", &plain),
            Err(value::EvalError::UnknownClient)
        );
        assert_eq!(
            eval("ip(request.host).in_cidr('10.0.0.0/8')", &plain),
            Err(value::EvalError::BadIp)
        );
    }

    #[test]
    fn inputs_are_bounded() {
        let long = "a".repeat(env::INPUT_LIMIT + 1);
        let hostile = request("GET", "/", &[("x-long", &long)]);
        assert_eq!(
            eval("request.headers['x-long'] == 'a'", &hostile),
            Err(value::EvalError::InputTooLong)
        );
        assert_eq!(eval("request.method == 'GET'", &hostile), Ok(true));
        let names: Vec<String> = (0..=env::MAX_HEADERS).map(|n| format!("x-{n}")).collect();
        let many: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "v")).collect();
        let crowded = request("GET", "/", &many);
        assert_eq!(
            eval("request.headers['x-1'] == 'v'", &crowded),
            Err(value::EvalError::TooManyHeaders)
        );
    }

    #[test]
    fn arguments_are_checked() {
        for good in [
            json!("true"),
            json!({"expression": "true", "max_cost": 1000}),
            json!({"expression": "true"}),
        ] {
            Cel::parse(&good).unwrap_or_else(|err| panic!("{good}: {err}"));
        }
        for bad in [
            json!(1),
            json!({}),
            json!({"expression": 1}),
            json!({"expression": "true", "max_cost": 0}),
            json!({"expression": "true", "max_cost": 1001}),
            json!({"expression": "true", "extra": 1}),
            json!("a".repeat(MAX_SOURCE + 1)),
            json!(""),
        ] {
            let err = Cel::parse(&bad).expect_err(&bad.to_string());
            assert_eq!(err.code, "invalid_matcher");
        }
    }

    #[test]
    fn cost_is_estimated_before_evaluation() {
        let one = "request.headers['user-agent'].contains('a')";
        Cel::parse(&json!(one)).expect("one scan fits the default limit");
        let many = [one; 4].join(" || ");
        let err = Cel::parse(&json!(many)).expect_err("four scans do not");
        assert!(err.message.contains("cel_cost_exceeded"), "{err}");
        Cel::parse(&json!({"expression": many, "max_cost": 300})).expect("raised limit");
    }

    #[test]
    fn cel_claims_no_host_unit() {
        let alone = crate::router::matcher::parse(&json!({ "cel": "request.host == 'x.test'" }))
            .expect("parses");
        assert_eq!(alone.claims(), None, "the expression names no host");
        let with_host = crate::router::matcher::parse(
            &json!({ "all": [{ "host": "a.test" }, { "cel": "request.host == 'b.test'" }] }),
        )
        .expect("parses");
        assert_eq!(
            with_host.claims(),
            crate::router::matcher::parse(&json!({ "host": "a.test" }))
                .expect("parses")
                .claims(),
            "next to a host the claim is the host's"
        );
        let either = crate::router::matcher::parse(
            &json!({ "any": [{ "host": "a.test" }, { "cel": "true" }] }),
        )
        .expect("parses");
        assert_eq!(either.claims(), None, "one unlimited branch frees the host");
    }

    #[test]
    fn cel_specificity_counts_one() {
        use crate::router::matcher::{Spec, disjoint, parse};
        let one = Spec { path: 0, others: 1 };
        assert_eq!(
            parse(&json!({ "cel": "true" })).expect("parses").spec(),
            one
        );
        let long =
            "request.method == 'GET' && request.path.startsWith('/a') && request.host == 'a'";
        assert_eq!(
            parse(&json!({ "cel": long })).expect("parses").spec(),
            one,
            "however much the expression says"
        );
        assert_eq!(
            parse(&json!({ "method": "GET" })).expect("parses").spec(),
            one,
            "the same as one typed constraint"
        );
        let with_path = parse(&json!({ "all": [{ "path_prefix": "/a" }, { "cel": "true" }] }))
            .expect("parses")
            .spec();
        assert_eq!(with_path.others, 1);
        assert!(with_path.path > 0);
        let (a, b) = (
            parse(&json!({ "cel": "request.method == 'GET'" })).expect("parses"),
            parse(&json!({ "cel": "request.method == 'POST'" })).expect("parses"),
        );
        assert!(
            !disjoint(&a, &b),
            "two expressions are never provably disjoint"
        );
    }
}
