//! Traefik rule strings in a snapshot.
//!
//! A router may carry ``rule: "Host(`a.test`) && PathPrefix(`/api`)"`` instead of a `match`
//! tree. The string is only an input syntax: [`resolve`] hands it to `podgate-rule`, the parser
//! the providers use, and replaces it with the matcher tree it returns before any other compile
//! step looks at the router. Claims, specificity, disjointness, the catch-all rule, explain and
//! the plan diff all read that tree, so a rule can never get a check a tree would not. The rule
//! text is never inspected here.
//!
//! The limits of the tree apply to the rule: a regular expression is compiled with the same
//! size limit as a `host_regexp` leaf, and the tree goes through [`super::matcher::parse`] like
//! any other.

use std::borrow::Cow;

use podgate_model::Router;
use podgate_rule::{Dialect, Rule, RuleErrorKind};
use serde_json::Value;

use super::matcher;
use crate::compile::Invalid;

/// The longest rule accepted, in bytes. The parser itself stops at 16 KiB; no real router rule
/// is within an order of magnitude of this.
pub(crate) const MAX_RULE_BYTES: usize = 2048;

/// `router` with its `rule` compiled into `match`, and the rule's length as the `priority` when it
/// sets none. A router without a rule is returned as it is.
///
/// # Errors
///
/// `invalid_router` when the router has both or neither of `match` and `rule`; otherwise the
/// errors of [`translate`], each with the byte `position` in the rule when one is known.
pub(crate) fn resolve(router: &Router) -> Result<Cow<'_, Router>, Invalid> {
    let Some(text) = router.rule.as_deref() else {
        return if router.matcher.is_null() {
            Err(exclusive())
        } else {
            Ok(Cow::Borrowed(router))
        };
    };
    if !router.matcher.is_null() {
        return Err(exclusive());
    }
    let rule = translate(text, Dialect::Http)?;
    let Some(tree) = rule.matcher else {
        return Err(Invalid::new(
            "invalid_rule",
            "the rule matches every request; an HTTP router needs a host, a path or another constraint",
        ));
    };
    let mut resolved = router.clone();
    resolved.matcher = tree;
    if resolved.priority.is_none() {
        resolved.priority = Some(i32::try_from(rule.len).unwrap_or(i32::MAX));
    }
    Ok(Cow::Owned(resolved))
}

/// The matcher of a TCP router that sets `match`, `rule` or neither: `match` as written, the tree
/// of `rule`, or `None` for a catch-all (also what a rule of ``HostSNI(`*`)`` is).
///
/// # Errors
///
/// `invalid_router` when both are set; otherwise the errors of [`translate`].
pub(crate) fn resolve_tcp(
    matcher: Option<&Value>,
    rule: Option<&str>,
) -> Result<Option<Value>, Invalid> {
    match (matcher, rule) {
        (Some(_), Some(_)) => Err(exclusive()),
        (matcher, None) => Ok(matcher.cloned()),
        (None, Some(text)) => Ok(translate(text, Dialect::Tcp)?.matcher),
    }
}

fn exclusive() -> Invalid {
    Invalid::new(
        "invalid_router",
        "a router needs exactly one of `match` and `rule`",
    )
}

/// Parses `text` with the shared grammar and holds its regular expressions to the matcher limits.
///
/// # Errors
///
/// `invalid_rule` for a rule over [`MAX_RULE_BYTES`], one that is malformed in any dialect (a
/// syntax error, a function of the other dialect, a regular expression that does not compile or
/// is over the size limit); `unsupported_rule` for Traefik syntax podgate does not translate.
pub(crate) fn translate(text: &str, dialect: Dialect) -> Result<Rule, Invalid> {
    if text.len() > MAX_RULE_BYTES {
        return Err(Invalid::new(
            "invalid_rule",
            format!(
                "rule: {} bytes is over the limit of {MAX_RULE_BYTES}",
                text.len()
            ),
        ));
    }
    let rule = podgate_rule::parse(text, dialect).map_err(|err| {
        let code = match err.kind() {
            RuleErrorKind::Unsupported => "unsupported_rule",
            RuleErrorKind::Invalid => "invalid_rule",
        };
        Invalid::new(code, format!("rule: {err}")).with("position", err.at())
    })?;
    for pattern in &rule.regexes {
        if let Err(err) = matcher::regex("rule", pattern) {
            let invalid = Invalid::new("invalid_rule", err.message);
            return Err(match text.find(&**pattern) {
                Some(at) => invalid.with("position", at),
                None => invalid,
            });
        }
    }
    Ok(rule)
}

/// `tree` with the operands of every `all` and `any`, and every list of names, in a fixed order.
/// The same set of requests written in another order gives the same value, which is what the plan
/// diff compares; matching never reads it.
pub(crate) fn canonical(tree: &Value) -> Value {
    let Value::Object(map) = tree else {
        return tree.clone();
    };
    let sorted = |items: Vec<Value>| {
        let mut items = items;
        items.sort_by_cached_key(Value::to_string);
        Value::Array(items)
    };
    map.iter()
        .map(|(key, value)| {
            let value = match (key.as_str(), value) {
                ("all" | "any", Value::Array(items)) => {
                    sorted(items.iter().map(canonical).collect())
                }
                ("host" | "method" | "client_ip" | "sni" | "alpn", Value::Array(names)) => {
                    sorted(names.clone())
                }
                (_, other) => canonical(other),
            };
            (key.clone(), value)
        })
        .collect()
}

#[cfg(test)]
mod test {
    use pingora::http::RequestHeader;
    use podgate_model::Router;
    use serde_json::json;

    use super::*;
    use crate::router::CompiledRouter;
    use crate::router::matcher::{Hello, View};

    fn router(rule: Option<&str>, matcher: Value, priority: Option<i32>) -> Router {
        serde_json::from_value(json!({
            "name": "r", "service": "web", "match": matcher, "rule": rule, "priority": priority,
        }))
        .expect("router")
    }

    fn app() -> podgate_model::App {
        serde_json::from_value(json!({
            "id": "a", "tenant": "t", "declared_by": "test", "tls": {"mode": "acme"},
            "routers": [], "revisions": [],
        }))
        .expect("app")
    }

    fn compiled(router: &Router) -> CompiledRouter {
        let resolved = resolve(router).expect("resolves");
        CompiledRouter::compile(&resolved, &app(), &[]).expect("compiles")
    }

    fn request(method: &str, target: &str, headers: &[(&str, &str)]) -> RequestHeader {
        let mut request = RequestHeader::build(method, target.as_bytes(), None).expect("request");
        for (name, value) in headers {
            request
                .insert_header((*name).to_owned(), *value)
                .expect("header");
        }
        request
    }

    /// Whether `router` takes the request `host`, `method`, `target` with `headers`.
    fn takes(
        router: &CompiledRouter,
        host: &str,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
    ) -> bool {
        let request = request(method, target, headers);
        let path = target.split('?').next().unwrap_or(target);
        router.matcher().matches(&View {
            host,
            path,
            entry_point: "web",
            tls: false,
            request: &request,
            client_ip: Some("10.1.2.3".parse().expect("ip")),
            hello: Hello::NONE,
        })
    }

    /// Requests the table below is run against.
    fn requests() -> Vec<(
        &'static str,
        &'static str,
        &'static str,
        Vec<(&'static str, &'static str)>,
    )> {
        let mut table = Vec::new();
        for host in ["a.test", "b.test", "x.a.test", "api-7.example.org"] {
            for method in ["GET", "POST", "DELETE"] {
                for target in ["/", "/api", "/api/v1/users?debug=1", "/admin/x", "/Api"] {
                    for headers in [
                        vec![],
                        vec![("x-env", "canary")],
                        vec![("x-env", "prod"), ("x-beta", "1")],
                    ] {
                        table.push((host, method, target, headers));
                    }
                }
            }
        }
        table
    }

    #[test]
    fn rule_equals_match_tree_behaviour() {
        let cases = [
            (
                "Host(`a.test`) && PathPrefix(`/api`)",
                json!({"all": [{"host": "a.test"}, {"path_prefix": "/api"}]}),
            ),
            (
                "Host(`a.test`, `b.test`)",
                json!({"host": ["a.test", "b.test"]}),
            ),
            (
                "Host(`*.a.test`) && Method(`POST`, `get`)",
                json!({"all": [{"host": "*.a.test"}, {"method": ["POST", "GET"]}]}),
            ),
            (
                "Host(`a.test`) && Path(`/api`, `/admin/x`)",
                json!({"all": [{"host": "a.test"}, {"any": [{"path": "/api"}, {"path": "/admin/x"}]}]}),
            ),
            (
                "Host(`a.test`) && PathRegexp(`^/api/v[0-9]+/`)",
                json!({"all": [{"host": "a.test"}, {"path_regexp": "^/api/v[0-9]+/"}]}),
            ),
            (
                "Host(`a.test`) && Header(`X-Env`, `canary`)",
                json!({"all": [{"host": "a.test"}, {"header": {"name": "x-env", "value": "canary"}}]}),
            ),
            (
                "Host(`a.test`) && HeaderRegexp(`x-env`, `^ca`)",
                json!({"all": [{"host": "a.test"}, {"header_regexp": {"name": "x-env", "regex": "^ca"}}]}),
            ),
            (
                "Host(`a.test`) && Query(`debug=1`)",
                json!({"all": [{"host": "a.test"}, {"query": {"name": "debug", "value": "1"}}]}),
            ),
            (
                "Host(`a.test`) && QueryRegexp(`debug`, `^[0-9]$`)",
                json!({"all": [{"host": "a.test"}, {"query_regexp": {"name": "debug", "regex": "^[0-9]$"}}]}),
            ),
            (
                "Host(`a.test`) && ClientIP(`10.0.0.0/8`)",
                json!({"all": [{"host": "a.test"}, {"client_ip": ["10.0.0.0/8"]}]}),
            ),
            (
                "HostRegexp(`^api-[0-9]+\\.example\\.org$`) && Host(`api-7.example.org`)",
                json!({"all": [{"host_regexp": "^api-[0-9]+\\.example\\.org$"}, {"host": "api-7.example.org"}]}),
            ),
            (
                "Host(`a.test`) || Host(`b.test`)",
                json!({"host": ["a.test", "b.test"]}),
            ),
        ];
        let requests = requests();
        for (rule, tree) in cases {
            let by_rule = compiled(&router(Some(rule), Value::Null, None));
            let len = i32::try_from(rule.len()).expect("length");
            let by_tree = compiled(&router(None, tree.clone(), Some(len)));
            assert_eq!(by_rule.priority(), len, "{rule}: priority is the length");
            assert_eq!(by_rule.priority(), by_tree.priority(), "{rule}");
            assert_eq!(by_rule.spec(), by_tree.spec(), "{rule}: specificity");
            assert_eq!(by_rule.tier(), by_tree.tier(), "{rule}: tier");
            assert_eq!(
                by_rule.patterns().collect::<Vec<_>>(),
                by_tree.patterns().collect::<Vec<_>>(),
                "{rule}: host claims"
            );
            assert_eq!(
                by_rule.matcher_json(),
                &tree,
                "{rule}: the tree it compiled to"
            );
            let mut hits = 0;
            for (host, method, target, headers) in &requests {
                let want = takes(&by_tree, host, method, target, headers);
                assert_eq!(
                    takes(&by_rule, host, method, target, headers),
                    want,
                    "{rule} on {method} {host}{target} {headers:?}"
                );
                hits += usize::from(want);
            }
            assert!(
                hits > 0 && hits < requests.len(),
                "{rule}: the table must both hit and miss ({hits} of {})",
                requests.len()
            );
        }
    }

    #[test]
    fn rule_nesting_and_negation() {
        let cases = [
            (
                "Host(`a.test`) && !PathPrefix(`/admin`)",
                json!({"all": [{"host": "a.test"}, {"not": {"path_prefix": "/admin"}}]}),
            ),
            (
                "Host(`a.test`) && (PathPrefix(`/api`) || Method(`DELETE`))",
                json!({"all": [{"host": "a.test"}, {"any": [{"path_prefix": "/api"}, {"method": "DELETE"}]}]}),
            ),
            (
                "(Host(`a.test`) || Host(`b.test`)) && !(Method(`POST`) || Header(`x-env`, `prod`))",
                json!({"all": [
                    {"host": ["a.test", "b.test"]},
                    {"not": {"any": [{"method": "POST"}, {"header": {"name": "x-env", "value": "prod"}}]}},
                ]}),
            ),
            (
                "Host(`a.test`) && !(!PathPrefix(`/api`))",
                json!({"all": [{"host": "a.test"}, {"not": {"not": {"path_prefix": "/api"}}}]}),
            ),
            (
                "Host(`a.test`) && PathPrefix(`/api`) || Host(`b.test`) && Method(`GET`)",
                json!({"any": [
                    {"all": [{"host": "a.test"}, {"path_prefix": "/api"}]},
                    {"all": [{"host": "b.test"}, {"method": "GET"}]},
                ]}),
            ),
        ];
        let requests = requests();
        for (rule, tree) in cases {
            let by_rule = compiled(&router(Some(rule), Value::Null, None));
            let by_tree = compiled(&router(None, tree.clone(), Some(by_rule.priority())));
            assert_eq!(by_rule.matcher_json(), &tree, "{rule}");
            assert_eq!(by_rule.spec(), by_tree.spec(), "{rule}: specificity");
            assert_eq!(by_rule.tier(), by_tree.tier(), "{rule}: tier");
            let mut hits = 0;
            for (host, method, target, headers) in &requests {
                let want = takes(&by_tree, host, method, target, headers);
                assert_eq!(
                    takes(&by_rule, host, method, target, headers),
                    want,
                    "{rule} on {method} {host}{target} {headers:?}"
                );
                hits += usize::from(want);
            }
            assert!(hits > 0 && hits < requests.len(), "{rule}: {hits}");
        }
    }

    #[test]
    fn a_rule_without_a_priority_gets_its_length_and_a_tree_gets_zero() {
        let rule = "Host(`a.test`)";
        assert_eq!(
            compiled(&router(Some(rule), Value::Null, None)).priority(),
            14
        );
        assert_eq!(
            compiled(&router(Some(rule), Value::Null, Some(-3))).priority(),
            -3
        );
        assert_eq!(
            compiled(&router(None, json!({"host": "a.test"}), None)).priority(),
            0
        );
    }

    #[test]
    fn hostile_rules_are_refused_and_never_panic() {
        let mut corpus: Vec<String> = [
            "",
            " ",
            "(",
            ")",
            "!",
            "&&",
            "||",
            "Host",
            "Host(",
            "Host()",
            "Host(`",
            "Host(``)",
            "Host(`a.test`",
            "Host(`a.test`))",
            "Host(`a.test`) &&",
            "&& Host(`a.test`)",
            "Host(`a.test`) & Host(`b.test`)",
            "Host(`a.test`) !",
            "!=",
            "Host(`a.test`,)",
            "Host(,`a.test`)",
            "Host(\"a.test",
            "Host(\"\\q\")",
            "\u{0}",
            "Host(`\u{0}`)",
            "Host(`\u{202e}a.test`)",
            "Host(`ä.test`)",
            "HostRegexp(`(`)",
            "HostRegexp(`(?=a)`)",
            "HostRegexp(`(a{1000}){1000}`)",
            "HostRegexp(`{x:[a-z]+}`)",
            "Headers(`a`, `b`)",
            "HostSNI(`a.test`)",
            "Path()",
            "Path(`a`)",
            "Method(``)",
            "ClientIP(`300.1.1.1`)",
            "ClientIP(`1.1.1.1/99`)",
            "Query(`a`)",
            "Query(`=a`)",
            "Header(`a`)",
            "Nope(`x`)",
            "Host(`a`) && Host(`b`) || ",
            "Host(`a.test`)\n&&\nPath(`/`)",
            "\\",
            "`",
            "\"",
        ]
        .iter()
        .map(|rule| (*rule).to_owned())
        .collect();
        corpus.push("(".repeat(5000));
        corpus.push("!".repeat(5000));
        corpus.push(format!(
            "{}Host(`a.test`){}",
            "(".repeat(200),
            ")".repeat(200)
        ));
        corpus.push("Host(`a.test`) && ".repeat(200));
        corpus.push(format!("Host({})", "`a.test`,".repeat(1000)));
        corpus.push("x".repeat(MAX_RULE_BYTES + 1));
        // A fixed xorshift stream over a grammar-flavoured alphabet: cheap, repeatable, bounded.
        let alphabet: Vec<&str> = vec![
            "Host",
            "Path",
            "PathPrefix",
            "HostRegexp",
            "Method",
            "Header",
            "Query",
            "(",
            ")",
            "`",
            "\"",
            ",",
            "&&",
            "||",
            "!",
            " ",
            "a.test",
            "/",
            "*",
            ".",
            "\\",
            "[",
            "{",
            "\u{e9}",
            "\u{0}",
            "=",
            "^",
            "$",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..4000 {
            let mut rule = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let pieces = 1 + (state % 24) as usize;
            for _ in 0..pieces {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                rule.push_str(alphabet[(state % alphabet.len() as u64) as usize]);
            }
            corpus.push(rule);
        }
        let started = std::time::Instant::now();
        let mut refused = 0;
        for rule in &corpus {
            for dialect in [Dialect::Http, Dialect::Tcp] {
                match translate(rule, dialect) {
                    Ok(_) => {}
                    Err(invalid) => {
                        refused += 1;
                        assert!(
                            ["invalid_rule", "unsupported_rule"].contains(&invalid.code),
                            "{rule:?}: {invalid:?}"
                        );
                    }
                }
            }
            let router = router(Some(rule), Value::Null, None);
            if let Ok(resolved) = resolve(&router) {
                let _ = CompiledRouter::compile(&resolved, &app(), &[]);
            }
        }
        assert!(
            refused > corpus.len(),
            "most hostile rules are refused: {refused}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "parsing {} rules took {:?}",
            corpus.len(),
            started.elapsed()
        );
    }

    #[test]
    fn positions_point_into_the_rule() {
        let err = translate("Host(`a.test`) && Nope(`x`)", Dialect::Http).expect_err("unknown");
        assert_eq!(err.code, "unsupported_rule");
        assert_eq!(err.details.get("position"), Some(&json!(18)));
        let err = translate("Host(`a.test`) && HostRegexp(`^a(`)", Dialect::Http).expect_err("re");
        assert_eq!(err.code, "invalid_rule");
        assert!(err.details.contains_key("position"));
    }

    #[test]
    fn rule_regexp_limit_is_the_matchers() {
        // The shared grammar only knows the regex crate's default limit (10 MiB), the matchers
        // hold a pattern to 1 MiB: there is a pattern each accepts and the matcher refuses.
        let between = (1..=10)
            .map(|step| format!("(a{{{n}}}){{{n}}}", n = step * 100))
            .find(|pattern| {
                podgate_rule::check_pattern(pattern).is_ok()
                    && matcher::regex("t", pattern).is_err()
            })
            .expect("a pattern between the two limits");
        for rule in [
            format!("Host(`a.test`) && PathRegexp(`{between}`)"),
            format!("Host(`a.test`) && HeaderRegexp(`x`, `{between}`)"),
            format!("Host(`a.test`) && QueryRegexp(`x`, `{between}`)"),
            format!("HostRegexp(`{between}`)"),
        ] {
            assert!(podgate_rule::parse(&rule, Dialect::Http).is_ok(), "{rule}");
            let invalid = translate(&rule, Dialect::Http).expect_err(&rule);
            assert_eq!(invalid.code, "invalid_rule", "{rule}");
            assert_eq!(
                invalid.details.get("position"),
                rule.find(&between).map(|at| json!(at)).as_ref()
            );
        }
        let rule = format!("HostSNIRegexp(`{between}`)");
        let invalid = translate(&rule, Dialect::Tcp).expect_err("tcp");
        assert_eq!(invalid.code, "invalid_rule");
        assert!(translate("PathRegexp(`(a{10}){10}`)", Dialect::Http).is_ok());
        println!("pattern between the limits: {between}");
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..3000 {
            let mut bytes = Vec::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            for _ in 0..(state % 96) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                bytes.push(state.to_le_bytes()[3]);
            }
            let rule = String::from_utf8_lossy(&bytes).into_owned();
            for dialect in [Dialect::Http, Dialect::Tcp] {
                if let Err(invalid) = translate(&rule, dialect) {
                    assert!(["invalid_rule", "unsupported_rule"].contains(&invalid.code));
                }
            }
        }
    }

    #[test]
    fn equivalent_trees_have_one_canonical_form() {
        let a = canonical(
            &json!({"all": [{"host": ["b.test", "a.test"]}, {"method": ["POST", "GET"]}]}),
        );
        let b = canonical(
            &json!({"all": [{"method": ["GET", "POST"]}, {"host": ["a.test", "b.test"]}]}),
        );
        assert_eq!(a, b);
        let c = canonical(&json!({"all": [{"host": ["a.test"]}, {"method": ["GET"]}]}));
        assert_ne!(a, c);
    }
}
