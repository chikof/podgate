//! The rule engine of `content_guard`: tenant-written patterns, compiled with hard caps, run in
//! one pass over the string values of a JSON body.
//!
//! The engine is the `regex` crate only, which matches in time linear in the input and has no
//! backtracking, so a pattern such as `(a+)+$` costs one pass. What a tenant can spend is
//! bounded anyway: at most [`MAX_RULES`] rules of at most [`MAX_PATTERN`] bytes, each compiled
//! program under [`PATTERN_SIZE_LIMIT`] bytes, every set of them under [`SET_SIZE_LIMIT`], the
//! lazy DFA of each under a fixed cache, and the input under `max_body_bytes`.
//!
//! The scan is a pure function of the rules and the body ([`Rules::scan`]). A matched value never
//! leaves it except inside the rewritten body: no error, no outcome and no `Debug` output of this
//! file carries one.

use std::borrow::Cow;

use regex::{NoExpand, Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::json::{Kind, Token, Tokens};

/// The most rules of one middleware.
pub(super) const MAX_RULES: usize = 64;

/// The longest pattern, in bytes.
pub(super) const MAX_PATTERN: usize = 1024;

/// The compiled size one pattern may take.
const PATTERN_SIZE_LIMIT: usize = 1 << 16;

/// The compiled size one set of patterns may take: every rule at its own limit fits.
const SET_SIZE_LIMIT: usize = MAX_RULES * PATTERN_SIZE_LIMIT;

/// The lazy DFA cache of one regex.
const DFA_LIMIT: usize = 1 << 18;

/// The lazy DFA cache of one set.
const SET_DFA_LIMIT: usize = 1 << 20;

/// How deeply a pattern may nest groups.
const NEST_LIMIT: u32 = 32;

/// The longest rule or category name.
const MAX_NAME: usize = 64;

/// The longest rule name: it is printed in `[redacted:<name>]`.
const MAX_RULE_NAME: usize = 32;

/// What a rule does with a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum Action {
    /// Refuse the exchange.
    Block,
    /// Replace each match with `[redacted:<name>]`.
    Redact,
}

impl Action {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Redact => "redact",
        }
    }
}

/// The part of an exchange a rule or the classifier looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum Phase {
    /// The request body.
    Request,
    /// The response body.
    Response,
    /// Both.
    Both,
}

impl Phase {
    /// Whether a rule of this phase runs on `at`, which is `Request` or `Response`.
    pub(super) fn covers(self, at: Self) -> bool {
        self == Self::Both || self == at
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Both => "both",
        }
    }
}

/// One rule as the snapshot declares it.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleConfig {
    /// Names the rule: `[a-z0-9_-]`, at most 32 bytes, unique. Printed in `[redacted:<name>]`.
    name: String,
    /// A `regex` crate pattern, at most 1024 bytes. A pattern that matches the empty string is
    /// refused.
    pattern: String,
    /// Where the rule runs (default `both`).
    #[serde(default)]
    phase: Option<Phase>,
    /// `block` or `redact`. No default.
    action: Action,
    /// The label a `block` shows the client: `[a-z0-9_.-]`, at most 64 bytes. Default: the name.
    #[serde(default)]
    category: Option<String>,
}

/// A rule after validation, as explain and the plan see it. The pattern is kept only to compare
/// two declarations; it is never shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    pub(super) name: Box<str>,
    pub(super) category: Box<str>,
    pub(super) action: Action,
    pub(super) phase: Phase,
    pattern: Box<str>,
}

/// What a scan could not do with a body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unscannable {
    /// Not JSON, not UTF-8, trailing data, or nested past the parser's limit.
    NotJson,
    /// The redacted body would pass the output limit.
    TooMuchOutput,
}

/// What a scan found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Nothing matched: the body stands.
    Clean,
    /// A `block` rule matched; the exchange stops.
    Blocked {
        /// The rule's category.
        category: Box<str>,
    },
    /// Some `redact` rules matched: the body to send instead.
    Redacted(Vec<u8>),
}

/// The result of [`Rules::scan`].
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Scan {
    pub(super) outcome: Outcome,
    /// The string values left after redaction, joined with a newline, for the classifier. Empty
    /// unless the scan was asked for it.
    pub(super) text: String,
}

/// A redact rule ready to run.
#[derive(Debug, Clone)]
struct Redactor {
    regex: Regex,
    replacement: Box<str>,
    category: Box<str>,
}

/// The rules of one phase.
#[derive(Debug)]
struct Engine {
    /// The patterns of the `block` rules, and their categories in the same order.
    block: RegexSet,
    block_categories: Box<[Box<str>]>,
    /// The patterns of the `redact` rules, and how to rewrite for each, in the same order.
    redact: RegexSet,
    redactors: Box<[Redactor]>,
}

/// The compiled rules of a `content_guard`.
#[derive(Debug)]
pub(super) struct Rules {
    declared: Box<[Rule]>,
    request: Engine,
    response: Engine,
}

fn build(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .dfa_size_limit(DFA_LIMIT)
        .nest_limit(NEST_LIMIT)
        .build()
        .map_err(|why| why.to_string())
}

fn valid_name(name: &str, longest: usize) -> bool {
    !name.is_empty()
        && name.len() <= longest
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn valid_category(category: &str) -> bool {
    !category.is_empty()
        && category.len() <= MAX_NAME
        && category.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

impl Engine {
    fn new(rules: &[(&Rule, &Regex)]) -> Result<Self, String> {
        let mut block = Vec::new();
        let mut block_categories = Vec::new();
        let mut redact = Vec::new();
        let mut redactors = Vec::new();
        for (rule, regex) in rules {
            match rule.action {
                Action::Block => {
                    block.push(&*rule.pattern);
                    block_categories.push(rule.category.clone());
                }
                Action::Redact => {
                    redact.push(&*rule.pattern);
                    redactors.push(Redactor {
                        regex: (*regex).clone(),
                        replacement: format!("[redacted:{}]", rule.name).into(),
                        category: rule.category.clone(),
                    });
                }
            }
        }
        let set = |patterns: &[&str]| {
            RegexSetBuilder::new(patterns)
                .size_limit(SET_SIZE_LIMIT)
                .dfa_size_limit(SET_DFA_LIMIT)
                .nest_limit(NEST_LIMIT)
                .build()
                .map_err(|why| why.to_string())
        };
        Ok(Self {
            block: set(&block)?,
            block_categories: block_categories.into_boxed_slice(),
            redact: set(&redact)?,
            redactors: redactors.into_boxed_slice(),
        })
    }

    /// The category of the first `block` rule that matches `text`.
    fn blocked(&self, text: &str) -> Option<&str> {
        let first = self.block.matches(text).iter().next()?;
        self.block_categories.get(first).map(AsRef::as_ref)
    }

    /// The category of the first `redact` rule that matches `text`: a key or a number cannot be
    /// rewritten without changing the document, so a match there blocks.
    fn would_redact(&self, text: &str) -> Option<&str> {
        let first = self.redact.matches(text).iter().next()?;
        self.redactors
            .get(first)
            .map(|redactor| &*redactor.category)
    }
}

impl Rules {
    /// Compiles `configs`.
    ///
    /// # Errors
    ///
    /// The reason, without a pattern in it, that the list is not accepted: too many rules, a bad
    /// or repeated name, a bad category, a pattern that is empty, too long, does not compile
    /// under the size limits or matches the empty string.
    pub(super) fn compile(configs: &[RuleConfig]) -> Result<Self, String> {
        if configs.len() > MAX_RULES {
            return Err(format!("`rules` lists more than {MAX_RULES} rules"));
        }
        let mut declared: Vec<Rule> = Vec::with_capacity(configs.len());
        let mut regexes: Vec<Regex> = Vec::with_capacity(configs.len());
        for config in configs {
            let at = declared.len() + 1;
            if !valid_name(&config.name, MAX_RULE_NAME) {
                return Err(format!(
                    "rule {at}: `name` is 1 to {MAX_RULE_NAME} bytes of a-z, 0-9, `_` and `-`"
                ));
            }
            if declared.iter().any(|known| *known.name == *config.name) {
                return Err(format!("rule {} is declared twice", config.name));
            }
            let category = config.category.as_deref().unwrap_or(&config.name);
            if !valid_category(category) {
                return Err(format!(
                    "rule {}: `category` is 1 to {MAX_NAME} bytes of a-z, 0-9, `_`, `-` and `.`",
                    config.name
                ));
            }
            if config.pattern.is_empty() || config.pattern.len() > MAX_PATTERN {
                return Err(format!(
                    "rule {}: `pattern` is 1 to {MAX_PATTERN} bytes",
                    config.name
                ));
            }
            let regex = build(&config.pattern).map_err(|_| {
                format!(
                    "rule {}: `pattern` is not a regex the engine accepts within its size limits",
                    config.name
                )
            })?;
            if regex.is_match("") {
                return Err(format!(
                    "rule {}: `pattern` matches the empty string",
                    config.name
                ));
            }
            declared.push(Rule {
                name: config.name.as_str().into(),
                category: category.into(),
                action: config.action,
                phase: config.phase.unwrap_or(Phase::Both),
                pattern: config.pattern.as_str().into(),
            });
            regexes.push(regex);
        }
        let engine = |at: Phase| {
            let chosen: Vec<(&Rule, &Regex)> = declared
                .iter()
                .zip(&regexes)
                .filter(|(rule, _)| rule.phase.covers(at))
                .collect();
            Engine::new(&chosen)
        };
        let request = engine(Phase::Request)?;
        let response = engine(Phase::Response)?;
        Ok(Self {
            declared: declared.into_boxed_slice(),
            request,
            response,
        })
    }

    /// The rules in declaration order.
    pub(super) fn declared(&self) -> &[Rule] {
        &self.declared
    }

    /// Whether some rule runs on `phase`.
    pub(super) fn has(&self, phase: Phase) -> bool {
        self.declared.iter().any(|rule| rule.phase.covers(phase))
    }

    /// Whether `new` runs fewer or weaker checks than `self`: a rule that is gone, has another
    /// pattern, is a redaction where it blocked, or runs in fewer phases.
    pub(super) fn weakened_by(&self, new: &Self) -> bool {
        self.declared.iter().any(|old| {
            !new.declared.iter().any(|now| {
                now.name == old.name
                    && now.pattern == old.pattern
                    && (now.action == old.action || now.action == Action::Block)
                    && (now.phase == Phase::Both || now.phase == old.phase)
            })
        })
    }

    fn engine(&self, phase: Phase) -> &Engine {
        if phase == Phase::Response {
            &self.response
        } else {
            &self.request
        }
    }

    /// Runs the rules of `phase` (`Request` or `Response`) over the JSON document `body`.
    ///
    /// Every string value is checked against the `block` rules (on the text as it came) and
    /// then the `redact` rules (each on the text the one before left). Keys and numbers are
    /// checked too, but a `redact` rule that matches one blocks instead: rewriting it would
    /// change the shape of the document. Only the spans of redacted strings are re-encoded;
    /// everything else of the body is copied byte for byte, so the result is valid JSON that
    /// differs from the input only in those values.
    ///
    /// `limit` is the most bytes the rewritten body may take. With `want_text` the scan also
    /// returns the text the classifier is shown.
    ///
    /// # Errors
    ///
    /// [`Unscannable`] when `body` is not JSON or the rewrite would pass `limit`.
    pub(super) fn scan(
        &self,
        phase: Phase,
        body: &[u8],
        limit: usize,
        want_text: bool,
    ) -> Result<Scan, Unscannable> {
        serde_json::from_slice::<IgnoredAny>(body).map_err(|_| Unscannable::NotJson)?;
        let engine = self.engine(phase);
        let mut out: Vec<u8> = Vec::new();
        let mut copied = 0;
        let mut rewritten = false;
        let mut text = String::new();
        let mut tokens = Tokens::new(body);
        for token in tokens.by_ref() {
            let value = decode(body, token)?;
            if let Some(category) = engine.blocked(&value) {
                return Ok(blocked(category));
            }
            let current = if token.kind == Kind::Str {
                let (current, changed) = engine.redact_value(value);
                if changed {
                    rewritten = true;
                    out.extend_from_slice(&body[copied..token.start]);
                    let encoded =
                        serde_json::to_vec(&*current).map_err(|_| Unscannable::NotJson)?;
                    out.extend_from_slice(&encoded);
                    copied = token.end;
                    if out.len() > limit {
                        return Err(Unscannable::TooMuchOutput);
                    }
                }
                current
            } else {
                if let Some(category) = engine.would_redact(&value) {
                    return Ok(blocked(category));
                }
                continue;
            };
            if want_text {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&current);
            }
        }
        if tokens.too_deep() {
            return Err(Unscannable::NotJson);
        }
        let outcome = if !rewritten {
            Outcome::Clean
        } else {
            out.extend_from_slice(&body[copied..]);
            if out.len() > limit {
                return Err(Unscannable::TooMuchOutput);
            }
            Outcome::Redacted(out)
        };
        Ok(Scan { outcome, text })
    }
}

fn blocked(category: &str) -> Scan {
    Scan {
        outcome: Outcome::Blocked {
            category: category.into(),
        },
        text: String::new(),
    }
}

impl Engine {
    /// Applies every `redact` rule that matches `value`, in declaration order, each to the text
    /// the one before left. Whether anything changed comes second.
    fn redact_value<'a>(&self, value: Cow<'a, str>) -> (Cow<'a, str>, bool) {
        let mut current = value;
        let mut changed = false;
        for index in self.redact.matches(&current).iter() {
            let Some(redactor) = self.redactors.get(index) else {
                continue;
            };
            let replaced = redactor
                .regex
                .replace_all(&current, NoExpand(&redactor.replacement));
            if let Cow::Owned(next) = replaced {
                current = Cow::Owned(next);
                changed = true;
            }
        }
        (current, changed)
    }
}

/// The text of a token: a string without its quotes and with its escapes decoded, a number as
/// written.
fn decode(body: &[u8], token: Token) -> Result<Cow<'_, str>, Unscannable> {
    let raw = body
        .get(token.start..token.end)
        .ok_or(Unscannable::NotJson)?;
    if token.kind == Kind::Num {
        return std::str::from_utf8(raw)
            .map(Cow::Borrowed)
            .map_err(|_| Unscannable::NotJson);
    }
    if raw.contains(&b'\\') {
        return serde_json::from_slice::<String>(raw)
            .map(Cow::Owned)
            .map_err(|_| Unscannable::NotJson);
    }
    let inner = raw
        .get(1..raw.len().saturating_sub(1))
        .ok_or(Unscannable::NotJson)?;
    std::str::from_utf8(inner)
        .map(Cow::Borrowed)
        .map_err(|_| Unscannable::NotJson)
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;

    fn rule(name: &str, pattern: &str, action: &str, phase: &str) -> RuleConfig {
        serde_json::from_value(json!({
            "name": name, "pattern": pattern, "action": action, "phase": phase,
        }))
        .expect("rule")
    }

    fn rules(list: &[(&str, &str, &str)]) -> Rules {
        let configs: Vec<RuleConfig> = list
            .iter()
            .map(|(name, pattern, action)| rule(name, pattern, action, "both"))
            .collect();
        Rules::compile(&configs).expect("compiled")
    }

    fn scan(rules: &Rules, body: &str) -> Scan {
        rules
            .scan(Phase::Request, body.as_bytes(), 1 << 20, true)
            .expect("scanned")
    }

    fn redacted(rules: &Rules, body: &str) -> String {
        match scan(rules, body).outcome {
            Outcome::Redacted(bytes) => String::from_utf8(bytes).expect("utf-8"),
            other => panic!("not redacted: {other:?}"),
        }
    }

    #[test]
    fn content_guard_rule_limits() {
        let ok = |list: Vec<RuleConfig>| Rules::compile(&list).is_ok();
        let many = |count: usize| -> Vec<RuleConfig> {
            (0..count)
                .map(|at| rule(&format!("r{at}"), "x", "block", "both"))
                .collect()
        };
        assert!(ok(many(MAX_RULES)));
        assert!(!ok(many(MAX_RULES + 1)));
        assert!(ok(vec![rule(
            "a",
            &"x".repeat(MAX_PATTERN),
            "block",
            "both"
        )]));
        assert!(!ok(vec![rule(
            "a",
            &"x".repeat(MAX_PATTERN + 1),
            "block",
            "both"
        )]));
        assert!(!ok(vec![rule("a", "", "block", "both")]));
        // Compiles to a program far over the size limit.
        assert!(!ok(vec![rule("a", r"\p{L}{2000}", "block", "both")]));
        assert!(!ok(vec![rule("a", "(unclosed", "block", "both")]));
        for empty in ["a*", "^", "(?:)", "x?"] {
            assert!(!ok(vec![rule("a", empty, "block", "both")]), "{empty}");
        }
        for name in ["", "A", "a b", &"a".repeat(33)] {
            assert!(!ok(vec![rule(name, "x", "block", "both")]), "{name:?}");
        }
        assert!(!ok(vec![
            rule("a", "x", "block", "both"),
            rule("a", "y", "block", "both")
        ]));
        let mut bad_category = rule("a", "x", "block", "both");
        bad_category.category = Some("Not Valid".into());
        assert!(!ok(vec![bad_category]));
        assert!(
            serde_json::from_value::<RuleConfig>(json!({"name": "a", "pattern": "x"})).is_err(),
            "no default action"
        );
        assert!(
            serde_json::from_value::<RuleConfig>(
                json!({"name": "a", "pattern": "x", "action": "log"})
            )
            .is_err()
        );
    }

    #[test]
    fn content_guard_error_never_carries_a_pattern() {
        let secret = "sentinel-(?P<oops";
        let err = Rules::compile(&[rule("a", secret, "block", "both")]).expect_err("refused");
        assert!(!err.contains("sentinel"), "{err}");
    }

    #[test]
    fn content_guard_pattern_linear_time() {
        let rules = rules(&[
            ("greedy", "(a+)+$", "block"),
            ("pairs", "(x+x+)+y", "block"),
        ]);
        let value = format!("{}!", "a".repeat(64 * 1024 - 64));
        let body = format!(r#"{{"text": "{value}"}}"#);
        let started = Instant::now();
        let scanned = scan(&rules, &body);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "a backtracking engine would not finish: {:?}",
            started.elapsed()
        );
        // `(a+)+$` needs the run of `a` to reach the end, which the `!` prevents.
        assert_eq!(scanned.outcome, Outcome::Clean);
        let ends_clean = format!(r#"{{"text": "!{}"}}"#, "a".repeat(64 * 1024 - 64));
        assert!(matches!(
            scan(&rules, &ends_clean).outcome,
            Outcome::Blocked { .. }
        ));
    }

    #[test]
    fn content_guard_redact_keeps_json_valid() {
        let rules = rules(&[
            ("email", r"[a-z]+@[a-z]+\.com", "redact"),
            ("ssn", r"\d{3}-\d{2}-\d{4}", "redact"),
        ]);
        let body = concat!(
            "{ \"id\": 12345678901234567890123456, \"big\": 1e400,\n",
            "  \"user\": {\"mail\": \"ann@example.com\", \"note\": \"x\\u00e9y \\\"q\\\" ann@example.com / 123-45-6789\"},\n",
            "  \"list\": [\"ok\", \"bob@site.com\", 3, null, true], \"ünï\": \"clean\" }"
        );
        let out = redacted(&rules, body);
        assert_eq!(
            out,
            concat!(
                "{ \"id\": 12345678901234567890123456, \"big\": 1e400,\n",
                "  \"user\": {\"mail\": \"[redacted:email]\", \"note\": \"xéy \\\"q\\\" [redacted:email] / [redacted:ssn]\"},\n",
                "  \"list\": [\"ok\", \"[redacted:email]\", 3, null, true], \"ünï\": \"clean\" }"
            )
        );
        serde_json::from_str::<IgnoredAny>(&out).expect("still JSON");
        assert_eq!(
            scan(&rules, r#"{"a": "nothing here", "b": [1, 2]}"#).outcome,
            Outcome::Clean
        );
    }

    #[test]
    fn content_guard_scan_text_is_what_redaction_left() {
        let rules = rules(&[("email", r"[a-z]+@[a-z]+\.com", "redact")]);
        let scanned = scan(&rules, r#"{"key": ["a@b.com", "plain", 7], "z": "q"}"#);
        assert_eq!(scanned.text, "[redacted:email]\nplain\nq");
        let off = rules
            .scan(Phase::Request, br#"["x"]"#, 1024, false)
            .expect("scanned");
        assert!(off.text.is_empty());
    }

    #[test]
    fn content_guard_block_precedes_redact() {
        let rules = rules(&[
            ("mail", r"[a-z]+@[a-z]+\.com", "redact"),
            ("secret", "hunter2", "block"),
        ]);
        let first = r#"{"a": "ann@example.com", "b": "my hunter2"}"#;
        assert_eq!(
            scan(&rules, first).outcome,
            Outcome::Blocked {
                category: "secret".into()
            },
            "a later block wins over an earlier redaction"
        );
        // A redaction never hides a value from a block rule on the same string.
        assert!(matches!(
            scan(&rules, r#"{"a": "ann@example.com hunter2"}"#).outcome,
            Outcome::Blocked { .. }
        ));
    }

    #[test]
    fn content_guard_key_and_number_match_blocks() {
        let rules = rules(&[
            ("mail", r"[a-z]+@[a-z]+\.com", "redact"),
            ("card", "^4[0-9]{15}$", "redact"),
        ]);
        assert!(matches!(
            scan(&rules, r#"{"ann@example.com": 1}"#).outcome,
            Outcome::Blocked { .. }
        ));
        assert!(matches!(
            scan(&rules, r#"{"card": 4111111111111111}"#).outcome,
            Outcome::Blocked { .. }
        ));
        assert!(matches!(
            scan(&rules, r#"{"card": "4111111111111111"}"#).outcome,
            Outcome::Redacted(_)
        ));
    }

    #[test]
    fn content_guard_rules_follow_their_phase() {
        let configs = vec![
            rule("req", "alpha", "block", "request"),
            rule("res", "beta", "block", "response"),
            rule("both", "gamma", "block", "both"),
        ];
        let rules = Rules::compile(&configs).expect("compiled");
        let blocked = |phase: Phase, text: &str| {
            let body = format!(r#"["{text}"]"#);
            matches!(
                rules
                    .scan(phase, body.as_bytes(), 1024, false)
                    .expect("scanned")
                    .outcome,
                Outcome::Blocked { .. }
            )
        };
        assert!(blocked(Phase::Request, "alpha") && !blocked(Phase::Response, "alpha"));
        assert!(!blocked(Phase::Request, "beta") && blocked(Phase::Response, "beta"));
        assert!(blocked(Phase::Request, "gamma") && blocked(Phase::Response, "gamma"));
        assert!(rules.has(Phase::Request) && rules.has(Phase::Response));
    }

    #[test]
    fn content_guard_scan_unscannable() {
        let rules = rules(&[("a", "x", "block")]);
        let deep = format!("{}{}", "[".repeat(129), "]".repeat(129));
        for bad in [
            "",
            "not json",
            r#"{"a": 1} trailing"#,
            r#"{"a": 1}{"b": 2}"#,
            "\u{feff}{\"a\": 1}",
            &deep,
            "{\"a\": ",
        ] {
            assert_eq!(
                rules.scan(Phase::Request, bad.as_bytes(), 1 << 20, false),
                Err(Unscannable::NotJson),
                "{bad:?}"
            );
        }
        assert_eq!(
            rules.scan(Phase::Request, b"[\"\xff\xfe\"]", 1 << 20, false),
            Err(Unscannable::NotJson)
        );
        // Scalars at the top level are JSON.
        assert!(rules.scan(Phase::Request, b"\"x\"", 64, false).is_ok());
    }

    #[test]
    fn content_guard_output_cap() {
        let rules = rules(&[("a", "a", "redact")]);
        let body = format!(r#"["{}"]"#, "a".repeat(1000));
        // Each `a` becomes `[redacted:a]`, 12 bytes.
        let grown = rules.scan(Phase::Request, body.as_bytes(), 4096, false);
        assert_eq!(grown, Err(Unscannable::TooMuchOutput));
        assert!(
            rules
                .scan(Phase::Request, body.as_bytes(), 1 << 20, false)
                .is_ok()
        );
    }

    #[test]
    fn content_guard_weakened_by() {
        let base = |action: &str, phase: &str, pattern: &str| {
            Rules::compile(&[rule("r", pattern, action, phase)]).expect("compiled")
        };
        let old = base("block", "both", "x");
        assert!(!old.weakened_by(&base("block", "both", "x")));
        assert!(old.weakened_by(&base("redact", "both", "x")));
        assert!(old.weakened_by(&base("block", "request", "x")));
        assert!(old.weakened_by(&base("block", "both", "y")));
        assert!(old.weakened_by(&Rules::compile(&[]).expect("compiled")));
        let redact = base("redact", "request", "x");
        assert!(!redact.weakened_by(&base("block", "both", "x")));
        assert!(!redact.weakened_by(&base("redact", "request", "x")));
        assert!(redact.weakened_by(&base("redact", "response", "x")));
        // A new rule is not a relaxation.
        let extra = Rules::compile(&[
            rule("r", "x", "block", "both"),
            rule("s", "y", "block", "both"),
        ])
        .expect("compiled");
        assert!(!old.weakened_by(&extra));
    }
}
