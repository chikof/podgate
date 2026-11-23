//! The rules of `tool_access`: which verified claims may use which tool. Pure: no I/O, no clock,
//! no request. The gateway calls [`Access::allows`] and [`Access::reaches`] with the tool or
//! server its registry resolved and the claims a `jwt_auth` stage verified; nothing a client
//! sent is an input here. Reference: `docs/ref/mw-mcp-gateway.md`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::tools::{self, MAX_QUALIFIED};
use crate::middleware::jwt_auth::claims::{Requirement, matches};

/// The most rules of one `tool_access`.
const MAX_RULES: usize = 64;
/// The most `tools` entries of one rule.
const MAX_TOOLS: usize = 64;
/// The most claims of one `allow`.
const MAX_CLAIMS: usize = 8;
/// The most values of one claim.
const MAX_VALUES: usize = 32;
/// The longest claim name.
const MAX_CLAIM_NAME: usize = 64;
/// The longest value.
const MAX_VALUE: usize = 256;

/// The `posture_changes` kind of a `tool_access` that lets someone use a tool they could not.
pub(super) const WIDENED: &str = "mcp_tool_access_widened";
/// The `posture_changes` kind of a gateway that had `tool_access` and no longer does.
pub(super) const REMOVED: &str = "mcp_tool_access_removed";

/// One rule as declared.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleConfig {
    /// The tools the rule opens: `<server>__<tool>` as the client sees the name, or
    /// `<server>__*` for every tool of that server. 1 to 64 entries.
    tools: Vec<String>,
    /// The claims of the caller's verified token that open them: every claim named here must
    /// hold one of its values (a string claim equal to it, or an array claim with such an
    /// item). 1 to 8 claims, 1 to 32 non-empty values each.
    allow: BTreeMap<String, Vec<String>>,
}

/// What a rule opens: one tool of one server, or every tool of it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Tool(Box<str>, Box<str>),
    All(Box<str>),
}

impl Target {
    fn server(&self) -> &str {
        match self {
            Self::Tool(server, _) | Self::All(server) => server,
        }
    }

    fn lists(&self, server: &str, tool: &str) -> bool {
        match self {
            Self::Tool(own, name) => **own == *server && **name == *tool,
            Self::All(own) => **own == *server,
        }
    }

    /// Whether everything `other` opens, this opens.
    fn covers(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All(server), other) => **server == *other.server(),
            (own, other) => own == other,
        }
    }

    fn qualified(&self) -> String {
        match self {
            Self::Tool(server, tool) => tools::qualify(server, tool),
            Self::All(server) => tools::qualify(server, "*"),
        }
    }
}

#[derive(Debug)]
struct Rule {
    tools: Box<[Target]>,
    /// Claim name and the values of which one must match, in name order.
    allow: Box<[Requirement]>,
}

impl Rule {
    fn holds(&self, claims: &Map<String, Value>) -> bool {
        self.allow
            .iter()
            .all(|(name, want)| claims.get(&**name).is_some_and(|have| matches(have, want)))
    }

    /// Whether a caller with `claims` is at least as strict a match as `self` asks: every claim
    /// of `self` is in `stricter` with values that are all values of `self`.
    fn allows_no_more_than(&self, other: &Self) -> bool {
        other.allow.iter().all(|(name, want)| {
            self.allow
                .iter()
                .find(|(own, _)| own == name)
                .is_some_and(|(_, have)| have.iter().all(|value| want.contains(value)))
        })
    }
}

/// The compiled `tool_access` of one gateway.
#[derive(Debug)]
pub(super) struct Access {
    rules: Box<[Rule]>,
}

fn text(what: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!(
            "{what} must be 1 to {max} bytes without control characters"
        ));
    }
    Ok(())
}

fn target(entry: &str, servers: &[&str]) -> Result<Target, String> {
    let bad = |why: &str| format!("`tool_access` tool {entry:?}: {why}");
    text("a `tools` entry", entry, MAX_QUALIFIED).map_err(|why| bad(&why))?;
    let Some((server, tool)) = tools::split(entry) else {
        return Err(bad(
            "name a tool as `<server>__<tool>` or `<server>__*`; a bare tool name is never a rule",
        ));
    };
    if !servers.contains(&server) {
        return Err(bad(&format!("{server:?} is not a server of this registry")));
    }
    if tool.is_empty() {
        return Err(bad("the tool is empty"));
    }
    if tool == "*" {
        return Ok(Target::All(server.into()));
    }
    if tool.contains('*') {
        return Err(bad("`*` is only the whole tool part, as in `<server>__*`"));
    }
    Ok(Target::Tool(server.into(), tool.into()))
}

fn rule(config: RuleConfig, servers: &[&str]) -> Result<Rule, String> {
    if config.tools.is_empty() || config.tools.len() > MAX_TOOLS {
        return Err(format!(
            "a `tool_access` rule lists 1 to {MAX_TOOLS} `tools`"
        ));
    }
    if config.allow.is_empty() || config.allow.len() > MAX_CLAIMS {
        return Err(format!(
            "a `tool_access` rule's `allow` names 1 to {MAX_CLAIMS} claims; an empty `allow` would open the tools to every verified token (name a claim every token holds, such as `iss`, to say that on purpose)"
        ));
    }
    let tools = config
        .tools
        .iter()
        .map(|entry| target(entry, servers))
        .collect::<Result<Vec<_>, _>>()?;
    let mut allow = Vec::with_capacity(config.allow.len());
    for (name, values) in config.allow {
        text("a claim name of `allow`", &name, MAX_CLAIM_NAME)?;
        if values.is_empty() || values.len() > MAX_VALUES {
            return Err(format!(
                "claim {name:?} of `allow` lists 1 to {MAX_VALUES} values"
            ));
        }
        for value in &values {
            text(&format!("a value of claim {name:?}"), value, MAX_VALUE)?;
        }
        allow.push((
            name.into_boxed_str(),
            values.into_iter().map(Value::String).collect(),
        ));
    }
    Ok(Rule {
        tools: tools.into_boxed_slice(),
        allow: allow.into_boxed_slice(),
    })
}

impl Access {
    /// Compiles `rules` against the names of the registered `servers`.
    ///
    /// # Errors
    ///
    /// What is wrong with the rules, for `invalid_middleware`.
    pub(super) fn compile(rules: Vec<RuleConfig>, servers: &[&str]) -> Result<Self, String> {
        if rules.len() > MAX_RULES {
            return Err(format!("`tool_access` lists at most {MAX_RULES} rules"));
        }
        let rules = rules
            .into_iter()
            .map(|config| rule(config, servers))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rules: rules.into_boxed_slice(),
        })
    }

    /// Whether the caller whose verified token holds `claims` may use `tool` of `server`. No
    /// claims, no tool.
    pub(super) fn allows(
        &self,
        claims: Option<&Map<String, Value>>,
        server: &str,
        tool: &str,
    ) -> bool {
        claims.is_some_and(|claims| {
            self.rules.iter().any(|rule| {
                rule.tools.iter().any(|target| target.lists(server, tool)) && rule.holds(claims)
            })
        })
    }

    /// Whether the caller may use some tool of `server`.
    pub(super) fn reaches(&self, claims: Option<&Map<String, Value>>, server: &str) -> bool {
        claims.is_some_and(|claims| {
            self.rules.iter().any(|rule| {
                rule.tools.iter().any(|target| target.server() == server) && rule.holds(claims)
            })
        })
    }

    /// Whether some rule lists `tool` of `server`, exactly or by `server__*`, whatever its
    /// claims.
    pub(super) fn lists(&self, server: &str, tool: &str) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.tools.iter().any(|target| target.lists(server, tool)))
    }

    /// Whether `self`, replacing `old`, lets someone use something `old` did not. Each tool a
    /// rule lists is an atom with the rule's claims; an atom is covered when an atom of `old`
    /// covers its tool and asks for no claim it does not. Conservative: it never unites two
    /// atoms of `old`, so a merge of two rules is reported although it widens nothing.
    pub(super) fn widens(&self, old: &Self) -> bool {
        self.rules.iter().any(|new| {
            new.tools.iter().any(|atom| {
                !old.rules.iter().any(|before| {
                    before.tools.iter().any(|target| target.covers(atom))
                        && new.allows_no_more_than(before)
                })
            })
        })
    }

    /// The rules as explain shows them: in declaration order, claims in name order.
    pub(super) fn describe(&self) -> Value {
        Value::Array(
            self.rules
                .iter()
                .map(|rule| {
                    let allow: Map<String, Value> = rule
                        .allow
                        .iter()
                        .map(|(name, values)| (name.to_string(), json!(values)))
                        .collect();
                    json!({
                        "tools": rule.tools.iter().map(Target::qualified).collect::<Vec<_>>(),
                        "allow": allow,
                    })
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SERVERS: [&str; 2] = ["alpha", "beta"];

    fn access(rules: &Value) -> Access {
        compile(rules).expect("compiled")
    }

    fn compile(rules: &Value) -> Result<Access, String> {
        let rules: Vec<RuleConfig> =
            serde_json::from_value(rules.clone()).map_err(|e| e.to_string())?;
        Access::compile(rules, &SERVERS)
    }

    fn claims(value: &Value) -> Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    fn admin_reads_alpha() -> Value {
        json!([{"tools": ["alpha__read", "alpha__search"], "allow": {"roles": ["admin", "ops"]}}])
    }

    #[test]
    fn tbac_default_deny() {
        let rules = access(&admin_reads_alpha());
        let admin = claims(&json!({"roles": ["admin"]}));
        assert!(rules.allows(Some(&admin), "alpha", "read"));
        // A tool no rule lists.
        assert!(!rules.allows(Some(&admin), "alpha", "delete"));
        assert!(!rules.allows(Some(&admin), "beta", "read"));
        // An empty `tool_access` opens nothing, for anyone.
        let none = access(&json!([]));
        assert!(!none.allows(Some(&admin), "alpha", "read"));
        assert!(!none.reaches(Some(&admin), "alpha"));
        // No verified token, no tool.
        assert!(!rules.allows(None, "alpha", "read"));
        assert!(!rules.reaches(None, "alpha"));
    }

    #[test]
    fn tbac_missing_claim_denies() {
        let rules = access(&admin_reads_alpha());
        for token in [json!({}), json!({"sub": "ann"}), json!({"role": ["admin"]})] {
            assert!(
                !rules.allows(Some(&claims(&token)), "alpha", "read"),
                "{token}"
            );
        }
        // Every claim of a rule is required, not one of them.
        let both = access(
            &json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin"], "org": ["acme"]}}]),
        );
        assert!(!both.allows(Some(&claims(&json!({"roles": ["admin"]}))), "alpha", "read"));
        assert!(both.allows(
            Some(&claims(&json!({"roles": ["admin"], "org": "acme"}))),
            "alpha",
            "read"
        ));
    }

    #[test]
    fn tbac_claim_wrong_type_denies() {
        let rules = access(&admin_reads_alpha());
        for token in [
            json!({"roles": 1}),
            json!({"roles": true}),
            json!({"roles": null}),
            json!({"roles": {"admin": true}}),
            json!({"roles": []}),
            json!({"roles": [1, null, {"admin": 1}]}),
            json!({"roles": "Admin"}),
            json!({"roles": "admin ops"}),
        ] {
            assert!(
                !rules.allows(Some(&claims(&token)), "alpha", "read"),
                "{token}"
            );
        }
        for token in [json!({"roles": "ops"}), json!({"roles": ["x", "admin"]})] {
            assert!(
                rules.allows(Some(&claims(&token)), "alpha", "read"),
                "{token}"
            );
        }
    }

    #[test]
    fn tbac_same_name_on_two_servers_is_two_tools() {
        let rules = access(&json!([{"tools": ["alpha__search"], "allow": {"roles": ["admin"]}}]));
        let admin = claims(&json!({"roles": ["admin"]}));
        assert!(rules.allows(Some(&admin), "alpha", "search"));
        assert!(!rules.allows(Some(&admin), "beta", "search"));
        assert!(!rules.reaches(Some(&admin), "beta"));
    }

    #[test]
    fn tbac_wildcard_covers_server() {
        let rules = access(&json!([{"tools": ["beta__*"], "allow": {"roles": ["admin"]}}]));
        let admin = claims(&json!({"roles": ["admin"]}));
        assert!(rules.allows(Some(&admin), "beta", "anything"));
        assert!(rules.allows(Some(&admin), "beta", "a__b"));
        assert!(!rules.allows(Some(&admin), "alpha", "anything"));
        assert!(rules.lists("beta", "x") && !rules.lists("alpha", "x"));
        // A tool name may hold the separator.
        let nested = access(&json!([{"tools": ["alpha__a__b"], "allow": {"roles": ["admin"]}}]));
        assert!(nested.allows(Some(&admin), "alpha", "a__b"));
        assert!(!nested.allows(Some(&admin), "alpha", "a"));
    }

    #[test]
    fn tbac_rule_shapes_rejected() {
        let allow = json!({"roles": ["admin"]});
        let many = |count: usize| vec!["alpha__read"; count];
        for bad in [
            json!([{"tools": ["read"], "allow": allow}]),
            json!([{"tools": ["gamma__read"], "allow": allow}]),
            json!([{"tools": ["__read"], "allow": allow}]),
            json!([{"tools": ["*__read"], "allow": allow}]),
            json!([{"tools": ["alpha__"], "allow": allow}]),
            json!([{"tools": ["alpha__re*"], "allow": allow}]),
            json!([{"tools": [""], "allow": allow}]),
            json!([{"tools": [], "allow": allow}]),
            json!([{"tools": ["alpha__read"], "allow": {}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": []}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": [""]}}]),
            json!([{"tools": ["alpha__read"], "allow": {"": ["admin"]}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": [1]}}]),
            json!([{"tools": ["alpha__read"], "allow": allow, "extra": 1}]),
            json!([{"tools": many(MAX_TOOLS + 1), "allow": allow}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": vec!["x"; MAX_VALUES + 1]}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["x".repeat(MAX_VALUE + 1)]}}]),
            json!(vec![
                json!({"tools": ["alpha__read"], "allow": allow});
                MAX_RULES + 1
            ]),
        ] {
            assert!(compile(&bad).is_err(), "{bad}");
        }
        let claims: Map<String, Value> = (0..=MAX_CLAIMS)
            .map(|index| (format!("c{index}"), json!(["x"])))
            .collect();
        assert!(compile(&json!([{"tools": ["alpha__read"], "allow": claims}])).is_err());
        assert!(compile(&admin_reads_alpha()).is_ok());
    }

    fn widens(old: &Value, new: &Value) -> bool {
        access(new).widens(&access(old))
    }

    #[test]
    fn tbac_widening_is_a_posture_change() {
        let base = json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin"]}}]);
        // Identical, reordered and tightened rules are not widening.
        assert!(!widens(&base, &base));
        assert!(!widens(&base, &json!([])));
        assert!(!widens(
            &json!([{"tools": ["alpha__read", "alpha__write"], "allow": {"roles": ["admin", "ops"]}}]),
            &base
        ));
        assert!(!widens(
            &base,
            &json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin"], "org": ["acme"]}}])
        ));
        assert!(!widens(
            &json!([{"tools": ["alpha__*"], "allow": {"roles": ["admin"]}}]),
            &base
        ));
        // A tool, a value, a rule, a wildcard or a dropped claim widens.
        for wider in [
            json!([{"tools": ["alpha__read", "alpha__write"], "allow": {"roles": ["admin"]}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin", "ops"]}}]),
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin"]}}, {"tools": ["beta__read"], "allow": {"roles": ["admin"]}}]),
            json!([{"tools": ["alpha__*"], "allow": {"roles": ["admin"]}}]),
            json!([{"tools": ["beta__read"], "allow": {"roles": ["admin"]}}]),
        ] {
            assert!(widens(&base, &wider), "{wider}");
        }
        let strict =
            json!([{"tools": ["alpha__read"], "allow": {"roles": ["admin"], "org": ["acme"]}}]);
        assert!(widens(&strict, &base), "dropping a claim widens");
    }

    #[test]
    fn tbac_describe_lists_rules_in_order() {
        let rules = access(&json!([
            {"tools": ["beta__*", "alpha__read"], "allow": {"roles": ["a"], "org": ["x", "y"]}},
        ]));
        assert_eq!(
            rules.describe(),
            json!([{"tools": ["beta__*", "alpha__read"], "allow": {"org": ["x", "y"], "roles": ["a"]}}])
        );
    }
}
