//! The tool identity of the MCP gateway: what a tool is called, which server owns it, and the
//! catalog of tools each server reports.
//!
//! A tool is named `<server>__<tool>`: the registered server's name, two underscores, and the
//! tool's name exactly as that server reports it. Server names hold no `_`, so the first `__` of
//! a qualified name always ends the server, and two different (server, tool) pairs never share a
//! qualified name, even when two servers have a tool of the same name. The gateway builds every
//! qualified name it lists itself, and a name a client sends resolves only through the registry
//! (`McpGateway::resolve`): nothing but that one name decides where a call goes.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;

/// The text between a server name and a tool name.
pub(super) const SEPARATOR: &str = "__";

/// The longest qualified name; the longest tool name MCP allows.
pub(super) const MAX_QUALIFIED: usize = 128;

/// The most tools of one server the catalog keeps.
pub(super) const MAX_TOOLS: usize = 512;

/// The qualified name of `tool` of `server`.
#[must_use]
pub(super) fn qualify(server: &str, tool: &str) -> String {
    format!("{server}{SEPARATOR}{tool}")
}

/// The server prefix and the tool name of a qualified name: split at the first separator.
#[must_use]
pub(super) fn split(qualified: &str) -> Option<(&str, &str)> {
    qualified.split_once(SEPARATOR)
}

/// A tool of a registered server, named as the registry knows it. Both strings are the
/// registry's own: the server's name as registered and the tool's name as that server reported
/// it, never text of a client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ToolRef {
    /// The registered server that owns the tool.
    pub(super) server: Box<str>,
    /// The tool's name at that server.
    pub(super) tool: Box<str>,
}

/// A tool a server reported: its name at the server and the whole tool object.
#[derive(Debug)]
pub(super) struct Tool {
    pub(super) name: Box<str>,
    pub(super) value: Value,
}

/// What one server reported at `fetched`.
#[derive(Debug, Clone)]
pub(super) struct Catalog {
    pub(super) tools: Arc<[Tool]>,
    pub(super) fetched: Instant,
    /// Tools left out: a bad or repeated name, a name too long, over [`MAX_TOOLS`].
    pub(super) skipped: usize,
}

/// A tool as the client sees it in `tools/list`.
#[derive(Debug)]
pub(super) struct Listed {
    pub(super) tool: ToolRef,
    /// The tool object, with its name qualified (`value["name"]`).
    pub(super) value: Value,
}

/// Whether `name` can be a tool of `server`: not empty, no control character, and the qualified
/// name fits.
fn admissible(server: &str, name: &str) -> bool {
    !name.is_empty()
        && !name.chars().any(char::is_control)
        && server.len() + SEPARATOR.len() + name.len() <= MAX_QUALIFIED
}

/// The catalog of `server` from the tool objects it reported across its pages, `fetched` now.
/// A tool that is not an object, has no usable name, repeats a name already seen (the first
/// stays) or is past [`MAX_TOOLS`] is left out and counted.
#[must_use]
pub(super) fn catalog(server: &str, reported: Vec<Value>, fetched: Instant) -> Catalog {
    let mut seen: HashSet<Box<str>> = HashSet::new();
    let mut tools = Vec::new();
    let mut skipped = 0;
    for value in reported {
        let Some(name) = value
            .as_object()
            .and_then(|tool| tool.get("name"))
            .and_then(Value::as_str)
            .filter(|name| admissible(server, name))
        else {
            skipped += 1;
            continue;
        };
        if tools.len() >= MAX_TOOLS || !seen.insert(name.into()) {
            skipped += 1;
            continue;
        }
        tools.push(Tool {
            name: name.into(),
            value,
        });
    }
    Catalog {
        tools: tools.into(),
        fetched,
        skipped,
    }
}

/// The tools of every server, under their qualified names, in registry order.
#[must_use]
pub(super) fn merge<'a>(servers: impl Iterator<Item = (&'a str, &'a [Tool])>) -> Vec<Listed> {
    let mut listed = Vec::new();
    for (server, tools) in servers {
        for tool in tools {
            let mut value = tool.value.clone();
            if let Some(object) = value.as_object_mut() {
                object.insert("name".into(), Value::String(qualify(server, &tool.name)));
            }
            listed.push(Listed {
                tool: ToolRef {
                    server: server.into(),
                    tool: tool.name.clone(),
                },
                value,
            });
        }
    }
    listed
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn tool(name: &str) -> Value {
        json!({"name": name, "description": "d", "inputSchema": {"type": "object"}})
    }

    #[test]
    fn mcp_names_qualify_and_split() {
        assert_eq!(qualify("alpha", "search"), "alpha__search");
        assert_eq!(split("alpha__search"), Some(("alpha", "search")));
        assert_eq!(split("search"), None);
        assert_eq!(split("alpha_search"), None);
        // A tool name may hold the separator and may start with an underscore.
        assert_eq!(split(&qualify("alpha", "a__b")), Some(("alpha", "a__b")));
        assert_eq!(split(&qualify("alpha", "_b")), Some(("alpha", "_b")));
        assert_eq!(split(&qualify("alpha", "__")), Some(("alpha", "__")));
    }

    #[test]
    fn mcp_names_are_injective_for_servers_without_underscores() {
        let servers = ["a", "ab", "a-b", "a1"];
        let tools = ["x", "_x", "x__y", "b__x", "", "__", "a"];
        let mut seen = HashSet::new();
        for server in servers {
            for tool in tools {
                let qualified = qualify(server, tool);
                assert!(seen.insert(qualified.clone()), "{qualified} repeats");
                assert_eq!(split(&qualified), Some((server, tool)));
            }
        }
    }

    #[test]
    fn mcp_catalog_keeps_what_a_client_can_call() {
        let now = Instant::now();
        let long = "t".repeat(MAX_QUALIFIED);
        let reported = vec![
            tool("search"),
            tool("search"),
            tool(""),
            tool("bad\nname"),
            tool(&long),
            json!("not an object"),
            json!({"description": "no name"}),
            json!({"name": 5}),
            tool("fetch"),
            tool("a__b"),
        ];
        let kept = catalog("alpha", reported, now);
        let names: Vec<&str> = kept.tools.iter().map(|tool| &*tool.name).collect();
        assert_eq!(names, ["search", "fetch", "a__b"]);
        assert_eq!(kept.skipped, 7);
    }

    #[test]
    fn mcp_catalog_is_capped() {
        let reported: Vec<Value> = (0..MAX_TOOLS + 5)
            .map(|index| tool(&format!("t{index}")))
            .collect();
        let kept = catalog("alpha", reported, Instant::now());
        assert_eq!(kept.tools.len(), MAX_TOOLS);
        assert_eq!(kept.skipped, 5);
    }

    #[test]
    fn mcp_names_same_tool_name_on_two_servers_is_two_tools() {
        let now = Instant::now();
        let alpha = catalog("alpha", vec![tool("search")], now);
        let beta = catalog("beta", vec![tool("search"), tool("only-beta")], now);
        let listed = merge([("alpha", &*alpha.tools), ("beta", &*beta.tools)].into_iter());
        let names: Vec<&str> = listed
            .iter()
            .filter_map(|tool| tool.value["name"].as_str())
            .collect();
        assert_eq!(names, ["alpha__search", "beta__search", "beta__only-beta"]);
        assert_eq!(listed[0].value["name"], "alpha__search");
        assert_eq!(listed[0].value["description"], "d");
        assert_eq!(&*listed[1].tool.server, "beta");
        assert_eq!(&*listed[1].tool.tool, "search");
        // The catalog keeps the server's own spelling.
        assert_eq!(&*beta.tools[0].name, "search");
        assert_eq!(beta.tools[0].value["name"], "search");
    }
}
