//! The JSON Schema of every matcher key, for `GET /v1/schema`.
//!
//! Written by hand: a leaf reads its argument from raw JSON, so there is no type to derive from.
//! `combinators` refer to `#/$defs/matcher`, the document's one-of over every key, so the schema
//! of a nested tree is only meaningful inside the document. The unit test
//! `every_built_leaf_has_a_schema` fails when `parse_at` builds a key this list lacks.

use serde_json::{Value, json};

/// A matcher object: exactly one key, whose argument is `argument`.
fn keyed(key: &str, description: &str, argument: &Value) -> Value {
    json!({
        "type": "object",
        "description": description,
        "properties": { key: argument },
        "required": [key],
        "additionalProperties": false
    })
}

fn string(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn one_or_many(description: &str) -> Value {
    json!({
        "description": description,
        "oneOf": [
            { "type": "string" },
            { "type": "array", "items": { "type": "string" }, "minItems": 1 }
        ]
    })
}

fn named(value_key: &str, required: bool, description: &str) -> Value {
    let mut argument = json!({
        "type": "object",
        "description": description,
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            value_key: { "type": "string" }
        },
        "required": ["name"],
        "additionalProperties": false
    });
    if required {
        argument["required"] = json!(["name", value_key]);
    }
    argument
}

fn children(description: &str) -> Value {
    json!({
        "description": description,
        "type": "array",
        "items": { "$ref": "#/$defs/matcher" },
        "minItems": 1
    })
}

/// The schema of every built matcher key, by key.
#[must_use]
pub fn schemas() -> Vec<(&'static str, Value)> {
    vec![
        (
            "host",
            keyed(
                "host",
                "The request's host, without port: an exact name or a `*.` wildcard, or a list of them.",
                &one_or_many("A host name or `*.` wildcard, or a list of them."),
            ),
        ),
        (
            "host_regexp",
            keyed(
                "host_regexp",
                "The host matches a regular expression. It only narrows a literal `host` claim.",
                &string("A Rust `regex` pattern."),
            ),
        ),
        (
            "path",
            keyed(
                "path",
                "The normalized path is exactly this.",
                &string("A path starting with `/`."),
            ),
        ),
        (
            "path_prefix",
            keyed(
                "path_prefix",
                "The normalized path is this or under it, at a segment boundary.",
                &string("A path starting with `/`."),
            ),
        ),
        (
            "path_regexp",
            keyed(
                "path_regexp",
                "The normalized path matches a regular expression.",
                &string("A Rust `regex` pattern."),
            ),
        ),
        (
            "method",
            keyed(
                "method",
                "The request method is one of these.",
                &one_or_many("An HTTP method, or a list of them."),
            ),
        ),
        (
            "client_ip",
            keyed(
                "client_ip",
                "The resolved client address is in one of these blocks.",
                &one_or_many("An address or CIDR block, or a list of them."),
            ),
        ),
        (
            "header",
            keyed(
                "header",
                "A request header is present, with the value when given.",
                &named(
                    "value",
                    false,
                    "The header `name` and, optionally, its exact `value`.",
                ),
            ),
        ),
        (
            "header_regexp",
            keyed(
                "header_regexp",
                "A request header's value matches a regular expression.",
                &named(
                    "regex",
                    true,
                    "The header `name` and a Rust `regex` pattern.",
                ),
            ),
        ),
        (
            "query",
            keyed(
                "query",
                "A query parameter is present, with the value when given.",
                &named(
                    "value",
                    false,
                    "The parameter `name` and, optionally, its exact `value`.",
                ),
            ),
        ),
        (
            "query_regexp",
            keyed(
                "query_regexp",
                "A query parameter's value matches a regular expression.",
                &named(
                    "regex",
                    true,
                    "The parameter `name` and a Rust `regex` pattern.",
                ),
            ),
        ),
        (
            "sni",
            keyed(
                "sni",
                "TCP routers only: the server name in the ClientHello is an exact name or a `*.` wildcard, or a list of them. Claims the names like `host`.",
                &one_or_many("A host name or `*.` wildcard, or a list of them."),
            ),
        ),
        (
            "sni_regexp",
            keyed(
                "sni_regexp",
                "TCP routers only: the server name in the ClientHello matches a regular expression. It only narrows a literal `sni` claim, like `host_regexp`.",
                &string("A Rust `regex` pattern."),
            ),
        ),
        (
            "alpn",
            keyed(
                "alpn",
                "TCP routers only: the ClientHello offers one of these application protocols.",
                &one_or_many("An ALPN protocol name, or a list of them."),
            ),
        ),
        (
            "cel",
            keyed(
                "cel",
                "A CEL expression over the request matches (HTTP routers only). Claims no host, counts as one constraint, and an evaluation error is a non-match.",
                &json!({
                    "description": "The expression (at most 2 KiB), or the expression with a `max_cost` from 1 to 1000 (default 100).",
                    "oneOf": [
                        { "type": "string", "minLength": 1, "maxLength": 2048 },
                        {
                            "type": "object",
                            "properties": {
                                "expression": { "type": "string", "minLength": 1, "maxLength": 2048 },
                                "max_cost": { "type": "integer", "minimum": 1, "maximum": 1000 }
                            },
                            "required": ["expression"],
                            "additionalProperties": false
                        }
                    ]
                }),
            ),
        ),
        (
            "all",
            keyed(
                "all",
                "Every child matches.",
                &children("Matchers, at least one."),
            ),
        ),
        (
            "any",
            keyed(
                "any",
                "Some child matches.",
                &children("Matchers, at least one."),
            ),
        ),
        (
            "not",
            keyed(
                "not",
                "The child does not match.",
                &json!({ "$ref": "#/$defs/matcher" }),
            ),
        ),
    ]
}
