//! `GET /v1/schema`: the JSON Schema of a snapshot, for editors, providers and CRD generators.
//!
//! The document is JSON Schema 2020-12. Its root describes [`Snapshot`], generated from the model
//! types (`podgate-model` with its `schema` feature), so it cannot drift from what the daemon
//! parses. A `Declared` object (a middleware, service or transport) is validated by its `type`:
//! `$defs` holds one entry per built kind, named `<category>.<type>` (`middleware.add_prefix`,
//! `service.loadbalancer`, `transport.servers_transport`) and describing the whole object,
//! `name` and `type` included, and the `kinds` index maps each type to its entry. Matcher keys are
//! `$defs` entries named `matcher.<key>` too; `$defs.matcher` is the one-of over them, and the
//! router's `match` refers to it. `unbuilt` lists the kinds that are planned and refused.
//!
//! The kind schemas come from registration lists: `schemas!` in `src/middleware.rs` and
//! `src/service.rs`, and `src/router/matcher/schema.rs`. The tests below fail when a built kind
//! is missing from one.

use std::sync::LazyLock;

use axum::Router;
use axum::body::Bytes;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use schemars::JsonSchema;
use schemars::generate::SchemaSettings;
use serde_json::{Map, Value, json};

use super::AppState;
use crate::middleware;
use crate::router::matcher;
use crate::service;
use podgate_model::Snapshot;

pub(super) fn routes() -> Router<AppState> {
    Router::new().route("/v1/schema", get(get_schema))
}

/// The document, built once: it depends on nothing but the binary.
static DOCUMENT: LazyLock<Bytes> = LazyLock::new(|| {
    // A `Value` always serializes.
    Bytes::from(serde_json::to_vec(&document()).unwrap_or_default())
});

/// `200` with the schema document.
async fn get_schema() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/schema+json")],
        DOCUMENT.clone(),
    )
}

/// The JSON Schema of `T` on its own: nested types are inlined, so a kind's entry in `$defs` is
/// self-contained and needs no `$defs` of its own.
pub(crate) fn of<T: JsonSchema>() -> Value {
    let settings =
        SchemaSettings::draft2020_12().with(|settings| settings.inline_subschemas = true);
    let schema = settings.into_generator().into_root_schema_for::<T>();
    let mut value = serde_json::to_value(&schema).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.remove("$schema");
    }
    value
}

/// The whole document.
fn document() -> Value {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    let root = generator.root_schema_for::<Snapshot>();
    let mut document = serde_json::to_value(&root).unwrap_or_default();
    let mut defs = match document.get_mut("$defs").map(Value::take) {
        Some(Value::Object(defs)) => defs,
        _ => Map::new(),
    };
    let mut kinds = Map::new();
    let mut unbuilt = Map::new();
    let categories = [
        (
            "middleware",
            middleware::schemas(),
            middleware::UNBUILT.to_vec(),
        ),
        ("service", service::schemas(), service::UNBUILT.to_vec()),
        ("transport", vec![service::transport_schema()], Vec::new()),
        (
            "udp_service",
            vec![("loadbalancer", of::<crate::l4::udp::ServiceConfig>())],
            Vec::new(),
        ),
    ];
    for (category, schemas, planned) in categories {
        let mut index = Map::new();
        for (kind, schema) in schemas {
            let name = format!("{category}.{kind}");
            index.insert(kind.to_owned(), json!(format!("#/$defs/{name}")));
            defs.insert(name, declared(kind, schema));
        }
        kinds.insert(category.to_owned(), Value::Object(index));
        unbuilt.insert(category.to_owned(), json!(planned));
    }
    let mut index = Map::new();
    let mut leaves = Vec::new();
    for (key, schema) in matcher::schemas() {
        let name = format!("matcher.{key}");
        index.insert(key.to_owned(), json!(format!("#/$defs/{name}")));
        leaves.push(json!({ "$ref": format!("#/$defs/{name}") }));
        defs.insert(name, schema);
    }
    kinds.insert("matcher".to_owned(), Value::Object(index));
    unbuilt.insert("matcher".to_owned(), json!(matcher::UNBUILT));
    defs.insert(
        "matcher".to_owned(),
        json!({
            "description": "A matcher tree: an object with exactly one key, a leaf or a combinator.",
            "oneOf": leaves
        }),
    );
    // The router keeps its matcher raw in the model, since the daemon parses it; the schema knows
    // the grammar.
    if let Some(slot) = defs
        .get_mut("Router")
        .and_then(|router| router.pointer_mut("/properties/match"))
    {
        *slot = json!({ "$ref": "#/$defs/matcher" });
    }
    // UDP routers are kept raw in the model, like the matcher of a router.
    defs.insert(
        "udp.router".to_owned(),
        of::<crate::l4::udp::RouterConfig>(),
    );
    if let Some(slot) = defs
        .get_mut("Udp")
        .and_then(|udp| udp.pointer_mut("/properties/routers/items"))
    {
        *slot = json!({ "$ref": "#/$defs/udp.router" });
    }
    let Some(object) = document.as_object_mut() else {
        return document;
    };
    object.insert("$defs".to_owned(), Value::Object(defs));
    object.insert("title".to_owned(), json!("podgate snapshot"));
    object.insert(
        "podgate_version".to_owned(),
        json!(env!("CARGO_PKG_VERSION")),
    );
    object.insert("kinds".to_owned(), Value::Object(kinds));
    object.insert("unbuilt".to_owned(), Value::Object(unbuilt));
    document
}

/// Widens a kind's configuration schema to the whole `Declared` object: the kind's own fields
/// plus the `name` and the `type` it is declared with.
fn declared(kind: &str, mut schema: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        let properties = object
            .entry("properties")
            .or_insert_with(|| json!({}))
            .as_object_mut();
        if let Some(properties) = properties {
            properties.insert("name".to_owned(), json!({ "type": "string" }));
            properties.insert("type".to_owned(), json!({ "const": kind }));
        }
        let required = object.entry("required").or_insert_with(|| json!([]));
        if let Some(required) = required.as_array_mut() {
            required.push(json!("name"));
            required.push(json!("type"));
        }
    }
    schema
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use super::*;

    /// The type names `document()` has a `$defs` entry for, in `category`.
    fn defined(document: &Value, category: &str) -> BTreeSet<String> {
        let defs = document["$defs"].as_object().expect("$defs");
        let prefix = format!("{category}.");
        defs.keys()
            .filter_map(|name| name.strip_prefix(&prefix))
            .map(str::to_owned)
            .collect()
    }

    fn listed(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn every_built_kind_has_a_schema() {
        let document = document();
        assert_eq!(
            defined(&document, "middleware"),
            listed(middleware::Stage::BUILT),
            "a middleware kind is built without a line in `schemas!` (src/middleware.rs), or has one without being built"
        );
        assert_eq!(
            defined(&document, "service"),
            listed(&service::BUILT),
            "a service type is built without a line in `schemas!` (src/service.rs), or has one without being built"
        );
        assert_eq!(
            defined(&document, "matcher"),
            listed(&matcher::BUILT),
            "a matcher key is built without an entry in src/router/matcher/schema.rs, or has one without being built"
        );
        assert_eq!(
            defined(&document, "transport"),
            listed(&[service::transport_schema().0])
        );
    }

    #[test]
    fn every_kind_entry_describes_the_whole_declared_object() {
        let document = document();
        for (category, kinds) in document["kinds"].as_object().expect("kinds") {
            for (kind, pointer) in kinds.as_object().expect("a category") {
                let pointer = pointer.as_str().expect("a pointer");
                let entry = document
                    .pointer(pointer.trim_start_matches('#'))
                    .unwrap_or_else(|| panic!("{category}.{kind}: {pointer} is not in $defs"));
                if category != "matcher" {
                    assert_eq!(entry["properties"]["type"]["const"], *kind, "{pointer}");
                    assert!(entry["properties"]["name"].is_object(), "{pointer}");
                }
            }
        }
    }
}
