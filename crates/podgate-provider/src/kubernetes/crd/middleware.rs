//! `PodgateMiddleware`: a middleware that routes of its namespace share.
//!
//! The daemon has no cross-app references, so a route that names a PodgateMiddleware gets its own
//! copy in its app (see [`super::route`]); this module only reads and checks the objects.

use std::collections::BTreeMap;

use podgate_model::Declared;
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{GROUP, VERSION};
use crate::kubernetes::client::{ObjectMeta, Resource};

/// A `podgate.io/v1alpha1` PodgateMiddleware.
///
/// The spec stays raw JSON until a route uses it: an object that cannot be read is refused with
/// a reason, and never breaks the watch of the others (a decode error would).
#[derive(Debug, Deserialize)]
pub struct PodgateMiddleware {
    /// Name, namespace.
    pub metadata: ObjectMeta,
    /// `{type, config}`.
    #[serde(default)]
    pub spec: Value,
}

impl Resource for PodgateMiddleware {
    const GROUP: &'static str = GROUP;
    const VERSION: &'static str = VERSION;
    const PLURAL: &'static str = "podgatemiddlewares";
    const KIND: &'static str = "PodgateMiddleware";

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    config: Map<String, Value>,
}

/// The middlewares of the cluster by namespace and name, each already read.
pub struct Middlewares<'a> {
    by_key: BTreeMap<String, (&'a PodgateMiddleware, Result<Declared, String>)>,
}

impl<'a> Middlewares<'a> {
    /// Reads every PodgateMiddleware in `items`.
    #[must_use]
    pub fn new(items: impl Iterator<Item = &'a PodgateMiddleware>) -> Self {
        Self {
            by_key: items
                .map(|item| (item.metadata.key(), (item, declare(item))))
                .collect(),
        }
    }

    /// The middleware `name` of `namespace`, as the app would declare it, or why it cannot be.
    /// `None` when there is no such object.
    #[must_use]
    pub fn get(&self, namespace: &str, name: &str) -> Option<&Result<Declared, String>> {
        self.by_key
            .get(&format!("{namespace}/{name}"))
            .map(|(_, declared)| declared)
    }

    /// The objects that cannot be read, with the reason, whether or not a route uses them.
    pub fn invalid(&self) -> impl Iterator<Item = (&PodgateMiddleware, &str)> {
        self.by_key
            .values()
            .filter_map(|(item, declared)| declared.as_ref().err().map(|why| (*item, why.as_str())))
    }
}

fn declare(item: &PodgateMiddleware) -> Result<Declared, String> {
    let spec = Spec::deserialize(&item.spec).map_err(|err| format!("spec: {err}"))?;
    if spec.kind.is_empty() {
        return Err("spec.type is empty".to_owned());
    }
    let mut object = spec.config;
    if object.contains_key("name") || object.contains_key("type") {
        return Err(
            "spec.config holds `name` or `type`; the object's name and spec.type say those"
                .to_owned(),
        );
    }
    object.insert("name".to_owned(), Value::from(item.metadata.name.as_str()));
    object.insert("type".to_owned(), Value::from(spec.kind));
    serde_json::from_value(Value::Object(object)).map_err(|err| format!("spec: {err}"))
}
