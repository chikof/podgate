//! Compiles the parts of an OpenAPI document the `openapi` middleware enforces: schemas (with
//! local `$ref` resolved into an arena), parameters and request bodies. Everything tenant-written
//! is bounded here, so the request path never has to be.

use std::collections::HashMap;
use std::fmt::Display;

use http::HeaderName;
use regex::RegexBuilder;
use serde_json::{Map, Number, Value};

use super::document::{
    Delimiter, Location, MAX_EXPANDED, MAX_NODES, MAX_PATTERNS, MAX_SCHEMA_DEPTH, Media,
    MediaRange, Parameter, RequestBody,
};
use super::schema::{
    Additional, Bound, Dialect, Fields, Format, Items, Logic, Numbers, Schema, SchemaId, Text,
    TypeSet, Values, compare,
};
use crate::compile::Invalid;

/// Most `enum` values, `required` names and `properties` of one schema.
const MAX_LIST: usize = 1_000;
/// Most branches of one `allOf`, `anyOf`, `oneOf` or `prefixItems`.
const MAX_BRANCHES: usize = 100;
/// Longest `pattern`.
const MAX_PATTERN: usize = 1_024;
/// Largest compiled `pattern`.
const PATTERN_SIZE: usize = 256 * 1024;
/// Most media types of one request body.
const MAX_MEDIA: usize = 32;
/// The most `$ref` hops of a parameter or request body.
const MAX_HOPS: usize = 8;

/// A refusal for a document that is wrong: `invalid_middleware`.
pub(super) fn bad(at: &str, why: impl Display) -> Invalid {
    Invalid::new("invalid_middleware", format!("openapi: {at}: {why}"))
}

/// A refusal for a document that asks for something podgate does not enforce.
pub(super) fn unsupported(at: &str, why: impl Display) -> Invalid {
    Invalid::new("unsupported_setting", format!("openapi: {at}: {why}"))
}

const KEYWORDS: &[&str] = &[
    "type",
    "enum",
    "format",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "multipleOf",
    "minLength",
    "maxLength",
    "pattern",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "properties",
    "required",
    "additionalProperties",
    "minProperties",
    "maxProperties",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "$ref",
];

const ANNOTATIONS: &[&str] = &[
    "title",
    "description",
    "default",
    "example",
    "deprecated",
    "readOnly",
    "writeOnly",
    "xml",
    "externalDocs",
    "discriminator",
    "$comment",
];

/// Keywords the standard has and podgate does not enforce.
const REFUSED: &[&str] = &[
    "if",
    "then",
    "else",
    "contains",
    "minContains",
    "maxContains",
    "patternProperties",
    "propertyNames",
    "dependencies",
    "dependentRequired",
    "dependentSchemas",
    "unevaluatedProperties",
    "unevaluatedItems",
    "additionalItems",
    "$id",
    "$anchor",
    "$dynamicRef",
    "$dynamicAnchor",
    "$vocabulary",
    "$schema",
    "contentEncoding",
    "contentMediaType",
    "contentSchema",
];

fn is_annotation(key: &str, dialect: Dialect) -> bool {
    ANNOTATIONS.contains(&key)
        || key.starts_with("x-")
        || (dialect == Dialect::V31 && matches!(key, "examples" | "$defs"))
}

#[derive(Debug, Clone, Copy)]
enum Memo {
    Building,
    Done(SchemaId),
}

/// Compiles schemas into an arena, memoizing by the JSON pointer a `$ref` names.
pub(super) struct Builder<'d> {
    root: &'d Map<String, Value>,
    dialect: Dialect,
    nodes: Vec<Schema>,
    weights: Vec<u32>,
    memo: HashMap<String, Memo>,
    patterns: usize,
    depth: u32,
}

fn percent_decode(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
            out.push(u8::try_from(high << 4 | low).ok()?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn uint(value: &Value, at: &str, key: &str) -> Result<u64, Invalid> {
    value
        .as_u64()
        .ok_or_else(|| bad(at, format!("{key} is a non-negative integer")))
}

fn number<'v>(value: &'v Value, at: &str, key: &str) -> Result<&'v Number, Invalid> {
    value
        .as_number()
        .ok_or_else(|| bad(at, format!("{key} is a number")))
}

impl<'d> Builder<'d> {
    pub(super) fn new(root: &'d Map<String, Value>, dialect: Dialect) -> Self {
        Self {
            root,
            dialect,
            nodes: Vec::new(),
            weights: Vec::new(),
            memo: HashMap::new(),
            patterns: 0,
            depth: 0,
        }
    }

    pub(super) fn finish(self) -> Box<[Schema]> {
        self.nodes.into_boxed_slice()
    }

    pub(super) fn node(&self, id: SchemaId) -> Option<&Schema> {
        self.nodes.get(usize::try_from(id.0).ok()?)
    }

    /// Follows a local reference: the value it names and its canonical pointer.
    fn resolve(&self, reference: &str, at: &str) -> Result<(&'d Value, String), Invalid> {
        let Some(pointer) = reference.strip_prefix('#') else {
            return Err(bad(
                at,
                format!("$ref {reference:?} is not local: podgate never fetches a document"),
            ));
        };
        let decoded = percent_decode(pointer)
            .ok_or_else(|| bad(at, format!("$ref {reference:?} is not a valid pointer")))?;
        let Some(path) = decoded.strip_prefix('/') else {
            return Err(bad(
                at,
                format!("$ref {reference:?} must be a pointer into this document, `#/...`"),
            ));
        };
        let mut tokens = path
            .split('/')
            .map(|token| token.replace("~1", "/").replace("~0", "~"));
        let first = tokens.next().unwrap_or_default();
        let mut current = self
            .root
            .get(&first)
            .ok_or_else(|| bad(at, format!("$ref {reference:?} names nothing")))?;
        for token in tokens {
            current = match current {
                Value::Object(map) => map.get(&token),
                Value::Array(items) => token.parse::<usize>().ok().and_then(|at| items.get(at)),
                _ => None,
            }
            .ok_or_else(|| bad(at, format!("$ref {reference:?} names nothing")))?;
        }
        Ok((current, decoded))
    }

    /// The object a `$ref` chain ends at (parameters and request bodies).
    fn deref(&self, node: &'d Value, at: &str) -> Result<&'d Value, Invalid> {
        let mut node = node;
        for _ in 0..MAX_HOPS {
            let Some(reference) = node.get("$ref") else {
                return Ok(node);
            };
            let Value::String(reference) = reference else {
                return Err(bad(at, "$ref is a string"));
            };
            node = self.resolve(reference, at)?.0;
        }
        Err(bad(at, format!("$ref chain is longer than {MAX_HOPS}")))
    }

    fn reference(&mut self, text: &str, at: &str) -> Result<SchemaId, Invalid> {
        let (target, key) = self.resolve(text, at)?;
        match self.memo.get(&key) {
            Some(Memo::Done(id)) => return Ok(*id),
            Some(Memo::Building) => {
                return Err(bad(
                    at,
                    format!(
                        "$ref cycle through #{key}: recursive schemas are not supported, unroll the recursion to a fixed depth"
                    ),
                ));
            }
            None => {}
        }
        self.memo.insert(key.clone(), Memo::Building);
        let id = self.schema(target, &format!("#{key}"))?;
        self.memo.insert(key, Memo::Done(id));
        Ok(id)
    }

    fn push(&mut self, schema: Schema, weight: u32, at: &str) -> Result<SchemaId, Invalid> {
        if weight > MAX_EXPANDED {
            return Err(bad(
                at,
                format!(
                    "the schema expands to over {MAX_EXPANDED} nodes once every $ref is followed"
                ),
            ));
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(bad(
                at,
                format!("the document has over {MAX_NODES} schemas"),
            ));
        }
        let id =
            SchemaId(u32::try_from(self.nodes.len()).map_err(|_| bad(at, "too many schemas"))?);
        self.nodes.push(schema);
        self.weights.push(weight);
        Ok(id)
    }

    fn weight_of(&self, id: SchemaId) -> u32 {
        usize::try_from(id.0)
            .ok()
            .and_then(|at| self.weights.get(at))
            .copied()
            .unwrap_or(u32::MAX)
    }

    fn sub(&mut self, node: &'d Value, at: &str, weight: &mut u32) -> Result<SchemaId, Invalid> {
        let id = self.schema(node, at)?;
        *weight = weight.saturating_add(self.weight_of(id));
        Ok(id)
    }

    /// Compiles one schema object.
    pub(super) fn schema(&mut self, node: &'d Value, at: &str) -> Result<SchemaId, Invalid> {
        self.depth += 1;
        let result = if self.depth > MAX_SCHEMA_DEPTH {
            Err(bad(
                at,
                format!("schemas nest deeper than {MAX_SCHEMA_DEPTH}, counting every $ref"),
            ))
        } else {
            self.schema_inner(node, at)
        };
        self.depth -= 1;
        result
    }

    fn schema_inner(&mut self, node: &'d Value, at: &str) -> Result<SchemaId, Invalid> {
        let map = match node {
            Value::Object(map) => map,
            Value::Bool(allowed) if self.dialect == Dialect::V31 => {
                return self.boolean(*allowed, at);
            }
            _ => return Err(bad(at, "a schema is an object")),
        };
        for key in map.keys() {
            let key = key.as_str();
            let known = KEYWORDS.contains(&key)
                || is_annotation(key, self.dialect)
                || match self.dialect {
                    Dialect::V30 => key == "nullable",
                    Dialect::V31 => matches!(key, "const" | "prefixItems"),
                };
            if known {
                continue;
            }
            return Err(
                if REFUSED.contains(&key) || matches!(key, "const" | "nullable" | "prefixItems") {
                    unsupported(
                        at,
                        format!(
                            "the schema keyword {key} is not supported in this OpenAPI version or not enforced by podgate"
                        ),
                    )
                } else {
                    bad(at, format!("unknown schema keyword {key}"))
                },
            );
        }
        let mut weight = 1_u32;
        let mut schema = Schema::default();
        if let Some(reference) = map.get("$ref") {
            let Value::String(text) = reference else {
                return Err(bad(at, "$ref is a string"));
            };
            if self.dialect == Dialect::V30
                && map
                    .keys()
                    .any(|key| key != "$ref" && !is_annotation(key, self.dialect))
            {
                return Err(bad(
                    at,
                    "in OpenAPI 3.0 a $ref has no siblings other than annotations",
                ));
            }
            let target = self.reference(text, at)?;
            weight = weight.saturating_add(self.weight_of(target));
            schema.reference = Some(target);
        }
        self.types(map, at, &mut schema)?;
        if let Some(format) = map.get("format") {
            let Value::String(name) = format else {
                return Err(bad(at, "format is a string"));
            };
            schema.format = Format::named(name);
        }
        schema.values = self.values(map, at)?;
        schema.numbers = self.numbers(map, at)?;
        schema.text = self.text(map, at)?;
        schema.items = self.items(map, at, &mut weight)?;
        schema.fields = self.fields(map, at, &mut weight)?;
        schema.logic = self.logic(map, at, &mut weight)?;
        self.push(schema, weight, at)
    }

    fn boolean(&mut self, allowed: bool, at: &str) -> Result<SchemaId, Invalid> {
        let everything = self.push(Schema::default(), 1, at)?;
        if allowed {
            return Ok(everything);
        }
        let schema = Schema {
            logic: Some(Box::new(Logic {
                not: Some(everything),
                ..Logic::default()
            })),
            ..Schema::default()
        };
        self.push(schema, 2, at)
    }

    fn types(
        &self,
        map: &Map<String, Value>,
        at: &str,
        schema: &mut Schema,
    ) -> Result<(), Invalid> {
        if let Some(Value::Bool(nullable)) = map.get("nullable") {
            schema.nullable = *nullable;
        } else if map.contains_key("nullable") {
            return Err(bad(at, "nullable is a boolean"));
        }
        let Some(declared) = map.get("type") else {
            return Ok(());
        };
        let names: Vec<&str> = match declared {
            Value::String(name) => vec![name],
            Value::Array(list) if self.dialect == Dialect::V31 && !list.is_empty() => list
                .iter()
                .map(|name| {
                    name.as_str()
                        .ok_or_else(|| bad(at, "type names are strings"))
                })
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(bad(
                    at,
                    "type is a string (an array of strings in OpenAPI 3.1)",
                ));
            }
        };
        let mut set = 0_u8;
        for name in names {
            let bit = match name {
                "null" if self.dialect == Dialect::V31 => TypeSet::NULL,
                "boolean" => TypeSet::BOOLEAN,
                "integer" => TypeSet::INTEGER,
                "number" => TypeSet::NUMBER,
                "string" => TypeSet::STRING,
                "array" => TypeSet::ARRAY,
                "object" => TypeSet::OBJECT,
                other => {
                    return Err(bad(
                        at,
                        format!(
                            "type {other:?} is not a type (in 3.0 use `nullable: true` for null)"
                        ),
                    ));
                }
            };
            if set & bit != 0 {
                return Err(bad(at, "type names a type twice"));
            }
            set |= bit;
        }
        schema.types = TypeSet(set);
        Ok(())
    }

    fn values(&self, map: &Map<String, Value>, at: &str) -> Result<Option<Box<Values>>, Invalid> {
        let enumeration = match map.get("enum") {
            None => None,
            Some(Value::Array(list)) if !list.is_empty() && list.len() <= MAX_LIST => {
                Some(list.clone().into_boxed_slice())
            }
            Some(_) => {
                return Err(bad(at, format!("enum is a list of 1 to {MAX_LIST} values")));
            }
        };
        let constant = map.get("const").cloned();
        Ok((enumeration.is_some() || constant.is_some()).then(|| {
            Box::new(Values {
                enumeration,
                constant,
            })
        }))
    }

    fn bound(
        &self,
        map: &Map<String, Value>,
        lower: bool,
        at: &str,
    ) -> Result<Option<Bound>, Invalid> {
        let (inclusive, exclusive) = if lower {
            ("minimum", "exclusiveMinimum")
        } else {
            ("maximum", "exclusiveMaximum")
        };
        let inclusive_value = map
            .get(inclusive)
            .map(|value| number(value, at, inclusive))
            .transpose()?;
        match self.dialect {
            Dialect::V30 => {
                let flag = match map.get(exclusive) {
                    None => false,
                    Some(Value::Bool(flag)) => *flag,
                    Some(_) => {
                        return Err(bad(at, format!("{exclusive} is a boolean in OpenAPI 3.0")));
                    }
                };
                match (inclusive_value, flag) {
                    (Some(value), exclusive) => Ok(Some(Bound {
                        value: value.clone(),
                        exclusive,
                    })),
                    (None, true) => Err(bad(at, format!("{exclusive} needs {inclusive}"))),
                    (None, false) => Ok(None),
                }
            }
            Dialect::V31 => {
                let exclusive_value = map
                    .get(exclusive)
                    .map(|value| number(value, at, exclusive))
                    .transpose()?;
                Ok(match (inclusive_value, exclusive_value) {
                    (None, None) => None,
                    (Some(value), None) => Some(Bound {
                        value: value.clone(),
                        exclusive: false,
                    }),
                    (None, Some(value)) => Some(Bound {
                        value: value.clone(),
                        exclusive: true,
                    }),
                    (Some(inc), Some(exc)) => {
                        let order = compare(exc, inc);
                        let exclusive_wins = if lower { order.is_ge() } else { order.is_le() };
                        Some(if exclusive_wins {
                            Bound {
                                value: exc.clone(),
                                exclusive: true,
                            }
                        } else {
                            Bound {
                                value: inc.clone(),
                                exclusive: false,
                            }
                        })
                    }
                })
            }
        }
    }

    fn numbers(&self, map: &Map<String, Value>, at: &str) -> Result<Option<Box<Numbers>>, Invalid> {
        let min = self.bound(map, true, at)?;
        let max = self.bound(map, false, at)?;
        let multiple_of = match map.get("multipleOf") {
            None => None,
            Some(value) => {
                let of = number(value, at, "multipleOf")?;
                if compare(of, &Number::from(0)).is_le() {
                    return Err(bad(at, "multipleOf is over 0"));
                }
                Some(of.clone())
            }
        };
        Ok(
            (min.is_some() || max.is_some() || multiple_of.is_some()).then(|| {
                Box::new(Numbers {
                    min,
                    max,
                    multiple_of,
                })
            }),
        )
    }

    fn text(&mut self, map: &Map<String, Value>, at: &str) -> Result<Option<Box<Text>>, Invalid> {
        let min = map
            .get("minLength")
            .map(|value| uint(value, at, "minLength"))
            .transpose()?;
        let max = map
            .get("maxLength")
            .map(|value| uint(value, at, "maxLength"))
            .transpose()?;
        let pattern = match map.get("pattern") {
            None => None,
            Some(Value::String(source)) => {
                if source.len() > MAX_PATTERN {
                    return Err(bad(at, format!("pattern is over {MAX_PATTERN} characters")));
                }
                self.patterns += 1;
                if self.patterns > MAX_PATTERNS {
                    return Err(bad(
                        at,
                        format!("the document has over {MAX_PATTERNS} patterns"),
                    ));
                }
                let compiled = RegexBuilder::new(source)
                    .size_limit(PATTERN_SIZE)
                    .dfa_size_limit(PATTERN_SIZE)
                    .build()
                    .map_err(|err| {
                        bad(
                            at,
                            format!("pattern is not a regular expression podgate can run (no look-around or back-references): {err}"),
                        )
                    })?;
                Some(compiled)
            }
            Some(_) => return Err(bad(at, "pattern is a string")),
        };
        Ok((min.is_some() || max.is_some() || pattern.is_some())
            .then(|| Box::new(Text { min, max, pattern })))
    }

    fn items(
        &mut self,
        map: &'d Map<String, Value>,
        at: &str,
        weight: &mut u32,
    ) -> Result<Option<Box<Items>>, Invalid> {
        let min = map
            .get("minItems")
            .map(|value| uint(value, at, "minItems"))
            .transpose()?;
        let max = map
            .get("maxItems")
            .map(|value| uint(value, at, "maxItems"))
            .transpose()?;
        let unique = match map.get("uniqueItems") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad(at, "uniqueItems is a boolean")),
        };
        let items = match map.get("items") {
            None => None,
            Some(node @ (Value::Object(_) | Value::Bool(_))) => {
                Some(self.sub(node, &format!("{at}/items"), weight)?)
            }
            Some(_) => return Err(bad(at, "items is a schema")),
        };
        let prefix = match map.get("prefixItems") {
            None => Box::default(),
            Some(Value::Array(list)) if list.len() <= MAX_BRANCHES => {
                let mut ids = Vec::with_capacity(list.len());
                for (index, node) in list.iter().enumerate() {
                    ids.push(self.sub(node, &format!("{at}/prefixItems/{index}"), weight)?);
                }
                ids.into_boxed_slice()
            }
            Some(_) => {
                return Err(bad(
                    at,
                    format!("prefixItems is a list of at most {MAX_BRANCHES} schemas"),
                ));
            }
        };
        Ok(
            (items.is_some() || !prefix.is_empty() || min.is_some() || max.is_some() || unique)
                .then(|| {
                    Box::new(Items {
                        items,
                        prefix,
                        min,
                        max,
                        unique,
                    })
                }),
        )
    }

    fn fields(
        &mut self,
        map: &'d Map<String, Value>,
        at: &str,
        weight: &mut u32,
    ) -> Result<Option<Box<Fields>>, Invalid> {
        let min = map
            .get("minProperties")
            .map(|value| uint(value, at, "minProperties"))
            .transpose()?;
        let max = map
            .get("maxProperties")
            .map(|value| uint(value, at, "maxProperties"))
            .transpose()?;
        let mut properties = Vec::new();
        match map.get("properties") {
            None => {}
            Some(Value::Object(declared)) if declared.len() <= MAX_LIST => {
                for (name, node) in declared {
                    let id = self.sub(node, &format!("{at}/properties/{name}"), weight)?;
                    properties.push((Box::<str>::from(name.as_str()), id));
                }
                properties.sort_by(|a, b| a.0.cmp(&b.0));
            }
            Some(_) => {
                return Err(bad(
                    at,
                    format!("properties is an object of at most {MAX_LIST} schemas"),
                ));
            }
        }
        let required: Vec<Box<str>> = match map.get("required") {
            None => Vec::new(),
            Some(Value::Array(list)) if list.len() <= MAX_LIST => list
                .iter()
                .map(|name| {
                    name.as_str()
                        .map(Box::from)
                        .ok_or_else(|| bad(at, "required names are strings"))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => {
                return Err(bad(
                    at,
                    format!("required is a list of at most {MAX_LIST} names"),
                ));
            }
        };
        let additional = match map.get("additionalProperties") {
            None | Some(Value::Bool(true)) => Additional::Any,
            Some(Value::Bool(false)) => Additional::Forbidden,
            Some(node @ Value::Object(_)) => {
                Additional::Schema(self.sub(node, &format!("{at}/additionalProperties"), weight)?)
            }
            Some(_) => return Err(bad(at, "additionalProperties is a boolean or a schema")),
        };
        let any = !properties.is_empty()
            || !required.is_empty()
            || additional != Additional::Any
            || min.is_some()
            || max.is_some();
        Ok(any.then(|| {
            Box::new(Fields {
                properties: properties.into_boxed_slice(),
                required: required.into_boxed_slice(),
                additional,
                min,
                max,
            })
        }))
    }

    fn branches(
        &mut self,
        map: &'d Map<String, Value>,
        key: &str,
        at: &str,
        weight: &mut u32,
    ) -> Result<Box<[SchemaId]>, Invalid> {
        match map.get(key) {
            None => Ok(Box::default()),
            Some(Value::Array(list)) if !list.is_empty() && list.len() <= MAX_BRANCHES => {
                let mut ids = Vec::with_capacity(list.len());
                for (index, node) in list.iter().enumerate() {
                    ids.push(self.sub(node, &format!("{at}/{key}/{index}"), weight)?);
                }
                Ok(ids.into_boxed_slice())
            }
            Some(_) => Err(bad(
                at,
                format!("{key} is a list of 1 to {MAX_BRANCHES} schemas"),
            )),
        }
    }

    fn logic(
        &mut self,
        map: &'d Map<String, Value>,
        at: &str,
        weight: &mut u32,
    ) -> Result<Option<Box<Logic>>, Invalid> {
        let all_of = self.branches(map, "allOf", at, weight)?;
        let any_of = self.branches(map, "anyOf", at, weight)?;
        let one_of = self.branches(map, "oneOf", at, weight)?;
        let not = match map.get("not") {
            None => None,
            Some(node) => Some(self.sub(node, &format!("{at}/not"), weight)?),
        };
        Ok(
            (!all_of.is_empty() || !any_of.is_empty() || !one_of.is_empty() || not.is_some()).then(
                || {
                    Box::new(Logic {
                        all_of,
                        any_of,
                        one_of,
                        not,
                    })
                },
            ),
        )
    }

    /// Compiles one parameter object; `None` for the headers the standard says to ignore.
    pub(super) fn parameter(
        &mut self,
        node: &'d Value,
        at: &str,
    ) -> Result<Option<Parameter>, Invalid> {
        let node = self.deref(node, at)?;
        let Some(map) = node.as_object() else {
            return Err(bad(at, "a parameter is an object"));
        };
        let name = match map.get("name") {
            Some(Value::String(name)) if !name.is_empty() => name.as_str(),
            _ => return Err(bad(at, "a parameter has a name")),
        };
        let location = match map.get("in").and_then(Value::as_str) {
            Some("path") => Location::Path,
            Some("query") => Location::Query,
            Some("header") => Location::Header,
            Some("cookie") => Location::Cookie,
            _ => return Err(bad(at, "in is path, query, header or cookie")),
        };
        let at = format!("{at} ({} parameter {name})", location.word());
        if location == Location::Header {
            let header = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| bad(&at, "the name is not a header name"))?;
            if matches!(header.as_str(), "accept" | "content-type" | "authorization") {
                return Ok(None);
            }
        }
        if map.contains_key("content") {
            return Err(unsupported(
                &at,
                "a parameter with `content` is not supported, use `schema`",
            ));
        }
        if map.get("allowEmptyValue").and_then(Value::as_bool) == Some(true) {
            return Err(unsupported(&at, "allowEmptyValue is not supported"));
        }
        let required = match map.get("required") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad(&at, "required is a boolean")),
        };
        if location == Location::Path && !required {
            return Err(bad(&at, "a path parameter is required: true"));
        }
        let explode = map.get("explode").and_then(Value::as_bool);
        let delimiter = match (location, map.get("style").map(Value::as_str)) {
            (Location::Path | Location::Header, None | Some(Some("simple"))) => Delimiter::Comma,
            (Location::Query | Location::Cookie, None | Some(Some("form"))) => {
                if explode.unwrap_or(true) {
                    Delimiter::Repeated
                } else {
                    Delimiter::Comma
                }
            }
            (Location::Query, Some(Some("spaceDelimited"))) if explode != Some(true) => {
                Delimiter::Space
            }
            (Location::Query, Some(Some("pipeDelimited"))) if explode != Some(true) => {
                Delimiter::Pipe
            }
            (_, style) => {
                return Err(unsupported(
                    &at,
                    format!(
                        "style {style:?} with this `explode` is not supported (deepObject, matrix, label and the like)"
                    ),
                ));
            }
        };
        let schema = match map.get("schema") {
            None => None,
            Some(node) => {
                let id = self.schema(node, &format!("{at}/schema"))?;
                if self
                    .node(id)
                    .is_some_and(|schema| schema.types.only(TypeSet::OBJECT))
                {
                    return Err(unsupported(&at, "an object parameter is not supported"));
                }
                Some(id)
            }
        };
        Ok(Some(Parameter {
            name: if location == Location::Header {
                name.to_ascii_lowercase().into_boxed_str()
            } else {
                Box::from(name)
            },
            location,
            required,
            delimiter,
            schema,
        }))
    }

    /// Compiles a request body object.
    pub(super) fn request_body(
        &mut self,
        node: &'d Value,
        at: &str,
    ) -> Result<RequestBody, Invalid> {
        let node = self.deref(node, at)?;
        let Some(map) = node.as_object() else {
            return Err(bad(at, "a requestBody is an object"));
        };
        let required = match map.get("required") {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(bad(at, "required is a boolean")),
        };
        let Some(Value::Object(content)) = map.get("content") else {
            return Err(bad(at, "a requestBody has `content`"));
        };
        if content.is_empty() || content.len() > MAX_MEDIA {
            return Err(bad(
                at,
                format!("content lists 1 to {MAX_MEDIA} media types"),
            ));
        }
        let mut media = Vec::with_capacity(content.len());
        for (key, value) in content {
            let range = MediaRange::parse(key)
                .ok_or_else(|| bad(at, format!("{key:?} is not a media type")))?;
            let Some(entry) = value.as_object() else {
                return Err(bad(at, format!("content {key:?} is an object")));
            };
            let json = range.is_json();
            let schema = match (json, entry.get("schema")) {
                (true, Some(node)) => {
                    Some(self.schema(node, &format!("{at}/content/{key}/schema"))?)
                }
                _ => None,
            };
            media.push(Media {
                range,
                json,
                schema,
            });
        }
        Ok(RequestBody {
            required,
            media: media.into_boxed_slice(),
        })
    }
}
