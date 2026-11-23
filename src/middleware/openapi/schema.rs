//! The bounded JSON Schema subset the `openapi` middleware enforces.
//!
//! A schema is compiled once ([`super::build`]) into a [`Schema`] in an arena; `$ref` is an index,
//! so a schema reached from many places is stored once. Checking walks the instance and the
//! schemas together, so the work is bounded by the instance, and a step budget ([`MAX_STEPS`])
//! bounds what a hostile `allOf` fan-out can still cost. Nothing here follows a reference at
//! run time, compiles a pattern or allocates for a valid instance (a violation allocates).

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use regex::Regex;
use serde_json::{Number, Value};

use super::request::Violation;

/// Most schema applications one request may cost; past it the request is refused.
pub(super) const MAX_STEPS: u32 = 200_000;
/// Most violations kept; the one after sets `truncated`.
pub(super) const MAX_VIOLATIONS: usize = 10;
/// Longest JSON pointer shown in a violation.
const MAX_POINTER: usize = 128;

/// An index into [`Schemas`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SchemaId(pub(super) u32);

/// The schema dialect of the document: `3.0.x` or `3.1.x`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// OpenAPI 3.0: the 3.0 schema object (`nullable`, boolean `exclusiveMinimum`).
    V30,
    /// OpenAPI 3.1: JSON Schema 2020-12.
    V31,
}

/// The JSON types a schema admits; empty admits every type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TypeSet(pub(super) u8);

impl TypeSet {
    pub(super) const NULL: u8 = 1;
    pub(super) const BOOLEAN: u8 = 2;
    pub(super) const INTEGER: u8 = 4;
    pub(super) const NUMBER: u8 = 8;
    pub(super) const STRING: u8 = 16;
    pub(super) const ARRAY: u8 = 32;
    pub(super) const OBJECT: u8 = 64;

    pub(super) fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(super) fn only(self, bit: u8) -> bool {
        self.0 == bit
    }

    fn admits(self, value: &Value, dialect: Dialect) -> bool {
        let bit = match value {
            Value::Null => Self::NULL,
            Value::Bool(_) => Self::BOOLEAN,
            Value::String(_) => Self::STRING,
            Value::Array(_) => Self::ARRAY,
            Value::Object(_) => Self::OBJECT,
            Value::Number(number) => {
                return self.0 & Self::NUMBER != 0
                    || (self.0 & Self::INTEGER != 0 && is_integer(number, dialect));
            }
        };
        self.0 & bit != 0
    }
}

impl fmt::Display for TypeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (bit, name) in [
            (Self::NULL, "null"),
            (Self::BOOLEAN, "boolean"),
            (Self::INTEGER, "integer"),
            (Self::NUMBER, "number"),
            (Self::STRING, "string"),
            (Self::ARRAY, "array"),
            (Self::OBJECT, "object"),
        ] {
            if self.0 & bit != 0 {
                if !first {
                    f.write_str(" or ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// The formats that are checked; every other `format` is an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Format {
    Int32,
    Int64,
    Uuid,
    Date,
    DateTime,
    Ipv4,
    Ipv6,
}

impl Format {
    pub(super) fn named(name: &str) -> Option<Self> {
        Some(match name {
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "uuid" => Self::Uuid,
            "date" => Self::Date,
            "date-time" => Self::DateTime,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            _ => return None,
        })
    }
}

/// A numeric limit.
#[derive(Debug, Clone)]
pub(super) struct Bound {
    pub(super) value: Number,
    pub(super) exclusive: bool,
}

/// `minimum`, `maximum` and `multipleOf`.
#[derive(Debug, Default)]
pub(super) struct Numbers {
    pub(super) min: Option<Bound>,
    pub(super) max: Option<Bound>,
    pub(super) multiple_of: Option<Number>,
}

/// `minLength`, `maxLength` and `pattern`.
#[derive(Debug, Default)]
pub(super) struct Text {
    pub(super) min: Option<u64>,
    pub(super) max: Option<u64>,
    pub(super) pattern: Option<Regex>,
}

/// `items`, `prefixItems`, `minItems`, `maxItems` and `uniqueItems`.
#[derive(Debug, Default)]
pub(super) struct Items {
    pub(super) items: Option<SchemaId>,
    pub(super) prefix: Box<[SchemaId]>,
    pub(super) min: Option<u64>,
    pub(super) max: Option<u64>,
    pub(super) unique: bool,
}

/// What `additionalProperties` says.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum Additional {
    #[default]
    Any,
    Forbidden,
    Schema(SchemaId),
}

/// `properties`, `required`, `additionalProperties`, `minProperties` and `maxProperties`.
#[derive(Debug, Default)]
pub(super) struct Fields {
    /// Sorted by name.
    pub(super) properties: Box<[(Box<str>, SchemaId)]>,
    pub(super) required: Box<[Box<str>]>,
    pub(super) additional: Additional,
    pub(super) min: Option<u64>,
    pub(super) max: Option<u64>,
}

/// `enum` and `const`.
#[derive(Debug, Default)]
pub(super) struct Values {
    pub(super) enumeration: Option<Box<[Value]>>,
    pub(super) constant: Option<Value>,
}

/// `allOf`, `anyOf`, `oneOf` and `not`.
#[derive(Debug, Default)]
pub(super) struct Logic {
    pub(super) all_of: Box<[SchemaId]>,
    pub(super) any_of: Box<[SchemaId]>,
    pub(super) one_of: Box<[SchemaId]>,
    pub(super) not: Option<SchemaId>,
}

/// One compiled schema. The rarely used groups are boxed, so a plain `{type: string}` is small.
#[derive(Debug, Default)]
pub(super) struct Schema {
    pub(super) types: TypeSet,
    pub(super) nullable: bool,
    pub(super) format: Option<Format>,
    pub(super) reference: Option<SchemaId>,
    pub(super) values: Option<Box<Values>>,
    pub(super) numbers: Option<Box<Numbers>>,
    pub(super) text: Option<Box<Text>>,
    pub(super) items: Option<Box<Items>>,
    pub(super) fields: Option<Box<Fields>>,
    pub(super) logic: Option<Box<Logic>>,
}

/// The arena of a document's schemas.
#[derive(Debug)]
pub(super) struct Schemas {
    pub(super) nodes: Box<[Schema]>,
    pub(super) dialect: Dialect,
}

#[derive(Debug, Clone, Copy)]
enum Step<'v> {
    Key(&'v str),
    Index(usize),
}

/// The state of one check: the work left, where in the instance it is, what it found.
#[derive(Debug)]
pub(super) struct Run<'v> {
    left: u32,
    exhausted: bool,
    probe: u32,
    probe_failed: bool,
    path: Vec<Step<'v>>,
    found: Vec<Violation>,
    more: bool,
    place: &'static str,
    name: Option<&'v str>,
}

impl<'v> Run<'v> {
    /// A check with `left` steps of work, reporting violations as `place` (`body`, `query`, ...)
    /// of the parameter `name`.
    pub(super) fn new(left: u32, place: &'static str, name: Option<&'v str>) -> Self {
        Self {
            left,
            exhausted: false,
            probe: 0,
            probe_failed: false,
            path: Vec::new(),
            found: Vec::new(),
            more: false,
            place,
            name,
        }
    }

    /// The work left after this check.
    pub(super) fn left(&self) -> u32 {
        self.left
    }

    /// Whether the work ran out: the instance is too much to check.
    pub(super) fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// The violations and whether there were more than are kept.
    pub(super) fn into_found(self) -> (Vec<Violation>, bool) {
        (self.found, self.more)
    }

    fn stop(&self) -> bool {
        self.exhausted || self.more || (self.probe > 0 && self.probe_failed)
    }

    fn spend(&mut self, steps: usize) -> bool {
        let steps = u32::try_from(steps).unwrap_or(u32::MAX);
        match self.left.checked_sub(steps) {
            Some(left) => {
                self.left = left;
                true
            }
            None => {
                self.left = 0;
                self.exhausted = true;
                false
            }
        }
    }

    fn fail(&mut self, message: impl FnOnce() -> Cow<'static, str>) {
        if self.probe > 0 {
            self.probe_failed = true;
        } else if self.found.len() >= MAX_VIOLATIONS {
            self.more = true;
        } else {
            let pointer = (self.place == "body").then(|| self.pointer());
            self.found.push(Violation {
                location: self.place,
                name: self.name.map(Box::from),
                pointer,
                message: message(),
            });
        }
    }

    fn pointer(&self) -> String {
        let mut out = String::new();
        for step in &self.path {
            out.push('/');
            match step {
                Step::Index(index) => out.push_str(&index.to_string()),
                Step::Key(key) => {
                    for ch in key.chars() {
                        match ch {
                            '~' => out.push_str("~0"),
                            '/' => out.push_str("~1"),
                            other => out.push(other),
                        }
                    }
                }
            }
            if out.len() > MAX_POINTER {
                break;
            }
        }
        if out.len() > MAX_POINTER {
            let mut end = MAX_POINTER;
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
            out.push_str("...");
        }
        out
    }
}

fn as_i128(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn as_f64(number: &Number) -> f64 {
    number.as_f64().unwrap_or(0.0)
}

fn is_integer(number: &Number, dialect: Dialect) -> bool {
    number.is_i64()
        || number.is_u64()
        || (dialect == Dialect::V31 && {
            let float = as_f64(number);
            float.is_finite() && float.fract() == 0.0
        })
}

/// Orders two JSON numbers: exactly for integers, as `f64` otherwise.
pub(super) fn compare(a: &Number, b: &Number) -> Ordering {
    match (as_i128(a), as_i128(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => as_f64(a).partial_cmp(&as_f64(b)).unwrap_or(Ordering::Equal),
    }
}

/// JSON Schema equality: `1` equals `1.0`, objects ignore key order.
pub(super) fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => compare(a, b) == Ordering::Equal,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| equal(a, b)))
        }
        _ => a == b,
    }
}

fn is_multiple(number: &Number, of: &Number) -> bool {
    if let (Some(a), Some(b)) = (as_i128(number), as_i128(of)) {
        return b != 0 && a % b == 0;
    }
    let quotient = as_f64(number) / as_f64(of);
    quotient.is_finite() && (quotient - quotient.round()).abs() <= 1e-9 * quotient.abs().max(1.0)
}

/// A string for `value` that is equal for values `equal` says are equal.
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Number(number) => match as_i128(number) {
            Some(int) => out.push_str(&int.to_string()),
            None => {
                let float = as_f64(number);
                if float.is_finite() && float.fract() == 0.0 && float.abs() < 1e30 {
                    // An integral float is the integer it names (`1.0` is `1`).
                    out.push_str(&format!("{float:.0}"));
                } else {
                    out.push_str(&format!("{float:?}"));
                }
            }
        },
        Value::Array(items) => {
            out.push('[');
            for item in items {
                canonical(item, out);
                out.push(',');
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for key in keys {
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                if let Some(item) = map.get(key) {
                    canonical(item, out);
                }
                out.push(',');
            }
            out.push('}');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn all_unique(items: &[Value]) -> bool {
    let mut seen = HashSet::with_capacity(items.len());
    items.iter().all(|item| {
        let mut key = String::new();
        canonical(item, &mut key);
        seen.insert(key)
    })
}

fn digits(text: &str, count: usize) -> Option<u32> {
    (text.len() == count && text.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

fn is_date(text: &str) -> bool {
    let mut parts = text.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Some(year), Some(month), Some(day)) = (digits(year, 4), digits(month, 2), digits(day, 2))
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + u32::from(leap),
        _ => return false,
    };
    (1..=longest).contains(&day)
}

fn is_time(text: &str) -> bool {
    let Some(zone_at) = text.rfind(['Z', 'z', '+', '-']) else {
        return false;
    };
    let (clock, zone) = text.split_at(zone_at);
    let zone_ok = match zone.as_bytes() {
        [b'Z' | b'z'] => true,
        [sign, ..] if matches!(*sign, b'+' | b'-') => {
            let mut parts = zone[1..].split(':');
            matches!(
                (parts.next(), parts.next(), parts.next()),
                (Some(hours), Some(minutes), None)
                    if digits(hours, 2).is_some_and(|hours| hours < 24)
                        && digits(minutes, 2).is_some_and(|minutes| minutes < 60)
            )
        }
        _ => false,
    };
    let (whole, fraction) = match clock.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (clock, None),
    };
    let mut parts = whole.split(':');
    let (Some(hours), Some(minutes), Some(seconds), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    zone_ok
        && digits(hours, 2).is_some_and(|hours| hours < 24)
        && digits(minutes, 2).is_some_and(|minutes| minutes < 60)
        && digits(seconds, 2).is_some_and(|seconds| seconds <= 60)
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

impl Format {
    fn admits_text(self, text: &str) -> bool {
        match self {
            Self::Uuid => is_uuid(text),
            Self::Date => is_date(text),
            Self::DateTime => text
                .split_once(['T', 't'])
                .is_some_and(|(date, time)| is_date(date) && is_time(time)),
            Self::Ipv4 => text.parse::<Ipv4Addr>().is_ok(),
            Self::Ipv6 => text.parse::<Ipv6Addr>().is_ok(),
            Self::Int32 | Self::Int64 => true,
        }
    }

    fn admits_number(self, number: &Number) -> bool {
        let Some(int) = as_i128(number) else {
            return true;
        };
        match self {
            Self::Int32 => i32::try_from(int).is_ok(),
            Self::Int64 => i64::try_from(int).is_ok(),
            _ => true,
        }
    }
}

impl Schemas {
    fn get(&self, id: SchemaId) -> Option<&Schema> {
        self.nodes.get(usize::try_from(id.0).ok()?)
    }

    /// The `items` schema of `id`, for a parameter that is a list.
    pub(super) fn item_schema(&self, id: SchemaId) -> Option<SchemaId> {
        let schema = self.get(id)?;
        schema
            .items
            .as_ref()
            .and_then(|items| items.items)
            .or_else(|| schema.reference.and_then(|target| self.item_schema(target)))
    }

    /// Whether the schema admits only lists.
    pub(super) fn is_list(&self, id: SchemaId) -> bool {
        self.get(id).is_some_and(|schema| {
            schema.types.only(TypeSet::ARRAY)
                || schema
                    .reference
                    .is_some_and(|target| schema.types.is_empty() && self.is_list(target))
        })
    }

    /// Checks `value` against `id`, recording what is wrong in `run`.
    pub(super) fn check<'v>(&self, id: SchemaId, value: &'v Value, run: &mut Run<'v>) {
        self.node(id, value, run);
    }

    /// Whether `value` fits `id`, stopping at the first failure and recording nothing.
    pub(super) fn valid<'v>(&self, id: SchemaId, value: &'v Value, run: &mut Run<'v>) -> bool {
        let outer = run.probe_failed;
        run.probe += 1;
        run.probe_failed = false;
        self.node(id, value, run);
        let ok = !run.probe_failed && !run.exhausted;
        run.probe -= 1;
        run.probe_failed = outer;
        ok
    }

    fn node<'v>(&self, id: SchemaId, value: &'v Value, run: &mut Run<'v>) {
        if run.stop() || !run.spend(1) {
            return;
        }
        let Some(schema) = self.get(id) else {
            return;
        };
        if let Some(target) = schema.reference {
            self.node(target, value, run);
        }
        if !schema.types.is_empty()
            && !schema.types.admits(value, self.dialect)
            && !(schema.nullable && value.is_null())
        {
            run.fail(|| format!("expected {}", schema.types).into());
            return;
        }
        if let Some(values) = &schema.values {
            if let Some(allowed) = &values.enumeration
                && !allowed.iter().any(|candidate| equal(candidate, value))
            {
                run.fail(|| "is not one of the allowed values".into());
            }
            if let Some(constant) = &values.constant
                && !equal(constant, value)
            {
                run.fail(|| "is not the required constant".into());
            }
        }
        match value {
            Value::Number(number) => self.numeric(schema, number, run),
            Value::String(text) => Self::textual(schema, text, run),
            Value::Array(items) => self.listed(schema, items, run),
            Value::Object(map) => self.keyed(schema, map, run),
            _ => {}
        }
        if let Some(logic) = &schema.logic {
            self.combined(logic, value, run);
        }
    }

    fn numeric(&self, schema: &Schema, number: &Number, run: &mut Run<'_>) {
        if let Some(format) = schema.format
            && !format.admits_number(number)
        {
            run.fail(|| format!("is out of range for format {}", format_name(format)).into());
        }
        let Some(limits) = &schema.numbers else {
            return;
        };
        if let Some(bound) = &limits.min {
            let order = compare(number, &bound.value);
            if order == Ordering::Less || (bound.exclusive && order == Ordering::Equal) {
                let word = if bound.exclusive { "over" } else { "at least" };
                run.fail(|| format!("must be {word} {}", bound.value).into());
            }
        }
        if let Some(bound) = &limits.max {
            let order = compare(number, &bound.value);
            if order == Ordering::Greater || (bound.exclusive && order == Ordering::Equal) {
                let word = if bound.exclusive { "under" } else { "at most" };
                run.fail(|| format!("must be {word} {}", bound.value).into());
            }
        }
        if let Some(of) = &limits.multiple_of
            && !is_multiple(number, of)
        {
            run.fail(|| format!("must be a multiple of {of}").into());
        }
    }

    fn textual(schema: &Schema, text: &str, run: &mut Run<'_>) {
        if let Some(format) = schema.format
            && !format.admits_text(text)
        {
            run.fail(|| format!("is not a valid {}", format_name(format)).into());
        }
        let Some(rules) = &schema.text else {
            return;
        };
        if rules.min.is_some() || rules.max.is_some() {
            let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
            if let Some(min) = rules.min
                && length < min
            {
                run.fail(|| format!("must have at least {min} characters").into());
            }
            if let Some(max) = rules.max
                && length > max
            {
                run.fail(|| format!("must have at most {max} characters").into());
            }
        }
        if let Some(pattern) = &rules.pattern
            && !pattern.is_match(text)
        {
            run.fail(|| "does not match the required pattern".into());
        }
    }

    fn listed<'v>(&self, schema: &Schema, items: &'v [Value], run: &mut Run<'v>) {
        let Some(rules) = &schema.items else {
            return;
        };
        let length = u64::try_from(items.len()).unwrap_or(u64::MAX);
        if let Some(min) = rules.min
            && length < min
        {
            run.fail(|| format!("must have at least {min} items").into());
        }
        if let Some(max) = rules.max
            && length > max
        {
            run.fail(|| format!("must have at most {max} items").into());
        }
        if rules.unique && (!run.spend(items.len()) || !all_unique(items)) {
            if !run.exhausted {
                run.fail(|| "must not repeat an item".into());
            }
            return;
        }
        for (index, item) in items.iter().enumerate() {
            let target = rules.prefix.get(index).copied().or(rules.items);
            let Some(target) = target else {
                continue;
            };
            run.path.push(Step::Index(index));
            self.node(target, item, run);
            run.path.pop();
            if run.stop() {
                return;
            }
        }
    }

    fn keyed<'v>(
        &self,
        schema: &Schema,
        map: &'v serde_json::Map<String, Value>,
        run: &mut Run<'v>,
    ) {
        let Some(rules) = &schema.fields else {
            return;
        };
        let length = u64::try_from(map.len()).unwrap_or(u64::MAX);
        if let Some(min) = rules.min
            && length < min
        {
            run.fail(|| format!("must have at least {min} properties").into());
        }
        if let Some(max) = rules.max
            && length > max
        {
            run.fail(|| format!("must have at most {max} properties").into());
        }
        for name in &rules.required {
            if !map.contains_key(&**name) {
                run.fail(|| format!("required property {name:?} is missing").into());
            }
        }
        for (key, item) in map {
            let declared = rules
                .properties
                .binary_search_by(|(name, _)| (**name).cmp(key.as_str()))
                .ok()
                .and_then(|at| rules.properties.get(at))
                .map(|(_, id)| *id);
            let target = match (declared, rules.additional) {
                (Some(id), _) | (None, Additional::Schema(id)) => Some(id),
                (None, Additional::Any) => None,
                (None, Additional::Forbidden) => {
                    run.path.push(Step::Key(key));
                    run.fail(|| "additional property is not allowed".into());
                    run.path.pop();
                    None
                }
            };
            if let Some(target) = target {
                run.path.push(Step::Key(key));
                self.node(target, item, run);
                run.path.pop();
            }
            if run.stop() {
                return;
            }
        }
    }

    fn combined<'v>(&self, logic: &Logic, value: &'v Value, run: &mut Run<'v>) {
        for id in &logic.all_of {
            self.node(*id, value, run);
            if run.stop() {
                return;
            }
        }
        if !logic.any_of.is_empty() {
            let mut hit = false;
            for id in &logic.any_of {
                if self.valid(*id, value, run) {
                    hit = true;
                    break;
                }
                if run.stop() {
                    return;
                }
            }
            if !hit {
                run.fail(|| "does not match any of the allowed shapes".into());
            }
        }
        if !logic.one_of.is_empty() {
            let mut hits = 0_u8;
            for id in &logic.one_of {
                if self.valid(*id, value, run) {
                    hits += 1;
                    if hits > 1 {
                        break;
                    }
                }
                if run.stop() {
                    return;
                }
            }
            match hits {
                0 => run.fail(|| "matches none of the allowed shapes".into()),
                1 => {}
                _ => run.fail(|| "matches more than one of the allowed shapes".into()),
            }
        }
        if let Some(id) = logic.not
            && self.valid(id, value, run)
        {
            run.fail(|| "matches a shape that is not allowed".into());
        }
    }
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Int32 => "int32",
        Format::Int64 => "int64",
        Format::Uuid => "uuid",
        Format::Date => "date",
        Format::DateTime => "date-time",
        Format::Ipv4 => "ipv4",
        Format::Ipv6 => "ipv6",
    }
}
