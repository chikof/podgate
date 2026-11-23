//! A JSON parse that refuses a repeated object key.
//!
//! `serde_json::Value` keeps the last of two equal keys; a backend may keep the first. A validator
//! that checks a value the backend then does not read is a bypass, so a body that repeats a key is
//! refused rather than read one way.

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Why a body is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refused {
    /// Not JSON, not UTF-8, nested over the parser's limit, or has data after the value.
    NotJson,
    /// An object repeats a key.
    RepeatedKey,
}

impl Refused {
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::NotJson => "the body is not valid JSON",
            Self::RepeatedKey => "the body repeats an object key",
        }
    }
}

const REPEATED: &str = "repeated object key";

struct Strict(Value);

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Strict, E> {
        Ok(Strict(Value::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Strict, E> {
        Ok(Strict(Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Strict, E> {
        Number::from_f64(value)
            .map(|number| Strict(Value::Number(number)))
            .ok_or_else(|| E::custom("not a finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(value)))
    }

    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut items = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
        while let Some(Strict(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Strict(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(REPEATED));
            }
            let Strict(value) = access.next_value()?;
            map.insert(key, value);
        }
        Ok(Strict(Value::Object(map)))
    }
}

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parses `bytes` as one JSON value.
///
/// # Errors
///
/// [`Refused`] for a body that is not JSON or repeats an object key.
pub(super) fn parse(bytes: &[u8]) -> Result<Value, Refused> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let Strict(value) = Strict::deserialize(&mut deserializer).map_err(|err| {
        if err.to_string().contains(REPEATED) {
            Refused::RepeatedKey
        } else {
            Refused::NotJson
        }
    })?;
    deserializer.end().map_err(|_| Refused::NotJson)?;
    Ok(value)
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn openapi_duplicate_keys_refused() {
        assert_eq!(
            parse(br#"{"a":1,"b":[{"c":true}]}"#),
            Ok(json!({"a":1,"b":[{"c":true}]}))
        );
        assert_eq!(
            parse(br#"{"role":"user","role":"admin"}"#),
            Err(Refused::RepeatedKey)
        );
        assert_eq!(parse(br#"{"a":{"b":1,"b":2}}"#), Err(Refused::RepeatedKey));
        assert_eq!(parse(br#"[{"a":1},{"a":2}]"#), Ok(json!([{"a":1},{"a":2}])));
        assert_eq!(parse(b"{"), Err(Refused::NotJson));
        assert_eq!(parse(b"1 2"), Err(Refused::NotJson));
        assert_eq!(parse(&[0xff, 0xfe]), Err(Refused::NotJson));
        assert_eq!(parse(&b"[".repeat(300)), Err(Refused::NotJson));
    }
}
