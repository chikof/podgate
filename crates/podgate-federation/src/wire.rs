//! The documents the exporter serves and the hub reads, and everything that bounds them.
//!
//! Both ends parse with the same code. A document starts with `format_version`; reading ignores
//! fields it does not know (a newer exporter adds fields without a new version), and writing
//! emits a closed set of fields, so the daemon's own document can grow without this protocol
//! growing. Every string that came from outside is length-capped here, and a catalog entry that
//! breaks a cap is dropped and counted, never repaired into something that could collide with
//! another entry.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

/// The format both documents are written in.
pub const FORMAT_VERSION: u32 = 1;

/// The formats the hub reads. A peer that answers anything else shows as stale with
/// `unsupported_format`.
pub const SUPPORTED: &[u32] = &[1];

/// Longest tenant, app, id and `declared_by`, in bytes.
pub const MAX_ID: usize = 128;
/// Longest API version, in bytes.
pub const MAX_VERSION: usize = 64;
/// Longest title, in bytes; longer text is cut.
pub const MAX_TITLE: usize = 256;
/// Longest description, in bytes; longer text is cut.
pub const MAX_DESCRIPTION: usize = 2048;
/// Longest host name, in bytes.
pub const MAX_HOST: usize = 253;
/// Most routers and most hosts of one entry; more are cut.
pub const MAX_LIST: usize = 64;
/// Longest OpenAPI name, title and version, in bytes.
pub const MAX_OPENAPI_TEXT: usize = 256;
/// Longest cursor, in bytes.
pub const MAX_CURSOR: usize = 512;
/// Most items one page may hold.
pub const MAX_PAGE_ITEMS: usize = 500;
/// Longest `boot_id` and `writer`, in bytes.
const MAX_LABEL: usize = 64;

/// Why a document is refused.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Not JSON, or not the document's shape.
    #[error("malformed document")]
    Malformed,
    /// A `format_version` this program does not read.
    #[error("unsupported format version {0}")]
    UnsupportedFormat(u32),
}

/// Why one catalog entry is left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// A field is missing or has the wrong type.
    Shape,
    /// A field is over its length cap.
    TooLong,
    /// A field holds a control character.
    Control,
}

#[derive(Deserialize)]
struct Envelope {
    format_version: u32,
}

/// Reads `format_version` alone, first, so a future format fails cleanly and never as a parse
/// error of its fields.
///
/// # Errors
///
/// [`ParseError::Malformed`] when the body has no integer `format_version`,
/// [`ParseError::UnsupportedFormat`] when it is not in [`SUPPORTED`].
pub fn check_format(body: &[u8]) -> Result<u32, ParseError> {
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| ParseError::Malformed)?;
    if SUPPORTED.contains(&envelope.format_version) {
        Ok(envelope.format_version)
    } else {
        Err(ParseError::UnsupportedFormat(envelope.format_version))
    }
}

/// The lifecycle stage of an API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    /// Not reachable.
    Draft,
    /// Reachable, not final.
    Preview,
    /// Reachable and final.
    Stable,
    /// Reachable, announces its end.
    Deprecated,
    /// Answers `410`.
    Retired,
    /// A stage a newer exporter added.
    #[serde(rename = "unknown")]
    Other,
}

impl Lifecycle {
    /// The stage a word names; [`Lifecycle::Other`] for any other word.
    #[must_use]
    pub fn from_word(word: &str) -> Self {
        match word {
            "draft" => Self::Draft,
            "preview" => Self::Preview,
            "stable" => Self::Stable,
            "deprecated" => Self::Deprecated,
            "retired" => Self::Retired,
            _ => Self::Other,
        }
    }
}

/// The identity of an entry within one cluster, ordered as the catalog sorts: by text, tenant
/// first.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// The tenant.
    pub tenant: Box<str>,
    /// The API id.
    pub id: Box<str>,
    /// The API version.
    pub version: Box<str>,
}

impl Key {
    /// The key of `item`.
    #[must_use]
    pub fn of(item: &Item) -> Self {
        Self {
            tenant: item.tenant.clone(),
            id: item.id.clone(),
            version: item.version.clone(),
        }
    }
}

/// A key as a page cursor: `<tenant>/<id>/<version>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(Box<str>);

/// A cursor that is not three parts within the caps.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("not a cursor")]
pub struct BadCursor;

impl Cursor {
    /// The cursor that continues after `key`.
    #[must_use]
    pub fn after(key: &Key) -> Self {
        Self(format!("{}/{}/{}", key.tenant, key.id, key.version).into())
    }

    /// Parses text a client sent: at most [`MAX_CURSOR`] bytes, no control character, three
    /// non-empty parts split from the right (a tenant id may contain `/`).
    ///
    /// # Errors
    ///
    /// [`BadCursor`] for anything else.
    pub fn parse(text: &str) -> Result<Self, BadCursor> {
        if text.len() > MAX_CURSOR || text.chars().any(char::is_control) {
            return Err(BadCursor);
        }
        let mut parts = text.rsplitn(3, '/');
        let (Some(version), Some(id), Some(tenant)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(BadCursor);
        };
        if tenant.is_empty()
            || id.is_empty()
            || version.is_empty()
            || tenant.len() > MAX_ID
            || id.len() > MAX_ID
            || version.len() > MAX_VERSION
        {
            return Err(BadCursor);
        }
        Ok(Self(text.into()))
    }

    /// The cursor text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key the cursor names.
    #[must_use]
    pub fn key(&self) -> Key {
        let mut parts = self.0.rsplitn(3, '/');
        let version = parts.next().unwrap_or_default();
        let id = parts.next().unwrap_or_default();
        let tenant = parts.next().unwrap_or_default();
        Key {
            tenant: tenant.into(),
            id: id.into(),
            version: version.into(),
        }
    }
}

/// The successor of a deprecated API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ref {
    /// The successor's id.
    pub id: Box<str>,
    /// The successor's version.
    pub version: Box<str>,
}

/// What an entry says about its OpenAPI document, never the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Openapi {
    /// The name of the middleware that holds it.
    pub name: Box<str>,
    /// `info.title`.
    pub title: Box<str>,
    /// `info.version`.
    pub version: Box<str>,
    /// `"3.0"` or `"3.1"`.
    pub dialect: Box<str>,
    /// The number of operations.
    pub operations: u64,
}

/// One catalog entry, with every string capped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Item {
    /// The tenant.
    pub tenant: Box<str>,
    /// The app that declares it.
    pub app: Box<str>,
    /// Who declared the app.
    pub declared_by: Box<str>,
    /// The API id.
    pub id: Box<str>,
    /// The API version.
    pub version: Box<str>,
    /// The title, cut to [`MAX_TITLE`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Box<str>>,
    /// The description, cut to [`MAX_DESCRIPTION`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Box<str>>,
    /// The stage.
    pub lifecycle: Lifecycle,
    /// `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset: Option<Box<str>>,
    /// The successor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub successor: Option<Ref>,
    /// The routers that serve it.
    pub routers: Box<[Box<str>]>,
    /// The hosts those routers claim.
    pub hosts: Box<[Box<str>]>,
    /// Whether the tenant lets the portal show it.
    pub published: bool,
    /// The OpenAPI summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openapi: Option<Openapi>,
    /// The daemon could not fit the whole entry in a page and sent a stub.
    #[serde(skip_serializing_if = "is_false")]
    pub too_large: bool,
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if passes a reference"
)]
fn is_false(flag: &bool) -> bool {
    !*flag
}

#[derive(Deserialize)]
struct RawRef {
    id: String,
    version: String,
}

#[derive(Deserialize)]
struct RawOpenapi {
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    dialect: String,
    #[serde(default)]
    operations: u64,
}

#[derive(Deserialize)]
struct RawItem {
    tenant: String,
    app: String,
    #[serde(default)]
    declared_by: String,
    id: String,
    version: String,
    title: Option<String>,
    description: Option<String>,
    lifecycle: String,
    sunset: Option<String>,
    successor: Option<RawRef>,
    #[serde(default)]
    routers: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    published: bool,
    openapi: Option<RawOpenapi>,
    #[serde(default)]
    too_large: bool,
}

/// `text` as an identifier: within `max` bytes and free of control characters.
fn ident(text: String, max: usize) -> Result<Box<str>, Dropped> {
    if text.len() > max {
        return Err(Dropped::TooLong);
    }
    if text.chars().any(char::is_control) {
        return Err(Dropped::Control);
    }
    Ok(text.into())
}

/// `text` as a key part: an identifier that is not empty.
fn key_part(text: String, max: usize) -> Result<Box<str>, Dropped> {
    if text.is_empty() {
        return Err(Dropped::Shape);
    }
    ident(text, max)
}

/// `text` as display text: cut at a character boundary to `max` bytes. Control characters are
/// refused, except line breaks and tabs where `multiline` allows them.
fn display(text: String, max: usize, multiline: bool) -> Result<Box<str>, Dropped> {
    let bad = |c: char| c.is_control() && !(multiline && matches!(c, '\n' | '\t'));
    if text.chars().any(bad) {
        return Err(Dropped::Control);
    }
    if text.len() <= max {
        return Ok(text.into());
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Ok(text[..end].into())
}

fn list(items: Vec<String>, max: usize) -> Result<Box<[Box<str>]>, Dropped> {
    items
        .into_iter()
        .take(MAX_LIST)
        .map(|text| ident(text, max))
        .collect()
}

fn sunset(text: String) -> Result<Box<str>, Dropped> {
    let bytes = text.as_bytes();
    let shaped = bytes.len() == 10
        && bytes.iter().enumerate().all(|(at, byte)| match at {
            4 | 7 => *byte == b'-',
            _ => byte.is_ascii_digit(),
        });
    if shaped {
        Ok(text.into())
    } else {
        Err(Dropped::Shape)
    }
}

impl Item {
    /// Reads one entry, enforcing every cap. The only way to make an [`Item`] from outside data.
    ///
    /// # Errors
    ///
    /// [`Dropped`] says which rule the entry broke.
    pub fn parse(value: Value) -> Result<Self, Dropped> {
        let raw: RawItem = serde_json::from_value(value).map_err(|_| Dropped::Shape)?;
        Ok(Self {
            tenant: key_part(raw.tenant, MAX_ID)?,
            app: key_part(raw.app, MAX_ID)?,
            declared_by: ident(raw.declared_by, MAX_ID)?,
            id: key_part(raw.id, MAX_ID)?,
            version: key_part(raw.version, MAX_VERSION)?,
            title: raw
                .title
                .map(|t| display(t, MAX_TITLE, false))
                .transpose()?,
            description: raw
                .description
                .map(|d| display(d, MAX_DESCRIPTION, true))
                .transpose()?,
            lifecycle: Lifecycle::from_word(&raw.lifecycle),
            sunset: raw.sunset.map(sunset).transpose()?,
            successor: raw
                .successor
                .map(|s| {
                    Ok(Ref {
                        id: key_part(s.id, MAX_ID)?,
                        version: key_part(s.version, MAX_VERSION)?,
                    })
                })
                .transpose()?,
            routers: list(raw.routers, MAX_ID)?,
            hosts: list(raw.hosts, MAX_HOST)?,
            published: raw.published,
            openapi: raw
                .openapi
                .map(|o| {
                    Ok(Openapi {
                        name: ident(o.name, MAX_OPENAPI_TEXT)?,
                        title: display(o.title, MAX_OPENAPI_TEXT, false)?,
                        version: display(o.version, MAX_OPENAPI_TEXT, false)?,
                        dialect: ident(o.dialect, 8)?,
                        operations: o.operations,
                    })
                })
                .transpose()?,
            too_large: raw.too_large,
        })
    }
}

/// The key of a raw entry, when its three key fields are usable. An entry that is dropped for
/// another reason still has one, so paging can step over it.
fn raw_key(value: &Value) -> Option<Key> {
    let part = |name: &str, max: usize| {
        let text = value.get(name)?.as_str()?;
        (!text.is_empty() && text.len() <= max && !text.chars().any(char::is_control))
            .then(|| Box::<str>::from(text))
    };
    Some(Key {
        tenant: part("tenant", MAX_ID)?,
        id: part("id", MAX_ID)?,
        version: part("version", MAX_VERSION)?,
    })
}

/// A list of raw entries that stops reading at [`MAX_PAGE_ITEMS`], so a body of empty objects
/// cannot make the parser allocate millions of values.
struct RawItems(Vec<Value>);

impl<'de> Deserialize<'de> for RawItems {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Bounded;
        impl<'de> Visitor<'de> for Bounded {
            type Value = RawItems;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<RawItems, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element::<Value>()? {
                    if items.len() == MAX_PAGE_ITEMS {
                        return Err(de::Error::custom("too many entries"));
                    }
                    items.push(item);
                }
                Ok(RawItems(items))
            }
        }
        deserializer.deserialize_seq(Bounded)
    }
}

#[derive(Deserialize)]
struct RawPage {
    // The daemon's document calls it `version`, the federation document `snapshot_version`.
    #[serde(alias = "version")]
    snapshot_version: u64,
    #[serde(default)]
    total: u64,
    items: RawItems,
    #[serde(default)]
    truncated: bool,
    next: Option<String>,
}

/// One page of the catalog, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The snapshot version the page was read at.
    pub snapshot_version: u64,
    /// The peer's count of entries the filters select.
    pub total: u64,
    /// The entries that passed every rule, ascending by key.
    pub items: Vec<Item>,
    /// How many entries were left out.
    pub dropped: u32,
    /// Whether the page ended before the end of the catalog.
    pub truncated: bool,
    /// The key of the last entry, dropped or not, whose key fields are usable.
    pub last_key: Option<Key>,
    /// The cursor the sender named, which the reader checks and never uses.
    pub next: Option<Box<str>>,
}

impl Page {
    /// Reads the daemon's `GET /v1/catalog` document.
    ///
    /// # Errors
    ///
    /// [`ParseError::Malformed`] for a body that is not the document, for more than
    /// [`MAX_PAGE_ITEMS`] entries, and for entries that are not strictly ascending by key.
    pub fn from_daemon(body: &[u8]) -> Result<Self, ParseError> {
        Self::parse(body)
    }

    /// Reads the exporter's catalog document.
    ///
    /// # Errors
    ///
    /// As [`check_format`], then as [`Page::from_daemon`].
    pub fn from_peer(body: &[u8]) -> Result<Self, ParseError> {
        check_format(body)?;
        Self::parse(body)
    }

    fn parse(body: &[u8]) -> Result<Self, ParseError> {
        let raw: RawPage = serde_json::from_slice(body).map_err(|_| ParseError::Malformed)?;
        let mut items = Vec::with_capacity(raw.items.0.len());
        let mut dropped = 0_u32;
        let mut last_key: Option<Key> = None;
        for value in raw.items.0 {
            if let Some(key) = raw_key(&value) {
                if last_key.as_ref().is_some_and(|last| key <= *last) {
                    return Err(ParseError::Malformed);
                }
                last_key = Some(key);
            }
            match Item::parse(value) {
                Ok(item) => items.push(item),
                Err(_) => dropped = dropped.saturating_add(1),
            }
        }
        Ok(Self {
            snapshot_version: raw.snapshot_version,
            total: raw.total,
            items,
            dropped,
            truncated: raw.truncated,
            last_key,
            next: raw.next.map(Into::into),
        })
    }
}

/// The server counts of a node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerCounts {
    /// Servers that are available.
    #[serde(default)]
    pub healthy: u64,
    /// Servers failing their health check.
    #[serde(default)]
    pub unhealthy: u64,
    /// Servers held out by outlier detection.
    #[serde(default)]
    pub ejected: u64,
}

/// What a node serves, in counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    /// Tenants.
    #[serde(default)]
    pub tenants: u64,
    /// Apps.
    #[serde(default)]
    pub apps: u64,
    /// Routers.
    #[serde(default)]
    pub routers: u64,
    /// Services.
    #[serde(default)]
    pub services: u64,
    /// Servers by state.
    #[serde(default)]
    pub servers: ServerCounts,
}

/// The status of one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The live snapshot version.
    pub snapshot_version: u64,
    /// Seconds since the Unix epoch when the table was compiled, as the node says.
    pub applied_at: u64,
    /// Identifies the running process.
    pub boot_id: Box<str>,
    /// The writer that owns the snapshot, when it has a plain name.
    pub writer: Option<Box<str>>,
    /// The counts.
    pub counts: Counts,
}

#[derive(Deserialize)]
struct RawStatus {
    #[serde(alias = "version")]
    snapshot_version: u64,
    #[serde(default)]
    applied_at: u64,
    boot_id: String,
    writer: Option<String>,
    #[serde(default)]
    counts: Counts,
}

#[derive(Deserialize)]
struct RawSummary {
    version: u64,
    #[serde(default)]
    applied_at: u64,
    boot_id: String,
    writer: Option<String>,
    #[serde(flatten)]
    counts: Counts,
}

#[derive(Deserialize)]
struct SummaryDoc {
    summary: RawSummary,
}

/// A label made of `[A-Za-z0-9._-]`, at most 64 bytes.
fn label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LABEL
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Status {
    fn from_parts(
        snapshot_version: u64,
        applied_at: u64,
        boot_id: String,
        writer: Option<String>,
        counts: Counts,
    ) -> Result<Self, ParseError> {
        if !label(&boot_id) {
            return Err(ParseError::Malformed);
        }
        Ok(Self {
            snapshot_version,
            applied_at,
            boot_id: boot_id.into(),
            writer: writer.filter(|w| label(w)).map(Into::into),
            counts,
        })
    }

    /// Reads the daemon's `GET /v1/overview?section=summary` document.
    ///
    /// # Errors
    ///
    /// [`ParseError::Malformed`] when the body is not that document or `boot_id` is not a plain
    /// label.
    pub fn from_daemon(body: &[u8]) -> Result<Self, ParseError> {
        let doc: SummaryDoc = serde_json::from_slice(body).map_err(|_| ParseError::Malformed)?;
        let raw = doc.summary;
        Self::from_parts(
            raw.version,
            raw.applied_at,
            raw.boot_id,
            raw.writer,
            raw.counts,
        )
    }

    /// Reads the exporter's status document.
    ///
    /// # Errors
    ///
    /// As [`check_format`], then [`ParseError::Malformed`].
    pub fn from_peer(body: &[u8]) -> Result<Self, ParseError> {
        check_format(body)?;
        let raw: RawStatus = serde_json::from_slice(body).map_err(|_| ParseError::Malformed)?;
        Self::from_parts(
            raw.snapshot_version,
            raw.applied_at,
            raw.boot_id,
            raw.writer,
            raw.counts,
        )
    }

    /// The exporter's status document.
    ///
    /// # Errors
    ///
    /// Fails only if serialization does, which a plain struct never does.
    pub fn to_doc(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct Doc<'a> {
            format_version: u32,
            snapshot_version: u64,
            applied_at: u64,
            boot_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            writer: Option<&'a str>,
            counts: &'a Counts,
        }
        serde_json::to_vec(&Doc {
            format_version: FORMAT_VERSION,
            snapshot_version: self.snapshot_version,
            applied_at: self.applied_at,
            boot_id: &self.boot_id,
            writer: self.writer.as_deref(),
            counts: &self.counts,
        })
    }
}

/// Percent-encodes everything but the unreserved characters.
#[must_use]
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes. `+` stays a plus. `None` for a broken escape or bytes that are not
/// UTF-8.
#[must_use]
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let pair = bytes.get(at + 1..at + 3)?;
            let pair = std::str::from_utf8(pair).ok()?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::*;

    fn entry() -> Value {
        json!({
            "tenant": "acme", "app": "pets", "declared_by": "podkit", "id": "pets", "version": "1",
            "title": "Pets", "lifecycle": "stable", "routers": ["r"], "hosts": ["a.test"],
            "published": true
        })
    }

    #[test]
    fn federation_wire_drops_overlong_keys() {
        let mut value = entry();
        value["tenant"] = json!("t".repeat(MAX_ID + 1));
        assert_eq!(Item::parse(value), Err(Dropped::TooLong));
        let mut value = entry();
        value["version"] = json!("v".repeat(MAX_VERSION + 1));
        assert_eq!(Item::parse(value), Err(Dropped::TooLong));
        let mut value = entry();
        value["id"] = json!("");
        assert_eq!(Item::parse(value), Err(Dropped::Shape));
        assert!(Item::parse(entry()).is_ok());
    }

    #[test]
    fn federation_wire_cuts_display_text() {
        let mut value = entry();
        value["description"] = json!("é".repeat(MAX_DESCRIPTION));
        value["title"] = json!("x".repeat(MAX_TITLE * 4));
        let item = Item::parse(value).expect("parses");
        assert_eq!(item.title.as_deref().map(str::len), Some(MAX_TITLE));
        let description = item.description.expect("description");
        assert!(description.len() <= MAX_DESCRIPTION);
        assert!(description.chars().all(|c| c == 'é'), "cut on a boundary");
    }

    #[test]
    fn federation_wire_ignores_unknown_fields() {
        let mut value = entry();
        value["cluster"] = json!("other");
        value["nested"] = json!({"a": [1, 2]});
        let item = Item::parse(value).expect("parses");
        let text = serde_json::to_string(&item).expect("serializes");
        assert!(!text.contains("cluster") && !text.contains("nested"));
    }

    #[test]
    fn federation_wire_unknown_lifecycle_is_other() {
        let mut value = entry();
        value["lifecycle"] = json!("sunsetting");
        assert_eq!(
            Item::parse(value).expect("parses").lifecycle,
            Lifecycle::Other
        );
    }

    #[test]
    fn federation_wire_control_characters() {
        let mut value = entry();
        value["tenant"] = json!("ac\u{1b}[2Jme");
        assert_eq!(Item::parse(value), Err(Dropped::Control));
        let mut value = entry();
        value["title"] = json!("a\nb");
        assert_eq!(Item::parse(value), Err(Dropped::Control));
        let mut value = entry();
        value["description"] = json!("a\nb\tc");
        assert!(Item::parse(value).is_ok(), "a description may have lines");
        let mut value = entry();
        value["description"] = json!("a\u{0}b");
        assert_eq!(Item::parse(value), Err(Dropped::Control));
    }

    #[test]
    fn federation_wire_sunset_shape() {
        let mut value = entry();
        value["sunset"] = json!("2027-03-01");
        assert!(Item::parse(value).is_ok());
        let mut value = entry();
        value["sunset"] = json!("tomorrow");
        assert_eq!(Item::parse(value), Err(Dropped::Shape));
    }

    #[test]
    fn federation_wire_cursor_rules() {
        let cursor = Cursor::parse("a/b/c/d/1").expect("a tenant may hold a slash");
        let key = cursor.key();
        assert_eq!((&*key.tenant, &*key.id, &*key.version), ("a/b/c", "d", "1"));
        for bad in [
            "",
            "a",
            "a/b",
            "/b/c",
            "a//c",
            "a/b/",
            "a/b/c\n",
            "a/b/c\u{0}",
        ] {
            assert!(Cursor::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Cursor::parse(&format!("t/i/{}", "v".repeat(MAX_CURSOR))).is_err());
        let round = Cursor::after(&key);
        assert_eq!(round.as_str(), "a/b/c/d/1");
    }

    #[test]
    fn federation_wire_percent_round_trip() {
        let text = "a b/c%d&e=f\r\n\u{e9}";
        assert_eq!(percent_decode(&percent_encode(text)).as_deref(), Some(text));
        assert!(!percent_encode(text).contains(['\r', '\n', ' ', '&', '=', '/']));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%4"), None);
        assert_eq!(percent_decode("%ff"), None);
    }

    fn page(items: &Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "format_version": 1, "snapshot_version": 3, "total": 9, "items": items,
            "truncated": false
        }))
        .expect("json")
    }

    #[test]
    fn federation_wire_page_counts_dropped_and_checks_order() {
        let mut bad = entry();
        bad["id"] = json!("b");
        bad["description"] = json!("x\u{0}");
        let mut late = entry();
        late["id"] = json!("c");
        let parsed = Page::from_peer(&page(&json!([late_of("a"), bad, late]))).expect("parses");
        assert_eq!((parsed.items.len(), parsed.dropped), (2, 1));
        assert_eq!(
            parsed.last_key.map(|k| k.id),
            Some("c".into()),
            "a dropped entry still has a key"
        );
        let unordered = page(&json!([late_of("b"), late_of("a")]));
        assert_eq!(Page::from_peer(&unordered), Err(ParseError::Malformed));
        let repeated = page(&json!([late_of("a"), late_of("a")]));
        assert_eq!(Page::from_peer(&repeated), Err(ParseError::Malformed));
    }

    fn late_of(id: &str) -> Value {
        let mut value = entry();
        value["id"] = json!(id);
        value
    }

    #[test]
    fn federation_wire_bounds_the_item_list() {
        let many = vec![json!({}); MAX_PAGE_ITEMS + 1];
        assert_eq!(
            Page::from_peer(&page(&Value::Array(many))),
            Err(ParseError::Malformed)
        );
    }

    #[test]
    fn federation_wire_format_version_is_read_first() {
        assert_eq!(
            check_format(br#"{"format_version":2,"items":"nonsense"}"#),
            Err(ParseError::UnsupportedFormat(2))
        );
        assert_eq!(
            check_format(br#"{"format_version":0}"#),
            Err(ParseError::UnsupportedFormat(0))
        );
        for bad in [
            &br#"{"format_version":"1"}"#[..],
            br#"{"format_version":-1}"#,
            br#"{"format_version":99999999999}"#,
            b"{}",
            b"[]",
            b"not json",
        ] {
            assert_eq!(
                check_format(bad),
                Err(ParseError::Malformed),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(check_format(br#"{"format_version":1}"#), Ok(1));
    }

    #[test]
    fn federation_wire_status_from_daemon_summary() {
        let body = br#"{"summary":{"version":12,"applied_at":5,"boot_id":"b-7","writer":"podgate-provider","metrics_addr":"127.0.0.1:1","tenants":2,"apps":9,"routers":14,"services":11,"servers":{"healthy":20,"unhealthy":1,"ejected":0},"secret":"x"}}"#;
        let status = Status::from_daemon(body).expect("parses");
        assert_eq!(status.snapshot_version, 12);
        assert_eq!(status.counts.servers.healthy, 20);
        let doc = String::from_utf8(status.to_doc().expect("doc")).expect("utf8");
        assert!(!doc.contains("secret") && !doc.contains("metrics_addr"));
        assert_eq!(
            Status::from_peer(doc.as_bytes()).expect("round trip"),
            status
        );
        let spoof = br#"{"summary":{"version":1,"boot_id":"a b","tenants":0}}"#;
        assert_eq!(Status::from_daemon(spoof), Err(ParseError::Malformed));
        let odd_writer = br#"{"summary":{"version":1,"boot_id":"b","writer":"<script>"}}"#;
        assert_eq!(
            Status::from_daemon(odd_writer).expect("parses").writer,
            None
        );
    }
}
