//! The shared layer of the key-value sources (etcd, Redis, an HTTP document store): the layouts
//! that turn keys and values into apps, the tenant mapping, the allowlist requirement and the
//! limits. It touches no store; a source reads its backend and hands the pairs to
//! [`Mapping::build`].
//!
//! ```toml
//! [[source.prefix]]
//! prefix = "podgate/acme"      # keys under "podgate/acme/"; the trailing slash is implied
//! tenant = "acme"              # the only place a tenant comes from
//! layout = "podgate-json"      # or "traefik-kv"
//! app = "acme-site"            # traefik-kv only: the app id, default the tenant
//! ```
//!
//! # Layouts
//!
//! - `podgate-json`: `<prefix>/apps/<id>` holds one app as JSON in the shape of the file source
//!   (an [`App`] without `tenant`), and `<prefix>/certificates/<name>` one [`Certificate`].
//! - `traefik-kv`: Traefik's key tree, with the prefix as its root key
//!   (`<prefix>/http/routers/<r>/rule`). The keys are flattened to the dotted label form
//!   (`traefik.http.routers.<r>.rule`), a list written as `<key>/0`, `<key>/1` becomes the
//!   comma separated value, and the labels go to [`crate::traefik::translate`]. The whole tree is
//!   one app. `servers/<n>/url` entries of a service are the one thing the translator refuses as
//!   an address; here they are the servers, because the writer is the tenant that owns the prefix
//!   and [`Mapping::new`] refuses a tenant that has no allow list.
//!
//! # Trust
//!
//! The writer of a key is the tenant that owns its prefix, and the tenant comes from nowhere
//! else: a document that names a tenant is ignored, and so is a key outside every prefix. Hosts,
//! catch-all routers and server addresses are judged by the merge ([`crate::merge`]) exactly as for any
//! other source. Because explicit server addresses are accepted, [`Mapping::new`] fails with
//! [`ConfigError::NoAllowlist`] for a tenant that the upstream policy file gives no `allow` list
//! of its own: the safe configuration is the only one that starts.
//!
//! # Limits
//!
//! A document larger than [`MAX_DOCUMENT_BYTES`], an app past [`MAX_APPS_PER_PREFIX`] (in key
//! order), a certificate past [`MAX_CERTIFICATES_PER_PREFIX`] and a document with a field the
//! model does not know are each left out on their own and reported; the other objects stay.
//!
//! The reference is `docs/ref/provider-kv.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use podgate_model::{App, Certificate, Declared, Router, TlsMode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::policy::UpstreamPolicy;
use crate::source::{Origin, SourceApp, SourceCertificate, State, TenantClaim};
use crate::traefik;

/// The largest document (one JSON value, or a whole `traefik-kv` tree with its keys), in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// The most apps one `podgate-json` prefix may declare. Apps past it, in key order, are left
/// out.
pub const MAX_APPS_PER_PREFIX: usize = 256;

/// The most certificates one `podgate-json` prefix may declare.
pub const MAX_CERTIFICATES_PER_PREFIX: usize = 256;

/// The most keys a prefix may hold. A store client reads no more than this many and treats a
/// prefix that holds more as unreadable, so a tenant cannot make the provider hold an unbounded
/// number of keys.
pub const MAX_KEYS_PER_PREFIX: usize = 4096;

/// The most characters of an app id or certificate name.
const MAX_NAME: usize = 63;

/// The most report lines a build returns; the rest are counted.
const MAX_REPORTS: usize = 50;

/// The most unknown fields one report names.
const MAX_NAMED_FIELDS: usize = 5;

/// The most characters of a key or an error a report quotes.
const MAX_QUOTED: usize = 120;

/// The `declared_by` placeholder of an app; the core overwrites it.
const DECLARED_BY: &str = "kv";

/// How a prefix's keys turn into objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Layout {
    /// `<prefix>/apps/<id>` and `<prefix>/certificates/<name>` hold JSON documents.
    #[serde(rename = "podgate-json")]
    PodgateJson,
    /// The Traefik key tree under the prefix, one app.
    #[serde(rename = "traefik-kv")]
    TraefikKv,
}

/// One `[[source.prefix]]` entry as written. Unknown keys are errors, so a misspelt `tenant`
/// cannot move a prefix's apps to another tenant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPrefix {
    /// The key prefix; the trailing slash is implied.
    pub prefix: String,
    /// The tenant that owns the prefix and writes its keys.
    pub tenant: String,
    /// How the keys are read.
    pub layout: Layout,
    /// `traefik-kv` only: the id of the app the tree becomes. Default: the tenant.
    #[serde(default)]
    pub app: Option<String>,
}

/// A `[[source.prefix]]` list that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// No prefix is configured: the source would read nothing.
    #[error("prefix: at least one [[source.prefix]] entry is required")]
    NoPrefix,
    /// One entry is wrong, or two overlap.
    #[error("prefix[{index}]: {reason}")]
    Prefix {
        /// The position of the entry in the list.
        index: usize,
        /// What is wrong, naming the key.
        reason: Box<str>,
    },
    /// The tenant has no allow list of its own in the upstream policy file.
    #[error(
        "kv_source_requires_tenant_allowlist: tenant {tenant:?} has no allow list in the upstream policy file (tenants.{tenant}.allow); a key-value source accepts explicit server addresses and would otherwise let the tenant point its servers at any address the policy permits"
    )]
    NoAllowlist {
        /// The tenant.
        tenant: Box<str>,
    },
}

impl ConfigError {
    /// The stable code of the error.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoPrefix | Self::Prefix { .. } => "invalid_prefix",
            Self::NoAllowlist { .. } => "kv_source_requires_tenant_allowlist",
        }
    }
}

/// One validated prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Prefix {
    /// The key prefix, ending in `/`: every key of the prefix starts with it. A store is asked
    /// for this text, never for the prefix without the slash, which would also match the keys of
    /// `acme2`.
    pub path: Box<str>,
    /// The tenant the prefix is mapped to.
    pub tenant: Box<str>,
    /// How its keys are read.
    pub layout: Layout,
    /// The app id of a `traefik-kv` prefix; empty for `podgate-json`.
    pub app: Box<str>,
}

/// The prefixes of one source: which keys it reads and what they mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    prefixes: Vec<Prefix>,
}

/// A text valid as an app id or certificate name: 1 to 63 letters, digits, `.`, `_` and `-`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl Mapping {
    /// Validates `raw` against `policy`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when the list is empty, a prefix is empty, holds a control character or is
    /// only slashes, a tenant is empty, two prefixes are equal or one lies inside the other (the
    /// writer of a key would be ambiguous), `app` is set for a layout that has no use for it or
    /// is not a valid id, two `traefik-kv` prefixes would become the same app, or a tenant has
    /// no allow list in `policy` ([`ConfigError::NoAllowlist`]).
    pub fn new(raw: Vec<RawPrefix>, policy: &UpstreamPolicy) -> Result<Self, ConfigError> {
        if raw.is_empty() {
            return Err(ConfigError::NoPrefix);
        }
        let mut prefixes: Vec<Prefix> = Vec::with_capacity(raw.len());
        for (index, entry) in raw.into_iter().enumerate() {
            let invalid = |reason: &str| ConfigError::Prefix {
                index,
                reason: reason.into(),
            };
            let trimmed = entry.prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                return Err(invalid(
                    "prefix: must name a key prefix, not the whole store",
                ));
            }
            if trimmed.chars().any(char::is_control) {
                return Err(invalid("prefix: must not hold control characters"));
            }
            if entry.tenant.is_empty() {
                return Err(invalid("tenant: is empty"));
            }
            let app = match (entry.layout, entry.app) {
                (Layout::PodgateJson, None) => String::new(),
                (Layout::PodgateJson, Some(_)) => {
                    return Err(invalid(
                        "app: only the traefik-kv layout has one app to name",
                    ));
                }
                (Layout::TraefikKv, app) => {
                    let app = app.unwrap_or_else(|| entry.tenant.clone());
                    if !valid_name(&app) {
                        return Err(invalid(
                            "app: must be 1 to 63 letters, digits, `-`, `_` or `.`; set `app` when the tenant is not such a name",
                        ));
                    }
                    app
                }
            };
            if !policy.has_tenant_allow_list(&entry.tenant) {
                return Err(ConfigError::NoAllowlist {
                    tenant: entry.tenant.into(),
                });
            }
            let path: Box<str> = format!("{trimmed}/").into();
            if let Some(other) = prefixes.iter().find(|other| {
                other.path.starts_with(&*path)
                    || path.starts_with(&*other.path)
                    || (entry.layout == Layout::TraefikKv
                        && other.layout == Layout::TraefikKv
                        && other.app == app.as_str().into())
            }) {
                return Err(invalid(&format!(
                    "prefix: overlaps {:?} (prefixes may not lie inside one another) or names the same app {:?}",
                    other.path, other.app
                )));
            }
            prefixes.push(Prefix {
                path,
                tenant: entry.tenant.into(),
                layout: entry.layout,
                app: app.into(),
            });
        }
        Ok(Self { prefixes })
    }

    /// The prefixes, in configuration order.
    #[must_use]
    pub fn prefixes(&self) -> &[Prefix] {
        &self.prefixes
    }

    /// Builds what the pairs of `entries` declare. The pairs are the keys and values the store
    /// holds under the prefixes; a key under none of them is ignored and reported.
    ///
    /// A pair that cannot be used is left out on its own and reported (a key that is not UTF-8,
    /// not in the layout's shape, a document over a limit, with a field the model does not know
    /// or naming a tenant). The result is deterministic: the order of `entries` does not matter.
    #[must_use]
    pub fn build<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        source: &str,
        entries: impl IntoIterator<Item = (K, V)>,
    ) -> Built {
        let entries: Vec<(K, V)> = entries.into_iter().collect();
        let mut built = Built::default();
        let mut buckets: Vec<BTreeMap<&str, &[u8]>> = vec![BTreeMap::new(); self.prefixes.len()];
        for (key, value) in &entries {
            let Ok(key) = std::str::from_utf8(key.as_ref()) else {
                built.report("a key that is not valid UTF-8: ignored".into());
                continue;
            };
            match self
                .prefixes
                .iter()
                .position(|prefix| key.starts_with(&*prefix.path))
            {
                Some(at) => {
                    buckets[at].insert(key, value.as_ref());
                }
                None => built.report(format!(
                    "key {}: outside every configured prefix; ignored",
                    shown(key)
                )),
            }
        }
        for (prefix, bucket) in self.prefixes.iter().zip(&buckets) {
            match prefix.layout {
                Layout::PodgateJson => podgate_json(source, prefix, bucket, &mut built),
                Layout::TraefikKv => traefik_tree(source, prefix, bucket, &mut built),
            }
        }
        built
    }
}

/// What [`Mapping::build`] made of the pairs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Built {
    /// The apps, in prefix then key order.
    pub apps: Vec<SourceApp>,
    /// The certificates, in prefix then key order.
    pub certificates: Vec<SourceCertificate>,
    /// One line per pair or tree that was left out and why, never holding a secret; at most 50,
    /// the last one counts the rest.
    pub reports: Vec<Box<str>>,
    omitted: usize,
}

impl Built {
    fn report(&mut self, line: String) {
        if self.reports.len() < MAX_REPORTS {
            self.reports.push(line.into());
        } else {
            self.omitted += 1;
        }
    }

    /// The reports as one text, or `None` when nothing was left out.
    #[must_use]
    pub fn report_text(&self) -> Option<Box<str>> {
        if self.reports.is_empty() {
            return None;
        }
        let mut text = self.reports.join("; ");
        if self.omitted > 0 {
            text.push_str(&format!("; and {} more", self.omitted));
        }
        Some(text.into())
    }

    /// The complete state of the source: its apps and certificates.
    #[must_use]
    pub fn into_state(self) -> State {
        State {
            apps: self.apps,
            certificates: self.certificates,
        }
    }
}

/// A key as a report quotes it: escaped, and cut when it is long.
fn shown(key: &str) -> String {
    let mut text: String = key.chars().take(MAX_QUOTED).collect();
    if text.len() < key.len() {
        text.push('…');
    }
    format!("{text:?}")
}

/// An error text of serde without the strings it quotes: a type error names the offending value,
/// and the value may be a private key.
fn without_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quoted = false;
    let mut escaped = false;
    for c in text.chars() {
        if quoted {
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    quoted = false;
                    out.push_str("…\"");
                }
                _ => escaped = false,
            }
        } else {
            if c == '"' {
                quoted = true;
            }
            out.push(c);
        }
    }
    out.chars().take(MAX_QUOTED * 2).collect()
}

// ---- podgate-json ---------------------------------------------------------------------------

fn podgate_json(source: &str, prefix: &Prefix, docs: &BTreeMap<&str, &[u8]>, built: &mut Built) {
    let (mut apps, mut certificates) = (0, 0);
    for (key, bytes) in docs {
        let rest = &key[prefix.path.len()..];
        let (directory, name) = rest.split_once('/').unwrap_or((rest, ""));
        if !matches!(directory, "apps" | "certificates") || name.contains('/') {
            built.report(format!(
                "key {}: not `apps/<id>` or `certificates/<name>` under {:?}; ignored",
                shown(key),
                prefix.path
            ));
            continue;
        }
        if !valid_name(name) {
            built.report(format!(
                "key {}: the name must be 1 to {MAX_NAME} letters, digits, `-`, `_` or `.`; ignored",
                shown(key)
            ));
            continue;
        }
        let origin = Origin {
            source: source.into(),
            object: name.into(),
            first_seen: 0,
        };
        let claim = TenantClaim::mapped(&prefix.tenant);
        if directory == "apps" {
            apps += 1;
            if apps > MAX_APPS_PER_PREFIX {
                built.report(format!(
                    "key {}: more than {MAX_APPS_PER_PREFIX} apps under {:?}; ignored",
                    shown(key),
                    prefix.path
                ));
                continue;
            }
            match app_document(name, &prefix.tenant, bytes) {
                Ok(app) => built.apps.push(SourceApp {
                    origin,
                    tenant: claim,
                    app,
                }),
                Err(why) => built.report(format!("key {}: {why}; ignored", shown(key))),
            }
        } else {
            certificates += 1;
            if certificates > MAX_CERTIFICATES_PER_PREFIX {
                built.report(format!(
                    "key {}: more than {MAX_CERTIFICATES_PER_PREFIX} certificates under {:?}; ignored",
                    shown(key),
                    prefix.path
                ));
                continue;
            }
            match certificate_document(bytes) {
                Ok(certificate) => built.certificates.push(SourceCertificate {
                    origin,
                    tenant: claim,
                    certificate,
                }),
                Err(why) => built.report(format!("key {}: {why}; ignored", shown(key))),
            }
        }
    }
}

/// The JSON object in `bytes`.
fn document(bytes: &[u8]) -> Result<Map<String, Value>, String> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "the document is {} bytes; the limit is {MAX_DOCUMENT_BYTES}",
            bytes.len()
        ));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err("the document is empty".to_owned());
    }
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err("the document must be a JSON object".to_owned()),
        Err(err) => Err(format!(
            "the document is not JSON ({})",
            without_quoted(&err.to_string())
        )),
    }
}

fn refuse_tenant(object: &Map<String, Value>) -> Result<(), String> {
    if object.contains_key("tenant") {
        return Err(
            "the document names a tenant; the tenant comes only from the prefix mapping".to_owned(),
        );
    }
    Ok(())
}

fn refuse_unknown(schema: &Value, value: &Value) -> Result<(), String> {
    let mut found = Vec::new();
    walk(schema, schema, value, "", &mut found, 0);
    if found.is_empty() {
        return Ok(());
    }
    let named: Vec<&str> = found
        .iter()
        .take(MAX_NAMED_FIELDS)
        .map(String::as_str)
        .collect();
    let more = found.len().saturating_sub(MAX_NAMED_FIELDS);
    Err(format!(
        "unknown field{} {}{}",
        if found.len() == 1 { "" } else { "s" },
        named.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        }
    ))
}

fn app_document(id: &str, tenant: &str, bytes: &[u8]) -> Result<App, String> {
    let mut object = document(bytes)?;
    refuse_tenant(&object)?;
    match object.get("id") {
        None => {}
        Some(Value::String(own)) if own == id => {}
        Some(_) => return Err("`id` must be the key's name, or absent".to_owned()),
    }
    object.insert("id".to_owned(), Value::String(id.to_owned()));
    object.insert("tenant".to_owned(), Value::String(tenant.to_owned()));
    object.insert(
        "declared_by".to_owned(),
        Value::String(DECLARED_BY.to_owned()),
    );
    let value = Value::Object(object);
    refuse_unknown(&APP_SCHEMA, &value)?;
    serde_json::from_value(value).map_err(|err| without_quoted(&err.to_string()))
}

fn certificate_document(bytes: &[u8]) -> Result<Certificate, String> {
    let object = document(bytes)?;
    refuse_tenant(&object)?;
    let value = Value::Object(object);
    refuse_unknown(&CERTIFICATE_SCHEMA, &value)?;
    serde_json::from_value(value).map_err(|err| without_quoted(&err.to_string()))
}

// ---- unknown fields -------------------------------------------------------------------------

/// The JSON schema of a model type, which says which fields it knows. It comes from the model
/// itself, so a field added there is known here without a second list.
fn schema_of(schema: &schemars::Schema) -> Value {
    serde_json::to_value(schema).unwrap_or(Value::Bool(true))
}

static APP_SCHEMA: LazyLock<Value> = LazyLock::new(|| schema_of(&schemars::schema_for!(App)));

static CERTIFICATE_SCHEMA: LazyLock<Value> =
    LazyLock::new(|| schema_of(&schemars::schema_for!(Certificate)));

/// Follows `$ref`s of the local `$defs` to the schema they name.
fn resolve<'a>(root: &'a Value, mut schema: &'a Value) -> Option<&'a Value> {
    for _ in 0..16 {
        let Some(target) = schema.get("$ref").and_then(Value::as_str) else {
            return Some(schema);
        };
        schema = root.pointer(target.strip_prefix('#')?)?;
    }
    None
}

/// Whether a schema describes an object (or, for `array`, a list).
fn describes(root: &Value, schema: &Value, value: &Value) -> bool {
    let Some(schema) = resolve(root, schema) else {
        return false;
    };
    let wanted = if value.is_array() { "array" } else { "object" };
    match schema.get("type") {
        Some(Value::String(kind)) => kind == wanted,
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == wanted),
        _ => schema.get("properties").is_some() && wanted == "object",
    }
}

/// Collects the paths of the object keys of `value` that `schema` does not describe.
fn walk(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    found: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    let Some(schema) = resolve(root, schema) else {
        return;
    };
    let Some(object) = schema.as_object() else {
        return;
    };
    if let Some(all) = object.get("allOf").and_then(Value::as_array) {
        for part in all {
            walk(root, part, value, path, found, depth + 1);
        }
    }
    for choice in ["anyOf", "oneOf"] {
        let Some(branches) = object.get(choice).and_then(Value::as_array) else {
            continue;
        };
        // The branch that fits best: the one that leaves the fewest keys unexplained.
        let mut best: Option<Vec<String>> = None;
        for branch in branches {
            if !describes(root, branch, value) {
                continue;
            }
            let mut here = Vec::new();
            walk(root, branch, value, path, &mut here, depth + 1);
            if best.as_ref().is_none_or(|best| here.len() < best.len()) {
                best = Some(here);
            }
        }
        found.extend(best.into_iter().flatten());
    }
    match value {
        Value::Object(map) => {
            let properties = object.get("properties").and_then(Value::as_object);
            let extra = object.get("additionalProperties");
            for (key, inner) in map {
                let here = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(known) = properties.and_then(|properties| properties.get(key)) {
                    walk(root, known, inner, &here, found, depth + 1);
                } else {
                    match extra {
                        Some(Value::Bool(true)) => {}
                        Some(extra @ Value::Object(_)) => {
                            walk(root, extra, inner, &here, found, depth + 1);
                        }
                        _ if properties.is_some() => found.push(here),
                        _ => {}
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(items_schema) = object.get("items") {
                for (at, item) in items.iter().enumerate() {
                    walk(
                        root,
                        items_schema,
                        item,
                        &format!("{path}[{at}]"),
                        found,
                        depth + 1,
                    );
                }
            }
        }
        _ => {}
    }
}

// ---- traefik-kv -----------------------------------------------------------------------------

fn traefik_tree(source: &str, prefix: &Prefix, docs: &BTreeMap<&str, &[u8]>, built: &mut Built) {
    if docs.is_empty() {
        return;
    }
    let size: usize = docs
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum();
    if size > MAX_DOCUMENT_BYTES {
        built.report(format!(
            "prefix {:?}: the tree is {size} bytes; the limit is {MAX_DOCUMENT_BYTES}; ignored",
            prefix.path
        ));
        return;
    }
    let mut reports = Vec::new();
    let pairs = flatten(prefix, docs, &mut reports);
    let app = tree_app(&prefix.app, &prefix.tenant, &pairs, &mut reports);
    for line in reports {
        built.report(line);
    }
    if let Some(app) = app {
        built.apps.push(SourceApp {
            origin: Origin {
                source: source.into(),
                object: prefix.app.clone(),
                first_seen: 0,
            },
            tenant: TenantClaim::mapped(&prefix.tenant),
            app,
        });
    }
}

/// The dotted label form of a tree: `traefik.<segments joined by '.'>`, with a list written
/// `<key>/0`, `<key>/1` joined by commas under `<key>`.
fn flatten(
    prefix: &Prefix,
    docs: &BTreeMap<&str, &[u8]>,
    reports: &mut Vec<String>,
) -> Vec<(String, String)> {
    let mut direct: BTreeMap<String, String> = BTreeMap::new();
    let mut lists: BTreeMap<String, BTreeMap<usize, String>> = BTreeMap::new();
    for (key, bytes) in docs {
        let rest = &key[prefix.path.len()..];
        let Ok(value) = std::str::from_utf8(bytes) else {
            reports.push(format!(
                "key {}: the value is not UTF-8; ignored",
                shown(key)
            ));
            continue;
        };
        let segments: Vec<&str> = rest.split('/').collect();
        if segments
            .iter()
            .any(|part| part.is_empty() || part.contains(['.', ' ', '\t']))
        {
            reports.push(format!(
                "key {}: a key segment is empty or holds `.` or a space; ignored",
                shown(key)
            ));
            continue;
        }
        match segments.split_last() {
            Some((last, parent))
                if !parent.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let Ok(index) = last.parse::<usize>() else {
                    reports.push(format!(
                        "key {}: the list index is too large; ignored",
                        shown(key)
                    ));
                    continue;
                };
                lists
                    .entry(format!("traefik.{}", parent.join(".")))
                    .or_default()
                    .insert(index, value.to_owned());
            }
            _ => {
                direct.insert(format!("traefik.{}", segments.join(".")), value.to_owned());
            }
        }
    }
    for (key, items) in lists {
        if direct.contains_key(&key) {
            reports.push(format!(
                "key {}: given both as a value and as a list; the list is ignored",
                shown(&key)
            ));
            continue;
        }
        let joined: Vec<&str> = items.values().map(String::as_str).collect();
        direct.insert(key, joined.join(","));
    }
    direct.into_iter().collect()
}

/// The servers a tree spells out, by service name, and the services that spell out more than
/// the translator can carry.
#[derive(Default)]
struct Servers {
    urls: BTreeMap<String, BTreeMap<usize, String>>,
    bad: BTreeSet<String>,
}

/// `traefik.http.services.<name>.loadbalancer.servers.<n>.<field>`: `(name, n, field)`.
fn server_key(key: &str) -> Option<(&str, usize, &str)> {
    let parts: Vec<&str> = key.split('.').collect();
    let [root, http, services, name, balancer, servers, index, field] = parts.as_slice() else {
        return None;
    };
    (root.eq_ignore_ascii_case("traefik")
        && http.eq_ignore_ascii_case("http")
        && services.eq_ignore_ascii_case("services")
        && balancer.eq_ignore_ascii_case("loadbalancer")
        && servers.eq_ignore_ascii_case("servers"))
    .then(|| index.parse().ok().map(|index| (*name, index, *field)))?
}

/// `scheme://host:port` of a server URL, or why it is not one. The scheme is `http`, `https` or
/// `h2c`, the port is given, and there is no path, query or credential: a server is an address.
fn server_url(text: &str) -> Result<String, String> {
    let uri: http::Uri = text.trim().parse().map_err(|_| "is not a URL".to_owned())?;
    let scheme = uri
        .scheme_str()
        .map(str::to_ascii_lowercase)
        .ok_or("needs a scheme: http, https or h2c")?;
    if !matches!(scheme.as_str(), "http" | "https" | "h2c") {
        return Err("the scheme must be http, https or h2c".to_owned());
    }
    let authority = uri.authority().ok_or("needs a host and a port")?;
    if authority.as_str().contains('@') {
        return Err("must not carry credentials".to_owned());
    }
    if authority.port_u16().is_none_or(|port| port == 0) {
        return Err("needs a port".to_owned());
    }
    if (uri.path() != "/" && !uri.path().is_empty()) || uri.query().is_some() {
        return Err("must be an address, without a path or a query".to_owned());
    }
    Ok(format!("{scheme}://{authority}"))
}

/// The key `traefik.http.services.<name>.loadbalancer.server.scheme`, which marks a service as
/// defined without changing what it translates to.
fn scheme_key(name: &str) -> String {
    format!("traefik.http.services.{name}.loadbalancer.server.scheme")
}

fn tree_app(
    id: &str,
    tenant: &str,
    pairs: &[(String, String)],
    reports: &mut Vec<String>,
) -> Option<App> {
    let mut servers = Servers::default();
    let mut kept: Vec<(&str, &str)> = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        match server_key(key) {
            Some((name, index, "url" | "URL" | "Url")) => match server_url(value) {
                Ok(url) => {
                    servers
                        .urls
                        .entry(name.to_owned())
                        .or_default()
                        .insert(index, url);
                }
                Err(why) => {
                    reports.push(format!("{key}: the server url {why}"));
                    servers.bad.insert(name.to_owned());
                }
            },
            Some((name, _, field)) => {
                reports.push(format!(
                    "{key}: only the url of a server is translated, not {field:?}"
                ));
                servers.bad.insert(name.to_owned());
            }
            None => kept.push((key, value)),
        }
    }
    let mut marks: Vec<(String, &str)> = Vec::new();
    for name in servers.urls.keys() {
        let scheme = scheme_key(name);
        if !kept
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(&scheme))
        {
            marks.push((scheme, "http"));
        }
    }
    let translation = traefik::translate(
        kept.iter()
            .copied()
            .chain(marks.iter().map(|(key, value)| (key.as_str(), *value))),
    );
    for problem in &translation.problems {
        reports.push(problem.to_string());
    }
    if translation.problems.iter().any(|problem| problem.fatal) {
        reports.push("the tree is ignored".to_owned());
        return None;
    }
    if translation.enabled == Some(false) {
        return None;
    }

    let mut services: Vec<Value> = Vec::new();
    let mut usable: BTreeSet<Box<str>> = BTreeSet::new();
    for declared in translation.services {
        let urls = servers.urls.get(&*declared.name);
        let Some(urls) = urls.filter(|_| !servers.bad.contains(&*declared.name)) else {
            reports.push(format!(
                "service {}: has no usable servers; list them as http/services/{}/loadbalancer/servers/<n>/url",
                declared.name, declared.name
            ));
            continue;
        };
        let mut unique: Vec<&String> = Vec::new();
        for url in urls.values() {
            if !unique.contains(&url) {
                unique.push(url);
            }
        }
        let mut config = declared.config.clone();
        let list: Vec<Value> = unique.iter().map(|url| json!({ "url": url })).collect();
        config.insert("servers".into(), Value::Array(list));
        usable.insert(declared.name.clone());
        services.push(declared_value(&Declared {
            name: declared.name.clone(),
            kind: declared.kind.clone(),
            config,
        }));
    }
    let routers: Vec<Router> = translation
        .routers
        .into_iter()
        .filter(|router| {
            let keep = usable.contains(&router.service);
            if !keep {
                reports.push(format!(
                    "router {}: its service {:?} has no usable servers; left out",
                    router.name, router.service
                ));
            }
            keep
        })
        .collect();
    if routers.is_empty() {
        reports.push("the tree declares no router that can be served; no app".to_owned());
        return None;
    }
    let tls = translation.tls.unwrap_or(TlsMode::Acme);
    let value = json!({
        "id": id,
        "tenant": tenant,
        "declared_by": DECLARED_BY,
        "tls": { "mode": match tls {
            TlsMode::Acme => "acme",
            TlsMode::OnDemand => "on_demand",
            TlsMode::Internal => "internal",
        } },
        "routers": routers,
        "middlewares": translation.middlewares,
        "revisions": [{
            "id": "default",
            "state": "serving",
            "weight": 1,
            "services": services,
        }],
    });
    match serde_json::from_value(value) {
        Ok(app) => Some(app),
        Err(err) => {
            reports.push(format!(
                "the translated tree is not a valid app: {}",
                without_quoted(&err.to_string())
            ));
            None
        }
    }
}

fn declared_value(declared: &Declared) -> Value {
    let mut object = Map::new();
    object.insert("name".into(), Value::String(declared.name.to_string()));
    object.insert("type".into(), Value::String(declared.kind.to_string()));
    object.extend(declared.config.clone());
    Value::Object(object)
}
