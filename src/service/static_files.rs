//! The `static` service: files from a directory the operator declared, with an index file,
//! `try_files` fallbacks, conditional and range requests and precompressed variants.
//!
//! ```json
//! { "name": "site", "type": "static", "root": "site",
//!   "index": ["index.html"], "try_files": ["{path}", "/index.html"],
//!   "status_pages": { "404": "/404.html" },
//!   "cache_control": { "default": "no-cache", "by_extension": { "js": "public, max-age=31536000, immutable" } },
//!   "precompressed": ["br", "gzip"], "max_file_bytes": 1073741824 }
//! ```
//!
//! `root` is a label, never a path. The operator declares the directories of each tenant in the
//! file `STATIC_ROOTS_FILE` (see [`roots`]); a service can name only a label of its own tenant
//! (`unknown_static_root` otherwise), and an unknown field, a path where a label belongs or a
//! `..` in a template is refused at compile time. At request time every file is opened relative
//! to the root's directory handle, so nothing a request or a snapshot says can reach outside it.
//!
//! A static service has no server: [`NO_SERVER`] stands in for the address a balancer would
//! pick, no backend admission or wake applies, and the proxy answers from the file system
//! through [`serve`]. The runtime shape of the answer is in `docs/ref/svc-static.md`.

mod mime;
mod precompressed;
mod range;
mod reader;
mod roots;
mod serve;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use http::HeaderValue;
use serde::Deserialize;

use super::state::{Lease, ServerState};
use crate::compile::Invalid;
use podgate_model::Declared;
use precompressed::Encoding;
use roots::RelPath;

pub use reader::Reads;
pub use roots::{LoadError, Root, StaticRoots, TenantRoots};
pub(crate) use serve::serve;

/// What a static service reports as the address of its server: it has none.
pub const NO_SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// The largest file a service serves unless its `max_file_bytes` says otherwise: 4 GiB.
const DEFAULT_MAX_FILE_BYTES: u64 = 4 << 30;

/// The configuration of a `static` service.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    root: String,
    #[serde(default)]
    index: Option<Vec<String>>,
    #[serde(default)]
    try_files: Option<Vec<String>>,
    #[serde(default)]
    status_pages: Option<HashMap<String, String>>,
    #[serde(default)]
    cache_control: Option<CacheControl>,
    #[serde(default)]
    precompressed: Option<Vec<String>>,
    #[serde(default)]
    max_file_bytes: Option<u64>,
}

/// `Cache-Control` values by file extension.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CacheControl {
    #[serde(default)]
    default: Option<String>,
    #[serde(default)]
    by_extension: HashMap<String, String>,
}

/// The `try_files` list: path templates, then optionally a status to answer when none matched.
#[derive(Debug)]
struct TryFiles {
    templates: Box<[Box<str>]>,
    status: Option<u16>,
}

/// A compiled `static` service.
#[derive(Debug)]
pub struct StaticSite {
    root: Arc<Root>,
    label: Box<str>,
    index: Box<[Box<str>]>,
    try_files: Option<TryFiles>,
    status_pages: HashMap<u16, RelPath>,
    cache_default: Option<Box<str>>,
    cache_by_extension: HashMap<Box<str>, Box<str>>,
    precompressed: Box<[Encoding]>,
    max_file_bytes: u64,
    state: Arc<ServerState>,
}

fn invalid(message: impl Into<String>) -> Invalid {
    Invalid::new("invalid_service", format!("static: {}", message.into()))
}

/// A header value, or why it is not one.
fn header_value(field: &str, value: &str) -> Result<Box<str>, Invalid> {
    HeaderValue::from_str(value)
        .map(|_| Box::from(value))
        .map_err(|_| invalid(format!("{field} is not a valid header value")))
}

/// A status code a `try_files` fallback or a status page may name.
fn error_status(text: &str) -> Option<u16> {
    let code: u16 = text.parse().ok().filter(|_| text.len() == 3)?;
    (400..=599).contains(&code).then_some(code)
}

/// A name an index entry may have: a plain file name.
fn plain_name(name: &str) -> bool {
    !name.is_empty() && !matches!(name, "." | "..") && !name.contains(['/', '\\', '\0'])
}

/// A template is a path (`/index.html`) or starts with `{path}`, and has no other placeholder.
fn template_is_valid(template: &str) -> bool {
    if !(template.starts_with('/') || template.starts_with("{path}")) {
        return false;
    }
    let rest = template.replace("{path}", "");
    !rest.contains(['{', '}', '\\', '\0'])
}

impl StaticSite {
    /// Compiles one declared service against the roots of its app's tenant.
    pub(super) fn compile(
        declared: &Declared,
        roots: Option<&TenantRoots>,
    ) -> Result<Self, Invalid> {
        let config: Config =
            serde_json::from_value(serde_json::Value::Object(declared.config.clone()))
                .map_err(|err| invalid(err.to_string()))?;
        let root = roots
            .and_then(|roots| roots.get(config.root.as_str()))
            .ok_or_else(|| {
                Invalid::new(
                    "unknown_static_root",
                    format!(
                        "static root {:?} is not declared for this tenant (the operator declares roots in STATIC_ROOTS_FILE)",
                        config.root
                    ),
                )
                .with("root", config.root.as_str())
            })?;
        let index: Box<[Box<str>]> = match config.index {
            None => Box::new([Box::from("index.html")]),
            Some(names) => {
                if let Some(bad) = names.iter().find(|name| !plain_name(name)) {
                    return Err(invalid(format!(
                        "index entry {bad:?} is not a plain file name"
                    )));
                }
                names.into_iter().map(String::into_boxed_str).collect()
            }
        };
        let try_files = config
            .try_files
            .map(|mut entries| {
                if entries.is_empty() {
                    return Err(invalid("try_files is empty"));
                }
                let status = match entries.last().map(String::as_str).and_then(error_status) {
                    Some(code) => {
                        entries.pop();
                        Some(code)
                    }
                    None => None,
                };
                if let Some(bad) = entries.iter().find(|entry| !template_is_valid(entry)) {
                    return Err(invalid(format!(
                        "try_files entry {bad:?} must start with / or {{path}} and use no placeholder but {{path}}"
                    )));
                }
                if entries.is_empty() {
                    return Err(invalid("try_files names a status and no file to try"));
                }
                Ok(TryFiles {
                    templates: entries.into_iter().map(String::into_boxed_str).collect(),
                    status,
                })
            })
            .transpose()?;
        let mut status_pages = HashMap::new();
        for (code, path) in config.status_pages.unwrap_or_default() {
            let status = error_status(&code).ok_or_else(|| {
                invalid(format!(
                    "status_pages key {code:?} is not a status 400..=599"
                ))
            })?;
            let page = RelPath::parse(&path).map_err(|why| {
                invalid(format!(
                    "status_pages {code}: {path:?} is not served ({why})"
                ))
            })?;
            status_pages.insert(status, page);
        }
        let cache = config.cache_control.unwrap_or_default();
        let cache_default = cache
            .default
            .as_deref()
            .map(|value| header_value("cache_control.default", value))
            .transpose()?;
        let mut cache_by_extension = HashMap::new();
        for (extension, value) in &cache.by_extension {
            let key = extension.trim_start_matches('.').to_ascii_lowercase();
            if key.is_empty() || key.contains(['/', '.']) {
                return Err(invalid(format!(
                    "cache_control.by_extension key {extension:?} is not an extension"
                )));
            }
            cache_by_extension.insert(
                key.into_boxed_str(),
                header_value("cache_control.by_extension", value)?,
            );
        }
        let mut precompressed = Vec::new();
        for name in config.precompressed.unwrap_or_default() {
            let encoding = Encoding::parse(&name)
                .ok_or_else(|| invalid(format!("precompressed {name:?} is not br or gzip")))?;
            if !precompressed.contains(&encoding) {
                precompressed.push(encoding);
            }
        }
        let max_file_bytes = config.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);
        if max_file_bytes == 0 {
            return Err(invalid("max_file_bytes is 0"));
        }
        Ok(Self {
            root: Arc::clone(root),
            label: config.root.into_boxed_str(),
            index,
            try_files,
            status_pages,
            cache_default,
            cache_by_extension,
            precompressed: precompressed.into_boxed_slice(),
            max_file_bytes,
            state: Arc::default(),
        })
    }

    /// The root label this service names.
    #[must_use]
    pub fn root_label(&self) -> &str {
        &self.label
    }

    /// Refuses the service when `tenant`'s whole `max_buffer_bytes` is below what one response
    /// reserves: such a tenant could never serve a file, and the refusal at request time is a
    /// capacity answer that auto-revert does not count.
    ///
    /// # Errors
    ///
    /// `invalid_service` naming the tenant, the bytes one response needs and the budget.
    pub(crate) fn check_budget(&self, tenant: &str, max_buffer_bytes: u64) -> Result<(), Invalid> {
        if max_buffer_bytes >= reader::RESERVATION {
            return Ok(());
        }
        Err(invalid(format!(
            "tenant {tenant} has max_buffer_bytes {max_buffer_bytes}, below the {} bytes one static response reserves",
            reader::RESERVATION
        ))
        .with("tenant", tenant)
        .with("needed_bytes", reader::RESERVATION)
        .with("max_buffer_bytes", max_buffer_bytes))
    }

    /// Counts a request on the service, for the revision's in-flight bookkeeping.
    pub(super) fn lease(&self) -> Lease {
        Lease::take(&self.state, None)
    }

    /// The `Cache-Control` of a file with `extension`: its entry, else the default.
    fn cache_control(&self, extension: Option<&str>) -> Option<&str> {
        extension
            .and_then(|extension| self.cache_by_extension.get(extension))
            .or(self.cache_default.as_ref())
            .map(AsRef::as_ref)
    }
}

#[cfg(test)]
mod test {
    use serde_json::{Value, json};

    use super::*;

    fn roots() -> (TenantRoots, std::path::PathBuf) {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "podgate-site-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create the root");
        let root = Root::open(&dir).expect("open the root");
        (
            TenantRoots::from([(Box::from("site"), Arc::new(root))]),
            dir,
        )
    }

    fn compile(config: Value) -> Result<StaticSite, Invalid> {
        let (roots, dir) = roots();
        let Value::Object(fields) = config else {
            panic!("the test passes an object");
        };
        let declared = Declared {
            name: "s".into(),
            kind: "static".into(),
            config: fields,
        };
        let result = StaticSite::compile(&declared, Some(&roots));
        drop(std::fs::remove_dir_all(dir));
        result
    }

    fn code(config: Value) -> &'static str {
        compile(config).expect_err("refused").code
    }

    #[test]
    fn defaults_and_a_full_configuration_compile() {
        let site = compile(json!({ "root": "site" })).expect("compiles");
        assert_eq!(&*site.index, [Box::from("index.html")]);
        assert_eq!(site.max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        let site = compile(json!({
            "root": "site",
            "index": ["index.html", "index.htm"],
            "try_files": ["{path}", "{path}/index.html", "/index.html", "404"],
            "status_pages": { "404": "/404.html" },
            "cache_control": { "default": "no-cache", "by_extension": { ".JS": "immutable" } },
            "precompressed": ["br", "gzip"],
            "max_file_bytes": 10,
        }))
        .expect("compiles");
        assert_eq!(site.try_files.as_ref().and_then(|t| t.status), Some(404));
        assert_eq!(site.try_files.as_ref().map(|t| t.templates.len()), Some(3));
        assert_eq!(site.cache_control(Some("js")), Some("immutable"));
        assert_eq!(site.cache_control(Some("css")), Some("no-cache"));
        assert_eq!(site.precompressed.len(), 2);
    }

    #[test]
    fn an_undeclared_root_is_refused() {
        assert_eq!(code(json!({ "root": "other" })), "unknown_static_root");
        let declared: Declared =
            serde_json::from_value(json!({ "name": "s", "type": "static", "root": "site" }))
                .expect("declared");
        let err = StaticSite::compile(&declared, None).expect_err("the tenant has no roots");
        assert_eq!(err.code, "unknown_static_root");
    }

    #[test]
    fn a_path_is_never_a_root() {
        // As a root name, a path names nothing the operator declared.
        for path in ["/etc", "/srv/static/t1/site", "../site", "site/.."] {
            assert_eq!(
                code(json!({ "root": path })),
                "unknown_static_root",
                "{path}"
            );
        }
        // As a field, it is not part of the service.
        for field in ["path", "directory", "dir", "root_path"] {
            assert_eq!(
                code(json!({ "root": "site", field: "/etc" })),
                "invalid_service",
                "{field}"
            );
        }
    }

    #[test]
    fn bad_fields_are_invalid_service() {
        for config in [
            json!({ "root": "site", "index": ["../x"] }),
            json!({ "root": "site", "index": ["a/b"] }),
            json!({ "root": "site", "index": [""] }),
            json!({ "root": "site", "try_files": [] }),
            json!({ "root": "site", "try_files": ["404"] }),
            json!({ "root": "site", "try_files": ["index.html"] }),
            json!({ "root": "site", "try_files": ["{other}"] }),
            json!({ "root": "site", "try_files": ["/a{"] }),
            json!({ "root": "site", "status_pages": { "200": "/x.html" } }),
            json!({ "root": "site", "status_pages": { "404": "x.html" } }),
            json!({ "root": "site", "status_pages": { "404": "/../x.html" } }),
            json!({ "root": "site", "status_pages": { "404": "/.env" } }),
            json!({ "root": "site", "cache_control": { "default": "a\nb" } }),
            json!({ "root": "site", "cache_control": { "by_extension": { "": "x" } } }),
            json!({ "root": "site", "cache_control": { "nope": "x" } }),
            json!({ "root": "site", "precompressed": ["zstd"] }),
            json!({ "root": "site", "max_file_bytes": 0 }),
            // There is no server to pin a client to, and nothing to dial or probe.
            json!({ "root": "site", "sticky": { "cookie": {} } }),
            json!({ "root": "site", "health_check": { "path": "/" } }),
            json!({ "root": "site", "servers": [{ "url": "http://127.0.0.1:1" }] }),
            json!({ "index": ["index.html"] }),
        ] {
            assert_eq!(code(config.clone()), "invalid_service", "{config}");
        }
    }

    #[test]
    fn templates_are_checked() {
        for good in [
            "/index.html",
            "{path}",
            "{path}/index.html",
            "{path}.html",
            "/a/{path}",
        ] {
            assert!(template_is_valid(good), "{good}");
        }
        assert!(!template_is_valid("{path"));
        assert!(!template_is_valid("index.html"));
        assert!(!template_is_valid("{path}\\.."));
    }
}
