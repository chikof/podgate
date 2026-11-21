//! Traefik's dynamic configuration file (YAML or TOML), translated to one podgate app.
//!
//! [`convert`] reads the `http`, `tcp`, `udp` and `tls` sections of one file: the routers
//! through the rule grammar of `podgate-rule`, the middleware options through the label
//! translator ([`crate::traefik`]) where it has the kind, and the rest option by option. The app
//! is a JSON object in the shape of `podgate-model` (without `tenant` and `declared_by`, which
//! are the source's to set), next to the certificates read from disk.
//!
//! Translate or reject, never approximate: an option podgate cannot express exactly is a
//! [`Problem`] naming its path in the file (`http.middlewares.m.plugin`), and the object it
//! belongs to is left out together with every object that names it. The converter is also the
//! `convert-traefik` command ([`cli::run`]), a migration linter.
//!
//! The reference is `docs/ref/provider-traefik-file.md`.

mod app;
pub mod cli;
mod files;
mod flat;
mod l4;
mod middleware;
mod names;
mod obj;
mod router;
mod service;
mod tls;
mod transport;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use podgate_model::Certificate;
use serde_json::Value;
use thiserror::Error;

pub use crate::traefik::Problem;

/// The largest Traefik file the converter reads, in bytes.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// How a Traefik file is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Syntax {
    /// YAML, and JSON, which is YAML.
    Yaml,
    /// TOML.
    Toml,
}

impl Syntax {
    /// The syntax of a file by its extension (`yml`, `yaml`, `json` or `toml`).
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        match extension.as_str() {
            "yaml" | "yml" | "json" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            _ => None,
        }
    }

    fn decode(self, text: &str) -> Result<Value, String> {
        match self {
            Self::Yaml => serde_yaml_ng::from_str(text).map_err(|err| err.to_string()),
            Self::Toml => toml::from_str(text).map_err(|err| err.to_string()),
        }
    }
}

/// A Traefik file that cannot be converted at all.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConvertError {
    /// The file cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The file is larger than [`MAX_FILE_BYTES`].
    #[error("{path} is larger than {MAX_FILE_BYTES} bytes")]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The extension names no syntax.
    #[error("{path}: unknown extension; use .yaml, .yml, .json or .toml")]
    Extension {
        /// The file.
        path: PathBuf,
    },
    /// The text is not valid in its syntax.
    #[error("{0}")]
    Decode(String),
    /// The file holds nothing. An editor that truncates a file before it writes it would otherwise
    /// remove every route for the moment between the two.
    #[error("has no content")]
    Empty,
}

/// What a Traefik file came to.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Converted {
    /// The app, in the shape of `podgate_model::App` without `tenant` and `declared_by`.
    pub app: Value,
    /// The certificates of `tls`, read from disk and inlined.
    pub certificates: Vec<Certificate>,
    /// Everything that was left out, each with its path in the file.
    pub problems: Vec<Problem>,
    /// The files the conversion read besides the Traefik file (certificates, keys, CAs, users
    /// files), for a source that must notice when one changes.
    pub files: Vec<PathBuf>,
}

/// Converts the text of a Traefik file. `id` is the id of the app, `dir` the directory relative
/// file paths in the file are read from.
///
/// # Errors
///
/// [`ConvertError::Empty`] when `text` has no content (blank, or only comments), and
/// [`ConvertError::Decode`] when `text` is not valid in `syntax`. A problem with any option is
/// not an error: it is in [`Converted::problems`].
pub fn convert(
    id: &str,
    text: &str,
    syntax: Syntax,
    dir: &Path,
) -> Result<Converted, ConvertError> {
    if text.trim().is_empty() {
        return Err(ConvertError::Empty);
    }
    let root = syntax.decode(text).map_err(ConvertError::Decode)?;
    if root.is_null() {
        return Err(ConvertError::Empty);
    }
    Ok(app::convert(id, &root, dir))
}

/// Reads and converts one Traefik file. The id of the app is the file's stem.
///
/// # Errors
///
/// [`ConvertError`] when the file cannot be read, is larger than [`MAX_FILE_BYTES`], has no
/// known extension or is not valid.
pub fn convert_file(path: &Path) -> Result<Converted, ConvertError> {
    let syntax = Syntax::of(path).ok_or_else(|| ConvertError::Extension {
        path: path.to_owned(),
    })?;
    let mut text = String::new();
    let read = File::open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_string(&mut text))
        .map_err(|source| ConvertError::Read {
            path: path.to_owned(),
            source,
        })?;
    if read as u64 > MAX_FILE_BYTES {
        return Err(ConvertError::TooLarge {
            path: path.to_owned(),
        });
    }
    let id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    convert(id, &text, syntax, dir)
}
