//! The exporter's file.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{ConfigError, RawServe, ServeSettings, parse, read_text};

/// Largest `admin_slots`: of the daemon's 8 overview slots the exporter may take at most half.
const MAX_SLOTS: u64 = 4;
const DEFAULT_SLOTS: u64 = 2;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    read_socket: PathBuf,
    admin_slots: Option<u64>,
    serve: RawServe,
}

/// The exporter's configuration.
#[derive(Debug, Clone)]
pub struct ExportFile {
    /// The daemon's read socket (`ADMIN_READ_SOCKET`).
    pub read_socket: PathBuf,
    /// Requests to the read socket at once.
    pub admin_slots: usize,
    /// Where the hubs connect.
    pub serve: ServeSettings,
}

impl ExportFile {
    /// Reads and checks the file at `path`, including its certificates and keys.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the field that is wrong.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_text(&read_text(path)?)
    }

    /// Checks `text` as the file's content.
    ///
    /// # Errors
    ///
    /// As [`ExportFile::load`].
    pub fn from_text(text: &str) -> Result<Self, ConfigError> {
        let raw: Raw = parse(text)?;
        let slots = raw.admin_slots.unwrap_or(DEFAULT_SLOTS);
        if !(1..=MAX_SLOTS).contains(&slots) {
            return Err(ConfigError::invalid(
                "admin_slots",
                format!("must be 1 to {MAX_SLOTS}, got {slots}"),
            ));
        }
        if raw.read_socket.as_os_str().is_empty() {
            return Err(ConfigError::invalid("read_socket", "is empty"));
        }
        Ok(Self {
            read_socket: raw.read_socket,
            admin_slots: usize::try_from(slots).unwrap_or(1),
            serve: ServeSettings::from_raw("serve", &raw.serve)?,
        })
    }
}
