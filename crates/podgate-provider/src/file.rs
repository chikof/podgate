//! The file source: apps declared in YAML, TOML or JSON files, picked up when the files change.
//!
//! ```toml
//! [[source]]
//! kind = "file"
//! name = "files"
//! path = "/etc/podgate/apps.d"   # a file, or a directory of *.yaml, *.yml, *.toml and *.json
//! poll_ms = 1000                 # how often the files are looked at
//! tenant = "acme"                # the tenant the operator maps this source to
//! ```
//!
//! A file is a partial snapshot, `{apps: [...], certificates: [...]}`, in the shape of the
//! `podgate-model` types. The tenant of an app is the one in the source's configuration; an app
//! that names a tenant of its own is a label claim that only tenants listing the source in
//! `label_sources` honour (see [`crate::trust`]). A `tenants` key is ignored with a warning: a
//! file cannot invent a tenant or a budget.
//!
//! Changes are found by polling, so the source needs no platform API and behaves the same on
//! bind mounts and network filesystems. A file counts as changed when its identity (device and
//! inode), size, modification time or change time moved, and as different when its content hash
//! did, which covers an in-place write and an atomic rename-replace alike. A file that does not
//! parse keeps its last good content and is reported; the other files carry on.
//!
//! The reference is `docs/ref/provider-file.md`.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podgate_model::{App, Certificate};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use crate::config::SourceConfig;
use crate::source::{
    Origin, Source, SourceApp, SourceCertificate, State, TenantClaim, Update, UpdateBody,
};

/// The largest file the source reads, in bytes. A larger file is reported like a broken one.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// The most files the source reads from a directory. More is an outage: dropping some files
/// would delete their apps.
pub const MAX_FILES: usize = 256;

/// The shortest `poll_ms`.
pub const MIN_POLL_MS: u64 = 10;

const DEFAULT_POLL_MS: u64 = 1000;

/// A file modified less than this many seconds ago is read again on the next poll even when its
/// stamp did not move: a second write inside one timestamp tick would leave the stamp alone.
const RACY_SECS: i64 = 3;

const OWN_TENANT: &str = "default";

/// A `[[source]]` entry of kind `file` that cannot be used.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
#[error("source {name}: {reason}")]
pub struct FileConfigError {
    /// The source's name.
    pub name: Box<str>,
    /// What is wrong, naming the key.
    pub reason: Box<str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    path: PathBuf,
    poll_ms: Option<u64>,
    tenant: Option<String>,
}

/// The file source.
#[derive(Debug)]
pub struct FileSource {
    name: Box<str>,
    path: PathBuf,
    poll: Duration,
    tenant: Box<str>,
}

impl FileSource {
    /// A file source from its `[[source]]` entry.
    ///
    /// # Errors
    ///
    /// [`FileConfigError`] when a key is unknown or has the wrong type, `path` is empty, or
    /// `poll_ms` is below [`MIN_POLL_MS`]. An unknown key is an error so a misspelt `tenant`
    /// cannot move the source's apps to the default tenant.
    pub fn from_config(config: &SourceConfig) -> Result<Self, FileConfigError> {
        let invalid = |reason: String| FileConfigError {
            name: config.name.clone(),
            reason: reason.into(),
        };
        let settings = Settings::deserialize(toml::Value::Table(config.settings.clone()))
            .map_err(|err| invalid(err.to_string()))?;
        if settings.path.as_os_str().is_empty() {
            return Err(invalid("path: is empty".to_owned()));
        }
        let poll_ms = settings.poll_ms.unwrap_or(DEFAULT_POLL_MS);
        if poll_ms < MIN_POLL_MS {
            return Err(invalid(format!(
                "poll_ms: must be at least {MIN_POLL_MS}, got {poll_ms}"
            )));
        }
        let tenant = settings.tenant.unwrap_or_else(|| OWN_TENANT.to_owned());
        if tenant.is_empty() {
            return Err(invalid("tenant: is empty".to_owned()));
        }
        Ok(Self {
            name: config.name.clone(),
            path: settings.path,
            poll: Duration::from_millis(poll_ms),
            tenant: tenant.into(),
        })
    }
}

impl Source for FileSource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn run(self, updates: Sender<Update>) {
        let mut tick = tokio::time::interval(self.poll);
        // After a stall one poll is enough; a burst of catch-up polls would only re-read files.
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let name = self.name.clone();
        let mut scanner = Scanner::new(self);
        loop {
            tick.tick().await;
            // Reading files blocks, so it stays off the async threads.
            let polled = tokio::task::spawn_blocking(move || {
                let found = scanner.poll(unix_now());
                (scanner, found)
            })
            .await;
            let Ok((back, found)) = polled else {
                // A panic in the scanner: nothing is left to poll with. The engine keeps the
                // last state in force and reports the outage.
                let _ = updates
                    .send(Update::outage(
                        &name,
                        "the file source stopped after an internal error",
                    ))
                    .await;
                return;
            };
            scanner = back;
            for update in found {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Yaml,
    Toml,
    Json,
}

impl Format {
    fn of(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?.to_ascii_lowercase();
        match extension.as_str() {
            "yaml" | "yml" => Some(Self::Yaml),
            "toml" => Some(Self::Toml),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Every format decodes into a JSON value, so the three share one path to the model types and
    /// the same app means the same thing in each.
    fn decode(self, text: &str) -> Result<Value, String> {
        match self {
            Self::Yaml => serde_yaml_ng::from_str(text).map_err(|err| err.to_string()),
            Self::Toml => toml::from_str(text).map_err(|err| err.to_string()),
            Self::Json => serde_json::from_str(text).map_err(|err| err.to_string()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(default)]
    tenants: Option<Value>,
    #[serde(default)]
    apps: Vec<Value>,
    #[serde(default)]
    certificates: Vec<Value>,
}

#[derive(Debug, Clone)]
struct ParsedApp {
    /// The tenant the app names for itself, when it differs from the source's mapping.
    label: Option<Box<str>>,
    app: App,
}

#[derive(Debug, Clone, Default)]
struct Content {
    apps: Vec<ParsedApp>,
    certificates: Vec<Certificate>,
}

/// Reads one file's content. Errors say what is wrong and where, without the file's path (the
/// caller adds it).
fn parse(path: &Path, bytes: &[u8], mapped: &str) -> Result<Content, String> {
    let format =
        Format::of(path).ok_or("unknown extension; use .yaml, .yml, .toml or .json".to_owned())?;
    let text = std::str::from_utf8(bytes).map_err(|err| format!("not valid UTF-8: {err}"))?;
    // An editor that truncates before it writes would otherwise delete every app of the file for
    // the moment between the two. A file with no apps says `apps: []`.
    if text.trim().is_empty() {
        return Err("is empty; write `apps: []` to declare no apps".to_owned());
    }
    let value = format.decode(text)?;
    if value.is_null() {
        return Err("has no content; write `apps: []` to declare no apps".to_owned());
    }
    let envelope: Envelope = serde_json::from_value(value).map_err(|err| err.to_string())?;
    if envelope.tenants.is_some() {
        warn!(
            file = %path.display(),
            "ignoring the tenants of the file: tenants come from the provider's configuration only"
        );
    }
    let mut content = Content::default();
    for (index, mut raw) in envelope.apps.into_iter().enumerate() {
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .map_or_else(String::new, |id| format!(" ({id})"));
        let place = |err: &dyn std::fmt::Display| format!("apps[{index}]{id}: {err}");
        let object = raw.as_object_mut().ok_or_else(|| place(&"must be a map"))?;
        // The model requires both fields; neither is the file's to decide. The core overwrites
        // them (the tenant comes from the claim, `declared_by` from the origin).
        let label = match object.remove("tenant") {
            None => None,
            Some(Value::String(tenant)) => Some(tenant).filter(|tenant| tenant != mapped),
            Some(_) => return Err(place(&"tenant: must be text")),
        };
        object.insert("tenant".to_owned(), Value::String(mapped.to_owned()));
        object.insert("declared_by".to_owned(), Value::String("file".to_owned()));
        let app: App = serde_json::from_value(raw).map_err(|err| place(&err))?;
        content.apps.push(ParsedApp {
            label: label.map(Into::into),
            app,
        });
    }
    for (index, raw) in envelope.certificates.into_iter().enumerate() {
        let certificate: Certificate =
            serde_json::from_value(raw).map_err(|err| format!("certificates[{index}]: {err}"))?;
        content.certificates.push(certificate);
    }
    Ok(content)
}

/// What identifies a version of a file without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn of(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn hash_of(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// What the source knows about one file.
#[derive(Debug, Default)]
struct Tracked {
    /// The stamp of the version last read.
    stamp: Option<Stamp>,
    /// Whether `stamp` alone proves nothing changed: false for a file modified a moment ago.
    settled: bool,
    /// The hash of the last content that was parsed (good or not).
    parsed: Option<u64>,
    /// The last content that parsed, with its hash.
    good: Option<(u64, Content)>,
    /// Why the file's current content is not in use.
    error: Option<String>,
}

impl Tracked {
    fn refresh(&mut self, path: &Path, mapped: &str, now: i64) {
        let meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(err) => return self.unreadable(&format!("cannot stat: {err}")),
        };
        let stamp = Stamp::of(&meta);
        if self.settled && self.stamp == Some(stamp) {
            return;
        }
        if stamp.size > MAX_FILE_BYTES {
            self.unreadable(&format!(
                "is {} bytes; the limit is {MAX_FILE_BYTES}",
                stamp.size
            ));
            self.stamp = Some(stamp);
            self.settled = true;
            return;
        }
        let bytes = match read_bounded(path) {
            Ok(bytes) => bytes,
            Err(err) => return self.unreadable(&format!("cannot read: {err}")),
        };
        // A write that overlapped the read can leave half a file in `bytes`; look again on the
        // next poll rather than parse it.
        if fs::metadata(path).map(|meta| Stamp::of(&meta)).ok() != Some(stamp) {
            self.stamp = None;
            return;
        }
        self.stamp = Some(stamp);
        self.settled = now.saturating_sub(stamp.modified.0) >= RACY_SECS;
        let hash = hash_of(&bytes);
        if self.parsed == Some(hash) {
            return;
        }
        self.parsed = Some(hash);
        match parse(path, &bytes, mapped) {
            Ok(content) => {
                self.good = Some((hash, content));
                self.error = None;
            }
            Err(err) => self.error = Some(err),
        }
    }

    /// The file cannot be read now. Its last good content stays; the next poll tries again.
    fn unreadable(&mut self, why: &str) {
        self.stamp = None;
        self.settled = false;
        self.parsed = None;
        self.error = Some(why.to_owned());
    }
}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "grew past the limit of {MAX_FILE_BYTES} bytes while reading"
        )));
    }
    Ok(bytes)
}

/// What was last told to the core.
#[derive(Debug, PartialEq, Eq)]
enum Sent {
    Unavailable(Box<str>),
    Available {
        content: Vec<(PathBuf, u64)>,
        errors: Vec<Box<str>>,
    },
}

struct Scanner {
    name: Box<str>,
    path: PathBuf,
    tenant: Box<str>,
    files: BTreeMap<PathBuf, Tracked>,
    /// When each object was first seen, so a conflict keeps the older object across edits.
    first_seen: BTreeMap<Box<str>, u64>,
    /// Whether every file has parsed once. Until then no state is sent: the files that failed
    /// have no last good content, and a state without their apps would delete them.
    ready: bool,
    sent: Option<Sent>,
}

impl Scanner {
    fn new(source: FileSource) -> Self {
        Self {
            name: source.name,
            path: source.path,
            tenant: source.tenant,
            files: BTreeMap::new(),
            first_seen: BTreeMap::new(),
            ready: false,
            sent: None,
        }
    }

    /// The files to read now.
    fn list(&self) -> Result<Vec<PathBuf>, String> {
        let unreadable =
            |err: std::io::Error| format!("cannot read {}: {err}", self.path.display());
        if fs::metadata(&self.path).map_err(unreadable)?.is_file() {
            return Ok(vec![self.path.clone()]);
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(&self.path).map_err(unreadable)? {
            let path = entry.map_err(unreadable)?.path();
            let hidden = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_none_or(|name| name.starts_with('.'));
            if hidden || Format::of(&path).is_none() || !path.is_file() {
                debug!(path = %path.display(), "not a podgate file; ignored");
                continue;
            }
            files.push(path);
            if files.len() > MAX_FILES {
                return Err(format!(
                    "{} holds more than {MAX_FILES} files; the apps of the extra ones would be lost",
                    self.path.display()
                ));
            }
        }
        files.sort();
        Ok(files)
    }

    /// Looks at the files once and returns what the core must be told, if anything.
    fn poll(&mut self, now: i64) -> Vec<Update> {
        let listed = match self.list() {
            Ok(listed) => listed,
            Err(why) => return self.unavailable(why.into()),
        };
        self.files.retain(|path, _| listed.contains(path));
        for path in listed {
            self.files
                .entry(path.clone())
                .or_default()
                .refresh(&path, &self.tenant, now);
        }
        let errors: Vec<Box<str>> = self
            .files
            .iter()
            .filter_map(|(path, tracked)| {
                tracked
                    .error
                    .as_ref()
                    .map(|err| format!("{}: {err}", path.display()).into())
            })
            .collect();
        if !self.ready {
            if !errors.is_empty() {
                let why = format!(
                    "{}; no state is sent until every file has parsed once",
                    errors.join("; ")
                );
                return self.unavailable(why.into());
            }
            self.ready = true;
        }
        let content: Vec<(PathBuf, u64)> = self
            .files
            .iter()
            .filter_map(|(path, tracked)| {
                tracked.good.as_ref().map(|(hash, _)| (path.clone(), *hash))
            })
            .collect();
        let observed = Sent::Available { content, errors };
        if self.sent.as_ref() == Some(&observed) {
            return Vec::new();
        }
        let Sent::Available { errors, .. } = &observed else {
            return Vec::new();
        };
        let mut updates = vec![self.state(now)];
        if !errors.is_empty() {
            let why = format!(
                "{}; their last good content stays in force",
                errors.join("; ")
            );
            updates.push(Update::outage(&self.name, &why));
        }
        self.sent = Some(observed);
        updates
    }

    fn unavailable(&mut self, why: Box<str>) -> Vec<Update> {
        let observed = Sent::Unavailable(why);
        if self.sent.as_ref() == Some(&observed) {
            return Vec::new();
        }
        let Sent::Unavailable(why) = &observed else {
            return Vec::new();
        };
        let update = Update::outage(&self.name, why);
        self.sent = Some(observed);
        vec![update]
    }

    /// The state of the last good content of every file.
    fn state(&mut self, now: i64) -> Update {
        let stamp = u64::try_from(now).unwrap_or(0);
        let mut apps = Vec::new();
        let mut certificates = Vec::new();
        let mut seen = BTreeMap::new();
        for (path, tracked) in &self.files {
            let Some((_, content)) = &tracked.good else {
                continue;
            };
            for parsed in &content.apps {
                let object: Box<str> = format!("{}#{}", path.display(), parsed.app.id).into();
                let first_seen = *self.first_seen.get(&object).unwrap_or(&stamp);
                seen.insert(object.clone(), first_seen);
                apps.push(SourceApp {
                    origin: Origin {
                        source: self.name.clone(),
                        object,
                        first_seen,
                    },
                    tenant: TenantClaim {
                        mapped: Some(self.tenant.clone()),
                        label: parsed.label.clone(),
                    },
                    app: parsed.app.clone(),
                });
            }
            for (index, certificate) in content.certificates.iter().enumerate() {
                let object: Box<str> = format!("{}#certificate-{index}", path.display()).into();
                let first_seen = *self.first_seen.get(&object).unwrap_or(&stamp);
                seen.insert(object.clone(), first_seen);
                certificates.push(SourceCertificate {
                    origin: Origin {
                        source: self.name.clone(),
                        object,
                        first_seen,
                    },
                    tenant: TenantClaim::mapped(&self.tenant),
                    certificate: certificate.clone(),
                });
            }
        }
        self.first_seen = seen;
        Update {
            source: self.name.clone(),
            body: UpdateBody::State(State { apps, certificates }),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn source(dir: &Path) -> Scanner {
        Scanner::new(FileSource {
            name: "files".into(),
            path: dir.to_owned(),
            poll: Duration::from_millis(10),
            tenant: "default".into(),
        })
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("pgp-file-unit-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create the test directory");
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const APP: &str = r#"{"apps": [{"id": "a", "tls": {"mode": "acme"},
        "routers": [{"name": "main", "match": {"host": ["a.test"]}, "service": "svc"}],
        "services": [{"name": "svc", "type": "loadbalancer", "servers": [{"url": "http://10.0.0.1:80"}]}],
        "revisions": [{"id": "r1", "state": "serving", "weight": 1}]}]}"#;

    fn outage(updates: &[Update]) -> Option<&str> {
        updates.iter().find_map(|update| match &update.body {
            UpdateBody::Outage(why) => Some(&**why),
            UpdateBody::State(_) => None,
        })
    }

    fn apps(updates: &[Update]) -> Option<usize> {
        updates.iter().find_map(|update| match &update.body {
            UpdateBody::State(state) => Some(state.apps.len()),
            UpdateBody::Outage(_) => None,
        })
    }

    #[test]
    fn oversized_file_is_reported_and_keeps_nothing() {
        let dir = Dir::new("oversized");
        let huge = format!(
            "{{\"apps\": [], \"pad\": \"{}\"}}",
            "x".repeat(2 * 1024 * 1024)
        );
        fs::write(dir.0.join("big.json"), huge).expect("write");
        let mut scanner = source(&dir.0);
        let updates = scanner.poll(unix_now());
        assert!(
            outage(&updates).is_some_and(|why| why.contains("the limit is 1048576")),
            "{updates:?}"
        );
        assert_eq!(apps(&updates), None);
    }

    #[test]
    fn too_many_files_is_an_outage() {
        let dir = Dir::new("count");
        for index in 0..=MAX_FILES {
            fs::write(dir.0.join(format!("f{index}.json")), "{\"apps\": []}").expect("write");
        }
        let updates = source(&dir.0).poll(unix_now());
        assert!(
            outage(&updates).is_some_and(|why| why.contains("more than 256 files")),
            "{updates:?}"
        );
    }

    #[test]
    fn empty_file_is_an_error_not_no_apps() {
        let dir = Dir::new("empty");
        fs::write(dir.0.join("a.json"), APP).expect("write");
        let mut scanner = source(&dir.0);
        assert_eq!(apps(&scanner.poll(unix_now())), Some(1));
        fs::write(dir.0.join("a.json"), "  \n").expect("truncate");
        let updates = scanner.poll(unix_now());
        assert_eq!(apps(&updates), Some(1), "the last good content stays");
        assert!(outage(&updates).is_some_and(|why| why.contains("is empty")));
    }

    #[test]
    fn unchanged_files_send_nothing() {
        let dir = Dir::new("quiet");
        fs::write(dir.0.join("a.json"), APP).expect("write");
        let mut scanner = source(&dir.0);
        assert_eq!(apps(&scanner.poll(unix_now())), Some(1));
        assert!(scanner.poll(unix_now()).is_empty());
        assert!(scanner.poll(unix_now()).is_empty());
    }

    #[test]
    fn broken_file_at_start_sends_no_state() {
        let dir = Dir::new("startup");
        fs::write(dir.0.join("a.json"), APP).expect("write");
        fs::write(dir.0.join("b.json"), "{").expect("write");
        let mut scanner = source(&dir.0);
        let updates = scanner.poll(unix_now());
        assert_eq!(apps(&updates), None);
        assert!(outage(&updates).is_some_and(|why| why.contains("b.json")));
        fs::write(dir.0.join("b.json"), "{\"apps\": []}").expect("fix");
        assert_eq!(apps(&scanner.poll(unix_now())), Some(1));
    }

    #[test]
    fn missing_path_is_an_outage_and_keeps_the_state() {
        let dir = Dir::new("missing");
        let file = dir.0.join("a.json");
        fs::write(&file, APP).expect("write");
        let mut scanner = source(&file);
        assert_eq!(apps(&scanner.poll(unix_now())), Some(1));
        fs::remove_file(&file).expect("remove");
        let updates = scanner.poll(unix_now());
        assert_eq!(apps(&updates), None);
        assert!(outage(&updates).is_some_and(|why| why.contains("cannot read")));
        fs::write(&file, APP).expect("restore");
        assert_eq!(apps(&scanner.poll(unix_now())), Some(1));
    }

    #[test]
    fn config_rejects_unknown_keys_and_short_polls() {
        let parse = |text: &str| {
            let config = crate::Config::parse(&format!(
                "admin_socket = \"/x\"\n[[source]]\nkind = \"file\"\nname = \"f\"\n{text}"
            ))
            .expect("config");
            FileSource::from_config(&config.sources[0])
        };
        assert!(parse("path = \"/x\"\npoll_ms = 1000").is_ok());
        let unknown = parse("path = \"/x\"\nwatch = true").expect_err("unknown key");
        assert!(unknown.reason.contains("watch"), "{unknown}");
        let short = parse("path = \"/x\"\npoll_ms = 5").expect_err("short poll");
        assert!(short.reason.contains("poll_ms"), "{short}");
        assert!(parse("poll_ms = 100").is_err());
    }
}
