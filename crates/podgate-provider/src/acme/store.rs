//! The broker's state directory: certificates, the account key, the event cursor, the challenge
//! answers and the on-demand approvals.
//!
//! ```text
//! <state_dir>/            mode 0700
//!   index.json            the certificate index, the commit point of every certificate
//!   certs/<id>.cert.pem   chain, leaf first
//!   certs/<id>.key.pem    private key
//!   cursor.json           the event feed position: boot id and last processed sequence
//!   challenges.json       HTTP-01 and TLS-ALPN-01 answers, read by followers
//!   approvals.json        on-demand approvals and the rate window they make
//!   account.key           the ACME account key, when the broker made it
//! ```
//!
//! Every file is mode `0600` and is replaced atomically: written to a temporary file in the same
//! directory, `fsync`ed, renamed over the target, and the directory is `fsync`ed. A certificate is
//! two files and an index entry; the index is written last, so a crash leaves either the old
//! state or the new one, plus orphan files that [`Store::clean_orphans`] removes. Nothing here
//! reads a clock: callers pass `now` (unix seconds), which keeps pruning testable.
//!
//! Keys never appear in an error or a log line: errors name paths and operations only.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::Secret;

const INDEX: &str = "index.json";
const CERTS: &str = "certs";
const ACCOUNT_KEY: &str = "account.key";

/// Why the state directory could not be read or written.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A file system operation failed: a full disk, a read-only mount, a missing file.
    #[error("{op} {path}")]
    Io {
        /// What was attempted.
        op: &'static str,
        /// The path.
        path: Box<str>,
        /// The cause.
        #[source]
        source: io::Error,
    },
    /// The directory or a key file is readable by group or others.
    #[error(
        "{path} has mode {mode:04o}: the state directory and its files must be private to the provider's user (chmod 700 for the directory, 600 for files)"
    )]
    Mode {
        /// The path.
        path: Box<str>,
        /// Its permission bits.
        mode: u32,
    },
    /// A file is not what the broker wrote.
    #[error("{path}: {reason}")]
    Corrupt {
        /// The path.
        path: Box<str>,
        /// What is wrong, without file content.
        reason: Box<str>,
    },
}

fn io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> StoreError {
    let path: Box<str> = path.display().to_string().into();
    move |source| StoreError::Io { op, path, source }
}

fn corrupt(path: &Path, reason: impl Into<Box<str>>) -> StoreError {
    StoreError::Corrupt {
        path: path.display().to_string().into(),
        reason: reason.into(),
    }
}

/// One certificate set as kept on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCert {
    /// The index id; the file names derive from it.
    pub id: u64,
    /// The hosts it answers for, sorted.
    pub hosts: Vec<Box<str>>,
    /// The chain, leaf first.
    pub cert_pem: String,
    /// The private key.
    pub key_pem: Secret,
    /// When the broker stored it (unix seconds).
    pub issued_at: u64,
    /// The last time an app claimed one of its hosts (unix seconds).
    pub last_claimed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    id: u64,
    hosts: Vec<Box<str>>,
    issued_at: u64,
    last_claimed: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Index {
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    certs: Vec<Entry>,
}

/// The state directory.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    index: Index,
}

fn mode_of(path: &Path) -> Result<u32, StoreError> {
    fs::metadata(path)
        .map(|meta| meta.mode() & 0o777)
        .map_err(io_err("stat", path))
}

fn check_private(path: &Path) -> Result<(), StoreError> {
    let mode = mode_of(path)?;
    if mode & 0o077 != 0 {
        return Err(StoreError::Mode {
            path: path.display().to_string().into(),
            mode,
        });
    }
    Ok(())
}

/// Reads a secret file an operator names (the account key, the EAB key): it must not be
/// readable by group or others. One trailing newline is removed.
///
/// # Errors
///
/// [`StoreError::Io`] when it cannot be read, [`StoreError::Mode`] when it is not private.
pub fn read_secret_file(path: &Path) -> Result<Secret, StoreError> {
    check_private(path)?;
    let text = fs::read_to_string(path).map_err(io_err("read", path))?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok(Secret::new(text.strip_suffix('\r').unwrap_or(text)))
}

/// Writes `bytes` to `path` atomically with mode `0600`: temporary file, `fsync`, rename,
/// `fsync` of the directory.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.tmp"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_err("remove", &tmp)(err)),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io_err("create", &tmp))?;
    file.write_all(bytes).map_err(io_err("write", &tmp))?;
    file.sync_all().map_err(io_err("fsync", &tmp))?;
    drop(file);
    fs::rename(&tmp, path).map_err(io_err("rename", path))?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(io_err("fsync", parent))
}

fn make_private_dir(path: &Path) -> Result<(), StoreError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(io_err("create", path))?;
    check_private(path)
}

impl Store {
    /// Opens the directory for writing, creating it (and `certs/`) with mode `0700` when it is
    /// missing. An existing directory that group or others can read is refused: the broker never
    /// widens or narrows a permission it did not set.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directory cannot be made or read, is not private, or holds an
    /// index the broker cannot read.
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        make_private_dir(dir)?;
        make_private_dir(&dir.join(CERTS))?;
        let index = read_index(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            index,
        })
    }

    /// Opens an existing directory for reading only (a follower, `print`). `None` when the
    /// directory does not exist yet.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when it exists but is not private or its index cannot be read.
    pub fn open_existing(dir: &Path) -> Result<Option<Self>, StoreError> {
        match fs::metadata(dir) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_err("stat", dir)(err)),
        }
        check_private(dir)?;
        let index = read_index(dir)?;
        Ok(Some(Self {
            dir: dir.to_owned(),
            index,
        }))
    }

    /// Reads the index again: a follower calls it on every look at a directory a broker writes.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the index cannot be read.
    pub fn reload(&mut self) -> Result<(), StoreError> {
        self.index = read_index(&self.dir)?;
        Ok(())
    }

    fn cert_path(&self, id: u64, kind: &str) -> PathBuf {
        self.dir.join(CERTS).join(format!("{id}.{kind}.pem"))
    }

    /// Every stored certificate with its files. A missing or world-readable file is an error:
    /// the index promised it.
    ///
    /// # Errors
    ///
    /// [`StoreError`] naming the file.
    pub fn certs(&self) -> Result<Vec<StoredCert>, StoreError> {
        self.index
            .certs
            .iter()
            .map(|entry| {
                let cert_path = self.cert_path(entry.id, "cert");
                let key_path = self.cert_path(entry.id, "key");
                check_private(&key_path)?;
                let cert_pem =
                    fs::read_to_string(&cert_path).map_err(io_err("read", &cert_path))?;
                let key_pem = fs::read_to_string(&key_path).map_err(io_err("read", &key_path))?;
                Ok(StoredCert {
                    id: entry.id,
                    hosts: entry.hosts.clone(),
                    cert_pem,
                    key_pem: Secret::new(key_pem),
                    issued_at: entry.issued_at,
                    last_claimed: entry.last_claimed,
                })
            })
            .collect()
    }

    /// Stores a certificate set. It replaces every stored set whose hosts it covers (a renewal,
    /// or a bigger order that holds the old names). Returns the entry as stored.
    ///
    /// The files are written first and the index last: when this returns `Ok` the certificate
    /// survives a crash, and when it returns `Err` the index is as it was.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when a write fails (a full disk, a read-only directory).
    pub fn put_cert(
        &mut self,
        hosts: &[Box<str>],
        cert_pem: &str,
        key_pem: &Secret,
        now: u64,
    ) -> Result<StoredCert, StoreError> {
        let mut hosts = hosts.to_vec();
        hosts.sort_unstable();
        hosts.dedup();
        let id = self.index.next_id.max(1);
        let cert_path = self.cert_path(id, "cert");
        let key_path = self.cert_path(id, "key");
        write_atomic(&key_path, key_pem.expose().as_bytes())?;
        write_atomic(&cert_path, cert_pem.as_bytes())?;
        let mut next = self.index.clone();
        let replaced: Vec<u64> = next
            .certs
            .iter()
            .filter(|old| old.hosts.iter().all(|host| hosts.contains(host)))
            .map(|old| old.id)
            .collect();
        next.certs.retain(|old| !replaced.contains(&old.id));
        next.certs.push(Entry {
            id,
            hosts: hosts.clone(),
            issued_at: now,
            last_claimed: now,
        });
        next.next_id = id + 1;
        write_atomic(
            &self.dir.join(INDEX),
            &to_json(&next, &self.dir.join(INDEX))?,
        )?;
        self.index = next;
        for old in replaced {
            self.remove_files(old);
        }
        Ok(StoredCert {
            id,
            hosts,
            cert_pem: cert_pem.to_owned(),
            key_pem: key_pem.clone(),
            issued_at: now,
            last_claimed: now,
        })
    }

    /// Records that an app claimed a host of each certificate in `ids` at `now`.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the index cannot be written.
    pub fn touch_claimed(&mut self, ids: &[u64], now: u64) -> Result<(), StoreError> {
        let mut next = self.index.clone();
        let mut changed = false;
        for entry in &mut next.certs {
            if ids.contains(&entry.id) && entry.last_claimed < now {
                entry.last_claimed = now;
                changed = true;
            }
        }
        if changed {
            self.write_index(next)?;
        }
        Ok(())
    }

    /// Drops the certificates no app has claimed for `max_age` seconds. Returns the hosts of
    /// each dropped set.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the index cannot be written; nothing is dropped then.
    pub fn prune(&mut self, now: u64, max_age: u64) -> Result<Vec<Vec<Box<str>>>, StoreError> {
        let mut next = self.index.clone();
        let (keep, drop): (Vec<Entry>, Vec<Entry>) = next
            .certs
            .into_iter()
            .partition(|entry| now.saturating_sub(entry.last_claimed) <= max_age);
        if drop.is_empty() {
            return Ok(Vec::new());
        }
        next.certs = keep;
        self.write_index(next)?;
        for entry in &drop {
            self.remove_files(entry.id);
        }
        Ok(drop.into_iter().map(|entry| entry.hosts).collect())
    }

    fn write_index(&mut self, next: Index) -> Result<(), StoreError> {
        let path = self.dir.join(INDEX);
        write_atomic(&path, &to_json(&next, &path)?)?;
        self.index = next;
        Ok(())
    }

    fn remove_files(&self, id: u64) {
        // Best effort: a file that stays is an orphan, which `clean_orphans` removes.
        for kind in ["cert", "key"] {
            drop(fs::remove_file(self.cert_path(id, kind)));
        }
    }

    /// Removes files in the directory that the index does not name: a crash between writing a
    /// certificate's files and the index, or temporary files of an interrupted write.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the directory cannot be listed.
    pub fn clean_orphans(&self) -> Result<(), StoreError> {
        let certs_dir = self.dir.join(CERTS);
        let listed = fs::read_dir(&certs_dir).map_err(io_err("list", &certs_dir))?;
        for item in listed.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            let referenced = self.index.certs.iter().any(|entry| {
                name == format!("{}.cert.pem", entry.id) || name == format!("{}.key.pem", entry.id)
            });
            if !referenced {
                drop(fs::remove_file(item.path()));
            }
        }
        if let Ok(listed) = fs::read_dir(&self.dir) {
            for item in listed.flatten() {
                let name = item.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && name.ends_with(".tmp") {
                    drop(fs::remove_file(item.path()));
                }
            }
        }
        Ok(())
    }

    /// Reads a JSON state file. `None` when it does not exist.
    pub(crate) fn read_json<T: DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, StoreError> {
        let path = self.dir.join(name);
        let text = match fs::read(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_err("read", &path)(err)),
        };
        serde_json::from_slice(&text).map(Some).map_err(|err| {
            corrupt(
                &path,
                format!("not the expected JSON ({})", err.classify_name()),
            )
        })
    }

    /// Replaces a JSON state file atomically.
    pub(crate) fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StoreError> {
        let path = self.dir.join(name);
        write_atomic(&path, &to_json(value, &path)?)
    }

    /// The account key the broker made, when there is one.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the file exists and cannot be read or is not private.
    pub fn account_key(&self) -> Result<Option<Secret>, StoreError> {
        let path = self.dir.join(ACCOUNT_KEY);
        if !path.exists() {
            return Ok(None);
        }
        read_secret_file(&path).map(Some)
    }

    /// Keeps `key` as the account key.
    ///
    /// # Errors
    ///
    /// [`StoreError`] when the file cannot be written.
    pub fn save_account_key(&self, key: &Secret) -> Result<(), StoreError> {
        write_atomic(&self.dir.join(ACCOUNT_KEY), key.expose().as_bytes())
    }

    /// Reads a private text file of the directory (the internal CA's keys and certificates).
    /// `None` when it does not exist; a file group or others can read is refused.
    pub(crate) fn read_text(&self, name: &str) -> Result<Option<String>, StoreError> {
        let path = self.dir.join(name);
        match fs::metadata(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_err("stat", &path)(err)),
        }
        check_private(&path)?;
        fs::read_to_string(&path)
            .map(Some)
            .map_err(io_err("read", &path))
    }

    /// Replaces a private text file of the directory atomically.
    pub(crate) fn write_text(&self, name: &str, text: &str) -> Result<(), StoreError> {
        write_atomic(&self.dir.join(name), text.as_bytes())
    }

    /// The directory.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }
}

fn read_index(dir: &Path) -> Result<Index, StoreError> {
    let path = dir.join(INDEX);
    let text = match fs::read(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Index::default()),
        Err(err) => return Err(io_err("read", &path)(err)),
    };
    serde_json::from_slice(&text).map_err(|err| {
        corrupt(
            &path,
            format!("not a certificate index ({})", err.classify_name()),
        )
    })
}

fn to_json<T: Serialize>(value: &T, path: &Path) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(value).map_err(|err| corrupt(path, format!("cannot serialize ({err})")))
}

/// The category of a `serde_json` error, which never repeats the content that failed to parse.
trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}

impl ClassifyName for serde_json::Error {
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "i/o",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "wrong data type",
            serde_json::error::Category::Eof => "truncated",
        }
    }
}

#[cfg(test)]
mod test {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pgp-store-{}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        dir
    }

    fn hosts(list: &[&str]) -> Vec<Box<str>> {
        list.iter().map(|host| Box::from(*host)).collect()
    }

    #[test]
    fn store_permissions() {
        let dir = scratch("perm");
        let mut store = Store::create(&dir.join("acme")).expect("create");
        store
            .put_cert(&hosts(&["a.test"]), "CERT", &Secret::new("KEY"), 10)
            .expect("put");
        store
            .write_json("cursor.json", &serde_json::json!({"after": 1}))
            .expect("cursor");
        store
            .save_account_key(&Secret::new("ACCOUNT"))
            .expect("account");
        let root = dir.join("acme");
        assert_eq!(mode_of(&root).expect("mode"), 0o700);
        assert_eq!(mode_of(&root.join("certs")).expect("mode"), 0o700);
        for file in [
            "index.json",
            "cursor.json",
            "account.key",
            "certs/1.cert.pem",
            "certs/1.key.pem",
        ] {
            assert_eq!(mode_of(&root.join(file)).expect("mode"), 0o600, "{file}");
        }
        // A directory somebody widened is refused, never silently used.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            Store::create(&root),
            Err(StoreError::Mode { mode: 0o755, .. })
        ));
        assert!(matches!(
            Store::open_existing(&root),
            Err(StoreError::Mode { .. })
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod");
        // So is a key file group or others can read.
        fs::set_permissions(
            root.join("certs/1.key.pem"),
            fs::Permissions::from_mode(0o640),
        )
        .expect("chmod");
        let reopened = Store::create(&root).expect("reopen");
        assert!(matches!(reopened.certs(), Err(StoreError::Mode { .. })));
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn put_replaces_covered_sets_and_survives_reopen() {
        let dir = scratch("replace");
        let root = dir.join("acme");
        let mut store = Store::create(&root).expect("create");
        store
            .put_cert(&hosts(&["a.test"]), "OLD", &Secret::new("K1"), 10)
            .expect("put");
        store
            .put_cert(&hosts(&["b.test"]), "OTHER", &Secret::new("K2"), 11)
            .expect("put");
        store
            .put_cert(&hosts(&["a.test", "c.test"]), "NEW", &Secret::new("K3"), 12)
            .expect("put");
        let reopened = Store::create(&root).expect("reopen");
        let certs = reopened.certs().expect("certs");
        let shown: Vec<(&str, Vec<&str>)> = certs
            .iter()
            .map(|cert| {
                (
                    cert.cert_pem.as_str(),
                    cert.hosts.iter().map(|h| &**h).collect(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [("OTHER", vec!["b.test"]), ("NEW", vec!["a.test", "c.test"])],
            "the set that holds a.test replaced the old one; the unrelated one stays"
        );
        assert!(
            !root.join("certs/1.key.pem").exists(),
            "the replaced set's files are gone"
        );
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn orphans_of_an_interrupted_write_are_removed() {
        let dir = scratch("orphan");
        let root = dir.join("acme");
        let mut store = Store::create(&root).expect("create");
        store
            .put_cert(&hosts(&["a.test"]), "CERT", &Secret::new("KEY"), 10)
            .expect("put");
        // The files of a certificate whose index entry was never written, and a torn temp file.
        fs::write(root.join("certs/9.key.pem"), "KEY").expect("orphan");
        fs::write(root.join(".index.json.tmp"), "{").expect("tmp");
        store.clean_orphans().expect("clean");
        assert!(!root.join("certs/9.key.pem").exists());
        assert!(!root.join(".index.json.tmp").exists());
        assert!(root.join("certs/1.key.pem").exists());
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn unclaimed_sets_are_pruned_after_the_age() {
        let dir = scratch("prune");
        let mut store = Store::create(&dir.join("acme")).expect("create");
        let day = 86_400;
        store
            .put_cert(&hosts(&["old.test"]), "A", &Secret::new("K"), 0)
            .expect("put");
        store
            .put_cert(&hosts(&["kept.test"]), "B", &Secret::new("K"), 0)
            .expect("put");
        let kept = store.certs().expect("certs")[1].id;
        store.touch_claimed(&[kept], 29 * day).expect("touch");
        assert!(store.prune(30 * day, 30 * day).expect("prune").is_empty());
        let dropped = store.prune(30 * day + 1, 30 * day).expect("prune");
        assert_eq!(dropped, [hosts(&["old.test"])]);
        let left = store.certs().expect("certs");
        assert_eq!(left.len(), 1);
        assert_eq!(&*left[0].hosts[0], "kept.test");
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn corrupt_index_names_the_file_not_the_content() {
        let dir = scratch("corrupt");
        let root = dir.join("acme");
        drop(Store::create(&root).expect("create"));
        fs::write(root.join("index.json"), "{\"certs\": \"PRIVATE-MATERIAL\"}").expect("write");
        let err = Store::create(&root).expect_err("corrupt");
        let shown = format!("{err} {err:?}");
        assert!(shown.contains("index.json"), "{shown}");
        assert!(!shown.contains("PRIVATE-MATERIAL"), "{shown}");
        drop(fs::remove_dir_all(&dir));
    }
}
