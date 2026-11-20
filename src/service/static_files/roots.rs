//! Operator-declared static roots, and the path resolution that keeps requests inside them.
//!
//! A root is a directory the operator names in `STATIC_ROOTS_FILE`; a snapshot only names one by
//! its label, among its own tenant's. Each root is opened once, at startup, as a `cap-std`
//! directory handle, and every file is opened relative to that handle: the kernel resolves the
//! path with `openat2(RESOLVE_BENEATH)` where it can and `cap-std` walks the components itself
//! where it cannot, and either way a `..` or a symlink (relative or absolute) that leads out of
//! the root is an error, not a file. A request path never reaches the file system before
//! [`RelPath::parse`] has refused `..`, backslashes, NUL, encoded separators and hidden names.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use thiserror::Error;

/// The roots of one tenant, by the label a snapshot service names.
pub type TenantRoots = HashMap<Box<str>, Arc<Root>>;

/// Every tenant's roots, as the operator declared them.
#[derive(Clone, Debug, Default)]
pub struct StaticRoots {
    tenants: Arc<HashMap<Box<str>, TenantRoots>>,
}

/// Why `STATIC_ROOTS_FILE` is refused. The message names the file and the entry.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The file cannot be read.
    #[error("{path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// Why it cannot be read.
        #[source]
        source: io::Error,
    },
    /// The file is not `{"<tenant>": {"<root>": "<absolute directory>"}}`.
    #[error("{path}: {reason}")]
    Parse {
        /// The file.
        path: String,
        /// What is wrong with its content.
        reason: String,
    },
    /// One entry is not usable.
    #[error("{path}: tenant {tenant:?} root {root:?}: {reason}")]
    Entry {
        /// The file.
        path: String,
        /// The tenant id of the entry.
        tenant: String,
        /// The root label of the entry.
        root: String,
        /// What is wrong with it.
        reason: String,
    },
}

impl StaticRoots {
    /// Reads the roots file at `path` and opens every directory in it.
    ///
    /// # Errors
    ///
    /// [`LoadError`] when the file is unreadable or malformed, a tenant or label is empty, a
    /// path is not absolute, or a path cannot be opened as a directory.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let shown = path.display().to_string();
        let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: shown.clone(),
            source,
        })?;
        let declared: HashMap<String, HashMap<String, PathBuf>> = serde_json::from_str(&text)
            .map_err(|err| LoadError::Parse {
                path: shown.clone(),
                reason: format!(
                    "expected {{\"<tenant>\": {{\"<root>\": \"<directory>\"}}}} ({err})"
                ),
            })?;
        let mut tenants = HashMap::with_capacity(declared.len());
        for (tenant, roots) in declared {
            let entry = |root: &str, reason: String| LoadError::Entry {
                path: shown.clone(),
                tenant: tenant.clone(),
                root: root.to_owned(),
                reason,
            };
            if tenant.is_empty() {
                return Err(entry("", "the tenant id is empty".into()));
            }
            let mut opened = TenantRoots::with_capacity(roots.len());
            for (label, directory) in roots {
                if label.is_empty() {
                    return Err(entry(&label, "the root name is empty".into()));
                }
                if !directory.is_absolute() {
                    return Err(entry(
                        &label,
                        format!("{} is not an absolute path", directory.display()),
                    ));
                }
                let root = Root::open(&directory).map_err(|err| {
                    entry(
                        &label,
                        format!("{} is not a usable directory ({err})", directory.display()),
                    )
                })?;
                opened.insert(label.into_boxed_str(), Arc::new(root));
            }
            tenants.insert(tenant.into_boxed_str(), opened);
        }
        Ok(Self {
            tenants: Arc::new(tenants),
        })
    }

    /// The roots of `tenant`; `None` when the operator declared none.
    #[must_use]
    pub fn of(&self, tenant: &str) -> Option<&TenantRoots> {
        self.tenants.get(tenant)
    }
}

/// One declared directory, open.
pub struct Root {
    dir: Dir,
    path: PathBuf,
}

impl fmt::Debug for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Root").field("path", &self.path).finish()
    }
}

/// What kind of file an open path turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
}

/// A file or directory opened inside a root.
#[derive(Debug)]
pub(super) struct Opened {
    /// The open file. Reads go through `read_at`, so it keeps no position.
    pub file: File,
    /// Regular file or directory; anything else is never returned.
    pub kind: Kind,
    /// Length in bytes.
    pub len: u64,
    /// Last modification time, when the file system has one.
    pub modified: Option<SystemTime>,
}

/// Why nothing was opened.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum OpenError {
    /// Nothing is served at the path: it does not exist, leaves the root, loops, is not a regular
    /// file or directory, or is not readable. The caller cannot tell which, and neither can the
    /// client.
    #[error("not found")]
    Missing,
    /// The process is out of file descriptors or memory; try again later.
    #[error("out of resources")]
    Exhausted,
}

/// A request path made safe for a root: segments that are plain names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RelPath {
    rel: String,
    trailing_slash: bool,
}

/// Why a path is not served.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum Refused {
    /// The path does not start with `/`.
    #[error("the path is not absolute")]
    NotAbsolute,
    /// A `.` or `..` segment, a backslash, a NUL or an encoded separator.
    #[error("the path tries to leave its directory")]
    Traversal,
    /// A name that starts with a dot, other than `.well-known`.
    #[error("the path names a hidden file")]
    Hidden,
    /// A broken percent escape or bytes that are not UTF-8.
    #[error("the path is not valid")]
    Encoding,
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// Decodes the percent escapes of one segment.
fn decode(segment: &str) -> Result<String, Refused> {
    if !segment.contains('%') {
        return Ok(segment.to_owned());
    }
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte != b'%' {
            out.push(byte);
            index += 1;
            continue;
        }
        let high = bytes.get(index + 1).copied().and_then(hex);
        let low = bytes.get(index + 2).copied().and_then(hex);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(Refused::Encoding);
        };
        out.push(high << 4 | low);
        index += 3;
    }
    String::from_utf8(out).map_err(|_| Refused::Encoding)
}

impl RelPath {
    /// Parses a request path (or the result of a `try_files` template). Percent escapes are
    /// decoded once, so `%252e` names a file called `%2e`, never a dot; empty segments are
    /// skipped.
    ///
    /// # Errors
    ///
    /// [`Refused`] for a path that is not absolute, has a `.` or `..` segment (after decoding),
    /// a backslash or NUL (raw or decoded), a decoded `/`, a hidden name or a broken escape.
    pub(super) fn parse(raw: &str) -> Result<Self, Refused> {
        if !raw.starts_with('/') {
            return Err(Refused::NotAbsolute);
        }
        let mut rel = String::with_capacity(raw.len());
        for segment in raw.split('/').filter(|segment| !segment.is_empty()) {
            let name = decode(segment)?;
            if matches!(name.as_str(), "." | "..") || name.contains(['\\', '/', '\0']) {
                return Err(Refused::Traversal);
            }
            if name.starts_with('.') && name != ".well-known" {
                return Err(Refused::Hidden);
            }
            if !rel.is_empty() {
                rel.push('/');
            }
            rel.push_str(&name);
        }
        Ok(Self {
            rel,
            trailing_slash: raw.ends_with('/'),
        })
    }

    /// Whether the path ends with `/`, or is the root itself.
    #[must_use]
    pub(super) fn names_directory(&self) -> bool {
        self.trailing_slash || self.rel.is_empty()
    }

    /// The path of `name` inside this path; `None` when `name` is not a plain name.
    #[must_use]
    pub(super) fn join(&self, name: &str) -> Option<Self> {
        if name.is_empty()
            || matches!(name, "." | "..")
            || name.contains(['\\', '/', '\0'])
            || (name.starts_with('.') && name != ".well-known")
        {
            return None;
        }
        let mut rel = self.rel.clone();
        if !rel.is_empty() {
            rel.push('/');
        }
        rel.push_str(name);
        Some(Self {
            rel,
            trailing_slash: false,
        })
    }

    /// The path with `suffix` appended to its last name (`.br`); `None` for the root.
    #[must_use]
    pub(super) fn with_suffix(&self, suffix: &str) -> Option<Self> {
        if self.rel.is_empty() {
            return None;
        }
        Some(Self {
            rel: format!("{}{suffix}", self.rel),
            trailing_slash: false,
        })
    }

    /// The extension of the last name, lowercased; `None` when it has none.
    #[must_use]
    pub(super) fn extension(&self) -> Option<String> {
        let name = self.rel.rsplit('/').next()?;
        let (stem, extension) = name.rsplit_once('.')?;
        (!stem.is_empty()).then(|| extension.to_ascii_lowercase())
    }

    /// The path as given to the root: relative, `/`-separated, `.` for the root itself.
    fn as_relative(&self) -> &str {
        if self.rel.is_empty() { "." } else { &self.rel }
    }

    /// The relative path, for messages.
    #[must_use]
    pub(super) fn as_str(&self) -> &str {
        &self.rel
    }
}

impl Root {
    /// Opens the directory at `path` as a root.
    ///
    /// # Errors
    ///
    /// The I/O error when `path` does not exist or is not a directory.
    pub fn open(path: &Path) -> io::Result<Self> {
        let dir = Dir::open_ambient_dir(path, ambient_authority())?;
        Ok(Self {
            dir,
            path: path.to_owned(),
        })
    }

    /// Opens the file or directory at `path` inside the root. Blocks on the file system: call it
    /// from the blocking pool.
    ///
    /// Symlinks that stay inside the root are followed; one that leaves it (relative, absolute,
    /// or through `..`) is [`OpenError::Missing`], like every other reason nothing is served. A
    /// FIFO, socket or device is opened without blocking and then refused.
    ///
    /// # Errors
    ///
    /// [`OpenError::Missing`] as above, [`OpenError::Exhausted`] when the process has no file
    /// descriptor or memory left.
    pub(super) fn open_path(&self, path: &RelPath) -> Result<Opened, OpenError> {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(NONBLOCK);
        let file = self
            .dir
            .open_with(path.as_relative(), &options)
            .map_err(|err| {
                if is_exhausted(&err) {
                    OpenError::Exhausted
                } else {
                    tracing::debug!(root = %self.path.display(), path = path.as_str(), %err, "static open refused");
                    OpenError::Missing
                }
            })?
            .into_std();
        let meta = file.metadata().map_err(|_| OpenError::Missing)?;
        let kind = if meta.is_file() {
            Kind::File
        } else if meta.is_dir() {
            Kind::Dir
        } else {
            return Err(OpenError::Missing);
        };
        Ok(Opened {
            file,
            kind,
            len: meta.len(),
            modified: meta.modified().ok(),
        })
    }
}

/// `O_NONBLOCK`, so opening a FIFO planted in a root returns at once instead of holding a
/// blocking thread until someone writes to it.
const NONBLOCK: i32 = rustix::fs::OFlags::NONBLOCK.bits().cast_signed();

fn is_exhausted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::OutOfMemory
        || matches!(
            err.raw_os_error(),
            Some(code) if code == rustix::io::Errno::MFILE.raw_os_error()
                || code == rustix::io::Errno::NFILE.raw_os_error()
        )
}

#[cfg(test)]
mod test {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A temporary tree: `<tmp>/root` is the static root, `<tmp>/secret.txt` is outside it.
    struct Tree {
        base: PathBuf,
    }

    impl Tree {
        fn new(name: &str) -> Self {
            let base =
                std::env::temp_dir().join(format!("podgate-roots-{name}-{}", std::process::id()));
            drop(std::fs::remove_dir_all(&base));
            std::fs::create_dir_all(base.join("root/dir")).expect("create the tree");
            std::fs::write(base.join("secret.txt"), "secret").expect("write the secret");
            std::fs::write(base.join("root/index.html"), "home").expect("write index");
            std::fs::write(base.join("root/dir/inner.txt"), "inner").expect("write inner");
            Self { base }
        }

        fn root(&self) -> Root {
            Root::open(&self.base.join("root")).expect("open the root")
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            drop(std::fs::remove_dir_all(&self.base));
        }
    }

    fn open(root: &Root, raw: &str) -> Result<Opened, OpenError> {
        root.open_path(&RelPath::parse(raw).map_err(|_| OpenError::Missing)?)
    }

    #[test]
    fn traversal_rejected() {
        for raw in [
            "/..",
            "/../secret.txt",
            "/dir/../../secret.txt",
            "/dir/%2e%2e/%2e%2e/secret.txt",
            "/%2E%2E/secret.txt",
            "/a\\b",
            "/dir\\..\\secret.txt",
            "/a%5Cb",
            "/a%00b",
            "/a\0b",
            "/dir%2F..%2F..%2Fsecret.txt",
        ] {
            assert!(
                matches!(RelPath::parse(raw), Err(Refused::Traversal)),
                "{raw:?}: {:?}",
                RelPath::parse(raw)
            );
        }
        let tree = Tree::new("traversal");
        let root = tree.root();
        assert!(open(&root, "/index.html").is_ok());
        // A doubly encoded dot is a file name that does not exist, never a dot.
        assert_eq!(
            RelPath::parse("/%252e%252e/secret.txt").map(|path| path.rel),
            Ok("%2e%2e/secret.txt".to_owned())
        );
        assert!(open(&root, "/%252e%252e/secret.txt").is_err());
    }

    #[test]
    fn hidden_names_are_refused_except_well_known() {
        assert_eq!(RelPath::parse("/.env"), Err(Refused::Hidden));
        assert_eq!(RelPath::parse("/a/.git/config"), Err(Refused::Hidden));
        assert_eq!(RelPath::parse("/%2eenv"), Err(Refused::Hidden));
        assert!(RelPath::parse("/.well-known/acme-challenge/x").is_ok());
    }

    #[test]
    fn symlink_escape_rejected() {
        let tree = Tree::new("symlink");
        symlink("../secret.txt", tree.base.join("root/up.txt")).expect("relative link");
        symlink(tree.base.join("secret.txt"), tree.base.join("root/abs.txt"))
            .expect("absolute link");
        symlink("../..", tree.base.join("root/dir/escape")).expect("link above the root");
        symlink("..", tree.base.join("root/dir/parent")).expect("link to the root itself");
        symlink("index.html", tree.base.join("root/inside.html")).expect("inside link");
        symlink("dir/inner.txt", tree.base.join("root/inside-dir.txt")).expect("inside link");
        let root = tree.root();
        for raw in [
            "/up.txt",
            "/abs.txt",
            "/dir/escape/secret.txt",
            "/dir/escape",
            "/dir/escape/root/index.html",
        ] {
            assert_eq!(open(&root, raw).err(), Some(OpenError::Missing), "{raw}");
        }
        // `dir/parent` is the root again: inside, so it opens, and it holds no secret.
        assert_eq!(
            open(&root, "/dir/parent").expect("the root").kind,
            Kind::Dir
        );
        assert_eq!(
            open(&root, "/dir/parent/secret.txt").err(),
            Some(OpenError::Missing)
        );
        assert_eq!(open(&root, "/inside.html").expect("inside").len, 4);
        assert_eq!(open(&root, "/inside-dir.txt").expect("inside").len, 5);
    }

    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let tree = Tree::new("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            tree.base.join("root/pipe"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("make a fifo");
        assert_eq!(open(&tree.root(), "/pipe").err(), Some(OpenError::Missing));
    }

    #[test]
    fn directories_and_files_are_told_apart() {
        let tree = Tree::new("kinds");
        let root = tree.root();
        assert_eq!(open(&root, "/dir").expect("dir").kind, Kind::Dir);
        assert_eq!(open(&root, "/").expect("root").kind, Kind::Dir);
        assert_eq!(
            open(&root, "/dir/inner.txt").expect("file").kind,
            Kind::File
        );
        assert_eq!(open(&root, "/nope").err(), Some(OpenError::Missing));
    }

    #[test]
    fn join_and_suffix_keep_names_plain() {
        let path = RelPath::parse("/dir/").expect("parses");
        assert!(path.names_directory());
        assert_eq!(
            path.join("index.html").map(|p| p.rel),
            Some("dir/index.html".into())
        );
        assert_eq!(path.join("../x"), None);
        assert_eq!(path.join(".env"), None);
        let file = RelPath::parse("/app.js").expect("parses");
        assert_eq!(
            file.with_suffix(".br").map(|p| p.rel),
            Some("app.js.br".into())
        );
        assert_eq!(file.extension().as_deref(), Some("js"));
        assert_eq!(
            RelPath::parse("/.well-known/x").expect("ok").extension(),
            None
        );
    }

    #[test]
    fn a_bad_roots_file_is_refused_with_the_entry() {
        let tree = Tree::new("file");
        let file = tree.base.join("roots.json");
        let good = format!(
            r#"{{"t1": {{"site": "{}"}}}}"#,
            tree.base.join("root").display()
        );
        std::fs::write(&file, &good).expect("write");
        let roots = StaticRoots::load(&file).expect("loads");
        assert!(roots.of("t1").is_some_and(|set| set.contains_key("site")));
        assert!(roots.of("t2").is_none());
        let not_dir = tree.base.join("secret.txt");
        let missing = tree.base.join("nope");
        for (json, expected) in [
            ("not json".to_owned(), "expected"),
            (
                r#"{"t1": {"site": "relative/dir"}}"#.to_owned(),
                "not an absolute path",
            ),
            (
                format!(r#"{{"t1": {{"site": "{}"}}}}"#, not_dir.display()),
                "not a usable directory",
            ),
            (
                format!(r#"{{"t1": {{"site": "{}"}}}}"#, missing.display()),
                "not a usable directory",
            ),
            (r#"{"t1": {"": "/tmp"}}"#.to_owned(), "root name is empty"),
            (r#"{"": {"a": "/tmp"}}"#.to_owned(), "tenant id is empty"),
        ] {
            std::fs::write(&file, &json).expect("write");
            let err = StaticRoots::load(&file).expect_err(&json).to_string();
            assert!(err.contains(&file.display().to_string()), "{err}");
            assert!(err.contains(expected), "{err} should contain {expected}");
        }
        let err = StaticRoots::load(&tree.base.join("absent.json")).expect_err("missing file");
        assert!(matches!(err, LoadError::Read { .. }));
    }
}
