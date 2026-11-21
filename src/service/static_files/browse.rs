//! Directory listings for a `static` service, the opt-in half of Caddy's `file_server browse`.
//!
//! A listing needs two opt-ins: the operator marks the root `{"path": "...", "browse": true}` in
//! `STATIC_ROOTS_FILE`, and the service says `"browse": true`. A file name is attacker-controlled
//! text (anyone who can upload a file picks it), so every name is treated as hostile: HTML-escaped
//! in the page, percent-encoded in `href`, and control and bidirectional characters are shown as
//! visible `\uXXXX` escapes. The page has no script and no inline style and is served with a
//! `Content-Security-Policy` that allows nothing.
//!
//! The directory is read on the bounded blocking pool of [`Reads`] through the root's `cap-std`
//! handle, keeping only the first `max_entries` entries in sorted order, and the tenant's buffer
//! budget is charged for them before the first entry is read. The runtime shape of the answer is in
//! `docs/ref/svc-static-browse.md`.

use std::cmp::Ordering;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use cap_std::fs::Dir;
use http::StatusCode;
use pingora::http::ResponseHeader;
use serde::Serialize;

use super::StaticSite;
use super::reader::Reads;
use super::roots::{Kind, OpenError, RelPath, Root};
use super::serve::{Asked, Failure};
use crate::budget::{BufferGuard, TenantBudget};
use crate::compile::Invalid;

/// Entries shown when the service does not say `max_entries`.
const DEFAULT_MAX_ENTRIES: usize = 1000;

/// The most entries a service may ask to show.
const MAX_ENTRIES_LIMIT: usize = 10_000;

/// Directory entries examined at most for one listing, hidden and filtered ones included: twice
/// the largest `max_entries`, so a directory of millions of names cannot hold a blocking thread.
const SCAN_CAP: usize = 2 * MAX_ENTRIES_LIMIT;

/// Buffer bytes charged for each entry that may be shown: its name, its row and its sort key.
const ENTRY_BYTES: u64 = 512;

/// Buffer bytes charged for the page around the entries.
const PAGE_BYTES: u64 = 64 * 1024;

/// The listing policy of one service whose `browse` is on.
#[derive(Debug)]
pub(super) struct Browse {
    max_entries: usize,
    hide: Box<[Pattern]>,
}

/// A `hide` glob: `*` matches any run of characters, `?` one character, everything else itself.
/// It is matched against an entry's name, never a path.
#[derive(Debug)]
struct Pattern(Box<[char]>);

impl Pattern {
    fn parse(text: &str) -> Result<Self, Invalid> {
        if text.is_empty() || text.contains(['/', '\0']) {
            return Err(super::invalid(format!(
                "hide entry {text:?} must be a non-empty file name pattern without /"
            )));
        }
        Ok(Self(text.chars().collect()))
    }

    fn matches(&self, name: &[char]) -> bool {
        let pattern = &*self.0;
        let (mut p, mut t) = (0, 0);
        let mut resume: Option<(usize, usize)> = None;
        while let Some(&c) = name.get(t) {
            match pattern.get(p) {
                Some('*') => {
                    resume = Some((p + 1, t));
                    p += 1;
                }
                Some(&expected) if expected == '?' || expected == c => {
                    p += 1;
                    t += 1;
                }
                _ => {
                    let Some((after_star, at)) = resume else {
                        return false;
                    };
                    resume = Some((after_star, at + 1));
                    p = after_star;
                    t = at + 1;
                }
            }
        }
        pattern
            .get(p..)
            .is_some_and(|rest| rest.iter().all(|c| *c == '*'))
    }
}

impl Browse {
    /// The policy a service asks for, or `None` when it does not ask.
    ///
    /// # Errors
    ///
    /// `invalid_service` for `hide` or `max_entries` without `browse`, a bad pattern or a
    /// `max_entries` outside `1..=10000`; `static_browse_not_allowed` when the operator did not
    /// mark the root `browse`.
    pub(super) fn compile(
        enabled: bool,
        hide: Option<Vec<String>>,
        max_entries: Option<usize>,
        root: &Root,
        label: &str,
    ) -> Result<Option<Arc<Self>>, Invalid> {
        if !enabled {
            if hide.is_some() || max_entries.is_some() {
                return Err(super::invalid("hide and max_entries need browse: true"));
            }
            return Ok(None);
        }
        if !root.browse_allowed() {
            return Err(Invalid::new(
                "static_browse_not_allowed",
                format!(
                    "static root {label:?} is not open to directory listings (the operator allows them with {{\"path\": ..., \"browse\": true}} in STATIC_ROOTS_FILE)"
                ),
            )
            .with("root", label));
        }
        let max_entries = max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
        if !(1..=MAX_ENTRIES_LIMIT).contains(&max_entries) {
            return Err(super::invalid(format!(
                "max_entries must be between 1 and {MAX_ENTRIES_LIMIT}"
            )));
        }
        let hide = hide
            .unwrap_or_default()
            .iter()
            .map(|text| Pattern::parse(text))
            .collect::<Result<Box<[_]>, _>>()?;
        Ok(Some(Arc::new(Self { max_entries, hide })))
    }

    /// Buffer bytes a listing charges before it reads the directory.
    pub(super) fn charge(&self) -> u64 {
        u64::try_from(self.max_entries)
            .map_or(u64::MAX, |entries| entries.saturating_mul(ENTRY_BYTES))
            .saturating_add(PAGE_BYTES)
    }

    fn hides(&self, name: &OsString) -> bool {
        if self.hide.is_empty() {
            return false;
        }
        let shown: Vec<char> = name.to_string_lossy().chars().collect();
        self.hide.iter().any(|pattern| pattern.matches(&shown))
    }
}

/// The buffer charge of a listing in flight. [`super::serve::serve`] keeps it until the page has
/// been written, so the bytes stay charged while a slow client drains them.
#[derive(Debug, Default)]
pub(super) struct Held {
    _charge: Option<BufferGuard>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Name,
    Size,
    Mtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    Asc,
    Desc,
}

/// What the request asked of the listing: `?sort=`, `?order=` and `?format=` or `Accept`.
#[derive(Clone, Copy, Debug)]
struct Params {
    sort: Sort,
    order: Order,
    json: bool,
}

impl Params {
    /// Unknown values fall back to the defaults: name, ascending, HTML.
    fn of(asked: &Asked) -> Self {
        let mut params = Self {
            sort: Sort::Name,
            order: Order::Asc,
            json: false,
        };
        let mut format = None;
        for pair in asked.query.as_deref().unwrap_or_default().split('&') {
            match pair.split_once('=') {
                Some(("sort", "size")) => params.sort = Sort::Size,
                Some(("sort", "mtime")) => params.sort = Sort::Mtime,
                Some(("sort", "name")) => params.sort = Sort::Name,
                Some(("order", "desc")) => params.order = Order::Desc,
                Some(("order", "asc")) => params.order = Order::Asc,
                Some(("format", value @ ("json" | "html"))) => format = Some(value == "json"),
                _ => {}
            }
        }
        params.json = format.unwrap_or_else(|| {
            asked.accept.as_deref().is_some_and(|accept| {
                accept.split(',').any(|item| {
                    item.split(';')
                        .next()
                        .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
                })
            })
        });
        params
    }
}

/// One shown entry.
#[derive(Debug)]
struct Entry {
    name: OsString,
    dir: bool,
    size: u64,
    modified: Option<SystemTime>,
}

/// Directories first, then by the requested key, then by name.
fn rank(a: &Entry, b: &Entry, params: Params) -> Ordering {
    let key = match params.sort {
        Sort::Name => a.name.as_bytes().cmp(b.name.as_bytes()),
        Sort::Size => a.size.cmp(&b.size),
        Sort::Mtime => a.modified.cmp(&b.modified),
    };
    let key = match params.order {
        Order::Asc => key,
        Order::Desc => key.reverse(),
    };
    b.dir
        .cmp(&a.dir)
        .then(key)
        .then_with(|| a.name.as_bytes().cmp(b.name.as_bytes()))
}

/// What the directory at the request path turned out to be.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// Not a directory, or not served.
    Absent,
    /// A directory with an index file: the index wins and nothing is listed.
    Indexed,
    /// A directory to list.
    Listable,
}

fn probe(root: &Root, rel: &RelPath, index: &[Box<str>]) -> Result<Probe, OpenError> {
    match root.open_path(rel) {
        Ok(opened) if opened.kind == Kind::Dir => {}
        Ok(_) | Err(OpenError::Missing) => return Ok(Probe::Absent),
        Err(err) => return Err(err),
    }
    for name in index {
        let Some(path) = rel.join(name) else { continue };
        match root.open_path(&path) {
            Ok(opened) if opened.kind == Kind::File => return Ok(Probe::Indexed),
            Err(OpenError::Exhausted) => return Err(OpenError::Exhausted),
            Ok(_) | Err(OpenError::Missing) => {}
        }
    }
    Ok(Probe::Listable)
}

/// Reads the directory: its first `max_entries` shown entries in sorted order, and whether there
/// were more. Memory stays within twice `max_entries`: the kept entries are cut back to the best
/// `max_entries + 1` each time they double.
fn read(
    root: &Root,
    rel: &RelPath,
    browse: &Browse,
    params: Params,
) -> Result<(Vec<Entry>, bool), OpenError> {
    let opened = root.open_path(rel)?;
    if opened.kind != Kind::Dir {
        return Err(OpenError::Missing);
    }
    let dir = Dir::from_std_file(opened.file);
    let items = dir.entries().map_err(|_| OpenError::Missing)?;
    let keep = browse.max_entries + 1;
    let mut kept: Vec<Entry> = Vec::new();
    let mut truncated = false;
    for (scanned, item) in items.enumerate() {
        if scanned == SCAN_CAP {
            truncated = true;
            break;
        }
        let Ok(item) = item else { continue };
        let name = item.file_name();
        if name.as_bytes().first() == Some(&b'.') || browse.hides(&name) {
            continue;
        }
        let Ok(kind) = item.file_type() else { continue };
        let (dir, size, modified) = if kind.is_symlink() {
            // Only a link that resolves inside the root is listed, and only as what it points at.
            let Some(path) = name.to_str().and_then(|text| rel.join(text)) else {
                continue;
            };
            match root.open_path(&path) {
                Ok(target) => (target.kind == Kind::Dir, target.len, target.modified),
                Err(OpenError::Missing) => continue,
                Err(err) => return Err(err),
            }
        } else if kind.is_dir() || kind.is_file() {
            let Ok(meta) = item.metadata() else { continue };
            (
                kind.is_dir(),
                meta.len(),
                meta.modified()
                    .ok()
                    .map(cap_std::time::SystemTime::into_std),
            )
        } else {
            continue;
        };
        kept.push(Entry {
            name,
            dir,
            size: if dir { 0 } else { size },
            modified,
        });
        if kept.len() >= 2 * keep {
            kept.sort_by(|a, b| rank(a, b, params));
            kept.truncate(keep);
            truncated = true;
        }
    }
    kept.sort_by(|a, b| rank(a, b, params));
    if kept.len() > browse.max_entries {
        kept.truncate(browse.max_entries);
        truncated = true;
    }
    Ok((kept, truncated))
}

/// Whether `c` could reorder or spoof text, or is invisible: a control character or a
/// bidirectional control (U+202A to U+202E, U+2066 to U+2069, and the marks U+061C, U+200E,
/// U+200F).
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// `name` as text to show: lossy for invalid UTF-8, unsafe characters as `\uXXXX`.
fn visible(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    for c in String::from_utf8_lossy(name).chars() {
        if is_unsafe(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// A name as one URL path segment: every byte but an unreserved one is `%XX`, so a `:` can never
/// make a relative link look like a scheme.
fn percent_encode(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    for &byte in name {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `2026-11-21T10:00:00Z`; `None` before 1970.
fn timestamp(time: SystemTime) -> Option<String> {
    let secs = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let (days, rest) = (secs / 86_400, secs % 86_400);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm), shifted to 0000-03-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let (month, year) = if shifted_month < 10 {
        (shifted_month + 3, year_of_era + era * 400)
    } else {
        (shifted_month - 9, year_of_era + era * 400 + 1)
    };
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    ))
}

fn stamp(entry: &Entry) -> Option<String> {
    entry.modified.and_then(timestamp)
}

/// The path shown in the title and in JSON: the request path, with a trailing `/`.
fn shown_path(rel: &RelPath) -> String {
    if rel.as_str().is_empty() {
        "/".to_owned()
    } else {
        format!("/{}/", rel.as_str())
    }
}

fn href(entry: &Entry) -> String {
    let mut href = percent_encode(entry.name.as_bytes());
    if entry.dir {
        href.push('/');
    }
    href
}

fn render_html(
    rel: &RelPath,
    entries: &[Entry],
    truncated: bool,
    params: Params,
    max: usize,
) -> String {
    let path = escape_html(&visible(shown_path(rel).as_bytes()));
    let mut page = String::with_capacity(1024 + entries.len() * 256);
    let _ = write!(
        page,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Index of {path}</title></head>\n<body>\n<h1>Index of {path}</h1>\n<table>\n<thead><tr>"
    );
    for (label, sort) in [
        ("Name", Sort::Name),
        ("Size", Sort::Size),
        ("Modified (UTC)", Sort::Mtime),
    ] {
        let order = if sort == params.sort && params.order == Order::Asc {
            "desc"
        } else {
            "asc"
        };
        let sort_name = match sort {
            Sort::Name => "name",
            Sort::Size => "size",
            Sort::Mtime => "mtime",
        };
        let _ = write!(
            page,
            "<th scope=\"col\"><a href=\"?sort={sort_name}&amp;order={order}\">{label}</a></th>"
        );
    }
    page.push_str("</tr></thead>\n<tbody>\n");
    if !rel.as_str().is_empty() {
        page.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>\n");
    }
    for entry in entries {
        let name = escape_html(&visible(entry.name.as_bytes()));
        let slash = if entry.dir { "/" } else { "" };
        let size = if entry.dir {
            "-".to_owned()
        } else {
            entry.size.to_string()
        };
        let modified = stamp(entry).unwrap_or_else(|| "-".to_owned());
        let _ = writeln!(
            page,
            "<tr><td><a href=\"{}\">{name}{slash}</a></td><td>{size}</td><td>{modified}</td></tr>",
            href(entry)
        );
    }
    page.push_str("</tbody>\n</table>\n");
    if truncated {
        let _ = writeln!(
            page,
            "<p>Listing truncated: only the first {max} entries are shown.</p>"
        );
    }
    page.push_str("</body></html>\n");
    page
}

#[derive(Serialize)]
struct JsonEntry {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    size: Option<u64>,
    modified: Option<String>,
    href: String,
}

#[derive(Serialize)]
struct JsonListing {
    path: String,
    entries: Vec<JsonEntry>,
    truncated: bool,
}

/// The listing as JSON. A name is exact (lossy for invalid UTF-8; `href` is the faithful
/// identifier), but control and bidirectional characters are written as `\uXXXX` escapes, so the
/// bytes on the wire cannot reorder text in a terminal or a page that prints them.
fn render_json(
    rel: &RelPath,
    entries: &[Entry],
    truncated: bool,
) -> Result<String, serde_json::Error> {
    let listing = JsonListing {
        path: shown_path(rel),
        entries: entries
            .iter()
            .map(|entry| JsonEntry {
                name: String::from_utf8_lossy(entry.name.as_bytes()).into_owned(),
                kind: if entry.dir { "dir" } else { "file" },
                size: (!entry.dir).then_some(entry.size),
                modified: stamp(entry),
                href: href(entry),
            })
            .collect(),
        truncated,
    };
    let text = serde_json::to_string(&listing)?;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_unsafe(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn redirect(asked: &Asked, raw: &str) -> Result<(ResponseHeader, Bytes), Failure> {
    let query = asked
        .query
        .as_deref()
        .map_or_else(String::new, |query| format!("?{query}"));
    let mut header = ResponseHeader::build(StatusCode::PERMANENT_REDIRECT, Some(3))?;
    header.insert_header("location", format!("{raw}/{query}"))?;
    header.insert_header("content-length", "0")?;
    Ok((header, Bytes::new()))
}

fn page(body: String, json: bool) -> Result<(ResponseHeader, Bytes), Failure> {
    let mut header = ResponseHeader::build(StatusCode::OK, Some(7))?;
    header.insert_header(
        "content-type",
        if json {
            "application/json"
        } else {
            "text/html; charset=utf-8"
        },
    )?;
    header.insert_header("content-length", body.len().to_string())?;
    header.insert_header("content-security-policy", "default-src 'none'")?;
    header.insert_header("x-content-type-options", "nosniff")?;
    header.insert_header("cache-control", "no-cache")?;
    header.insert_header("vary", "accept")?;
    Ok((header, Bytes::from(body)))
}

/// Answers a request for which nothing else was found, with a listing of the directory it names
/// when the service allows it; `None` when it does not apply and the usual `404` stands.
///
/// A directory with an index file is not listed (the index is served before this runs, and one
/// that could not be served is not replaced by a listing). A directory named without its trailing
/// slash is redirected to the slash form. The listing's buffer charge is stored in `held`.
///
/// # Errors
///
/// [`Failure::Busy`] when the file-system pool has no slot, [`Failure::OverBudget`] when the
/// tenant cannot take the listing's buffer charge.
pub(super) async fn listing(
    site: &StaticSite,
    reads: &Reads,
    tenant: Option<&Arc<TenantBudget>>,
    asked: &Asked,
    held: &mut Held,
) -> Result<Option<(ResponseHeader, Bytes)>, Failure> {
    let Some(browse) = site.browse.as_ref().map(Arc::clone) else {
        return Ok(None);
    };
    let Some(raw) = asked.path.as_deref() else {
        return Ok(None);
    };
    // `.well-known` is served, but like every hidden name it is never listed.
    let Some(rel) = RelPath::parse(raw)
        .ok()
        .filter(|rel| !rel.as_str().split('/').any(|name| name.starts_with('.')))
    else {
        return Ok(None);
    };
    let (root, names) = (Arc::clone(&site.root), site.index.clone());
    let checked = rel.clone();
    let probed = reads
        .run(move || probe(&root, &checked, &names))
        .await?
        .map_err(|_| super::reader::Busy)?;
    if probed != Probe::Listable {
        return Ok(None);
    }
    if !rel.names_directory() {
        return redirect(asked, raw).map(Some);
    }
    let Some(guard) = tenant.and_then(|tenant| tenant.charge(browse.charge())) else {
        return Err(Failure::OverBudget);
    };
    held._charge = Some(guard);
    let params = Params::of(asked);
    let (root, wanted) = (Arc::clone(&site.root), rel.clone());
    let reading = Arc::clone(&browse);
    let read = reads
        .run(move || read(&root, &wanted, &reading, params))
        .await?;
    let (entries, truncated) = match read {
        Ok(read) => read,
        Err(OpenError::Missing) => return Ok(None),
        Err(OpenError::Exhausted) => return Err(Failure::Busy(super::reader::Busy)),
    };
    let body = if params.json {
        render_json(&rel, &entries, truncated).map_err(|err| {
            Failure::Http(pingora::Error::because(
                pingora::ErrorType::InternalError,
                "cannot render the listing",
                err,
            ))
        })?
    } else {
        render_html(&rel, &entries, truncated, params, browse.max_entries)
    };
    page(body, params.json).map(Some)
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;

    fn glob(pattern: &str, name: &str) -> bool {
        let chars: Vec<char> = name.chars().collect();
        Pattern::parse(pattern).expect("a pattern").matches(&chars)
    }

    #[test]
    fn globs_match_names() {
        assert!(glob("*.bak", "a.bak"));
        assert!(glob("*.bak", ".bak"));
        assert!(!glob("*.bak", "a.bak2"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "ac"));
        assert!(glob("*a*b*", "xxaYYbzz"));
        assert!(glob("*", ""));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("a/b").is_err());
    }

    #[test]
    fn unsafe_characters_become_visible_escapes() {
        assert_eq!(visible("a\u{202e}b".as_bytes()), "a\\u202eb");
        assert_eq!(visible(b"line\nbreak"), "line\\u000abreak");
        assert_eq!(visible("\u{2066}x\u{2069}".as_bytes()), "\\u2066x\\u2069");
        assert_eq!(visible(b"bad\xff"), "bad\u{fffd}");
        assert_eq!(visible("héllo".as_bytes()), "héllo");
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn names_are_percent_encoded_by_bytes() {
        assert_eq!(percent_encode(b"a b"), "a%20b");
        assert_eq!(
            percent_encode(b"javascript:alert(1)"),
            "javascript%3Aalert%281%29"
        );
        assert_eq!(percent_encode(b"../x"), "..%2Fx");
        assert_eq!(percent_encode(b"bad\xff"), "bad%FF");
        assert_eq!(percent_encode("é".as_bytes()), "%C3%A9");
    }

    #[test]
    fn timestamps_are_utc() {
        assert_eq!(
            timestamp(UNIX_EPOCH).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400 + 3600 * 12 + 61);
        assert_eq!(timestamp(leap).as_deref(), Some("2000-02-29T12:01:01Z"));
        let late = UNIX_EPOCH + Duration::from_secs(1_798_000_000);
        assert_eq!(timestamp(late).as_deref(), Some("2026-12-23T04:26:40Z"));
        assert_eq!(timestamp(UNIX_EPOCH - Duration::from_secs(1)), None);
    }

    fn entry(name: &str, dir: bool, size: u64) -> Entry {
        Entry {
            name: name.into(),
            dir,
            size,
            modified: Some(UNIX_EPOCH + Duration::from_secs(size)),
        }
    }

    #[test]
    fn directories_come_first_and_the_key_orders_the_rest() {
        let params = |sort, order| Params {
            sort,
            order,
            json: false,
        };
        let mut entries = vec![
            entry("b", false, 1),
            entry("a", false, 3),
            entry("z", true, 0),
            entry("c", false, 2),
        ];
        let names = |entries: &[Entry]| {
            entries
                .iter()
                .map(|e| e.name.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        entries.sort_by(|a, b| rank(a, b, params(Sort::Name, Order::Asc)));
        assert_eq!(names(&entries), ["z", "a", "b", "c"]);
        entries.sort_by(|a, b| rank(a, b, params(Sort::Name, Order::Desc)));
        assert_eq!(names(&entries), ["z", "c", "b", "a"]);
        entries.sort_by(|a, b| rank(a, b, params(Sort::Size, Order::Desc)));
        assert_eq!(names(&entries), ["z", "a", "c", "b"]);
        entries.sort_by(|a, b| rank(a, b, params(Sort::Mtime, Order::Asc)));
        assert_eq!(names(&entries), ["z", "b", "c", "a"]);
    }

    #[test]
    fn the_roots_file_takes_the_string_and_the_object_form() {
        use super::super::StaticRoots;
        let base =
            std::env::temp_dir().join(format!("podgate-browse-roots-{}", std::process::id()));
        std::fs::create_dir_all(base.join("a")).expect("create a root");
        std::fs::create_dir_all(base.join("b")).expect("create a root");
        let file = base.join("roots.json");
        let (a, b) = (base.join("a"), base.join("b"));
        let write = |json: String| std::fs::write(&file, json).expect("write the roots file");
        write(format!(
            r#"{{"t1": {{"plain": "{}", "open": {{"path": "{}", "browse": true}}, "shut": {{"path": "{}"}}}}}}"#,
            a.display(),
            b.display(),
            a.display()
        ));
        let roots = StaticRoots::load(&file).expect("both forms load");
        let of = |name: &str| {
            roots
                .of("t1")
                .and_then(|set| set.get(name))
                .map(|r| r.browse_allowed())
        };
        assert_eq!(of("plain"), Some(false), "the string form is as before");
        assert_eq!(of("open"), Some(true));
        assert_eq!(of("shut"), Some(false));
        for bad in [
            format!(
                r#"{{"t1": {{"x": {{"path": "{}", "browse": "yes"}}}}}}"#,
                a.display()
            ),
            format!(
                r#"{{"t1": {{"x": {{"path": "{}", "listing": true}}}}}}"#,
                a.display()
            ),
            r#"{"t1": {"x": {"browse": true}}}"#.to_owned(),
            r#"{"t1": {"x": {"path": "relative", "browse": true}}}"#.to_owned(),
        ] {
            write(bad.clone());
            assert!(StaticRoots::load(&file).is_err(), "{bad}");
        }
        drop(std::fs::remove_dir_all(&base));
    }
}
