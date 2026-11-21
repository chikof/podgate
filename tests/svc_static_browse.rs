//! End to end: directory listings of the `static` service on the real binary. The operator opens
//! a root with `{"path": ..., "browse": true}` in `STATIC_ROOTS_FILE`; the service opts in with
//! `"browse": true`. Every test builds its own tree and starts its own `podgate`.

mod common;

use std::ffi::OsStr;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use common::{Podgate, Response, app, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const RESERVATION: u64 = 128 * 1024;

/// A tenant's buffer charge for a listing that may show `max_entries` entries.
const fn listing_charge(max_entries: u64) -> u64 {
    max_entries * 512 + 64 * 1024
}

/// A temporary tree and a running `podgate` serving it.
///
/// `<base>/root` is the root `site` of tenant `t1` (the operator allows listings), `<base>/closed`
/// is its root `closed` (a plain string entry: no listings), and `<base>/secret.txt` and
/// `<base>/outside` lie beside them.
struct Site {
    base: PathBuf,
    podgate: Podgate,
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("create parents");
    std::fs::write(path, content).expect("write a file");
}

fn set_mtime(path: &Path, seconds: u64) {
    std::fs::File::open(path)
        .expect("open for mtime")
        .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
        .expect("set the mtime");
}

fn populate(base: &Path) {
    let root = base.join("root");
    write(&base.join("secret.txt"), "TOPSECRET");
    write(&base.join("outside/inner.txt"), "TOPSECRET-INNER");
    write(&base.join("closed/file.txt"), "closed");
    write(&root.join("alpha.txt"), "a");
    write(&root.join("beta.txt"), "bbb");
    write(&root.join("gamma.txt"), "gg");
    write(&root.join("docs/readme.txt"), "readme");
    std::fs::create_dir_all(root.join("zeta")).expect("empty dir");
    write(&root.join("withindex/index.html"), "<h1>the index</h1>");
    write(&root.join("withindex/other.txt"), "other");
    set_mtime(&root.join("alpha.txt"), 3000);
    set_mtime(&root.join("beta.txt"), 1000);
    set_mtime(&root.join("gamma.txt"), 2000);
    set_mtime(&root.join("docs"), 500);
    set_mtime(&root.join("withindex"), 600);
    set_mtime(&root.join("zeta"), 700);
}

impl Site {
    async fn start() -> Self {
        let base = std::env::temp_dir().join(format!(
            "podgate-browse-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&base).expect("create the temp tree");
        populate(&base);
        let roots = base.join("roots.json");
        let declared = json!({
            "t1": {
                "site": { "path": base.join("root"), "browse": true },
                "closed": base.join("closed"),
            },
        });
        std::fs::write(&roots, declared.to_string()).expect("write the roots file");
        let roots = roots.to_string_lossy().into_owned();
        let podgate = Podgate::start_with_env(&[("STATIC_ROOTS_FILE", roots.as_str())]).await;
        Self { base, podgate }
    }

    fn root(&self) -> PathBuf {
        self.base.join("root")
    }

    /// Pushes app `a.test` of tenant `t1` whose service `web` is `static` with `config`.
    async fn serve(&self, version: u64, config: Value) -> Response {
        self.podgate
            .push_snapshot(&snapshot(version, &[static_app(config)]))
            .await
    }

    async fn serve_ok(&self, config: Value) {
        let pushed = self.serve(1, config).await;
        assert_eq!(pushed.status, 200, "snapshot refused: {}", pushed.body);
    }

    async fn browse(&self) {
        self.serve_ok(json!({ "root": "site", "browse": true }))
            .await;
    }

    async fn get(&self, path: &str) -> Response {
        self.podgate.get("a.test", path).await
    }

    async fn get_json(&self, path: &str) -> Value {
        let response = self
            .podgate
            .get_with_headers("a.test", path, &[("Accept", "application/json")])
            .await;
        assert_eq!(response.status, 200, "{response:?}");
        response.json()
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Drop for Site {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.base));
    }
}

fn static_app(config: Value) -> Value {
    let Value::Object(fields) = config else {
        panic!("config is an object");
    };
    let mut service = json!({ "name": "web", "type": "static" });
    service.as_object_mut().expect("object").extend(fields);
    let revision = json!({
        "id": "r1", "state": "serving", "weight": 100, "services": [service]
    });
    app("a", &["a.test"], &[revision])
}

fn conflict_codes(response: &Response) -> Vec<String> {
    response.json()["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|conflict| conflict["code"].as_str().expect("code").to_owned())
        .filter(|code| code != "unknown_service")
        .collect()
}

/// The `href` values of an HTML page, in order.
fn hrefs(page: &str) -> Vec<&str> {
    page.split("href=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect()
}

/// The entry names of a JSON listing, in order.
fn names(listing: &Value) -> Vec<String> {
    listing["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["name"].as_str().expect("name").to_owned())
        .collect()
}

fn mknod_fifo(path: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .expect("make a fifo");
}

// -- what is listed --------------------------------------------------------------------------

#[tokio::test]
async fn browse_lists_html() {
    let site = Site::start().await;
    site.browse().await;
    let response = site.get("/").await;
    assert_eq!(response.status, 200, "{response:?}");
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert!(response.body.contains("<title>Index of /</title>"));
    assert_eq!(
        hrefs(&response.body)
            .into_iter()
            .filter(|href| !href.starts_with('?'))
            .collect::<Vec<_>>(),
        [
            "docs/",
            "withindex/",
            "zeta/",
            "alpha.txt",
            "beta.txt",
            "gamma.txt"
        ],
        "directories first, then files, each sorted by name"
    );
    assert!(
        response.body.contains("<td>1970-01-01T00:50:00Z</td>"),
        "alpha.txt was modified at 3000 s: {}",
        response.body
    );
    assert!(!response.body.contains("<script"));
    let sub = site.get("/docs/").await;
    assert_eq!(sub.status, 200);
    assert!(sub.body.contains("<title>Index of /docs/</title>"));
    assert!(
        hrefs(&sub.body).contains(&"../"),
        "a parent link: {}",
        sub.body
    );
    assert!(hrefs(&sub.body).contains(&"readme.txt"));
    let head = site.podgate.request("HEAD", "a.test", "/", &[]).await;
    assert_eq!(head.status, 200);
    assert_eq!(head.body, "");
    assert_eq!(
        head.header("content-length"),
        Some(response.body.len().to_string().as_str())
    );
}

#[tokio::test]
async fn browse_lists_json() {
    let site = Site::start().await;
    site.browse().await;
    for listing in [site.get_json("/").await, {
        let response = site.get("/?format=json").await;
        assert_eq!(response.header("content-type"), Some("application/json"));
        response.json()
    }] {
        assert_eq!(listing["path"], "/");
        assert_eq!(listing["truncated"], false);
        assert_eq!(
            names(&listing),
            [
                "docs",
                "withindex",
                "zeta",
                "alpha.txt",
                "beta.txt",
                "gamma.txt"
            ]
        );
        let entries = listing["entries"].as_array().expect("entries");
        let docs = entries.first().expect("docs");
        assert_eq!(docs["type"], "dir");
        assert_eq!(docs["size"], Value::Null);
        assert_eq!(docs["href"], "docs/");
        let alpha = entries.get(3).expect("alpha");
        assert_eq!(alpha["type"], "file");
        assert_eq!(alpha["size"], 1);
        assert_eq!(alpha["modified"], "1970-01-01T00:50:00Z");
        assert_eq!(alpha["href"], "alpha.txt");
    }
    let forced = site
        .podgate
        .get_with_headers("a.test", "/?format=html", &[("Accept", "application/json")])
        .await;
    assert!(
        forced
            .header("content-type")
            .is_some_and(|kind| kind.starts_with("text/html")),
        "?format wins over Accept: {forced:?}"
    );
}

#[tokio::test]
async fn browse_sorting() {
    let site = Site::start().await;
    site.browse().await;
    let sorted = async |query: &str| names(&site.get_json(&format!("/?{query}")).await);
    let order = |names: [&str; 6]| names.map(str::to_owned).to_vec();
    assert_eq!(
        sorted("sort=name&order=asc").await,
        order([
            "docs",
            "withindex",
            "zeta",
            "alpha.txt",
            "beta.txt",
            "gamma.txt"
        ])
    );
    assert_eq!(
        sorted("sort=name&order=desc").await,
        order([
            "zeta",
            "withindex",
            "docs",
            "gamma.txt",
            "beta.txt",
            "alpha.txt"
        ])
    );
    assert_eq!(
        sorted("sort=size&order=asc").await,
        order([
            "docs",
            "withindex",
            "zeta",
            "alpha.txt",
            "gamma.txt",
            "beta.txt"
        ])
    );
    assert_eq!(
        sorted("sort=size&order=desc").await,
        order([
            "docs",
            "withindex",
            "zeta",
            "beta.txt",
            "gamma.txt",
            "alpha.txt"
        ])
    );
    assert_eq!(
        sorted("sort=mtime&order=asc").await,
        order([
            "docs",
            "withindex",
            "zeta",
            "beta.txt",
            "gamma.txt",
            "alpha.txt"
        ])
    );
    assert_eq!(
        sorted("sort=mtime&order=desc").await,
        order([
            "zeta",
            "withindex",
            "docs",
            "alpha.txt",
            "gamma.txt",
            "beta.txt"
        ])
    );
    assert_eq!(
        sorted("sort=bogus&order=sideways").await,
        order([
            "docs",
            "withindex",
            "zeta",
            "alpha.txt",
            "beta.txt",
            "gamma.txt"
        ]),
        "unknown values fall back to the defaults"
    );
    let page = site.get("/?sort=size&order=asc").await;
    assert!(
        page.body.contains("href=\"?sort=size&amp;order=desc\""),
        "the active column offers the opposite order: {}",
        page.body
    );
    assert!(page.body.contains("href=\"?sort=name&amp;order=asc\""));
}

#[tokio::test]
async fn browse_redirects_to_trailing_slash() {
    let site = Site::start().await;
    site.browse().await;
    let response = site.get("/docs").await;
    assert_eq!(response.status, 308, "{response:?}");
    assert_eq!(response.header("location"), Some("/docs/"));
    assert_eq!(response.header("content-length"), Some("0"));
    let query = site.get("/docs?sort=size&order=desc").await;
    assert_eq!(query.status, 308);
    assert_eq!(
        query.header("location"),
        Some("/docs/?sort=size&order=desc")
    );
    assert_eq!(
        site.get("/nope").await.status,
        404,
        "only directories redirect"
    );
    assert_eq!(
        site.get("/alpha.txt").await.body,
        "a",
        "files are served as before"
    );
}

// -- the two opt-ins -------------------------------------------------------------------------

#[tokio::test]
async fn browse_requires_root_and_service_opt_in() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site" })).await;
    for path in ["/", "/docs/", "/docs"] {
        let response = site.get(path).await;
        assert_eq!(
            response.status, 404,
            "{path}: a service that did not opt in lists nothing"
        );
        assert_eq!(response.json(), json!({ "error": "not found" }));
    }
    let pushed = site
        .serve(2, json!({ "root": "site", "browse": true }))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(site.get("/docs/").await.status, 200);
    let closed = site
        .serve(3, json!({ "root": "closed", "browse": false }))
        .await;
    assert_eq!(closed.status, 200, "{}", closed.body);
    assert_eq!(site.get("/").await.status, 404);
    assert_eq!(site.get("/file.txt").await.body, "closed");
}

#[tokio::test]
async fn browse_snapshot_cannot_enable_for_closed_root() {
    let site = Site::start().await;
    let refused = site
        .serve(1, json!({ "root": "closed", "browse": true }))
        .await;
    assert_eq!(refused.status, 422, "{}", refused.body);
    assert_eq!(conflict_codes(&refused), ["static_browse_not_allowed"]);
    assert_eq!(
        site.get("/").await.status,
        404,
        "the refused snapshot is not live"
    );
    for (version, config) in [
        (2, json!({ "root": "site", "hide": ["*.bak"] })),
        (3, json!({ "root": "site", "max_entries": 5 })),
        (
            4,
            json!({ "root": "site", "browse": true, "max_entries": 0 }),
        ),
        (
            5,
            json!({ "root": "site", "browse": true, "max_entries": 10_001 }),
        ),
        (
            6,
            json!({ "root": "site", "browse": true, "hide": ["a/b"] }),
        ),
        (7, json!({ "root": "site", "browse": true, "hide": [""] })),
    ] {
        let response = site.serve(version, config.clone()).await;
        assert_eq!(response.status, 422, "{config}: {}", response.body);
        assert_eq!(conflict_codes(&response), ["invalid_service"], "{config}");
    }
}

// -- what is left out ------------------------------------------------------------------------

#[tokio::test]
async fn browse_hides_dotfiles_and_globs() {
    let site = Site::start().await;
    let root = site.root();
    write(&root.join(".env"), "SECRET=1");
    write(&root.join(".git/config"), "[core]");
    write(&root.join(".well-known/ok.txt"), "well-known");
    write(&root.join("notes.bak"), "old");
    write(&root.join("sub.bak/x.txt"), "x");
    write(&root.join("keep.txt"), "keep");
    write(&root.join("tmp~"), "t");
    site.serve_ok(json!({
        "root": "site", "browse": true, "hide": ["*.bak", "tmp?"],
    }))
    .await;
    let listing = names(&site.get_json("/").await);
    for hidden in [
        ".env",
        ".git",
        ".well-known",
        "notes.bak",
        "sub.bak",
        "tmp~",
    ] {
        assert!(
            !listing.iter().any(|name| name == hidden),
            "{hidden}: {listing:?}"
        );
    }
    assert!(listing.iter().any(|name| name == "keep.txt"), "{listing:?}");
    let page = site.get("/").await.body;
    assert!(!page.contains(".env") && !page.contains(".git"), "{page}");
    assert_eq!(site.get("/.git/").await.status, 404);
    assert_eq!(site.get("/.well-known/").await.status, 404);
}

#[tokio::test]
async fn browse_omits_special_files() {
    let site = Site::start().await;
    let root = site.root();
    mknod_fifo(&root.join("pipe"));
    let socket = std::os::unix::net::UnixListener::bind(root.join("sock")).expect("bind a socket");
    site.browse().await;
    let listing = names(&site.get_json("/").await);
    assert!(
        listing.iter().any(|name| name == "alpha.txt"),
        "{listing:?}"
    );
    for special in ["pipe", "sock"] {
        assert!(
            !listing.iter().any(|name| name == special),
            "{special}: {listing:?}"
        );
    }
    drop(socket);
}

#[tokio::test]
async fn browse_symlink_escape_omitted() {
    let site = Site::start().await;
    let (root, base) = (site.root(), site.base.clone());
    symlink("alpha.txt", root.join("inside.txt")).expect("link inside");
    symlink("docs", root.join("inside-dir")).expect("directory link inside");
    symlink("../secret.txt", root.join("up")).expect("relative escape");
    symlink(base.join("secret.txt"), root.join("abs")).expect("absolute escape");
    symlink("../outside", root.join("dirlink")).expect("directory escape");
    symlink("nope", root.join("dangling")).expect("dangling link");
    symlink("../alpha.txt", root.join("docs/uplink")).expect("link up but inside");
    symlink("../../secret.txt", root.join("docs/out")).expect("link out from a subdirectory");
    site.browse().await;
    let top = site.get_json("/").await;
    let listing = names(&top);
    for shown in ["inside.txt", "inside-dir"] {
        assert!(
            listing.iter().any(|name| name == shown),
            "{shown}: {listing:?}"
        );
    }
    for omitted in ["up", "abs", "dirlink", "dangling"] {
        assert!(
            !listing.iter().any(|name| name == omitted),
            "{omitted}: {listing:?}"
        );
    }
    let entries = top["entries"].as_array().expect("entries");
    let kind_of = |name: &str| {
        entries
            .iter()
            .find(|entry| entry["name"] == name)
            .map(|entry| entry["type"].clone())
    };
    assert_eq!(kind_of("inside.txt"), Some(json!("file")));
    assert_eq!(kind_of("inside-dir"), Some(json!("dir")));
    let docs = names(&site.get_json("/docs/").await);
    assert!(docs.iter().any(|name| name == "uplink"), "{docs:?}");
    assert!(!docs.iter().any(|name| name == "out"), "{docs:?}");
    let page = site.get("/").await.body;
    assert!(
        !page.contains("TOPSECRET") && !page.contains("secret.txt"),
        "{page}"
    );
}

#[tokio::test]
async fn browse_never_shows_link_target() {
    let site = Site::start().await;
    let root = site.root();
    write(&root.join("deep/zz-target.txt"), "target");
    symlink("deep/zz-target.txt", root.join("pointer")).expect("link");
    site.browse().await;
    for body in [
        site.get("/").await.body,
        site.get("/?format=json").await.body,
    ] {
        assert!(body.contains("pointer"), "{body}");
        assert!(
            !body.contains("zz-target"),
            "the target of a link is never shown: {body}"
        );
    }
    let sizes = site.get_json("/").await;
    let pointer = sizes["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|entry| entry["name"] == "pointer")
        .expect("pointer is listed")
        .clone();
    assert_eq!(pointer["size"], 6, "it is listed as what it points at");
}

// -- hostile names ---------------------------------------------------------------------------

#[tokio::test]
async fn browse_escapes_html_names() {
    let site = Site::start().await;
    let root = site.root();
    for name in [
        "<img src=x onerror=alert(1)>.txt",
        "\"quoted\".txt",
        "a&b.txt",
        "it's.txt",
        "<script>alert(1)<script>",
    ] {
        write(&root.join(name), "x");
    }
    write(&root.join("<i>d/inner.txt"), "x");
    site.browse().await;
    let page = site.get("/").await.body;
    assert!(
        page.contains("&lt;img src=x onerror=alert(1)&gt;.txt"),
        "{page}"
    );
    assert!(page.contains("&quot;quoted&quot;.txt"), "{page}");
    assert!(page.contains("a&amp;b.txt"), "{page}");
    assert!(page.contains("it&#39;s.txt"), "{page}");
    assert!(
        page.contains("&lt;script&gt;alert(1)&lt;script&gt;"),
        "{page}"
    );
    for injected in ["<img", "<script", "\"quoted\"", "onerror=alert(1)>"] {
        assert!(!page.contains(injected), "{injected}: {page}");
    }
    let sub = site.get("/%3Ci%3Ed/").await;
    assert_eq!(sub.status, 200, "{sub:?}");
    assert!(sub.body.contains("Index of /&lt;i&gt;d/"), "{}", sub.body);
    assert!(!sub.body.contains("<i>"), "{}", sub.body);
}

#[tokio::test]
async fn browse_escapes_bidi_controls() {
    let site = Site::start().await;
    let root = site.root();
    for name in [
        "evil\u{202e}txt.exe",
        "line\nbreak.txt",
        "iso\u{2066}x\u{2069}.txt",
        "esc\u{1b}[31m.txt",
        "del\u{7f}.txt",
        "mark\u{200e}.txt",
    ] {
        write(&root.join(name), "x");
    }
    site.browse().await;
    let page = site.get("/").await.body;
    for escaped in [
        "evil\\u202etxt.exe",
        "line\\u000abreak.txt",
        "iso\\u2066x\\u2069.txt",
        "esc\\u001b[31m.txt",
        "del\\u007f.txt",
        "mark\\u200e.txt",
    ] {
        assert!(page.contains(escaped), "{escaped}: {page}");
    }
    let json = site.get("/?format=json").await;
    for body in [&page, &json.body] {
        for raw in [
            '\u{202e}', '\u{2066}', '\u{2069}', '\u{1b}', '\u{7f}', '\u{200e}',
        ] {
            assert!(
                !body.contains(raw),
                "{raw:?} must not reach the wire: {body}"
            );
        }
    }
    assert!(
        !page.contains("line\nbreak") && !page.contains("<td><a href=\"break"),
        "a newline in a name does not break the row: {page}"
    );
    let listing = json.json();
    assert!(
        names(&listing)
            .iter()
            .any(|name| name == "evil\u{202e}txt.exe"),
        "JSON keeps the exact name: {listing}"
    );
}

#[tokio::test]
async fn browse_href_percent_encoded() {
    let site = Site::start().await;
    let root = site.root();
    for name in [
        "a b#c?d:e.txt",
        "javascript:alert(1)",
        "%2e%2e",
        "é.txt",
        "semi;colon",
        "100%.txt",
    ] {
        write(&root.join(name), "body");
    }
    site.browse().await;
    let page = site.get("/").await.body;
    let links = hrefs(&page);
    for expected in [
        "a%20b%23c%3Fd%3Ae.txt",
        "javascript%3Aalert%281%29",
        "%252e%252e",
        "%C3%A9.txt",
        "semi%3Bcolon",
        "100%25.txt",
    ] {
        assert!(links.contains(&expected), "{expected}: {links:?}");
    }
    for link in links.iter().filter(|link| !link.starts_with('?')) {
        assert!(
            !link.contains([':', ' ', '?', '#', ';', '"', '<']),
            "{link} could be read as something other than a path segment"
        );
    }
    for link in ["a%20b%23c%3Fd%3Ae.txt", "100%25.txt", "%252e%252e"] {
        let followed = site.get(&format!("/{link}")).await;
        assert_eq!(
            (followed.status, followed.body.as_str()),
            (200, "body"),
            "{link}"
        );
    }
    let listing = site.get_json("/").await;
    let hrefs: Vec<&str> = listing["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["href"].as_str().expect("href"))
        .collect();
    assert!(hrefs.contains(&"javascript%3Aalert%281%29"), "{hrefs:?}");
}

#[tokio::test]
async fn browse_invalid_utf8_names() {
    let site = Site::start().await;
    let name = OsStr::from_bytes(b"bad\xff.txt");
    write(&site.root().join(name), "x");
    site.browse().await;
    let page = site.get("/").await.body;
    assert!(page.contains("bad\u{fffd}.txt"), "shown lossily: {page}");
    assert!(
        hrefs(&page).contains(&"bad%FF.txt"),
        "linked by its bytes: {page}"
    );
    let listing = site.get_json("/").await;
    assert!(names(&listing).iter().any(|name| name == "bad\u{fffd}.txt"));
    assert!(
        listing["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(|entry| entry["href"] == "bad%FF.txt")
    );
}

// -- bounds ----------------------------------------------------------------------------------

#[tokio::test]
async fn browse_truncates_large_directory() {
    let site = Site::start().await;
    for index in 0..30 {
        write(&site.root().join(format!("big/f{index:02}.txt")), "x");
    }
    for index in 0..10 {
        write(&site.root().join(format!("ten/g{index}.txt")), "x");
    }
    site.serve_ok(json!({ "root": "site", "browse": true, "max_entries": 10 }))
        .await;
    let listing = site.get_json("/big/").await;
    assert_eq!(listing["truncated"], true);
    assert_eq!(
        names(&listing),
        (0..10).map(|i| format!("f{i:02}.txt")).collect::<Vec<_>>(),
        "the first entries in sorted order"
    );
    let page = site.get("/big/").await.body;
    assert!(page.contains("truncated"), "{page}");
    assert_eq!(page.matches("<td><a href=\"f").count(), 10, "{page}");
    let descending = site.get_json("/big/?order=desc").await;
    assert_eq!(
        names(&descending),
        (20..30)
            .rev()
            .map(|i| format!("f{i:02}.txt"))
            .collect::<Vec<_>>()
    );
    let exact = site.get_json("/ten/").await;
    assert_eq!(
        exact["truncated"], false,
        "exactly max_entries is not truncated"
    );
    assert_eq!(names(&exact).len(), 10);
    assert!(!site.get("/ten/").await.body.contains("truncated"));
}

fn buffered_in(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.trim().parse().expect("a number"))
}

async fn buffered(podgate: &Podgate, name: &str) -> u64 {
    buffered_in(&podgate.admin_get("/metrics").await.body, name)
}

async fn wait_until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !done().await {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn browse_charges_tenant_buffer() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "browse": true, "max_entries": 10 }))
        .await;
    assert_eq!(
        buffered(&site.podgate, "podgate_tenant_buffer_bytes_peak").await,
        0
    );
    assert_eq!(site.get("/docs/").await.status, 200);
    assert_eq!(
        buffered(&site.podgate, "podgate_tenant_buffer_bytes_peak").await,
        RESERVATION + listing_charge(10),
        "the read reservation plus 512 bytes per entry and the page buffer"
    );
    wait_until("the charge to end", async || {
        buffered(&site.podgate, "podgate_tenant_buffer_bytes").await == 0
    })
    .await;
}

/// Sends `GET path` and reads until the response header is complete; the stream stays open with
/// the body unread.
async fn begin(addr: SocketAddr, host: &str, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read the header");
            assert_eq!(read, 1, "the connection ended inside the header");
            head.push(byte[0]);
        }
    })
    .await
    .expect("header in time");
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    stream
}

#[tokio::test]
async fn browse_over_budget_503() {
    let site = Site::start().await;
    let file = std::fs::File::create(site.root().join("big.bin")).expect("create");
    file.set_len(512 << 20).expect("sparse file");
    let needed = RESERVATION + listing_charge(1000);
    let snapshot_with = |version: u64, budget: u64| {
        let mut pushed = snapshot(
            version,
            &[static_app(json!({ "root": "site", "browse": true }))],
        );
        pushed["tenants"][0]["budget"]["max_buffer_bytes"] = json!(budget);
        pushed
    };
    let too_small = site
        .podgate
        .push_snapshot(&snapshot_with(1, needed - 1))
        .await;
    assert_eq!(too_small.status, 422, "{}", too_small.body);
    assert_eq!(conflict_codes(&too_small), ["invalid_service"]);
    let pushed = site.podgate.push_snapshot(&snapshot_with(2, needed)).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(
        site.get("/docs/").await.status,
        200,
        "alone, a listing fits"
    );
    let held = begin(site.podgate.proxy_addr, "a.test", "/big.bin").await;
    let refused = site.get("/docs/").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        site.get("/alpha.txt").await.status,
        200,
        "a file still fits beside the download"
    );
    assert!(
        buffered(&site.podgate, "podgate_tenant_buffer_bytes_peak").await <= needed,
        "the budget is never passed, not even briefly"
    );
    drop(held);
    wait_until("the held response to end", async || {
        site.get("/docs/").await.status == 200
    })
    .await;
}

// -- headers and disclosure ------------------------------------------------------------------

#[tokio::test]
async fn browse_security_headers() {
    let site = Site::start().await;
    site.browse().await;
    for path in ["/", "/?format=json"] {
        let response = site.get(path).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("content-security-policy"),
            Some("default-src 'none'"),
            "{path}"
        );
        assert_eq!(
            response.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(response.header("cache-control"), Some("no-cache"), "{path}");
    }
    let page = site.get("/").await.body;
    for forbidden in ["<script", "<style", " style=", " onclick", "javascript:"] {
        assert!(!page.contains(forbidden), "{forbidden}: {page}");
    }
}

#[tokio::test]
async fn browse_never_discloses_root_path() {
    let site = Site::start().await;
    site.browse().await;
    let base = site.base.to_string_lossy().into_owned();
    let mut seen = vec![
        site.get("/").await,
        site.get("/docs/").await,
        site.get("/?format=json").await,
        site.get("/docs").await,
        site.get("/nope/").await,
        site.get("/docs/?sort=%00&order=%ff").await,
    ];
    seen.push(
        site.podgate
            .get_with_headers("a.test", "/", &[("Accept", "application/json")])
            .await,
    );
    for response in seen {
        let everything = format!("{} {:?}", response.body, response.headers);
        assert!(!everything.contains(&base), "{everything}");
        assert!(!everything.contains("podgate-browse"), "{everything}");
    }
}

// -- interplay -------------------------------------------------------------------------------

#[tokio::test]
async fn browse_index_file_wins() {
    let site = Site::start().await;
    site.browse().await;
    let indexed = site.get("/withindex/").await;
    assert_eq!(indexed.status, 200);
    assert_eq!(indexed.body, "<h1>the index</h1>");
    assert!(
        indexed
            .header("content-type")
            .is_some_and(|kind| kind.starts_with("text/html")),
        "{indexed:?}"
    );
    assert_eq!(
        indexed.header("content-security-policy"),
        None,
        "it is the file, not a listing"
    );
    let redirected = site.get("/withindex").await;
    assert_eq!(redirected.status, 308);
    assert_eq!(redirected.header("location"), Some("/withindex/"));
    // `try_files` and `status_pages` are tried before a listing.
    write(&site.root().join("404.html"), "custom not found");
    let pushed = site
        .serve(
            2,
            json!({
                "root": "site", "browse": true,
                "try_files": ["{path}", "/withindex/index.html"],
                "status_pages": { "404": "/404.html" },
            }),
        )
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(
        site.get("/zeta/").await.body,
        "<h1>the index</h1>",
        "the fallback is tried before a listing"
    );
    let pushed = site
        .serve(
            3,
            json!({
                "root": "site", "browse": true,
                "status_pages": { "404": "/404.html" },
            }),
        )
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(site.get("/nope/").await.body, "custom not found");
    let listed = site.get("/zeta/").await;
    assert_eq!(listed.status, 200);
    assert!(listed.body.contains("Index of /zeta/"), "{}", listed.body);
}
