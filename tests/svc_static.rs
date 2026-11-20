//! End to end: the `static` service on the real binary. Static roots come from the operator's
//! `STATIC_ROOTS_FILE`; every test builds its own temporary tree and starts its own `podgate`.

mod common;

use std::net::SocketAddr;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{Podgate, Response, app, snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const SECRET: &str = "TOPSECRET";
const GIB: u64 = 1 << 30;

/// A temporary tree and a running `podgate` that serves roots from it.
///
/// `<base>/root` is the static root of tenant `t1` (named `site`), `<base>/theirs` the root of
/// tenant `t2` (named `theirs`), `<base>/secret.txt` and `<base>/outside` are beside the root and
/// must never be served.
struct Site {
    base: PathBuf,
    podgate: Podgate,
}

fn temp_base(name: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let base = std::env::temp_dir().join(format!(
        "podgate-static-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&base).expect("create the temp tree");
    base
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("create parents");
    std::fs::write(path, content).expect("write a file");
}

fn populate(base: &Path) {
    let root = base.join("root");
    write(&base.join("secret.txt"), SECRET);
    write(&base.join("outside/inner.txt"), "TOPSECRET-INNER");
    write(&root.join("hello.txt"), "hello static\n");
    write(&root.join("range.txt"), "0123456789");
    write(&root.join("index.html"), "<h1>home</h1>");
    write(&root.join("sub/index.html"), "sub home");
    write(&root.join("sub/page.html"), "<p>page</p>");
    write(&root.join("404.html"), "custom not found");
    write(&root.join("app.js"), "console.log('plain');");
    write(&root.join("app.js.br"), "BROTLI-BYTES");
    write(&root.join("app.js.gz"), "GZIP-BYTES");
    write(&root.join("plain.js"), "console.log('only plain');");
    write(&root.join(".env"), "SECRET=1");
    write(&root.join(".git/config"), "[core]");
    write(&root.join(".well-known/ok.txt"), "well-known");
    std::fs::create_dir_all(root.join("emptydir")).expect("empty dir");
    symlink("hello.txt", root.join("alias.txt")).expect("link inside");
    symlink("../secret.txt", root.join("up")).expect("relative escape");
    symlink("../outside", root.join("dirlink")).expect("directory escape");
    symlink(base.join("secret.txt"), root.join("abs")).expect("absolute escape");
    write(&base.join("theirs/theirs.txt"), "tenant two");
}

impl Site {
    async fn start() -> Self {
        Self::start_with(&[]).await
    }

    async fn start_with(env: &[(&str, &str)]) -> Self {
        let base = temp_base("site");
        populate(&base);
        let roots = base.join("roots.json");
        let json = json!({
            "t1": { "site": base.join("root"), "other": base.join("outside") },
            "t2": { "theirs": base.join("theirs") },
        });
        std::fs::write(&roots, json.to_string()).expect("write the roots file");
        let roots = roots.to_string_lossy().into_owned();
        let mut vars = vec![("STATIC_ROOTS_FILE", roots.as_str())];
        vars.extend_from_slice(env);
        let podgate = Podgate::start_with_env(&vars).await;
        Self { base, podgate }
    }

    fn root(&self) -> PathBuf {
        self.base.join("root")
    }

    /// Pushes one app `a.test` of tenant `t1` whose service `web` is `static` with `config`.
    async fn serve(&self, version: u64, config: Value) -> Response {
        self.podgate
            .push_snapshot(&snapshot(
                version,
                &[static_app("a", "t1", "a.test", config)],
            ))
            .await
    }

    async fn serve_ok(&self, config: Value) {
        let pushed = self.serve(1, config).await;
        assert_eq!(pushed.status, 200, "snapshot refused: {}", pushed.body);
    }

    async fn get(&self, path: &str) -> Response {
        self.podgate.get("a.test", path).await
    }

    async fn get_with(&self, path: &str, headers: &[(&str, &str)]) -> Response {
        self.podgate.get_with_headers("a.test", path, headers).await
    }
}

impl Drop for Site {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.base));
    }
}

/// An app `id` of `tenant` answering `host` with a serving revision whose service `web` is
/// `static` with `config`.
fn static_app(id: &str, tenant: &str, host: &str, config: Value) -> Value {
    let Value::Object(fields) = config else {
        panic!("config is an object");
    };
    let mut service = json!({ "name": "web", "type": "static" });
    service.as_object_mut().expect("object").extend(fields);
    let revision = json!({
        "id": "r1", "state": "serving", "weight": 100, "services": [service]
    });
    let mut app = app(id, &[host], &[revision]);
    app["tenant"] = json!(tenant);
    app
}

fn site_config() -> Value {
    json!({ "root": "site" })
}

/// The codes of a `422`, without `unknown_service`: a service that did not compile leaves its
/// router with nothing to point at, which the compiler reports next to the cause.
fn conflict_codes(response: &Response) -> Vec<String> {
    response.json()["conflicts"]
        .as_array()
        .expect("conflicts")
        .iter()
        .map(|conflict| conflict["code"].as_str().expect("code").to_owned())
        .filter(|code| code != "unknown_service")
        .collect()
}

#[tokio::test]
async fn static_serves_file_with_headers() {
    let site = Site::start().await;
    site.serve_ok(json!({
        "root": "site",
        "cache_control": { "default": "no-cache", "by_extension": { "txt": "public, max-age=60" } },
    }))
    .await;
    let response = site.get("/hello.txt").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello static\n");
    assert_eq!(
        response.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(response.header("content-length"), Some("13"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(response.header("accept-ranges"), Some("bytes"));
    assert_eq!(response.header("cache-control"), Some("public, max-age=60"));
    assert!(
        response
            .header("etag")
            .is_some_and(|tag| tag.starts_with("W/\"")),
        "{response:?}"
    );
    assert!(
        response
            .header("last-modified")
            .is_some_and(|date| date.ends_with("GMT"))
    );
    let other = site.get("/plain.js").await;
    assert_eq!(
        other.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert_eq!(other.header("cache-control"), Some("no-cache"));
    assert_eq!(
        site.get("/range.txt").await.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    let opaque = site.get("/hello.txt").await;
    assert_eq!(opaque.status, 200);
}

#[tokio::test]
async fn static_head_matches_get() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let get = site.get("/hello.txt").await;
    let head = site
        .podgate
        .request("HEAD", "a.test", "/hello.txt", &[])
        .await;
    assert_eq!(head.status, 200);
    assert_eq!(head.body, "");
    for name in [
        "content-type",
        "content-length",
        "etag",
        "last-modified",
        "accept-ranges",
        "x-content-type-options",
    ] {
        assert_eq!(head.header(name), get.header(name), "{name}");
        assert!(head.header(name).is_some(), "{name} is present");
    }
    let ranged = site
        .podgate
        .request("HEAD", "a.test", "/range.txt", &[("Range", "bytes=2-4")])
        .await;
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.header("content-length"), Some("3"));
    assert_eq!(ranged.body, "");
}

#[tokio::test]
async fn static_index_file() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    assert_eq!(site.get("/").await.body, "<h1>home</h1>");
    assert_eq!(
        site.get("/").await.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(site.get("/sub/").await.body, "sub home");
    let redirect = site.get("/sub?x=1").await;
    assert_eq!(redirect.status, 308);
    assert_eq!(redirect.header("location"), Some("/sub/?x=1"));
    site.podgate
        .push_snapshot(&snapshot(
            2,
            &[static_app(
                "a",
                "t1",
                "a.test",
                json!({ "root": "site", "index": ["missing.html", "page.html"] }),
            )],
        ))
        .await;
    assert_eq!(site.get("/sub/").await.body, "<p>page</p>");
}

#[tokio::test]
async fn static_try_files_spa_fallback() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "try_files": ["{path}", "/index.html"] }))
        .await;
    let route = site.get("/app/deep/route").await;
    assert_eq!(route.status, 200);
    assert_eq!(route.body, "<h1>home</h1>");
    assert_eq!(site.get("/hello.txt").await.body, "hello static\n");
    assert_eq!(site.get("/").await.body, "<h1>home</h1>");
    site.podgate
        .push_snapshot(&snapshot(
            2,
            &[static_app(
                "a",
                "t1",
                "a.test",
                json!({ "root": "site", "try_files": ["{path}.html", "{path}/index.html", "404"] }),
            )],
        ))
        .await;
    assert_eq!(site.get("/sub/page").await.body, "<p>page</p>");
    assert_eq!(site.get("/sub").await.body, "sub home");
    assert_eq!(site.get("/nothing").await.status, 404);
}

#[tokio::test]
async fn static_status_page() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "status_pages": { "404": "/404.html" } }))
        .await;
    let missing = site.get("/nope").await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, "custom not found");
    assert_eq!(
        missing.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    let hidden = site.get("/.env").await;
    assert_eq!(hidden.status, 404);
    assert_eq!(hidden.body, "custom not found");
    site.podgate
        .push_snapshot(&snapshot(
            2,
            &[static_app("a", "t1", "a.test", site_config())],
        ))
        .await;
    let plain = site.get("/nope").await;
    assert_eq!(plain.status, 404);
    assert_eq!(plain.json(), json!({ "error": "not found" }));
}

#[tokio::test]
async fn static_if_none_match_304() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "cache_control": { "default": "no-cache" } }))
        .await;
    let first = site.get("/hello.txt").await;
    let etag = first.header("etag").expect("etag").to_owned();
    let modified = first
        .header("last-modified")
        .expect("last-modified")
        .to_owned();
    let same = site
        .get_with("/hello.txt", &[("If-None-Match", &etag)])
        .await;
    assert_eq!(same.status, 304);
    assert_eq!(same.body, "");
    assert_eq!(same.header("etag"), Some(etag.as_str()));
    assert_eq!(same.header("cache-control"), Some("no-cache"));
    let listed = site
        .get_with(
            "/hello.txt",
            &[("If-None-Match", &format!("\"x\", {etag}"))],
        )
        .await;
    assert_eq!(listed.status, 304);
    let star = site.get_with("/hello.txt", &[("If-None-Match", "*")]).await;
    assert_eq!(star.status, 304);
    let other = site
        .get_with("/hello.txt", &[("If-None-Match", "W/\"0-0\"")])
        .await;
    assert_eq!(other.status, 200);
    let since = site
        .get_with("/hello.txt", &[("If-Modified-Since", &modified)])
        .await;
    assert_eq!(since.status, 304);
    let old = site
        .get_with(
            "/hello.txt",
            &[("If-Modified-Since", "Thu, 01 Jan 1970 00:00:01 GMT")],
        )
        .await;
    assert_eq!(old.status, 200);
    let precedence = site
        .get_with(
            "/hello.txt",
            &[
                ("If-None-Match", "W/\"0-0\""),
                ("If-Modified-Since", &modified),
            ],
        )
        .await;
    assert_eq!(
        precedence.status, 200,
        "If-None-Match wins over If-Modified-Since"
    );
}

#[tokio::test]
async fn static_single_range_206() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let first = site.get_with("/range.txt", &[("Range", "bytes=2-5")]).await;
    assert_eq!(first.status, 206);
    assert_eq!(first.body, "2345");
    assert_eq!(first.header("content-range"), Some("bytes 2-5/10"));
    assert_eq!(first.header("content-length"), Some("4"));
    let suffix = site.get_with("/range.txt", &[("Range", "bytes=-3")]).await;
    assert_eq!((suffix.status, suffix.body.as_str()), (206, "789"));
    let open = site.get_with("/range.txt", &[("Range", "bytes=7-")]).await;
    assert_eq!((open.status, open.body.as_str()), (206, "789"));
    let date = site.get("/range.txt").await;
    let modified = date
        .header("last-modified")
        .expect("last-modified")
        .to_owned();
    let honoured = site
        .get_with(
            "/range.txt",
            &[("Range", "bytes=0-1"), ("If-Range", &modified)],
        )
        .await;
    assert_eq!((honoured.status, honoured.body.as_str()), (206, "01"));
    let stale = site
        .get_with(
            "/range.txt",
            &[
                ("Range", "bytes=0-1"),
                ("If-Range", "Thu, 01 Jan 1970 00:00:01 GMT"),
            ],
        )
        .await;
    assert_eq!((stale.status, stale.body.as_str()), (200, "0123456789"));
}

#[tokio::test]
async fn static_unsatisfiable_416() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let response = site
        .get_with("/range.txt", &[("Range", "bytes=50-60")])
        .await;
    assert_eq!(response.status, 416);
    assert_eq!(response.header("content-range"), Some("bytes */10"));
    assert_eq!(response.body, "");
}

#[tokio::test]
async fn static_multi_range_full_body() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let response = site
        .get_with("/range.txt", &[("Range", "bytes=0-1,4-5,8-9")])
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "0123456789");
    assert_eq!(response.header("content-range"), None);
    assert!(
        response
            .header("content-type")
            .is_some_and(|kind| !kind.starts_with("multipart/")),
        "{response:?}"
    );
}

#[tokio::test]
async fn static_precompressed_chosen() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "precompressed": ["br", "gzip"] }))
        .await;
    let brotli = site
        .get_with("/app.js", &[("Accept-Encoding", "gzip, br")])
        .await;
    assert_eq!(brotli.status, 200);
    assert_eq!(brotli.body, "BROTLI-BYTES");
    assert_eq!(brotli.header("content-encoding"), Some("br"));
    assert_eq!(
        brotli.header("content-type"),
        Some("text/javascript; charset=utf-8"),
        "the type is the file's, not the sidecar's"
    );
    assert_eq!(brotli.header("vary"), Some("accept-encoding"));
    let gzip = site
        .get_with("/app.js", &[("Accept-Encoding", "gzip")])
        .await;
    assert_eq!(gzip.body, "GZIP-BYTES");
    assert_eq!(gzip.header("content-encoding"), Some("gzip"));
    assert_ne!(gzip.header("etag"), brotli.header("etag"));
    let weighted = site
        .get_with("/app.js", &[("Accept-Encoding", "br;q=0, gzip")])
        .await;
    assert_eq!(weighted.body, "GZIP-BYTES");
    let plain = site.get("/app.js").await;
    assert_eq!(plain.body, "console.log('plain');");
    assert_eq!(plain.header("content-encoding"), None);
}

#[tokio::test]
async fn static_precompressed_missing_falls_back() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "precompressed": ["br", "gzip"] }))
        .await;
    let response = site
        .get_with("/plain.js", &[("Accept-Encoding", "br, gzip")])
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "console.log('only plain');");
    assert_eq!(response.header("content-encoding"), None);
    assert_eq!(response.header("vary"), Some("accept-encoding"));
    let sidecar_only = site
        .get_with("/app.js", &[("Accept-Encoding", "identity")])
        .await;
    assert_eq!(sidecar_only.body, "console.log('plain');");
}

/// What a traversal attempt may answer: never the secret, never a file.
fn assert_refused(response: &Response, what: &str) {
    assert!(
        matches!(response.status, 400 | 404),
        "{what}: {} {:?}",
        response.status,
        response.body
    );
    assert!(
        !response.body.contains("TOPSECRET"),
        "{what} leaked the secret"
    );
}

#[tokio::test]
async fn static_traversal_dotdot_refused() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for path in [
        "/../secret.txt",
        "/../../secret.txt",
        "/sub/../../secret.txt",
        "/sub/../../outside/inner.txt",
        "/./../secret.txt",
        "/%2e%2e/secret.txt",
        "/%2E%2E/%2E%2E/secret.txt",
        "/sub/%2e%2e/%2e%2e/secret.txt",
    ] {
        assert_refused(&site.get(path).await, path);
    }
    // Dot segments collapse to the root, which is inside it: the index, never the parent.
    for path in ["/..", "/../", "/../../.."] {
        assert_eq!(site.get(path).await.body, "<h1>home</h1>", "{path}");
    }
    assert_eq!(site.get("/sub/../hello.txt").await.body, "hello static\n");
}

#[tokio::test]
async fn static_traversal_encoded_refused() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for path in [
        "/..%2fsecret.txt",
        "/%2e%2e%2fsecret.txt",
        "/sub%2f..%2f..%2fsecret.txt",
        "/%252e%252e/secret.txt",
        "/%252e%252e%252fsecret.txt",
        "/%2e%2e;/secret.txt",
        "/..%252fsecret.txt",
        "/%c0%ae%c0%ae/secret.txt",
        "/%2e%2e%5csecret.txt",
        "/sub/%2e%2e%2f%2e%2e%2fsecret.txt",
    ] {
        assert_refused(&site.get(path).await, path);
    }
}

#[tokio::test]
async fn static_nul_and_backslash_refused() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for path in [
        "/hello.txt%00.png",
        "/%00",
        "/..%5csecret.txt",
        "/sub%5c..%5c..%5csecret.txt",
        "/%5c..%5csecret.txt",
        "/hello.txt%5c",
        "/..\\secret.txt",
        "/sub\\..\\..\\secret.txt",
    ] {
        assert_refused(&site.get(path).await, path);
    }
}

#[tokio::test]
async fn static_symlink_escape_refused() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for path in ["/up", "/dirlink/inner.txt", "/dirlink", "/dirlink/"] {
        let response = site.get(path).await;
        assert_eq!(response.status, 404, "{path}");
        assert!(!response.body.contains("TOPSECRET"), "{path}");
    }
    // Planting a link after the service started changes nothing: the check is per open.
    symlink("../secret.txt", site.root().join("late")).expect("late link");
    assert_eq!(site.get("/late").await.status, 404);
}

#[tokio::test]
async fn static_absolute_symlink_refused() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let response = site.get("/abs").await;
    assert_eq!(response.status, 404);
    assert!(!response.body.contains("TOPSECRET"));
}

#[tokio::test]
async fn static_symlink_inside_root_served() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    let response = site.get("/alias.txt").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "hello static\n");
}

#[tokio::test]
async fn static_root_of_other_tenant_rejected() {
    let site = Site::start().await;
    // Tenant t2 names `site`, a root of tenant t1.
    let tenants = json!([
        { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
        { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
    ]);
    let mut stolen = json!({
        "version": 1, "tenants": tenants,
        "apps": [static_app("b", "t2", "b.test", json!({ "root": "site" }))],
    });
    let response = site.podgate.push_snapshot(&stolen).await;
    assert_eq!(response.status, 422, "{}", response.body);
    assert_eq!(conflict_codes(&response), ["unknown_static_root"]);
    // The same tenant naming its own root is accepted, and t1 can use `site`.
    stolen["apps"] = json!([
        static_app("a", "t1", "a.test", json!({ "root": "site" })),
        static_app("b", "t2", "b.test", json!({ "root": "theirs" })),
    ]);
    let accepted = site.podgate.push_snapshot(&stolen).await;
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_eq!(
        site.podgate.get("b.test", "/theirs.txt").await.body,
        "tenant two"
    );
    assert_eq!(site.podgate.get("b.test", "/hello.txt").await.status, 404);
    assert_eq!(site.get("/hello.txt").await.body, "hello static\n");
}

#[tokio::test]
async fn static_snapshot_cannot_supply_path() {
    let site = Site::start().await;
    for (version, root) in [
        (1, "/etc"),
        (2, base_path(&site)),
        (3, "../outside"),
        (4, "site/.."),
        (5, ""),
    ] {
        let response = site.serve(version, json!({ "root": root })).await;
        assert_eq!(response.status, 422, "{root}: {}", response.body);
        assert_eq!(conflict_codes(&response), ["unknown_static_root"], "{root}");
    }
    for field in ["path", "directory", "dir", "root_path", "alias"] {
        let mut config = site_config();
        config[field] = json!("/etc");
        let response = site.serve(10, config).await;
        assert_eq!(response.status, 422, "{field}: {}", response.body);
        assert_eq!(conflict_codes(&response), ["invalid_service"], "{field}");
    }
    assert_eq!(
        site.podgate.get("a.test", "/hello.txt").await.status,
        404,
        "nothing was applied"
    );
}

fn base_path(site: &Site) -> &str {
    site.base.to_str().expect("utf-8 temp dir")
}

#[tokio::test]
async fn static_unknown_root_rejected() {
    let site = Site::start().await;
    let response = site.serve(1, json!({ "root": "nope" })).await;
    assert_eq!(response.status, 422);
    assert_eq!(conflict_codes(&response), ["unknown_static_root"]);
    let missing = site.serve(2, json!({ "index": ["index.html"] })).await;
    assert_eq!(missing.status, 422);
    assert_eq!(conflict_codes(&missing), ["invalid_service"]);
}

#[tokio::test]
async fn static_hidden_files_404() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for path in [
        "/.env",
        "/.git/config",
        "/.git/",
        "/%2eenv",
        "/sub/.hidden",
        "/.%65nv",
    ] {
        let response = site.get(path).await;
        assert_eq!(response.status, 404, "{path}: {response:?}");
        assert!(!response.body.contains("SECRET"), "{path}");
    }
    let allowed = site.get("/.well-known/ok.txt").await;
    assert_eq!((allowed.status, allowed.body.as_str()), (200, "well-known"));
}

#[tokio::test]
async fn static_no_directory_listing() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "index": ["nothing.html"] }))
        .await;
    for path in ["/", "/sub/", "/emptydir/", "/emptydir", "/sub"] {
        let response = site.get(path).await;
        assert_eq!(response.status, 404, "{path}");
        assert!(
            !response.body.contains("hello.txt") && !response.body.contains("page.html"),
            "{path} listed a directory: {}",
            response.body
        );
    }
}

#[tokio::test]
async fn static_method_not_allowed() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let response = site
            .podgate
            .request(method, "a.test", "/hello.txt", &[])
            .await;
        assert_eq!(response.status, 405, "{method}");
        assert_eq!(response.header("allow"), Some("GET, HEAD"), "{method}");
    }
}

#[tokio::test]
async fn static_max_file_bytes_404() {
    let site = Site::start().await;
    site.serve_ok(json!({ "root": "site", "max_file_bytes": 12 }))
        .await;
    assert_eq!(site.get("/range.txt").await.body, "0123456789");
    let large = site.get("/hello.txt").await;
    assert_eq!(large.status, 404, "13 bytes is over the limit of 12");
    assert_eq!(large.json(), json!({ "error": "not found" }));
}

#[tokio::test]
async fn static_runs_the_middleware_chain() {
    let site = Site::start().await;
    let chained = common::with_middleware(
        static_app("a", "t1", "a.test", site_config()),
        "tag",
        "headers",
        json!({ "response": { "set": { "x-served-by": "podgate" } } }),
    );
    let pushed = site.podgate.push_snapshot(&snapshot(1, &[chained])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    for path in ["/hello.txt", "/nope", "/.env"] {
        let response = site.get(path).await;
        assert_eq!(
            response.header("x-served-by"),
            Some("podgate"),
            "{path}: the response hooks run on a static answer"
        );
    }
}

#[tokio::test]
async fn static_text_is_gzipped_by_the_compress_stage() {
    let site = Site::start().await;
    site.serve_ok(site_config()).await;
    write(
        &site.root().join("big.css"),
        &"body { color: red; }\n".repeat(100),
    );
    let request = "GET /big.css HTTP/1.1\r\nHost: a.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n";
    let mut stream = TcpStream::connect(site.podgate.proxy_addr)
        .await
        .expect("connect");
    stream.write_all(request.as_bytes()).await.expect("send");
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("in time")
        .expect("read");
    let head = String::from_utf8_lossy(&raw).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("content-encoding: gzip"), "{head}");
    assert!(head.contains("transfer-encoding: chunked"), "{head}");
}

#[tokio::test]
async fn static_path_rewrites_apply_to_the_lookup() {
    let site = Site::start().await;
    let chained = common::with_middleware(
        static_app("a", "t1", "a.test", site_config()),
        "strip",
        "strip_prefix",
        json!({ "prefixes": ["/assets"] }),
    );
    let pushed = site.podgate.push_snapshot(&snapshot(1, &[chained])).await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    assert_eq!(site.get("/assets/hello.txt").await.body, "hello static\n");
    assert_eq!(site.get("/hello.txt").await.body, "hello static\n");
    assert_eq!(
        site.get("/assets/../assets/%2e%2e/secret.txt").await.status,
        400
    );
    assert_refused(
        &site.get("/assets/../../secret.txt").await,
        "rewritten traversal",
    );
}

// -- memory: the read buffers are charged to the tenant ------------------------------------

/// The `podgate_tenant_buffer_bytes` metric of `tenant`; 0 when it has no line.
async fn buffered(podgate: &Podgate, tenant: &str, name: &str) -> u64 {
    let metrics = podgate.admin_get("/metrics").await.body;
    let prefix = format!("{name}{{tenant=\"{tenant}\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.trim().parse().expect("a number"))
}

/// Sends `GET path` and reads until the response header is complete; the stream stays open with
/// the body unread.
async fn begin(addr: SocketAddr, host: &str, path: &str) -> (TcpStream, String) {
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
    (stream, String::from_utf8_lossy(&head).into_owned())
}

fn header_of<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// A sparse file of `len` bytes.
fn sparse(path: &Path, len: u64) {
    let file = std::fs::File::create(path).expect("create the sparse file");
    file.set_len(len).expect("set its length");
}

async fn wait_until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        sleep(Duration::from_millis(50)).await;
    }
}

/// A site whose tenant `t1` may buffer `budget` bytes, with a 512 MiB file that a client can
/// leave half read to hold its response in flight, and tenant `t2` with a root and a larger
/// budget on `b.test`.
async fn two_tenants(budget: u64) -> Site {
    let site = Site::start().await;
    sparse(&site.root().join("big.bin"), 512 << 20);
    let tenants = json!([
        { "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": budget } },
        { "id": "t2", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 1_048_576 } },
    ]);
    let pushed = site
        .podgate
        .push_snapshot(&json!({
            "version": 1, "tenants": tenants,
            "apps": [
                static_app("a", "t1", "a.test", json!({ "root": "site" })),
                static_app("b", "t2", "b.test", json!({ "root": "theirs" })),
            ],
        }))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    site
}

const RESERVATION: u64 = 128 * 1024;

#[tokio::test]
async fn static_read_buffers_charged_to_tenant() {
    let site = two_tenants(1_048_576).await;
    assert_eq!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await,
        0
    );
    let (first, head) = begin(site.podgate.proxy_addr, "a.test", "/big.bin").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await,
        RESERVATION,
        "one response in flight holds two 64 KiB chunks"
    );
    let (second, _) = begin(site.podgate.proxy_addr, "a.test", "/big.bin").await;
    assert_eq!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await,
        2 * RESERVATION
    );
    assert_eq!(
        buffered(&site.podgate, "t2", "podgate_tenant_buffer_bytes").await,
        0,
        "another tenant is not charged"
    );
    drop((first, second));
}

#[tokio::test]
async fn static_over_budget_503() {
    let site = two_tenants(RESERVATION).await;
    let (held, _) = begin(site.podgate.proxy_addr, "a.test", "/big.bin").await;
    let refused = site.get("/hello.txt").await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert_eq!(refused.header("retry-after"), Some("1"));
    let served = site.podgate.get("b.test", "/theirs.txt").await;
    assert_eq!((served.status, served.body.as_str()), (200, "tenant two"));
    assert!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes_peak").await <= RESERVATION,
        "the budget is never passed, not even briefly"
    );
    drop(held);
    wait_until("the held response to end", async || {
        site.get("/hello.txt").await.status == 200
    })
    .await;
}

#[tokio::test]
async fn static_charge_released_on_abort() {
    let site = two_tenants(RESERVATION).await;
    let (held, _) = begin(site.podgate.proxy_addr, "a.test", "/big.bin").await;
    assert_eq!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await,
        RESERVATION
    );
    assert_eq!(site.get("/hello.txt").await.status, 503);
    drop(held);
    wait_until(
        "the charge of the aborted response to be released",
        async || buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await == 0,
    )
    .await;
    assert_eq!(site.get("/hello.txt").await.status, 200);
}

#[tokio::test]
async fn static_large_file_bounded_memory() {
    let site = two_tenants(1_048_576).await;
    sparse(&site.root().join("huge.bin"), 2 * GIB);
    let started = Instant::now();
    let (mut stream, head) = begin(site.podgate.proxy_addr, "a.test", "/huge.bin").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        header_of(&head, "content-length").map(str::to_owned),
        Some((2 * GIB).to_string())
    );
    let mut received = 0_u64;
    let mut buffer = vec![0_u8; 1 << 20];
    let mut samples = 0;
    let mut highest = 0;
    timeout(Duration::from_secs(120), async {
        loop {
            let read = stream.read(&mut buffer).await.expect("read the body");
            if read == 0 {
                break;
            }
            received += read as u64;
            if received / (256 << 20) >= samples {
                samples += 1;
                highest =
                    highest.max(buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await);
            }
        }
    })
    .await
    .expect("the transfer finishes");
    assert_eq!(
        received,
        2 * GIB,
        "the whole file arrived ({:?})",
        started.elapsed()
    );
    assert!(samples >= 8, "sampled the buffer while it streamed");
    assert!(highest <= RESERVATION, "{highest} bytes buffered at once");
    assert_eq!(
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes_peak").await,
        RESERVATION,
        "the peak over the whole transfer is the two chunks"
    );
    wait_until("the charge to be released", async || {
        buffered(&site.podgate, "t1", "podgate_tenant_buffer_bytes").await == 0
    })
    .await;
}

#[tokio::test]
async fn static_read_pool_bounded_under_load() {
    let site = Site::start_with(&[("STATIC_MAX_CONCURRENT_READS", "1")]).await;
    let tenants = json!([{
        "id": "t1", "weight": 1, "budget": { "max_inflight": 100, "max_buffer_bytes": 64 << 20 }
    }]);
    let pushed = site
        .podgate
        .push_snapshot(&json!({
            "version": 1, "tenants": tenants,
            "apps": [static_app("a", "t1", "a.test", site_config())],
        }))
        .await;
    assert_eq!(pushed.status, 200, "{}", pushed.body);
    sparse(&site.root().join("some.bin"), 8 << 20);
    let addr = site.podgate.proxy_addr;
    let fetches: Vec<_> = (0..24)
        .map(|_| {
            tokio::spawn(async move {
                let (mut stream, head) = begin(addr, "a.test", "/some.bin").await;
                let mut total = 0_u64;
                let mut buffer = vec![0_u8; 1 << 16];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    total += read as u64;
                }
                (head.starts_with("HTTP/1.1 200"), total)
            })
        })
        .collect();
    for fetch in fetches {
        let (ok, total) = fetch.await.expect("joins");
        assert!(ok, "a read slot never stays held across a slow client");
        assert_eq!(total, 8 << 20);
    }
}

// -- startup ---------------------------------------------------------------------------------

#[test]
fn static_roots_file_invalid_stops_startup() {
    let base = temp_base("startup");
    let file = base.join("roots.json");
    let not_a_dir = base.join("file.txt");
    write(&not_a_dir, "x");
    let missing = base.join("missing");
    for (content, expected) in [
        ("not json".to_owned(), "expected"),
        (
            r#"{"t1": {"site": "relative"}}"#.to_owned(),
            "not an absolute path",
        ),
        (
            json!({ "t1": { "site": not_a_dir } }).to_string(),
            "not a usable directory",
        ),
        (
            json!({ "t1": { "site": missing } }).to_string(),
            "not a usable directory",
        ),
    ] {
        std::fs::write(&file, &content).expect("write the roots file");
        let admin = base.join("admin.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_podgate"))
            .env("STATIC_ROOTS_FILE", &file)
            .env("ADMIN_SOCKET", &admin)
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn podgate");
        let output = child.wait_with_output().expect("podgate exits");
        assert!(!output.status.success(), "{content}: startup must fail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("STATIC_ROOTS_FILE"), "{content}: {stderr}");
        assert!(stderr.contains(expected), "{content}: {stderr}");
        assert!(stderr.contains("roots.json"), "the file is named: {stderr}");
        assert!(!admin.exists(), "nothing was bound");
    }
    std::fs::write(
        &file,
        json!({ "t1": { "site": "/tmp" }, "": { "x": "/tmp" } }).to_string(),
    )
    .expect("write");
    let output = Command::new(env!("CARGO_BIN_EXE_podgate"))
        .env("STATIC_ROOTS_FILE", &file)
        .env("ADMIN_SOCKET", base.join("admin.sock"))
        .stdin(Stdio::null())
        .output()
        .expect("run podgate");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tenant id is empty"));
    drop(std::fs::remove_dir_all(&base));
}
