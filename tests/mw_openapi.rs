//! The `openapi` middleware through the real binary, with an upstream that records
//! what it receives: each refusal class and that the upstream sees nothing, the held body's
//! charge to the tenant budget, and a hostile document refused with the previous snapshot still
//! serving.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{Podgate, app, serving, snapshot, with_middleware};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// One request an upstream saw.
#[derive(Clone, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

/// An upstream that records what it receives and answers `200 ok`.
struct Recorder {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Recorder {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (counter, log) = (Arc::clone(&connections), Arc::clone(&seen));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(record(stream, Arc::clone(&log)));
            }
        });
        Self {
            addr,
            connections,
            seen,
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("log").clone()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The body in `raw` (what follows the head) when it is complete under `head`'s framing.
fn complete_body(head: &str, raw: &[u8]) -> Option<Vec<u8>> {
    let lower = head.to_ascii_lowercase();
    if lower.contains("transfer-encoding: chunked") {
        return dechunk(raw);
    }
    let length = lower
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("content-length"));
    (raw.len() >= length).then(|| raw[..length].to_vec())
}

fn dechunk(mut raw: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = find(raw, b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).ok()?, 16).ok()?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if raw.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

async fn record(mut stream: TcpStream, log: Arc<Mutex<Vec<Seen>>>) {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(end) = find(&raw, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&raw[..end]).into_owned();
            if let Some(body) = complete_body(&head, &raw[end + 4..]) {
                log.lock().expect("log").push(Seen { head, body });
                break;
            }
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
        }
    }
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    drop(stream.write_all(head.as_bytes()).await);
    drop(stream.shutdown().await);
}

/// A response as the proxy sent it.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn parse(raw: &[u8]) -> Self {
        let end = find(raw, b"\r\n\r\n")
            .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(raw)));
        let head = String::from_utf8_lossy(&raw[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line in {head:?}"));
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Self {
            status,
            headers,
            body: raw[end + 4..].to_vec(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|err| panic!("body is not JSON ({err}): {:?}", self.body))
    }

    fn violations(&self) -> Vec<Value> {
        self.json()["violations"]
            .as_array()
            .expect("violations")
            .clone()
    }
}

async fn connect(podgate: &Podgate) -> TcpStream {
    TcpStream::connect(podgate.proxy_addr)
        .await
        .expect("connect to the proxy")
}

async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    timeout(IO_TIMEOUT, async {
        // A connection the proxy resets after answering still delivered the answer.
        drop(stream.read_to_end(&mut raw).await);
    })
    .await
    .expect("response in time");
    raw
}

async fn exchange(podgate: &Podgate, request: &[u8]) -> Raw {
    let mut stream = connect(podgate).await;
    stream.write_all(request).await.expect("send request");
    Raw::parse(&read_all(&mut stream).await)
}

/// A request with `Content-Length` when it has a body.
fn request(method: &str, target: &str, extra: &str, body: Option<&[u8]>) -> Vec<u8> {
    let length = body.map_or_else(String::new, |body| {
        format!("Content-Length: {}\r\n", body.len())
    });
    let mut out = format!(
        "{method} {target} HTTP/1.1\r\nHost: a.test\r\n{extra}{length}Connection: close\r\n\r\n"
    )
    .into_bytes();
    out.extend_from_slice(body.unwrap_or_default());
    out
}

fn json_post(target: &str, body: &str) -> Vec<u8> {
    request(
        "POST",
        target,
        "Content-Type: application/json\r\n",
        Some(body.as_bytes()),
    )
}

/// The document every test uses (OpenAPI 3.1).
fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": { "title": "Pets", "version": "1.0" },
        "paths": {
            "/health": { "get": {} },
            "/pets": {
                "get": { "parameters": [
                    { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 100 } },
                    { "name": "x-trace", "in": "header", "required": true, "schema": { "type": "string", "minLength": 3 } }
                ] },
                "post": { "requestBody": { "required": true, "content": {
                    "application/json": { "schema": { "$ref": "#/components/schemas/Pet" } },
                    "text/plain": {} } } }
            },
            "/pets/{id}": { "get": { "parameters": [
                { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } } ] } }
        },
        "components": { "schemas": { "Pet": {
            "type": "object", "required": ["name"], "additionalProperties": false,
            "properties": {
                "name": { "type": "string", "minLength": 1 },
                "tag": { "type": ["string", "null"] },
                "age": { "type": "integer", "minimum": 0 }
            } } } }
    })
}

async fn serve_with(max_buffer_bytes: u64, upstream: SocketAddr, config: Value) -> Podgate {
    let podgate = Podgate::start().await;
    let pushed = pushed(1, max_buffer_bytes, upstream, config);
    let response = podgate.push_snapshot(&pushed).await;
    assert_eq!(response.status, 200, "{}", response.body);
    podgate
}

fn pushed(version: u64, max_buffer_bytes: u64, upstream: SocketAddr, config: Value) -> Value {
    let routed = with_middleware(
        app("a.test", &["a.test"], &[serving("r1", upstream)]),
        "api",
        "openapi",
        config,
    );
    let mut value = snapshot(version, &[routed]);
    value["tenants"][0]["budget"]["max_buffer_bytes"] = json!(max_buffer_bytes);
    value
}

async fn serve(upstream: &Recorder) -> Podgate {
    serve_with(1 << 20, upstream.addr, json!({ "document": document() })).await
}

fn series(metrics: &str, name: &str) -> u64 {
    let prefix = format!("{name}{{tenant=\"t1\"}} ");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map_or(0, |value| value.parse().expect("integer sample"))
}

async fn metric(podgate: &Podgate, name: &str) -> u64 {
    series(&podgate.admin_get("/metrics").await.body, name)
}

async fn wait_for_metric(podgate: &Podgate, name: &str, wanted: u64) {
    for _ in 0..200 {
        if metric(podgate, name).await == wanted {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{name} never reached {wanted}; it is {}",
        metric(podgate, name).await
    );
}

const WHY: &str = "request does not match the API description";

#[tokio::test]
async fn openapi_valid_request_passes() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;

    let get = exchange(
        &podgate,
        &request("GET", "/pets?limit=5&other=1", "X-Trace: abc\r\n", None),
    )
    .await;
    assert_eq!(get.status, 200);
    let by_id = exchange(&podgate, &request("GET", "/pets/42", "", None)).await;
    assert_eq!(by_id.status, 200);
    let health = exchange(&podgate, &request("GET", "/health", "", None)).await;
    assert_eq!(health.status, 200);

    let body = r#"{"name":"rex","tag":null,"age":3}"#;
    let post = exchange(&podgate, &json_post("/pets", body)).await;
    assert_eq!(post.status, 200);
    let text = exchange(
        &podgate,
        &request(
            "POST",
            "/pets",
            "Content-Type: text/plain\r\n",
            Some(b"free text"),
        ),
    )
    .await;
    assert_eq!(text.status, 200);

    let seen = upstream.seen();
    assert_eq!(seen.len(), 5);
    assert!(
        seen[0]
            .head
            .starts_with("GET /pets?limit=5&other=1 HTTP/1.1"),
        "{}",
        seen[0].head
    );
    assert!(seen[0].head.to_ascii_lowercase().contains("x-trace: abc"));
    assert_eq!(seen[3].body, body.as_bytes(), "the body arrives untouched");
    assert_eq!(seen[4].body, b"free text");
}

#[tokio::test]
async fn openapi_unknown_path_404() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    for path in ["/nope", "/pets/", "/pets/1/2"] {
        let refused = exchange(&podgate, &request("GET", path, "X-Trace: abc\r\n", None)).await;
        assert_eq!(refused.status, 404, "{path}");
        assert_eq!(refused.json()["error"], WHY);
        assert_eq!(refused.violations()[0]["in"], "path");
    }
    assert_eq!(upstream.connections(), 0, "the upstream was never dialled");
}

#[tokio::test]
async fn openapi_wrong_method_405() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let refused = exchange(&podgate, &request("DELETE", "/pets", "", None)).await;
    assert_eq!(refused.status, 405);
    assert_eq!(refused.header("allow"), Some("GET, POST"));
    assert_eq!(refused.violations()[0]["in"], "method");
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_bad_parameter_400() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let trace = "X-Trace: abc\r\n";
    for target in [
        "/pets?limit=abc",
        "/pets?limit=0",
        "/pets?limit=1&limit=2",
        "/pets/seven",
    ] {
        let refused = exchange(&podgate, &request("GET", target, trace, None)).await;
        assert_eq!(refused.status, 400, "{target}");
        assert_eq!(refused.json()["error"], WHY);
        assert!(refused.violations().len() == 1, "{target}");
    }
    let refused = exchange(&podgate, &request("GET", "/pets?limit=abc", trace, None)).await;
    let first = &refused.violations()[0];
    assert_eq!(first["in"], "query");
    assert_eq!(first["name"], "limit");
    assert!(
        !String::from_utf8_lossy(&refused.body).contains("abc"),
        "a value from the request is never echoed"
    );
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_required_header_400() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let missing = exchange(&podgate, &request("GET", "/pets", "", None)).await;
    assert_eq!(missing.status, 400);
    let first = &missing.violations()[0];
    assert_eq!(
        (first["in"].as_str(), first["name"].as_str()),
        (Some("header"), Some("x-trace"))
    );
    let short = exchange(&podgate, &request("GET", "/pets", "X-Trace: ab\r\n", None)).await;
    assert_eq!(short.status, 400);
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_body_schema_400() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    for body in [
        r#"{"tag":"x"}"#,
        r#"{"name":""}"#,
        r#"{"name":"rex","age":-1}"#,
        r#"{"name":"rex","extra":true}"#,
        r#"{"name":7}"#,
    ] {
        let refused = exchange(&podgate, &json_post("/pets", body)).await;
        assert_eq!(refused.status, 400, "{body}");
        assert_eq!(refused.json()["error"], WHY);
        assert_eq!(refused.violations()[0]["in"], "body");
    }
    let refused = exchange(&podgate, &json_post("/pets", r#"{"name":"rex","age":-1}"#)).await;
    assert_eq!(refused.violations()[0]["pointer"], "/age");
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_required_body_400() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let refused = exchange(&podgate, &request("POST", "/pets", "", None)).await;
    assert_eq!(refused.status, 400);
    assert_eq!(refused.violations()[0]["in"], "body");
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_undeclared_body_400() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let refused = exchange(
        &podgate,
        &request(
            "GET",
            "/health",
            "Content-Type: application/json\r\n",
            Some(b"{}"),
        ),
    )
    .await;
    assert_eq!(refused.status, 400);
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_media_type_415() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let xml = exchange(
        &podgate,
        &request(
            "POST",
            "/pets",
            "Content-Type: application/xml\r\n",
            Some(b"<a/>"),
        ),
    )
    .await;
    assert_eq!(xml.status, 415);
    assert_eq!(xml.violations()[0]["name"], "content-type");
    let none = exchange(&podgate, &request("POST", "/pets", "", Some(b"{}"))).await;
    assert_eq!(none.status, 415);
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_body_too_large_413() {
    let upstream = Recorder::start().await;
    let podgate = serve_with(
        1 << 20,
        upstream.addr,
        json!({ "document": document(), "max_body_bytes": 64 }),
    )
    .await;
    let big = format!(r#"{{"name":"{}"}}"#, "a".repeat(100));

    let declared = exchange(&podgate, &json_post("/pets", &big)).await;
    assert_eq!(declared.status, 413);
    assert_eq!(declared.json()["error"], WHY);

    let mut head = b"POST /pets HTTP/1.1\r\nHost: a.test\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for piece in big.as_bytes().chunks(40) {
        head.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        head.extend_from_slice(piece);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"0\r\n\r\n");
    let chunked = exchange(&podgate, &head).await;
    assert_eq!(chunked.status, 413);
    assert_eq!(upstream.connections(), 0);

    let small = exchange(&podgate, &json_post("/pets", r#"{"name":"rex"}"#)).await;
    assert_eq!(small.status, 200);
}

#[tokio::test]
async fn openapi_unparsable_body_refused() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    for body in [
        "{not json",
        r#"{"name":"a","name":"b"}"#,
        "",
        r#"{"name":"a"} {}"#,
    ] {
        let refused = exchange(&podgate, &json_post("/pets", body)).await;
        assert_eq!(refused.status, 400, "{body:?}");
        assert_eq!(refused.violations()[0]["in"], "body");
    }
    assert_eq!(upstream.connections(), 0, "nothing unchecked is forwarded");
}

#[tokio::test]
async fn openapi_body_charged_to_budget() {
    let upstream = Recorder::start().await;
    let podgate = serve_with(2100, upstream.addr, json!({ "document": document() })).await;
    let body = format!(r#"{{"name":"{}"}}"#, "a".repeat(989));
    assert_eq!(body.len(), 1000);
    let larger = format!(r#"{{"name":"{}"}}"#, "a".repeat(1189));

    let mut holder = connect(&podgate).await;
    let full = json_post("/pets", &body);
    let split = full.len() - 600;
    holder
        .write_all(&full[..split])
        .await
        .expect("part of the body");
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 1000).await;
    assert_eq!(upstream.connections(), 0);

    let refused = exchange(&podgate, &json_post("/pets", &larger)).await;
    assert_eq!(refused.status, 503, "1000 held plus 1200 is over 2100");
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(
        metric(&podgate, "podgate_tenant_buffering_refused_total").await,
        1
    );

    holder.write_all(&full[split..]).await.expect("the rest");
    assert_eq!(Raw::parse(&read_all(&mut holder).await).status, 200);
    wait_for_metric(&podgate, "podgate_tenant_buffer_bytes", 0).await;
    // The held body, then the cost of parsing it (its text and 64 bytes for the one `{`).
    let peak = metric(&podgate, "podgate_tenant_buffer_bytes_peak").await;
    assert_eq!(peak, 1000 + 1000 + 64);
}

#[tokio::test]
async fn openapi_parse_cost_is_charged() {
    let upstream = Recorder::start().await;
    let podgate = serve_with(1500, upstream.addr, json!({ "document": document() })).await;
    let body = format!(r#"{{"name":"{}"}}"#, "a".repeat(989));
    let refused = exchange(&podgate, &json_post("/pets", &body)).await;
    assert_eq!(
        refused.status, 503,
        "1000 held plus 1064 to parse is over 1500"
    );
    assert_eq!(refused.header("retry-after"), Some("1"));
    assert_eq!(upstream.connections(), 0);
    let fits = exchange(&podgate, &json_post("/pets", r#"{"name":"rex"}"#)).await;
    assert_eq!(fits.status, 200);
}

#[tokio::test]
async fn openapi_violations_bounded() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let refused = exchange(
        &podgate,
        &json_post(
            "/pets",
            &json!({ "name": 1, "age": "secret-age" }).to_string(),
        ),
    )
    .await;
    assert_eq!(refused.status, 400);
    assert!(!String::from_utf8_lossy(&refused.body).contains("secret-age"));

    let mut props = serde_json::Map::new();
    for index in 0..30 {
        props.insert(format!("k{index}"), json!(index));
    }
    let many = exchange(
        &podgate,
        &json_post("/pets", &Value::Object(props).to_string()),
    )
    .await;
    assert_eq!(many.status, 400);
    assert_eq!(many.violations().len(), 10);
    assert_eq!(many.json()["truncated"], true);
    assert_eq!(upstream.connections(), 0);
}

#[tokio::test]
async fn openapi_hostile_document_is_422() {
    let upstream = Recorder::start().await;
    let podgate = serve(&upstream).await;
    let mut remote = document();
    remote["paths"]["/pets"]["post"]["requestBody"]["content"]["application/json"]["schema"] =
        json!({ "$ref": "https://evil.test/pet.json" });
    let rejected = podgate
        .push_snapshot(&pushed(
            2,
            1 << 20,
            upstream.addr,
            json!({ "document": remote }),
        ))
        .await;
    assert_eq!(rejected.status, 422, "{}", rejected.body);
    assert_eq!(
        rejected.json()["conflicts"][0]["code"],
        "invalid_middleware"
    );

    let mut cyclic = document();
    cyclic["components"]["schemas"]["Pet"] = json!({ "type": "object", "properties": { "friend": { "$ref": "#/components/schemas/Pet" } } });
    let rejected = podgate
        .push_snapshot(&pushed(
            3,
            1 << 20,
            upstream.addr,
            json!({ "document": cyclic }),
        ))
        .await;
    assert_eq!(rejected.status, 422, "{}", rejected.body);

    let unparsable = podgate
        .push_snapshot(&pushed(
            4,
            1 << 20,
            upstream.addr,
            json!({ "document": { "openapi": "2.0" } }),
        ))
        .await;
    assert_eq!(unparsable.status, 422, "{}", unparsable.body);

    let still = exchange(&podgate, &json_post("/pets", r#"{"name":"rex"}"#)).await;
    assert_eq!(still.status, 200, "the previous snapshot still serves");
}
