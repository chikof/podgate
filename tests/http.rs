//! HTTP tests: in-process via `oneshot`, plus one real socket with graceful shutdown.

use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tower::ServiceExt;

use podgate::{AppState, Config, router, serve_on};

const TIMEOUT: Duration = Duration::from_secs(5);

fn ready_app() -> Router {
    let state = AppState::new();
    state.set_ready(true);
    router(state, TIMEOUT)
}

async fn get(app: Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, Value) {
    let request = Request::get(uri)
        .body(Body::empty())
        .expect("valid request");
    let response = app.oneshot(request).await.expect("router is infallible");
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, usize::MAX).await.expect("body reads");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (parts.status, parts.headers, json)
}

#[tokio::test]
async fn healthz_is_ok() {
    let (status, _, body) = get(ready_app(), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn healthz_is_ok_even_when_not_ready() {
    let (status, _, _) = get(router(AppState::new(), TIMEOUT), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn readyz_follows_state() {
    let (status, _, body) = get(ready_app(), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");

    let (status, _, body) = get(router(AppState::new(), TIMEOUT), "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not ready");
}

#[tokio::test]
async fn example_route_greets() {
    let (status, _, body) = get(ready_app(), "/v1/greet/Ada").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["message"], "Hello, Ada!");
}

#[tokio::test]
async fn example_route_rejects_long_name() {
    let uri = format!("/v1/greet/{}", "a".repeat(65));
    let (status, _, body) = get(ready_app(), &uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn unknown_route_is_json_404() {
    let (status, _, body) = get(ready_app(), "/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not found");
}

#[tokio::test]
async fn request_id_is_set_and_propagated() {
    let (_, headers, _) = get(ready_app(), "/healthz").await;
    assert!(headers.contains_key("x-request-id"), "generated id missing");

    let request = Request::get("/healthz")
        .header("x-request-id", "abc-123")
        .body(Body::empty())
        .expect("valid request");
    let response = ready_app()
        .oneshot(request)
        .await
        .expect("router is infallible");
    assert_eq!(response.headers()["x-request-id"], "abc-123");
}

#[tokio::test]
async fn serves_over_tcp_and_shuts_down_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let config = Config::default();
        serve_on(listener, &config, async {
            // A dropped sender also counts as a shutdown request.
            let _ = stopped.await;
        })
        .await
    });

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("send request");
    let mut raw = Vec::new();
    tokio::time::timeout(TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .expect("response in time")
        .expect("read response");
    let text = String::from_utf8_lossy(&raw);
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "unexpected response: {text}"
    );
    assert!(
        text.contains(r#"{"status":"ok"}"#),
        "unexpected body: {text}"
    );

    stop.send(()).expect("server still running");
    let result = tokio::time::timeout(TIMEOUT, server)
        .await
        .expect("server stops after shutdown")
        .expect("server task does not panic");
    assert!(result.is_ok(), "serve returned {result:?}");
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "listener still accepting"
    );
}
