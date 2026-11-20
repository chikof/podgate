//! Answering one request from a [`StaticSite`]: find the file, decide the status from the
//! request's validators and range, and stream the bytes.
//!
//! The response is written from `request_filter`, but it goes through the same response hooks
//! as a proxied one (`Gateway::response_filter` and `response_body_filter`), so the router's
//! middlewares (`headers`, compression, failure capture) see a static answer like any other.

use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{Method, StatusCode};
use pingora::ErrorType::InternalError;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{ProxyHttp, Session};
use pingora::{BError, Error};
use thiserror::Error;

use super::StaticSite;
use super::mime;
use super::precompressed::{self, Encoding};
use super::range::{self, Plan};
use super::reader::{Busy, RESERVATION, Reads, Stream, StreamError};
use super::roots::{Kind, OpenError, Opened, RelPath};
use crate::budget::Budgets;
use crate::error::AppError;
use crate::middleware;
use crate::proxy::{Ctx, Gateway};
use crate::respond;
use crate::router::path;

/// What the request asked, copied out of its header so the session can be borrowed mutably while
/// the answer is written.
#[derive(Debug)]
struct Asked {
    method: Method,
    /// The normalized path; `None` when it cannot be normalized.
    path: Option<String>,
    query: Option<String>,
    range: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
    if_range: Option<String>,
    accept_encoding: Vec<String>,
}

impl Asked {
    fn of(request: &RequestHeader) -> Self {
        let text = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let joined = |name: &str| {
            let values: Vec<&str> = request
                .headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(","))
        };
        Self {
            method: request.method.clone(),
            path: path::normalize(request.uri.path())
                .ok()
                .map(std::borrow::Cow::into_owned),
            query: request.uri.query().map(str::to_owned),
            range: text("range"),
            if_none_match: joined("if-none-match"),
            if_modified_since: text("if-modified-since"),
            if_range: text("if-range"),
            accept_encoding: request
                .headers
                .get_all("accept-encoding")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(str::to_owned)
                .collect(),
        }
    }
}

/// Why an answer could not be built.
#[derive(Debug, Error)]
enum Failure {
    #[error(transparent)]
    Busy(#[from] Busy),
    #[error("cannot build the response: {0}")]
    Http(Box<Error>),
}

impl From<BError> for Failure {
    fn from(err: BError) -> Self {
        Self::Http(err)
    }
}

/// What the answer carries after its header.
#[derive(Debug)]
enum Body {
    Empty,
    Bytes(Bytes),
    File { stream: Stream, len: u64 },
}

/// A file chosen to answer with, and the path whose name decides its type.
#[derive(Debug)]
struct Hit {
    path: RelPath,
    opened: Opened,
}

/// The outcome of the file search.
#[derive(Debug)]
enum Found {
    File(Box<Hit>),
    /// A directory named without its trailing slash: send the client to the slash form.
    Redirect(String),
    /// Nothing to serve: answer this status, with its status page if the service has one.
    Status(u16),
}

/// The file the client gets: the file itself or its precompressed sidecar.
#[derive(Debug)]
struct Representation {
    path: RelPath,
    opened: Opened,
    encoding: Option<Encoding>,
}

async fn open(site: &StaticSite, reads: &Reads, path: RelPath) -> Result<Option<Opened>, Busy> {
    let root = std::sync::Arc::clone(&site.root);
    match reads.run(move || root.open_path(&path)).await? {
        Ok(opened) => Ok(Some(opened)),
        Err(OpenError::Missing) => Ok(None),
        Err(OpenError::Exhausted) => Err(Busy),
    }
}

/// Finds what to serve for the request path: the file, a directory's index, or the first
/// `try_files` entry that exists.
async fn find(site: &StaticSite, reads: &Reads, asked: &Asked) -> Result<Found, Busy> {
    let Some(raw) = asked.path.as_deref() else {
        return Ok(Found::Status(404));
    };
    let Ok(first) = RelPath::parse(raw) else {
        return Ok(Found::Status(404));
    };
    let candidates: Vec<RelPath> = match &site.try_files {
        None => vec![first.clone()],
        Some(tries) => tries
            .templates
            .iter()
            .filter_map(|template| RelPath::parse(&template.replace("{path}", raw)).ok())
            .collect(),
    };
    for candidate in candidates {
        let Some(opened) = open(site, reads, candidate.clone()).await? else {
            continue;
        };
        let hit = match opened.kind {
            Kind::File => Hit {
                path: candidate,
                opened,
            },
            Kind::Dir => {
                let mut indexed = None;
                for name in &site.index {
                    let Some(path) = candidate.join(name) else {
                        continue;
                    };
                    if let Some(index) = open(site, reads, path.clone()).await?
                        && index.kind == Kind::File
                    {
                        indexed = Some(Hit {
                            path,
                            opened: index,
                        });
                        break;
                    }
                }
                let Some(index) = indexed else { continue };
                if !candidate.names_directory() && candidate == first {
                    let query = asked
                        .query
                        .as_deref()
                        .map_or_else(String::new, |query| format!("?{query}"));
                    return Ok(Found::Redirect(format!("{raw}/{query}")));
                }
                index
            }
        };
        if hit.opened.len > site.max_file_bytes {
            tracing::warn!(
                root = site.root_label(),
                path = hit.path.as_str(),
                len = hit.opened.len,
                max = site.max_file_bytes,
                "static file is over max_file_bytes and is not served"
            );
            return Ok(Found::Status(404));
        }
        return Ok(Found::File(Box::new(hit)));
    }
    Ok(Found::Status(
        site.try_files
            .as_ref()
            .and_then(|tries| tries.status)
            .unwrap_or(404),
    ))
}

/// Picks the precompressed sidecar the client accepts, if the service offers them and one exists.
async fn represent(
    site: &StaticSite,
    reads: &Reads,
    asked: &Asked,
    hit: Hit,
) -> Result<Representation, Busy> {
    let accept: Vec<&str> = asked.accept_encoding.iter().map(String::as_str).collect();
    for encoding in precompressed::acceptable(&site.precompressed, &accept) {
        let Some(sidecar) = hit.path.with_suffix(encoding.suffix()) else {
            continue;
        };
        if let Some(opened) = open(site, reads, sidecar).await?
            && opened.kind == Kind::File
            && opened.len <= site.max_file_bytes
        {
            return Ok(Representation {
                path: hit.path,
                opened,
                encoding: Some(encoding),
            });
        }
    }
    Ok(Representation {
        path: hit.path,
        opened: hit.opened,
        encoding: None,
    })
}

fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The weak validator of a representation: its size and modification time.
fn etag(opened: &Opened) -> String {
    let nanos = opened
        .modified
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |since| since.as_nanos());
    format!("W/\"{:x}-{nanos:x}\"", opened.len)
}

/// Whether the request's `If-None-Match`, or without it `If-Modified-Since`, is satisfied by the
/// representation, so that the answer is `304`.
fn not_modified(asked: &Asked, etag: &str, modified: Option<SystemTime>) -> bool {
    let opaque = |tag: &str| {
        tag.trim()
            .strip_prefix("W/")
            .unwrap_or(tag.trim())
            .to_owned()
    };
    if let Some(list) = &asked.if_none_match {
        let ours = opaque(etag);
        return list
            .split(',')
            .any(|tag| tag.trim() == "*" || opaque(tag) == ours);
    }
    let since = asked
        .if_modified_since
        .as_deref()
        .and_then(|value| httpdate::parse_http_date(value.trim()).ok());
    match (since, modified) {
        (Some(since), Some(modified)) => seconds(modified) <= seconds(since),
        _ => false,
    }
}

/// Whether `If-Range` lets the `Range` apply. Our validator is weak and `If-Range` compares
/// strongly (RFC 9110), so an entity tag never matches; a date matches the exact
/// `Last-Modified`.
fn if_range_holds(asked: &Asked, modified: Option<SystemTime>) -> bool {
    let Some(value) = asked.if_range.as_deref().map(str::trim) else {
        return true;
    };
    if value.starts_with('"') || value.starts_with("W/") {
        return false;
    }
    match (httpdate::parse_http_date(value), modified) {
        (Ok(date), Some(modified)) => seconds(date) == seconds(modified),
        _ => false,
    }
}

fn error_body(status: StatusCode) -> Bytes {
    let reason = status
        .canonical_reason()
        .unwrap_or("error")
        .to_ascii_lowercase();
    Bytes::from(serde_json::json!({ "error": reason }).to_string())
}

fn json_answer(status: StatusCode) -> Result<(ResponseHeader, Body), Failure> {
    let body = error_body(status);
    let mut header = ResponseHeader::build(status, Some(3))?;
    header.insert_header("content-type", "application/json")?;
    header.insert_header("content-length", body.len().to_string())?;
    Ok((header, Body::Bytes(body)))
}

/// The answer for `status` when there is no file to serve: the service's status page, else a JSON
/// error like the proxy's own.
async fn status_answer(
    site: &StaticSite,
    reads: &Reads,
    status: u16,
) -> Result<(ResponseHeader, Body), Failure> {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::NOT_FOUND);
    if let Some(page) = site.status_pages.get(&status)
        && let Some(opened) = open(site, reads, page.clone()).await?
        && opened.kind == Kind::File
        && opened.len <= site.max_file_bytes
    {
        let mut header = ResponseHeader::build(code, Some(4))?;
        header.insert_header(
            "content-type",
            mime::content_type(page.extension().as_deref()),
        )?;
        header.insert_header("content-length", opened.len.to_string())?;
        header.insert_header("x-content-type-options", "nosniff")?;
        let len = opened.len;
        return Ok((
            header,
            Body::File {
                stream: Stream::new(opened.file, 0, len),
                len,
            },
        ));
    }
    json_answer(code)
}

/// Decides the response for the request: status, headers and what follows them.
async fn answer(
    site: &StaticSite,
    reads: &Reads,
    asked: &Asked,
) -> Result<(ResponseHeader, Body), Failure> {
    let hit = match find(site, reads, asked).await? {
        Found::File(hit) => *hit,
        Found::Redirect(target) => {
            let mut header = ResponseHeader::build(StatusCode::PERMANENT_REDIRECT, Some(3))?;
            header.insert_header("location", target)?;
            header.insert_header("content-length", "0")?;
            return Ok((header, Body::Empty));
        }
        Found::Status(status) => return status_answer(site, reads, status).await,
    };
    let representation = represent(site, reads, asked, hit).await?;
    let Representation {
        path,
        opened,
        encoding,
    } = representation;
    let extension = path.extension();
    let tag = etag(&opened);
    let mut header;
    let body;
    if not_modified(asked, &tag, opened.modified) {
        header = ResponseHeader::build(StatusCode::NOT_MODIFIED, Some(6))?;
        body = Body::Empty;
    } else {
        let plan = if if_range_holds(asked, opened.modified) {
            range::plan(asked.range.as_deref(), opened.len)
        } else {
            Plan::Full
        };
        match plan {
            Plan::Unsatisfiable => {
                let mut header = ResponseHeader::build(StatusCode::RANGE_NOT_SATISFIABLE, Some(3))?;
                header.insert_header("content-range", format!("bytes */{}", opened.len))?;
                header.insert_header("content-length", "0")?;
                return Ok((header, Body::Empty));
            }
            Plan::Partial { start, end } => {
                let len = end - start + 1;
                header = ResponseHeader::build(StatusCode::PARTIAL_CONTENT, Some(10))?;
                header.insert_header(
                    "content-range",
                    format!("bytes {start}-{end}/{}", opened.len),
                )?;
                header.insert_header("content-length", len.to_string())?;
                body = Body::File {
                    stream: Stream::new(opened.file, start, len),
                    len,
                };
            }
            Plan::Full => {
                header = ResponseHeader::build(StatusCode::OK, Some(10))?;
                header.insert_header("content-length", opened.len.to_string())?;
                body = Body::File {
                    stream: Stream::new(opened.file, 0, opened.len),
                    len: opened.len,
                };
            }
        }
        header.insert_header("content-type", mime::content_type(extension.as_deref()))?;
        if let Some(encoding) = encoding {
            header.insert_header("content-encoding", encoding.token())?;
        }
    }
    header.insert_header("etag", tag)?;
    if let Some(modified) = opened.modified {
        header.insert_header("last-modified", httpdate::fmt_http_date(modified))?;
    }
    header.insert_header("accept-ranges", "bytes")?;
    header.insert_header("x-content-type-options", "nosniff")?;
    if let Some(value) = site.cache_control(extension.as_deref()) {
        header.insert_header("cache-control", value)?;
    }
    if !site.precompressed.is_empty() {
        header.insert_header("vary", "accept-encoding")?;
    }
    Ok((header, body))
}

fn method_not_allowed() -> Result<(ResponseHeader, Body), Failure> {
    let (mut header, body) = json_answer(StatusCode::METHOD_NOT_ALLOWED)?;
    header.insert_header("allow", "GET, HEAD")?;
    Ok((header, body))
}

/// Refuses the request with a capacity error, like every other admission does.
async fn refuse(session: &mut Session, ctx: &mut Ctx, err: AppError) -> pingora::Result<()> {
    ctx.capacity_refusal = err.is_capacity_refusal();
    ctx.access.refused(&err);
    respond::write_error(session, &err).await
}

/// Writes one body chunk through the response body hooks.
async fn send(
    gateway: &Gateway,
    session: &mut Session,
    ctx: &mut Ctx,
    chunk: Option<Bytes>,
    last: bool,
) -> pingora::Result<()> {
    let mut body = chunk;
    gateway.response_body_filter(session, &mut body, last, ctx)?;
    if body.is_some() || last {
        session.write_response_body(body, last).await?;
    }
    Ok(())
}

/// Writes `header` and `body` to the client.
async fn emit(
    gateway: &Gateway,
    reads: &Reads,
    session: &mut Session,
    ctx: &mut Ctx,
    mut header: ResponseHeader,
    body: Body,
) -> pingora::Result<()> {
    gateway.response_filter(session, &mut header, ctx).await?;
    let head_only = session.req_header().method == Method::HEAD;
    let header_only = match &body {
        Body::Empty | Body::File { len: 0, .. } => true,
        Body::Bytes(_) | Body::File { .. } => head_only,
    };
    if header_only {
        return session.write_response_header(Box::new(header), true).await;
    }
    session
        .write_response_header(Box::new(header), false)
        .await?;
    match body {
        Body::Bytes(bytes) => send(gateway, session, ctx, Some(bytes), true).await,
        Body::File { mut stream, .. } => loop {
            let chunk = stream.next(reads).await.map_err(|err: StreamError| {
                Error::because(InternalError, "static file read failed", err)
            })?;
            let last = stream.is_done();
            send(gateway, session, ctx, chunk, last).await?;
            if last {
                return Ok(());
            }
        },
        Body::Empty => Ok(()),
    }
}

/// Answers the request the router matched with the static service it selected.
///
/// Charges [`RESERVATION`] to the tenant's buffer budget first (`503` with `retry-after` when it
/// does not fit); the charge ends with this call, which is when the response has been written or
/// the client has gone.
///
/// # Errors
///
/// A Pingora error when the response cannot be written or the file stops short of its length;
/// the connection is then closed.
pub(crate) async fn serve(
    gateway: &Gateway,
    reads: &Reads,
    budgets: &Budgets,
    session: &mut Session,
    ctx: &mut Ctx,
) -> pingora::Result<()> {
    let outside = || Error::explain(InternalError, "static request without a static service");
    let selected = ctx.route.ok_or_else(outside)?;
    let app = ctx.table.app(selected.app).ok_or_else(outside)?;
    let site = app
        .static_site(selected.revision, selected.router)
        .cloned()
        .ok_or_else(outside)?;
    let tenant = ctx
        .table
        .tenant_budget(app.tenant())
        .map(|limits| budgets.tenant(app.tenant(), limits));
    // The chain's path rewrites (`strip_prefix`, `replace_path`, ...) edit the request that goes
    // upstream; the file lookup is that request, so they apply here too, and each re-normalizes.
    let mut request = session.req_header().clone();
    if let Some((owner, router)) = ctx.matched.and_then(|matched| ctx.table.router(matched)) {
        middleware::run_upstream_request(
            owner.stages(),
            router.chain(),
            &mut request,
            &mut ctx.chain,
        )?;
    }
    let asked = Asked::of(&request);
    let reading = asked.method == Method::GET || asked.method == Method::HEAD;
    let _charge = if reading {
        let Some(charge) = tenant
            .as_ref()
            .and_then(|tenant| tenant.charge(RESERVATION))
        else {
            return refuse(session, ctx, AppError::StaticOverBudget).await;
        };
        Some(charge)
    } else {
        None
    };
    let built = if reading {
        answer(&site, reads, &asked).await
    } else {
        method_not_allowed()
    };
    match built {
        Ok((header, body)) => emit(gateway, reads, session, ctx, header, body).await,
        Err(Failure::Busy(Busy)) => refuse(session, ctx, AppError::StaticBusy).await,
        Err(Failure::Http(err)) => Err(err),
    }
}
