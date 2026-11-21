//! A plugin for the `plugin` middleware tests: a gRPC server on a unix socket that speaks
//! `podgate.plugin.v1`, written on `h2` so a test controls exactly what it answers.
//!
//! - [`Server`]: runs in the test's process; a closure decides each `Process` call
//!   ([`Reply`]), every call is recorded, and dropping it closes the socket.
//! - [`echo`]: the closure of the `echo_plugin` example (`examples/echo_plugin.rs`), which
//!   acts on the `config` the middleware passes, so a test steers a real plugin process from
//!   its snapshot.
//! - [`Process`]: the `echo_plugin` example as a child process the test started itself,
//!   stopped by its pid when dropped.
//! - [`serve_forever`]: what the example's `main` runs.
//!
//! The example includes this file with `#[path]`, so everything here depends on the library and
//! `h2` only.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, Request, Response};
use podgate::middleware::plugin::wire::{
    Action, Call, Decision, DescribeResponse, Header, Phase, Response as Answer,
};
use prost::Message;
use serde_json::{Value, json};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

const DESCRIBE: &str = "/podgate.plugin.v1.Plugin/Describe";
const PROCESS: &str = "/podgate.plugin.v1.Plugin/Process";

/// What a plugin does with one `Process` call.
pub enum Reply {
    /// Answers this decision.
    Decision(Decision),
    /// Waits, then does the other.
    After(Duration, Box<Reply>),
    /// Never answers.
    Hang,
    /// Answers a gRPC error status in a trailers-only response.
    Status(u32),
    /// Answers these bytes as the message, which may not be a decision at all.
    Raw(Vec<u8>),
    /// Answers a decision with a response body of this many bytes.
    Big(usize),
}

/// Decides a call.
pub type Handler = Arc<dyn Fn(&Call) -> Reply + Send + Sync>;

/// How the server answers `Describe`.
#[derive(Clone)]
pub enum Describe {
    /// The protocol and these phases.
    Phases(Vec<Phase>),
    /// This protocol version, and every phase.
    Version(u32),
    /// A gRPC status instead of a description.
    Status(u32),
}

impl Describe {
    /// Serves all three phases of protocol 1.
    pub fn all() -> Self {
        Self::Phases(vec![
            Phase::RequestHeaders,
            Phase::RequestBody,
            Phase::ResponseHeaders,
        ])
    }
}

fn describe_message(name: &str, describe: &Describe) -> Option<DescribeResponse> {
    let all = || {
        [
            Phase::RequestHeaders,
            Phase::RequestBody,
            Phase::ResponseHeaders,
        ]
        .map(|phase| phase as i32)
        .to_vec()
    };
    match describe {
        Describe::Phases(phases) => Some(DescribeResponse {
            name: name.to_owned(),
            protocol_version: 1,
            phases: phases.iter().map(|phase| *phase as i32).collect(),
        }),
        Describe::Version(version) => Some(DescribeResponse {
            name: name.to_owned(),
            protocol_version: *version,
            phases: all(),
        }),
        Describe::Status(_) => None,
    }
}

/// One gRPC message with its prefix.
fn framed(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + message.len());
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&u32::try_from(message.len()).expect("small").to_be_bytes());
    out.extend_from_slice(message);
    out.freeze()
}

/// The message of a request body.
async fn read_message(body: &mut RecvStream) -> Vec<u8> {
    let mut all = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("request data");
        drop(body.flow_control().release_capacity(chunk.len()));
        all.extend_from_slice(&chunk);
    }
    all.get(5..).unwrap_or_default().to_vec()
}

async fn send_data(stream: &mut SendStream<Bytes>, mut data: Bytes, end: bool) {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .and_then(Result::ok)
            .unwrap_or(0);
        if capacity == 0 {
            return;
        }
        let part = data.split_to(capacity.min(data.len()));
        let last = data.is_empty() && end;
        if stream.send_data(part, last).is_err() {
            return;
        }
    }
    if end && data.is_empty() {
        drop(stream.send_data(Bytes::new(), true));
    }
}

fn trailers_only(mut respond: SendResponse<Bytes>, status: u32) {
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("grpc-status", status.to_string())
        .body(())
        .expect("response");
    drop(respond.send_response(response, true));
}

async fn answer_message(mut respond: SendResponse<Bytes>, message: &[u8]) {
    let response = Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .expect("response");
    let Ok(mut stream) = respond.send_response(response, false) else {
        return;
    };
    send_data(&mut stream, framed(message), false).await;
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().expect("value"));
    drop(stream.send_trailers(trailers));
}

/// A plugin server on a unix socket. Dropping it closes the socket and every connection.
pub struct Server {
    pub socket: PathBuf,
    calls: Arc<Mutex<Vec<Call>>>,
    peak: Arc<AtomicUsize>,
    describes: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
}

struct Shared {
    name: String,
    describe: Describe,
    handler: Handler,
    calls: Arc<Mutex<Vec<Call>>>,
    active: AtomicUsize,
    peak: Arc<AtomicUsize>,
    describes: Arc<AtomicUsize>,
}

async fn handle(shared: Arc<Shared>, request: Request<RecvStream>, respond: SendResponse<Bytes>) {
    let path = request.uri().path().to_owned();
    let mut body = request.into_body();
    let message = read_message(&mut body).await;
    if path == DESCRIBE {
        shared.describes.fetch_add(1, Ordering::SeqCst);
        match describe_message(&shared.name, &shared.describe) {
            Some(described) => answer_message(respond, &described.encode_to_vec()).await,
            None => {
                let Describe::Status(code) = &shared.describe else {
                    return;
                };
                trailers_only(respond, *code);
            }
        }
        return;
    }
    if path != PROCESS {
        trailers_only(respond, 12);
        return;
    }
    let call = Call::decode(message.as_slice()).expect("a call");
    shared
        .calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(call.clone());
    let now = shared.active.fetch_add(1, Ordering::SeqCst) + 1;
    shared.peak.fetch_max(now, Ordering::SeqCst);
    let mut reply = (shared.handler)(&call);
    loop {
        match reply {
            Reply::After(delay, next) => {
                tokio::time::sleep(delay).await;
                reply = *next;
            }
            Reply::Decision(decision) => {
                answer_message(respond, &decision.encode_to_vec()).await;
                break;
            }
            Reply::Hang => {
                std::future::pending::<()>().await;
                break;
            }
            Reply::Status(code) => {
                trailers_only(respond, code);
                break;
            }
            Reply::Raw(bytes) => {
                answer_message(respond, &bytes).await;
                break;
            }
            Reply::Big(size) => {
                let decision = Decision {
                    add_response_headers: vec![Header {
                        name: "x-big".into(),
                        value: vec![b'a'; size],
                    }],
                    ..Decision::default()
                };
                answer_message(respond, &decision.encode_to_vec()).await;
                break;
            }
        }
    }
    shared.active.fetch_sub(1, Ordering::SeqCst);
}

async fn serve_connection(
    shared: Arc<Shared>,
    stream: UnixStream,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let Some(Ok((request, respond))) = accepted else { return };
                tokio::spawn(handle(Arc::clone(&shared), request, respond));
            }
            _ = stop.changed() => return,
        }
    }
}

impl Server {
    /// Listens on `socket` as `name`, answering `Describe` as `describe` says and every call as
    /// `handler` says.
    pub async fn start(socket: &Path, name: &str, describe: Describe, handler: Handler) -> Self {
        drop(std::fs::remove_file(socket));
        let listener = UnixListener::bind(socket).expect("bind the plugin socket");
        let (stop, watcher) = watch::channel(false);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let peak = Arc::new(AtomicUsize::new(0));
        let describes = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Shared {
            name: name.to_owned(),
            describe,
            handler,
            calls: Arc::clone(&calls),
            active: AtomicUsize::new(0),
            peak: Arc::clone(&peak),
            describes: Arc::clone(&describes),
        });
        let mut accept_stop = watcher.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { return };
                        tokio::spawn(serve_connection(Arc::clone(&shared), stream, watcher.clone()));
                    }
                    _ = accept_stop.changed() => return,
                }
            }
        });
        Self {
            socket: socket.to_owned(),
            calls,
            peak,
            describes,
            stop,
        }
    }

    /// A server whose every call continues, recording what it was asked.
    pub async fn passive(socket: &Path, name: &str) -> Self {
        Self::start(
            socket,
            name,
            Describe::all(),
            Arc::new(|_| Reply::Decision(Decision::default())),
        )
        .await
    }

    /// The calls the plugin has been asked, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The most calls the plugin has had in flight at once.
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }

    /// The `Describe` calls so far.
    pub fn describes(&self) -> usize {
        self.describes.load(Ordering::SeqCst)
    }

    /// Closes the socket and every connection: the plugin is dead.
    pub fn kill(&self) {
        let _ = self.stop.send(true);
        drop(std::fs::remove_file(&self.socket));
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.kill();
    }
}

fn header(name: &str, value: &str) -> Header {
    Header {
        name: name.to_owned(),
        value: value.as_bytes().to_vec(),
    }
}

fn pairs(value: Option<&Value>) -> Vec<Header> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(name, value)| header(name, value.as_str().unwrap_or_default()))
                .collect()
        })
        .unwrap_or_default()
}

/// Allocates and touches `megabytes` of memory, then keeps it until the process ends.
fn hold_memory(megabytes: u64) {
    let mut held: Vec<Vec<u8>> = Vec::new();
    for _ in 0..megabytes {
        held.push(vec![1_u8; 1 << 20]);
    }
    std::mem::forget(held);
}

/// What the `echo_plugin` does with a call: acts on the middleware's `config`.
///
/// | key | effect |
/// |---|---|
/// | `set`, `remove`, `add_response` | header changes of the decision |
/// | `saw` | sets the request header `x-plugin-saw` to what the call carried, as JSON |
/// | `saw_response` | adds the response header `x-plugin-saw-response`, with the upstream's status and header names, in the response phase |
/// | `respond` | `{"status", "headers", "body"}`: answers the request |
/// | `sleep_ms` | waits before answering |
/// | `alloc_mb` | touches that much memory, so a cgroup limit can kill the process |
/// | `exit` | the process exits at once |
/// | `big` | a decision of that many bytes |
pub fn echo(call: &Call) -> Reply {
    let config: Value = serde_json::from_slice(&call.config).unwrap_or_else(|_| json!({}));
    if config["exit"].as_bool() == Some(true) {
        std::process::exit(3);
    }
    if let Some(megabytes) = config["alloc_mb"].as_u64() {
        hold_memory(megabytes);
    }
    let response_phase = call.phase == Phase::ResponseHeaders as i32;
    let mut decision = Decision::default();
    if let Some(respond) = config.get("respond").filter(|_| !response_phase) {
        decision.action = Action::Respond as i32;
        decision.response = Some(Answer {
            status: respond["status"].as_u64().unwrap_or(200) as u32,
            headers: pairs(respond.get("headers")),
            body: respond["body"]
                .as_str()
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
        });
    } else if !response_phase {
        decision.set_request_headers = pairs(config.get("set"));
        decision.remove_request_headers = config["remove"]
            .as_array()
            .map(|names| {
                names
                    .iter()
                    .filter_map(|name| name.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        if config["saw"].as_bool() == Some(true) {
            let seen = json!({
                "phase": call.phase, "tenant": call.tenant, "app": call.app,
                "router": call.router, "middleware": call.middleware,
                "client_addr": call.client_addr, "method": call.method,
                "target": call.target, "host": call.host, "scheme": call.scheme,
                "headers": call.headers.iter().map(|h| h.name.clone()).collect::<Vec<_>>(),
                "body_len": call.body.len(),
                "config": String::from_utf8_lossy(&call.config),
            });
            decision
                .set_request_headers
                .push(header("x-plugin-saw", &seen.to_string()));
        }
    }
    decision.add_response_headers = pairs(config.get("add_response"));
    if response_phase && config["saw_response"].as_bool() == Some(true) {
        let seen = json!({
            "status": call.status,
            "headers": call.response_headers.iter().map(|h| h.name.clone()).collect::<Vec<_>>(),
        });
        decision
            .add_response_headers
            .push(header("x-plugin-saw-response", &seen.to_string()));
    }
    let reply = if let Some(size) = config["big"].as_u64() {
        Reply::Big(usize::try_from(size).expect("size"))
    } else {
        Reply::Decision(decision)
    };
    match config["sleep_ms"].as_u64() {
        Some(ms) => Reply::After(Duration::from_millis(ms), Box::new(reply)),
        None => reply,
    }
}

/// Serves [`echo`] on `socket` until the process ends: what `echo_plugin`'s `main` runs.
pub async fn serve_forever(socket: &Path, name: &str) {
    if let Some(file) = std::env::var_os("PLUGIN_PID_FILE") {
        let mut line = std::process::id().to_string();
        line.push('\n');
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file);
        if let Ok(mut file) = appended {
            drop(std::io::Write::write_all(&mut file, line.as_bytes()));
        }
    }
    let server = Server::start(socket, name, Describe::all(), Arc::new(echo)).await;
    std::future::pending::<()>().await;
    drop(server);
}

/// The `echo_plugin` example, run as a process by the test. Killed by its pid when dropped.
pub struct Process {
    child: Child,
    pub socket: PathBuf,
}

/// Where cargo put the examples of the test binary being run.
fn example(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary's path");
    let debug = exe
        .parent()
        .and_then(Path::parent)
        .expect("target/<profile>/deps/<test>");
    let path = debug.join("examples").join(name);
    assert!(
        path.exists(),
        "{} is not built: run `cargo build --example {name}` (cargo test builds it)",
        path.display()
    );
    path
}

/// The path of the built `echo_plugin` example.
pub fn echo_plugin_path() -> PathBuf {
    example("echo_plugin")
}

impl Process {
    /// Starts `echo_plugin` serving on `socket`, and waits until it listens.
    pub async fn start(socket: &Path) -> Self {
        let child = Command::new(echo_plugin_path())
            .env("PODGATE_PLUGIN_SOCKET", socket)
            .env("PODGATE_PLUGIN_NAME", "echo")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start echo_plugin");
        let process = Self {
            child,
            socket: socket.to_owned(),
        };
        wait_for_socket(socket).await;
        process
    }

    /// The process id.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Kills the process now, as a crash does.
    pub fn crash(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.crash();
        drop(std::fs::remove_file(&self.socket));
    }
}

/// Waits until something accepts connections on `socket`.
pub async fn wait_for_socket(socket: &Path) {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if UnixStream::connect(socket).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("nothing listens on {}", socket.display());
}

/// The process ids a pid file lists, one per line.
pub fn pids(file: &Path) -> Vec<u32> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// Kills the processes a plugin wrote to its pid file when dropped: the plugins a `podgate`
/// under test started itself are not its test's children, and `podgate` is killed, not stopped.
pub struct PidGuard(pub PathBuf);

impl Drop for PidGuard {
    fn drop(&mut self) {
        for pid in pids(&self.0) {
            drop(
                Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .stderr(Stdio::null())
                    .status(),
            );
        }
    }
}
