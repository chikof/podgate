//! An authoritative DNS server for one zone, in process: it answers TXT (and CNAME) queries over
//! UDP and TCP, and accepts RFC 2136 updates over TCP, verifying their TSIG and signing the
//! answer. It is what `pebble` queries for the DNS-01 end-to-end test, and what the solver's
//! verification polls, so a record exists only when an update reached the server.
//!
//! Records are kept per name. A test sets records by hand (`set_txt`, `add_cname`) to stand in for
//! a slow secondary, and reads what the solver did through `txt`, `queries` and `updates`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, TSigResponseContext, TSigner};
use podgate_provider::Config;
use podgate_provider::acme::dns::Timing;
use podgate_provider::acme::events::DnsChallenge;
use podgate_provider::acme::{ClaimedApp, Claims};
use podgate_provider::trust::HostPattern;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// One accepted change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// `true` for an addition, `false` for the removal of one value.
    pub add: bool,
    pub name: String,
    pub value: String,
}

#[derive(Default)]
struct State {
    zone: Option<Name>,
    key: Option<TSigner>,
    txt: BTreeMap<Name, Vec<String>>,
    cname: BTreeMap<Name, Name>,
    asked: HashMap<Name, usize>,
    updates: Vec<Update>,
    refused: usize,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn name(text: &str) -> Name {
    Name::from_ascii(format!("{}.", text.trim_end_matches('.'))).expect("a DNS name")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

pub struct DnsServer {
    /// UDP and TCP both listen here.
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl DnsServer {
    /// A server for `zone` that accepts updates signed with `key` (name, algorithm, key bytes),
    /// or no updates at all when there is none.
    pub async fn start(zone: &str, key: Option<(&str, TsigAlgorithm, Vec<u8>)>) -> Self {
        let state = Arc::new(Mutex::new(State {
            zone: Some(name(zone)),
            key: key.map(|(key_name, algorithm, bytes)| {
                TSigner::new(bytes, algorithm, name(key_name), 300).expect("a TSIG key")
            }),
            ..State::default()
        }));
        // UDP and TCP must share a port: the solver updates over TCP, asks over UDP, and pebble
        // asks over UDP. Another process can take the TCP port between the two binds.
        let (udp, tcp) = 'bound: {
            for _ in 0..50 {
                let udp = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
                let port = udp.local_addr().expect("udp address").port();
                if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)).await {
                    break 'bound (udp, tcp);
                }
            }
            panic!("no port free for both udp and tcp");
        };
        let addr = udp.local_addr().expect("udp address");
        let udp_task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                while let Ok((read, from)) = udp.recv_from(&mut buffer).await {
                    if let Some(answer) = respond(&state, &buffer[..read]) {
                        let _ = udp.send_to(&answer, from).await;
                    }
                }
            })
        };
        let tcp_task = {
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = tcp.accept().await {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        loop {
                            let mut prefix = [0u8; 2];
                            if stream.read_exact(&mut prefix).await.is_err() {
                                return;
                            }
                            let mut request = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                            if stream.read_exact(&mut request).await.is_err() {
                                return;
                            }
                            let Some(answer) = respond(&state, &request) else {
                                return;
                            };
                            let mut frame = u16::try_from(answer.len())
                                .expect("short answer")
                                .to_be_bytes()
                                .to_vec();
                            frame.extend_from_slice(&answer);
                            if stream.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            })
        };
        Self {
            addr,
            state,
            tasks: vec![udp_task, tcp_task],
        }
    }

    /// The TXT values at `at`, as the server holds them.
    pub fn txt(&self, at: &str) -> Vec<String> {
        lock(&self.state)
            .txt
            .get(&name(at))
            .cloned()
            .unwrap_or_default()
    }

    /// Adds a TXT value without an update, the way a zone transfer would.
    pub fn set_txt(&self, at: &str, value: &str) {
        let mut state = lock(&self.state);
        let values = state.txt.entry(name(at)).or_default();
        if !values.iter().any(|known| known == value) {
            values.push(value.to_owned());
        }
    }

    /// Puts a CNAME at `at` that points to `target`.
    pub fn add_cname(&self, at: &str, target: &str) {
        lock(&self.state).cname.insert(name(at), name(target));
    }

    /// How many TXT queries the server answered for `at`.
    pub fn queries(&self, at: &str) -> usize {
        lock(&self.state).asked.get(&name(at)).copied().unwrap_or(0)
    }

    /// Every update the server applied, oldest first.
    pub fn updates(&self) -> Vec<Update> {
        lock(&self.state).updates.clone()
    }

    /// How many updates the server refused because their TSIG did not verify.
    pub fn refused(&self) -> usize {
        lock(&self.state).refused
    }
}

fn txt_record(at: &Name, value: &str) -> Record {
    Record::from_rdata(at.clone(), 60, RData::TXT(TXT::new(vec![value.to_owned()])))
}

fn txt_value(record: &Record) -> Option<String> {
    match &record.data {
        RData::TXT(txt) => Some(String::from_utf8_lossy(&txt.txt_data.concat()).into_owned()),
        _ => None,
    }
}

fn respond(state: &Mutex<State>, request: &[u8]) -> Option<Vec<u8>> {
    let message = Message::from_vec(request).ok()?;
    let mut state = lock(state);
    match message.metadata.op_code {
        OpCode::Update => update(&mut state, &message, request),
        OpCode::Query => query(&mut state, &message),
        _ => Message::error_msg(
            message.metadata.id,
            message.metadata.op_code,
            ResponseCode::NotImp,
        )
        .to_vec()
        .ok(),
    }
}

fn query(state: &mut State, request: &Message) -> Option<Vec<u8>> {
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.authoritative = true;
    for question in &request.queries {
        response.add_query(question.clone());
        let at = question.name().to_lowercase();
        if question.query_type() == RecordType::TXT {
            *state.asked.entry(at.clone()).or_default() += 1;
        }
        if let Some(target) = state.cname.get(&at) {
            response.add_answer(Record::from_rdata(
                at.clone(),
                60,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
            ));
        } else if question.query_type() == RecordType::TXT {
            for value in state.txt.get(&at).into_iter().flatten() {
                response.add_answer(txt_record(&at, value));
            }
        }
    }
    response.to_vec().ok()
}

fn refuse(request: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    Message::error_msg(request.metadata.id, OpCode::Update, code)
        .to_vec()
        .ok()
}

fn update(state: &mut State, request: &Message, bytes: &[u8]) -> Option<Vec<u8>> {
    let signer = state.key.clone()?;
    let verified = signer.verify_message_byte(bytes, None, true);
    let Ok((mac, signed_at, window)) = verified else {
        state.refused += 1;
        return refuse(request, ResponseCode::NotAuth);
    };
    if !window.contains(&now()) {
        state.refused += 1;
        return refuse(request, ResponseCode::NotAuth);
    }
    let in_zone = request
        .queries
        .first()
        .is_some_and(|zone| Some(&zone.name().to_lowercase()) == state.zone.as_ref());
    if !in_zone {
        return refuse(request, ResponseCode::NotZone);
    }
    for record in &request.authorities {
        let at = record.name.to_lowercase();
        let Some(zone) = &state.zone else { continue };
        if !zone.zone_of(&at) {
            return refuse(request, ResponseCode::NotZone);
        }
        match (record.dns_class, txt_value(record)) {
            (DNSClass::IN, Some(value)) => {
                let values = state.txt.entry(at.clone()).or_default();
                if !values.contains(&value) {
                    values.push(value.clone());
                }
                state.updates.push(Update {
                    add: true,
                    name: at.to_ascii(),
                    value,
                });
            }
            (DNSClass::NONE, Some(value)) => {
                if let Some(values) = state.txt.get_mut(&at) {
                    values.retain(|known| *known != value);
                }
                state.updates.push(Update {
                    add: false,
                    name: at.to_ascii(),
                    value,
                });
            }
            _ => return refuse(request, ResponseCode::FormErr),
        }
    }
    let mut response = Message::response(request.metadata.id, OpCode::Update);
    response.metadata.message_type = MessageType::Response;
    let unsigned = response.to_vec().ok()?;
    let signature = TSigResponseContext::new(request.metadata.id, signed_at, signer, mac, None)
        .sign(&unsigned)
        .ok()?;
    response.set_signature(signature);
    response.to_vec().ok()
}

impl DnsServer {
    /// Removes one TXT value without an update.
    pub fn clear_txt(&self, at: &str, value: &str) {
        if let Some(values) = lock(&self.state).txt.get_mut(&name(at)) {
            values.retain(|known| known != value);
        }
    }
}

/// One request the webhook received.
#[derive(Debug, Clone)]
pub struct Hook {
    pub method: String,
    pub path: String,
    /// Header names are lowercase.
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// What the webhook answers.
#[derive(Debug, Clone, Copy)]
pub enum Answer {
    /// This status, an empty body.
    Status(u16),
    /// This status, with the request's own header block as the body: a hostile endpoint that
    /// echoes secrets.
    Echo(u16),
    /// No answer: the connection stays open.
    Hang,
}

type Script = Box<dyn Fn(&Hook, usize) -> Answer + Send + Sync>;

/// A webhook on a loopback port. `script` gets each request and its number (from 0).
pub struct WebhookServer {
    pub addr: SocketAddr,
    seen: Arc<Mutex<Vec<Hook>>>,
    task: JoinHandle<()>,
}

impl Drop for WebhookServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_hook(stream: &mut tokio::net::TcpStream) -> Option<(Hook, String)> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(at) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut request_line = lines.next()?.split_whitespace();
    let (method, path) = (
        request_line.next()?.to_owned(),
        request_line.next()?.to_owned(),
    );
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length: usize = headers.get("content-length")?.parse().ok()?;
    while raw.len() < head_end + length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8_lossy(&raw[head_end..head_end + length]).into_owned();
    Some((
        Hook {
            method,
            path,
            headers,
            body,
        },
        head,
    ))
}

impl WebhookServer {
    pub async fn start(script: impl Fn(&Hook, usize) -> Answer + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind webhook");
        let addr = listener.local_addr().expect("webhook address");
        let seen: Arc<Mutex<Vec<Hook>>> = Arc::default();
        let script: Arc<Script> = Arc::new(Box::new(script));
        let task = {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let (seen, script) = (Arc::clone(&seen), Arc::clone(&script));
                    tokio::spawn(async move {
                        let Some((hook, head)) = read_hook(&mut stream).await else {
                            return;
                        };
                        let number = {
                            let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
                            seen.push(hook.clone());
                            seen.len() - 1
                        };
                        let (status, body) = match script(&hook, number) {
                            Answer::Status(status) => (status, String::new()),
                            Answer::Echo(status) => (status, head),
                            Answer::Hang => {
                                tokio::time::sleep(Duration::from_secs(30)).await;
                                return;
                            }
                        };
                        let answer = format!(
                            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(answer.as_bytes()).await;
                    });
                }
            })
        };
        Self { addr, seen, task }
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Hook> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

// ---- fixtures shared by acme_dns.rs and acme_dns_logs.rs -----------------------------------

pub const KEY_NAME: &str = "podgate-key.acme.test";
pub const SECRET: &[u8] = b"a-tsig-key-that-must-never-be-logged";
pub const TOKEN: &str = "webhook-bearer-token-7f3a";

pub fn timing() -> Timing {
    Timing {
        query_timeout: Duration::from_millis(500),
        poll_interval: Duration::from_millis(20),
        update_timeout: Duration::from_secs(3),
        retry_min: Duration::from_millis(10),
        retry_max: Duration::from_millis(40),
        give_up: Duration::from_secs(10),
    }
}

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgp-dns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

pub fn file(dir: &Path, name: &str, content: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub async fn tsig_server(zone: &str, secret: &[u8]) -> Arc<DnsServer> {
    Arc::new(
        DnsServer::start(
            zone,
            Some((KEY_NAME, TsigAlgorithm::HmacSha256, secret.to_vec())),
        )
        .await,
    )
}

/// A `[[acme.dns]]` entry for `zone` that updates `server` and checks `resolvers`.
pub fn rfc2136_zone(
    zone: &str,
    server: &Arc<DnsServer>,
    secret_file: &Path,
    resolvers: &[&Arc<DnsServer>],
) -> String {
    let resolvers: Vec<String> = resolvers
        .iter()
        .map(|r| format!("\"{}\"", r.addr))
        .collect();
    format!(
        "[[acme.dns]]\nzone = \"{zone}\"\nkind = \"rfc2136\"\nserver = \"{}\"\ntsig_key_name = \"{KEY_NAME}\"\ntsig_algorithm = \"hmac-sha256\"\ntsig_secret_file = {:?}\ncheck_resolvers = [{}]\n",
        server.addr,
        secret_file.display().to_string(),
        resolvers.join(", ")
    )
}

pub fn webhook_zone(
    zone: &str,
    hook: &WebhookServer,
    token_file: &Path,
    resolvers: &[&Arc<DnsServer>],
) -> String {
    let resolvers: Vec<String> = resolvers
        .iter()
        .map(|r| format!("\"{}\"", r.addr))
        .collect();
    format!(
        "[[acme.dns]]\nzone = \"{zone}\"\nkind = \"webhook\"\nurl = \"http://{}/hook/\"\nbearer_token_file = {:?}\ncheck_resolvers = [{}]\n",
        hook.addr,
        token_file.display().to_string(),
        resolvers.join(", ")
    )
}

/// The provider configuration: two tenants and the given `[[acme.dns]]` entries.
pub fn config(dir: &Path, zones: &str) -> Config {
    let text = format!(
        r#"admin_socket = "/nonexistent/admin.sock"
[[tenant]]
id = "acme"
hosts = ["acme.test", "*.acme.test"]

[[tenant]]
id = "globex"
hosts = ["globex.test", "*.globex.test"]

[acme]
enabled = true
state_dir = {:?}
directory_url = "https://ca.test/dir"
issuer_node = "n1"
{zones}"#,
        dir.join("state").display().to_string()
    );
    Config::parse(&text).unwrap_or_else(|err| panic!("test config is invalid: {err}\n{text}"))
}

pub fn claims(apps: &[(&str, &str, &[&str])]) -> Arc<Claims> {
    Arc::new(Claims {
        apps: apps
            .iter()
            .map(|(app, tenant, hosts)| ClaimedApp {
                app: (*app).into(),
                tenant: (*tenant).into(),
                on_demand: false,
                hosts: hosts
                    .iter()
                    .map(|host| HostPattern::parse(host).expect("host"))
                    .collect(),
            })
            .collect(),
    })
}

/// The apex and wildcard of `acme.test`, claimed by tenant `acme`.
pub fn acme_claims() -> Arc<Claims> {
    claims(&[("shop", "acme", &["acme.test", "*.acme.test"])])
}

pub fn challenge(name: &str, value: &str) -> DnsChallenge {
    DnsChallenge {
        name: name.into(),
        value: value.into(),
    }
}

pub async fn within<T>(what: &str, wait: impl Future<Output = T>) -> T {
    tokio::time::timeout(super::DEADLINE, wait)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish in {:?}", super::DEADLINE))
}

pub fn refusal(err: &podgate_provider::acme::events::SolveError) -> &str {
    &err.0
}
