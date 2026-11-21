//! A tiny DNS server for tests: a UDP responder on a free loopback port whose answers, TTLs and
//! failures the test controls, and that records every query it gets.
//!
//! It answers `A` and `AAAA` questions from the names a test [`Dns::set`], `NXDOMAIN` for a name
//! it does not know and an empty answer (`NODATA`) for a known name that has no record of the
//! asked type. [`Dns::fail`] makes it answer `SERVFAIL` and [`Dns::silence`] makes it not answer
//! at all, which is how a test takes the resolver away. Point podgate at it with
//! [`Dns::servers`] (`DNS_SERVERS`).
//!
//! It also answers `SRV` questions from [`Dns::set_srv`], with the address records of the targets
//! in the additional section when [`Dns::glue`] is on, and answers a `CNAME` for a name made an
//! alias by [`Dns::set_cname`], followed by the address records of its target as a recursive
//! resolver would.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

const A: u16 = 1;
const CNAME: u16 = 5;
const AAAA: u16 = 28;
const SRV: u16 = 33;
const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;

/// What the server does with a question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Answer,
    Fail,
    Silent,
}

/// One `SRV` record: priority, weight, port and the target host name.
type SrvRecord = (u16, u16, u16, String);

/// The records of one name.
#[derive(Clone, Debug, Default)]
struct Records {
    a: Vec<IpAddr>,
    aaaa: Vec<IpAddr>,
    ttl: u32,
    srv: Vec<SrvRecord>,
    srv_ttl: u32,
    /// The name is an alias of this one: its address questions get a `CNAME` first.
    cname: Option<String>,
}

#[derive(Debug)]
struct State {
    names: HashMap<String, Records>,
    glue: bool,
    mode: Mode,
    queries: Vec<(String, u16, Instant)>,
}

/// A running test DNS server; stops when dropped.
pub struct Dns {
    /// Where it listens.
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Dns {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Dns {
    /// Starts the server on a free loopback UDP port.
    pub async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind DNS");
        let addr = socket.local_addr().expect("DNS address");
        let state = Arc::new(Mutex::new(State {
            names: HashMap::new(),
            glue: false,
            mode: Mode::Answer,
            queries: Vec::new(),
        }));
        let task = tokio::spawn(serve(socket, Arc::clone(&state)));
        Self { addr, state, task }
    }

    /// The `DNS_SERVERS` value that points podgate at this server.
    pub fn servers(&self) -> String {
        self.addr.to_string()
    }

    /// Makes `name` answer `addrs` (`A` for the IPv4 ones, `AAAA` for the IPv6 ones) with a TTL
    /// of `ttl` seconds. Replaces what the name answered.
    pub fn set(&self, name: &str, addrs: &[&str], ttl: u32) {
        let parsed: Vec<IpAddr> = addrs
            .iter()
            .map(|addr| addr.parse().expect("an IP address"))
            .collect();
        let records = Records {
            a: parsed.iter().copied().filter(IpAddr::is_ipv4).collect(),
            aaaa: parsed.iter().copied().filter(IpAddr::is_ipv6).collect(),
            ttl,
            ..Records::default()
        };
        lock(&self.state)
            .names
            .insert(name.to_ascii_lowercase(), records);
    }

    /// Makes `owner` answer `SRV` records, `(priority, weight, port, target)` each, with a TTL
    /// of `ttl` seconds. Replaces the `SRV` records it answered; its address records stay.
    pub fn set_srv(&self, owner: &str, targets: &[(u16, u16, u16, &str)], ttl: u32) {
        let mut state = lock(&self.state);
        let records = state.names.entry(owner.to_ascii_lowercase()).or_default();
        records.srv = targets
            .iter()
            .map(|(priority, weight, port, target)| {
                (*priority, *weight, *port, target.to_ascii_lowercase())
            })
            .collect();
        records.srv_ttl = ttl;
    }

    /// Makes `alias` a `CNAME` of `target`: an `A` or `AAAA` question about it is answered with
    /// the `CNAME` and the address records of `target` (when `target` has some).
    pub fn set_cname(&self, alias: &str, target: &str, ttl: u32) {
        let mut state = lock(&self.state);
        let records = state.names.entry(alias.to_ascii_lowercase()).or_default();
        records.cname = Some(target.to_ascii_lowercase());
        records.ttl = ttl;
    }

    /// Whether an `SRV` answer carries the address records of its targets (and the `CNAME` of
    /// an alias target) in the additional section. Off at first, so the resolver has to ask.
    pub fn glue(&self, on: bool) {
        lock(&self.state).glue = on;
    }

    /// Makes `name` unknown again: `NXDOMAIN`.
    pub fn remove(&self, name: &str) {
        lock(&self.state).names.remove(&name.to_ascii_lowercase());
    }

    /// Answers `SERVFAIL` to everything until [`Self::recover`].
    pub fn fail(&self) {
        lock(&self.state).mode = Mode::Fail;
    }

    /// Does not answer anything until [`Self::recover`], so queries time out.
    pub fn silence(&self) {
        lock(&self.state).mode = Mode::Silent;
    }

    /// Answers from the records again.
    pub fn recover(&self) {
        lock(&self.state).mode = Mode::Answer;
    }

    /// How many `A`, `AAAA` and `SRV` questions about `name` arrived so far.
    pub fn queries_for(&self, name: &str) -> usize {
        let name = name.to_ascii_lowercase();
        lock(&self.state)
            .queries
            .iter()
            .filter(|(asked, _, _)| *asked == name)
            .count()
    }

    /// How many `A` questions about `name` arrived so far.
    pub fn a_queries_for(&self, name: &str) -> usize {
        self.typed(name, A)
    }

    /// How many `AAAA` questions about `name` arrived so far.
    pub fn aaaa_queries_for(&self, name: &str) -> usize {
        self.typed(name, AAAA)
    }

    /// How many `SRV` questions about `name` arrived so far.
    pub fn srv_queries_for(&self, name: &str) -> usize {
        self.typed(name, SRV)
    }

    fn typed(&self, name: &str, kind: u16) -> usize {
        let name = name.to_ascii_lowercase();
        lock(&self.state)
            .queries
            .iter()
            .filter(|(asked, asked_kind, _)| *asked == name && *asked_kind == kind)
            .count()
    }

    /// How many questions arrived so far, about any name and type.
    pub fn total_queries(&self) -> usize {
        lock(&self.state).queries.len()
    }

    /// How many questions arrived in the last `window`.
    pub fn queries_within(&self, window: Duration) -> usize {
        let now = Instant::now();
        lock(&self.state)
            .queries
            .iter()
            .filter(|(_, _, at)| now.saturating_duration_since(*at) <= window)
            .count()
    }
}

/// Reads the question of `packet`: its lower-cased name, its type and the offset just past it.
fn question(packet: &[u8]) -> Option<(String, u16, usize)> {
    let mut at = 12;
    let mut name = String::new();
    loop {
        let length = usize::from(*packet.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        // A question never compresses its name.
        if length > 63 {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(packet.get(at..at + length)?));
        at += length;
    }
    let kind = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    Some((name.to_ascii_lowercase(), kind, at + 4))
}

/// `name` as DNS labels, uncompressed.
fn labels(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(u8::try_from(label.len()).expect("a label of at most 63 bytes"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// One resource record of a response.
struct Rr {
    /// The owner; `None` is the name of the question.
    owner: Option<String>,
    kind: u16,
    ttl: u32,
    rdata: Vec<u8>,
}

impl Rr {
    fn address(owner: Option<&str>, ip: IpAddr, ttl: u32) -> Self {
        let (kind, rdata) = match ip {
            IpAddr::V4(ip) => (A, ip.octets().to_vec()),
            IpAddr::V6(ip) => (AAAA, ip.octets().to_vec()),
        };
        Self {
            owner: owner.map(str::to_owned),
            kind,
            ttl,
            rdata,
        }
    }

    fn cname(target: &str, ttl: u32) -> Self {
        Self {
            owner: None,
            kind: CNAME,
            ttl,
            rdata: labels(target),
        }
    }

    fn srv((priority, weight, port, target): &SrvRecord, ttl: u32) -> Self {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&priority.to_be_bytes());
        rdata.extend_from_slice(&weight.to_be_bytes());
        rdata.extend_from_slice(&port.to_be_bytes());
        rdata.extend_from_slice(&labels(target));
        Self {
            owner: None,
            kind: SRV,
            ttl,
            rdata,
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        match &self.owner {
            None => out.extend_from_slice(&[0xc0, 0x0c]),
            Some(name) => out.extend_from_slice(&labels(name)),
        }
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(self.rdata.len()).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.rdata);
    }
}

/// The response to `packet`: the question echoed back with `rcode`, `answers` and `additionals`.
fn respond(packet: &[u8], end: usize, rcode: u8, answers: &[Rr], additionals: &[Rr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(end + answers.len() * 28);
    out.extend_from_slice(&packet[..2]);
    // Response, authoritative, recursion available; recursion desired as asked.
    out.push(0x84 | (packet[2] & 0x01));
    out.push(0x80 | rcode);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&u16::try_from(additionals.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&packet[12..end]);
    for record in answers.iter().chain(additionals) {
        record.write(&mut out);
    }
    out
}

/// The address records `name` holds for `kind`, as records owned by `owner`.
fn addresses(records: &Records, kind: u16, owner: Option<&str>) -> Vec<Rr> {
    let found: &[IpAddr] = match kind {
        A => &records.a,
        AAAA => &records.aaaa,
        _ => &[],
    };
    found
        .iter()
        .map(|ip| Rr::address(owner, *ip, records.ttl))
        .collect()
}

/// The answer and additional records for a question of `kind` about the known `records`.
fn answer_known(state: &State, kind: u16, records: &Records) -> (Vec<Rr>, Vec<Rr>) {
    match kind {
        A | AAAA => match &records.cname {
            Some(target) => {
                let mut answers = vec![Rr::cname(target, records.ttl)];
                if let Some(real) = state.names.get(target) {
                    answers.extend(addresses(real, kind, Some(target)));
                }
                (answers, Vec::new())
            }
            None => (addresses(records, kind, None), Vec::new()),
        },
        SRV => {
            let answers: Vec<Rr> = records
                .srv
                .iter()
                .map(|record| Rr::srv(record, records.srv_ttl))
                .collect();
            let mut additionals = Vec::new();
            if state.glue {
                for (_, _, _, target) in &records.srv {
                    let Some(host) = state.names.get(target) else {
                        continue;
                    };
                    if let Some(real) = &host.cname {
                        additionals.push(Rr {
                            owner: Some(target.clone()),
                            kind: CNAME,
                            ttl: host.ttl,
                            rdata: labels(real),
                        });
                        continue;
                    }
                    additionals.extend(addresses(host, A, Some(target)));
                    additionals.extend(addresses(host, AAAA, Some(target)));
                }
            }
            (answers, additionals)
        }
        _ => (Vec::new(), Vec::new()),
    }
}

async fn serve(socket: UdpSocket, state: Arc<Mutex<State>>) {
    let mut buffer = [0_u8; 1500];
    while let Ok((length, from)) = socket.recv_from(&mut buffer).await {
        let packet = &buffer[..length];
        let Some((name, kind, end)) = question(packet) else {
            continue;
        };
        let reply = {
            let mut state = lock(&state);
            if matches!(kind, A | AAAA | SRV) {
                state.queries.push((name.clone(), kind, Instant::now()));
            }
            match state.mode {
                Mode::Silent => continue,
                Mode::Fail => respond(packet, end, SERVFAIL, &[], &[]),
                Mode::Answer => match state.names.get(&name) {
                    None => respond(packet, end, NXDOMAIN, &[], &[]),
                    Some(records) => {
                        let (answers, additionals) = answer_known(&state, kind, records);
                        respond(packet, end, 0, &answers, &additionals)
                    }
                },
            }
        };
        // A lost reply is the resolver's retry to handle.
        drop(socket.send_to(&reply, from).await);
    }
}
