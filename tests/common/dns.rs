//! A tiny DNS server for tests: a UDP responder on a free loopback port whose answers, TTLs and
//! failures the test controls, and that records every query it gets.
//!
//! It answers `A` and `AAAA` questions from the names a test [`Dns::set`], `NXDOMAIN` for a name
//! it does not know and an empty answer (`NODATA`) for a known name that has no record of the
//! asked type. [`Dns::fail`] makes it answer `SERVFAIL` and [`Dns::silence`] makes it not answer
//! at all, which is how a test takes the resolver away. Point podgate at it with
//! [`Dns::servers`] (`DNS_SERVERS`). Change 0096 extends it with `SRV`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

const A: u16 = 1;
const AAAA: u16 = 28;
const SERVFAIL: u8 = 2;
const NXDOMAIN: u8 = 3;

/// What the server does with a question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Answer,
    Fail,
    Silent,
}

/// The records of one name.
#[derive(Clone, Debug, Default)]
struct Records {
    a: Vec<IpAddr>,
    aaaa: Vec<IpAddr>,
    ttl: u32,
}

#[derive(Debug)]
struct State {
    names: HashMap<String, Records>,
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
        };
        lock(&self.state)
            .names
            .insert(name.to_ascii_lowercase(), records);
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

    /// How many `A` and `AAAA` questions about `name` arrived so far.
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

    fn typed(&self, name: &str, kind: u16) -> usize {
        let name = name.to_ascii_lowercase();
        lock(&self.state)
            .queries
            .iter()
            .filter(|(asked, asked_kind, _)| *asked == name && *asked_kind == kind)
            .count()
    }

    /// How many questions arrived so far, about any name.
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

/// The response to `packet`: the question echoed back with `rcode` and `answers`.
fn respond(
    packet: &[u8],
    end: usize,
    rcode: u8,
    kind: u16,
    answers: &[IpAddr],
    ttl: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(end + answers.len() * 28);
    out.extend_from_slice(&packet[..2]);
    // Response, authoritative, recursion available; recursion desired as asked.
    out.push(0x84 | (packet[2] & 0x01));
    out.push(0x80 | rcode);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&packet[12..end]);
    for answer in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        match answer {
            IpAddr::V4(ip) => {
                out.extend_from_slice(&[0, 4]);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.extend_from_slice(&[0, 16]);
                out.extend_from_slice(&ip.octets());
            }
        }
    }
    out
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
            if matches!(kind, A | AAAA) {
                state.queries.push((name.clone(), kind, Instant::now()));
            }
            match state.mode {
                Mode::Silent => continue,
                Mode::Fail => respond(packet, end, SERVFAIL, kind, &[], 0),
                Mode::Answer => match state.names.get(&name) {
                    None => respond(packet, end, NXDOMAIN, kind, &[], 0),
                    Some(records) => {
                        let answers: &[IpAddr] = match kind {
                            A => &records.a,
                            AAAA => &records.aaaa,
                            _ => &[],
                        };
                        respond(packet, end, 0, kind, answers, records.ttl)
                    }
                },
            }
        };
        // A lost reply is the resolver's retry to handle.
        drop(socket.send_to(&reply, from).await);
    }
}
