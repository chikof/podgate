//! Asking authoritative DNS servers what they serve.
//!
//! A record counts as published when every authoritative server of its zone returns the exact
//! TXT value at the exact name. The CA validates once, on its first query, so reporting a record
//! before the slowest server has it would spend the order. Queries go to the servers directly
//! (recursion off, UDP with a TCP retry on truncation), never through a cache.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout};

use super::{Job, Timing};

/// What one server answered for one name.
#[derive(Debug, Default)]
pub(super) struct Reply {
    /// The TXT values at the name (the strings of one record joined).
    pub txt: Vec<String>,
    /// The name a CNAME at the name points to.
    pub cname: Option<Name>,
}

fn query_message(name: &Name) -> Result<(u16, Vec<u8>), String> {
    let mut message = Message::query();
    message.metadata.recursion_desired = false;
    message.add_query(Query::query(name.clone(), RecordType::TXT));
    let bytes = message.to_vec().map_err(|err| err.to_string())?;
    Ok((message.metadata.id, bytes))
}

fn reply_of(bytes: &[u8], id: u16) -> Result<(bool, Reply), String> {
    let message = Message::from_vec(bytes).map_err(|err| format!("unreadable answer ({err})"))?;
    if message.metadata.id != id || message.metadata.message_type != MessageType::Response {
        return Err("the answer does not belong to the query".into());
    }
    match message.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        other => return Err(format!("the server answered {other}")),
    }
    let mut reply = Reply::default();
    for record in &message.answers {
        match &record.data {
            RData::TXT(txt) => {
                let joined: Vec<u8> = txt
                    .txt_data
                    .iter()
                    .flat_map(|s| s.iter().copied())
                    .collect();
                reply
                    .txt
                    .push(String::from_utf8_lossy(&joined).into_owned());
            }
            RData::CNAME(target) => reply.cname = Some(target.0.clone()),
            _ => {}
        }
    }
    Ok((message.metadata.truncation, reply))
}

async fn over_udp(server: SocketAddr, id: u16, query: &[u8]) -> Result<(bool, Reply), String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|err| format!("cannot open a socket ({err})"))?;
    socket
        .connect(server)
        .await
        .map_err(|err| format!("cannot reach the server ({err})"))?;
    socket
        .send(query)
        .await
        .map_err(|err| format!("cannot send the query ({err})"))?;
    let mut buffer = vec![0u8; 4096];
    loop {
        let read = socket
            .recv(&mut buffer)
            .await
            .map_err(|err| format!("no answer ({err})"))?;
        // A datagram that does not answer this query is noise: keep waiting for the real one.
        if let Ok(parsed) = reply_of(&buffer[..read], id) {
            return Ok(parsed);
        }
    }
}

async fn over_tcp(server: SocketAddr, id: u16, query: &[u8]) -> Result<Reply, String> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|err| format!("cannot connect ({err})"))?;
    let length = u16::try_from(query.len()).map_err(|_| "the query is too long".to_owned())?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(query);
    stream
        .write_all(&frame)
        .await
        .map_err(|err| format!("cannot send the query ({err})"))?;
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|err| format!("no answer ({err})"))?;
    let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream
        .read_exact(&mut answer)
        .await
        .map_err(|err| format!("short answer ({err})"))?;
    reply_of(&answer, id).map(|(_, reply)| reply)
}

/// Asks `server` for the TXT records (and a CNAME) at `name`.
pub(super) async fn ask(server: SocketAddr, name: &Name, wait: Duration) -> Result<Reply, String> {
    let (id, query) = query_message(name)?;
    let exchange = async {
        let (truncated, reply) = over_udp(server, id, &query).await?;
        if truncated {
            over_tcp(server, id, &query).await
        } else {
            Ok(reply)
        }
    };
    timeout(wait, exchange)
        .await
        .map_err(|_| "no answer in time".to_owned())?
}

/// The addresses of the authoritative servers of `zone`, from the system resolver: its NS
/// records, then their addresses (port 53).
pub(super) async fn discover(zone: &str, wait: Duration) -> Result<Vec<SocketAddr>, String> {
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .map_err(|err| format!("cannot read the system resolver configuration ({err})"))?
        .build()
        .map_err(|err| format!("cannot build a resolver ({err})"))?;
    let lookup = async {
        let name = Name::from_ascii(format!("{zone}.")).map_err(|err| err.to_string())?;
        let ns = resolver
            .ns_lookup(name)
            .await
            .map_err(|err| format!("the NS lookup of {zone} failed ({err})"))?;
        let mut servers = Vec::new();
        for record in ns.answers() {
            if let RData::NS(host) = &record.data
                && let Ok(ips) = resolver.lookup_ip(host.0.clone()).await
            {
                servers.extend(ips.iter().map(|ip| SocketAddr::new(ip, 53)));
            }
        }
        servers.sort_unstable();
        servers.dedup();
        if servers.is_empty() {
            return Err(format!(
                "the zone {zone} has no name server with an address"
            ));
        }
        Ok(servers)
    };
    timeout(wait, lookup)
        .await
        .map_err(|_| format!("the NS lookup of {zone} timed out"))?
}

/// One pass: the servers that do not return `value` at `name` yet, with why.
async fn missing(
    servers: &[SocketAddr],
    name: &Name,
    value: &str,
    wait: Duration,
) -> Vec<(SocketAddr, String)> {
    let mut asked = JoinSet::new();
    for server in servers.iter().copied() {
        let name = name.clone();
        asked.spawn(async move { (server, ask(server, &name, wait).await) });
    }
    let mut missing = Vec::new();
    while let Some(done) = asked.join_next().await {
        match done {
            Ok((_, Ok(reply))) if reply.txt.iter().any(|txt| txt == value) => {}
            Ok((server, Ok(_))) => missing.push((server, "the value is not there yet".into())),
            Ok((server, Err(why))) => missing.push((server, why)),
            Err(_) => {}
        }
    }
    missing.sort();
    missing
}

/// Polls every server until all return `value` at `name`, for at most `limit`.
///
/// # Errors
///
/// A message naming the servers that did not have it, when the limit passes, or when `job` ends
/// meanwhile.
pub(super) async fn wait_visible(
    servers: &[SocketAddr],
    name: &Name,
    value: &str,
    limit: Duration,
    timing: &Timing,
    job: &Job,
) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        let pending = missing(servers, name, value, timing.query_timeout).await;
        if pending.is_empty() {
            return Ok(());
        }
        if Instant::now() + timing.poll_interval >= deadline {
            let list: Vec<String> = pending
                .iter()
                .map(|(server, why)| format!("{server}: {why}"))
                .collect();
            return Err(format!(
                "not visible on every authoritative server after {}s ({})",
                limit.as_secs(),
                list.join("; ")
            ));
        }
        if !job.nap(timing.poll_interval).await {
            return Err("the challenge ended".into());
        }
    }
}
