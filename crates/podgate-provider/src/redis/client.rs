//! A client for the few commands of a Redis-compatible store that the source needs.
//!
//! The only way to send anything is [`Conn::call`] (and, for the subscription, [`Conn::subscribe`]
//! and [`Subscription`]), and they take a [`Command`]: `AUTH`, `SELECT`, `SCAN`, `MGET`,
//! `SUBSCRIBE`, `PSUBSCRIBE` and `PING`. There is no variant for a write, for `KEYS`, for `CONFIG`
//! or for a script, so a source that only follows configuration cannot change what it follows or
//! scan a store in one blocking call, and a read-only ACL user is enough.
//!
//! Keys are found with `SCAN MATCH <prefix>*` and read with `MGET`. Values past
//! [`MAX_VALUE_BYTES`] are never held: the reader throws them away as they arrive and the key is
//! reported. A prefix holding more than [`MAX_KEYS_PER_PREFIX`] keys or [`MAX_PREFIX_BYTES`] of
//! values is not read at all.
//!
//! The password is read from its file once, lives in a [`Secret`] and is part of no error, `Debug`
//! output or log line. The error text of a server that refuses it is replaced by a fixed one.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use rustls_pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::resp::{Reader, Reply, RespError, encode};
use crate::acme::Secret;
use crate::kv::MAX_KEYS_PER_PREFIX;

/// The largest value the source reads. A key with a longer one is left out and reported.
pub(super) const MAX_VALUE_BYTES: usize = 256 * 1024;

/// The most value bytes one prefix may hold. A prefix with more is not read.
pub(super) const MAX_PREFIX_BYTES: usize = 32 * 1024 * 1024;

/// Keys asked for by one `MGET`.
const MGET_BATCH: usize = 32;

/// How many keys `SCAN` is asked to look at per call.
const SCAN_COUNT: &[u8] = b"512";

/// The longest a connection may take to open, TLS and login included.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The longest the store may take to answer one command.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a server's error text that is quoted.
const MAX_QUOTED: usize = 200;

/// What the source asks the store. Nothing here writes.
#[derive(Debug, Clone, Copy)]
pub(super) enum Command<'a> {
    /// `AUTH [username] password`.
    Auth {
        username: Option<&'a str>,
        password: &'a Secret,
    },
    /// `SELECT db`.
    Select(u32),
    /// `SCAN cursor MATCH pattern COUNT n`.
    Scan { cursor: u64, pattern: &'a [u8] },
    /// `MGET key...`.
    MGet(&'a [Vec<u8>]),
    /// `SUBSCRIBE channel`.
    Subscribe(&'a str),
    /// `PSUBSCRIBE pattern`.
    PSubscribe(&'a [u8]),
    /// `PING`.
    Ping,
}

impl Command<'_> {
    /// The command name as it goes on the wire.
    #[cfg(test)]
    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Auth { .. } => "AUTH",
            Self::Select(_) => "SELECT",
            Self::Scan { .. } => "SCAN",
            Self::MGet(_) => "MGET",
            Self::Subscribe(_) => "SUBSCRIBE",
            Self::PSubscribe(_) => "PSUBSCRIBE",
            Self::Ping => "PING",
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Auth {
                username: Some(username),
                password,
            } => encode(
                out,
                &[b"AUTH", username.as_bytes(), password.expose().as_bytes()],
            ),
            Self::Auth {
                username: None,
                password,
            } => encode(out, &[b"AUTH", password.expose().as_bytes()]),
            Self::Select(db) => encode(out, &[b"SELECT", db.to_string().as_bytes()]),
            Self::Scan { cursor, pattern } => encode(
                out,
                &[
                    b"SCAN",
                    cursor.to_string().as_bytes(),
                    b"MATCH",
                    pattern,
                    b"COUNT",
                    SCAN_COUNT,
                ],
            ),
            Self::MGet(keys) => {
                let mut args: Vec<&[u8]> = Vec::with_capacity(keys.len() + 1);
                args.push(b"MGET");
                args.extend(keys.iter().map(Vec::as_slice));
                encode(out, &args);
            }
            Self::Subscribe(channel) => encode(out, &[b"SUBSCRIBE", channel.as_bytes()]),
            Self::PSubscribe(pattern) => encode(out, &[b"PSUBSCRIBE", pattern]),
            Self::Ping => encode(out, &[b"PING"]),
        }
    }
}

/// What went wrong talking to the store.
#[derive(Debug, Error)]
pub(super) enum ClientError {
    /// The connection could not be made or broke.
    #[error("cannot reach the store: {0}")]
    Transport(Box<str>),
    /// The store did not answer in time.
    #[error("the store did not answer in time")]
    Timeout,
    /// The store refused the credentials.
    #[error("the store refused the credentials")]
    Credentials,
    /// The store answered a command with an error.
    #[error("the store answered an error: {0}")]
    Server(Box<str>),
    /// The store sent something that is not what the command asks for.
    #[error("the store sent an unexpected reply: {0}")]
    Protocol(&'static str),
    /// The prefix holds more keys than the provider reads.
    #[error("the prefix holds more than {MAX_KEYS_PER_PREFIX} keys; nothing is read from it")]
    TooManyKeys,
    /// The values of the prefix are more than the provider reads.
    #[error(
        "the values under the prefix are more than {MAX_PREFIX_BYTES} bytes; nothing is read from it"
    )]
    TooLarge,
}

impl ClientError {
    /// Whether only the prefix is at fault, so the connection and every other prefix are fine.
    pub(super) fn is_prefix_limit(&self) -> bool {
        matches!(self, Self::TooManyKeys | Self::TooLarge)
    }
}

impl From<RespError> for ClientError {
    fn from(err: RespError) -> Self {
        match err {
            RespError::Io(err) => Self::Transport(err.to_string().into()),
            RespError::Protocol(what) => Self::Protocol(what),
        }
    }
}

/// The text of a server's error, cut short.
fn quote(text: &str) -> Box<str> {
    text.trim()
        .chars()
        .take(MAX_QUOTED)
        .collect::<String>()
        .into()
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Where and how to connect, and who to be.
pub(super) struct Client {
    /// `host:port`, for errors and for the connection.
    address: Box<str>,
    host: Box<str>,
    port: u16,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    username: Option<Box<str>>,
    password: Option<Secret>,
    db: u32,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("address", &self.address)
            .field("tls", &self.tls.is_some())
            .field("username", &self.username)
            .field("password", &self.password)
            .field("db", &self.db)
            .finish()
    }
}

/// The parts of a store's address.
pub(super) struct Target {
    pub(super) host: Box<str>,
    pub(super) port: u16,
}

impl Client {
    pub(super) fn new(
        target: Target,
        tls: Option<(Arc<rustls::ClientConfig>, ServerName<'static>)>,
        username: Option<Box<str>>,
        password: Option<Secret>,
        db: u32,
    ) -> Self {
        Self {
            address: format!("{}:{}", target.host, target.port).into(),
            host: target.host,
            port: target.port,
            tls: tls.map(|(config, name)| (TlsConnector::from(config), name)),
            username,
            password,
            db,
        }
    }

    /// `host:port`.
    pub(super) fn address(&self) -> &str {
        &self.address
    }

    async fn open(&self) -> Result<Conn, ClientError> {
        let tcp = TcpStream::connect((&*self.host, self.port))
            .await
            .map_err(|err| ClientError::Transport(format!("{}: {err}", self.address).into()))?;
        // A failure to set the option only costs latency.
        drop(tcp.set_nodelay(true));
        let io: Box<dyn Io> = match &self.tls {
            None => Box::new(tcp),
            Some((connector, name)) => {
                Box::new(connector.connect(name.clone(), tcp).await.map_err(|err| {
                    ClientError::Transport(format!("{}: TLS: {err}", self.address).into())
                })?)
            }
        };
        let mut conn = Conn {
            io,
            reader: Reader::new(MAX_VALUE_BYTES),
        };
        if let Some(password) = &self.password {
            let auth = Command::Auth {
                username: self.username.as_deref(),
                password,
            };
            match conn.call(auth).await {
                Err(ClientError::Server(_)) => return Err(ClientError::Credentials),
                other => other?,
            };
        }
        Ok(conn)
    }

    async fn connect(&self) -> Result<Conn, ClientError> {
        timeout(CONNECT_TIMEOUT, self.open())
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    /// A connection that reads: logged in and on the configured database.
    pub(super) async fn reader(&self) -> Result<Conn, ClientError> {
        let mut conn = self.connect().await?;
        if self.db != 0 {
            conn.call(Command::Select(self.db)).await?;
        }
        Ok(conn)
    }

    /// A connection that follows `channel` and the keyspace `patterns`.
    pub(super) async fn subscription(
        &self,
        channel: &str,
        patterns: &[Vec<u8>],
    ) -> Result<Subscription, ClientError> {
        let mut conn = self.connect().await?;
        conn.subscribe(Command::Subscribe(channel)).await?;
        for pattern in patterns {
            conn.subscribe(Command::PSubscribe(pattern)).await?;
        }
        let Conn { io, reader } = conn;
        let (read, write) = tokio::io::split(io);
        Ok(Subscription {
            read,
            write: Some(write),
            reader,
        })
    }
}

/// One logged in connection.
pub(super) struct Conn {
    io: Box<dyn Io>,
    reader: Reader,
}

impl Conn {
    /// Sends `command` and reads its reply. An error reply is an error.
    pub(super) async fn call(&mut self, command: Command<'_>) -> Result<Reply, ClientError> {
        let mut out = Vec::new();
        command.encode(&mut out);
        timeout(REPLY_TIMEOUT, async {
            self.io
                .write_all(&out)
                .await
                .map_err(|err| ClientError::Transport(err.to_string().into()))?;
            match self.reader.reply(&mut self.io).await? {
                Reply::Error(text) => Err(ClientError::Server(quote(&text))),
                reply => Ok(reply),
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    /// Sends a subscribe command and reads its confirmation.
    async fn subscribe(&mut self, command: Command<'_>) -> Result<(), ClientError> {
        match self.call(command).await? {
            Reply::Array(items) if items.len() == 3 => Ok(()),
            _ => Err(ClientError::Protocol("not a subscription confirmation")),
        }
    }

    /// Every key under `path` and its value, in key order, and the keys whose value is past
    /// [`MAX_VALUE_BYTES`].
    ///
    /// # Errors
    ///
    /// [`ClientError`]; [`ClientError::TooManyKeys`] and [`ClientError::TooLarge`] leave the
    /// connection usable.
    pub(super) async fn read_prefix(&mut self, path: &str) -> Result<Read, ClientError> {
        let mut pattern = glob_escape(path.as_bytes());
        pattern.push(b'*');
        let mut keys: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut cursor = 0_u64;
        loop {
            let reply = self
                .call(Command::Scan {
                    cursor,
                    pattern: &pattern,
                })
                .await?;
            let Reply::Array(parts) = reply else {
                return Err(ClientError::Protocol("SCAN did not answer an array"));
            };
            let [Reply::Bulk(next), Reply::Array(found)] = <[Reply; 2]>::try_from(parts)
                .map_err(|_| ClientError::Protocol("SCAN did not answer two parts"))?
            else {
                return Err(ClientError::Protocol("SCAN answered the wrong parts"));
            };
            cursor = std::str::from_utf8(&next)
                .ok()
                .and_then(|text| text.parse().ok())
                .ok_or(ClientError::Protocol("SCAN answered a bad cursor"))?;
            for key in found {
                // A key longer than a value may be is not a key of ours; one outside the prefix
                // is the store's business, the mapping would ignore it.
                if let Reply::Bulk(key) = key
                    && key.starts_with(path.as_bytes())
                {
                    keys.insert(key.into_vec());
                    if keys.len() > MAX_KEYS_PER_PREFIX {
                        return Err(ClientError::TooManyKeys);
                    }
                }
            }
            if cursor == 0 {
                break;
            }
        }
        let keys: Vec<Vec<u8>> = keys.into_iter().collect();
        let mut read = Read::default();
        let mut held = 0_usize;
        for batch in keys.chunks(MGET_BATCH) {
            let Reply::Array(values) = self.call(Command::MGet(batch)).await? else {
                return Err(ClientError::Protocol("MGET did not answer an array"));
            };
            if values.len() != batch.len() {
                return Err(ClientError::Protocol(
                    "MGET answered the wrong number of values",
                ));
            }
            for (key, value) in batch.iter().zip(values) {
                match value {
                    Reply::Bulk(value) => {
                        held += key.len() + value.len();
                        if held > MAX_PREFIX_BYTES {
                            return Err(ClientError::TooLarge);
                        }
                        read.entries.push((key.clone(), value.into_vec()));
                    }
                    Reply::Oversize => read.oversize.push(key.clone()),
                    // The key went away since the scan, or holds something that is not a string.
                    Reply::Nil => {}
                    _ => return Err(ClientError::Protocol("MGET answered an unexpected value")),
                }
            }
        }
        Ok(read)
    }
}

/// What reading one prefix found.
#[derive(Debug, Default)]
pub(super) struct Read {
    pub(super) entries: Vec<(Vec<u8>, Vec<u8>)>,
    pub(super) oversize: Vec<Vec<u8>>,
}

/// `text` as a glob pattern that matches only itself.
pub(super) fn glob_escape(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for &byte in text {
        if matches!(byte, b'*' | b'?' | b'[' | b']' | b'\\') {
            out.push(b'\\');
        }
        out.push(byte);
    }
    out
}

/// A connection in subscriber mode: it only receives, and the write half sends heartbeats.
pub(super) struct Subscription {
    read: ReadHalf<Box<dyn Io>>,
    write: Option<WriteHalf<Box<dyn Io>>>,
    reader: Reader,
}

impl Subscription {
    /// The write half, once: the caller sends `PING`s on it.
    pub(super) fn take_writer(&mut self) -> Option<Heartbeat> {
        self.write.take().map(|write| Heartbeat { write })
    }

    /// Reads the next push: `true` for a message of a followed channel, `false` for anything else
    /// the store sends (a `PING` answer).
    ///
    /// # Errors
    ///
    /// [`ClientError`] when the connection breaks, stays silent for `silence`, or the store
    /// sends what is not a push.
    pub(super) async fn next(&mut self, silence: Duration) -> Result<bool, ClientError> {
        let reply = timeout(silence, self.reader.reply(&mut self.read))
            .await
            .map_err(|_| ClientError::Timeout)??;
        let Reply::Array(items) = reply else {
            return Err(ClientError::Protocol("a push that is not an array"));
        };
        Ok(matches!(
            items.first(),
            Some(Reply::Bulk(kind)) if &**kind == b"message" || &**kind == b"pmessage"
        ))
    }
}

/// The write half of a subscription.
pub(super) struct Heartbeat {
    write: WriteHalf<Box<dyn Io>>,
}

impl Heartbeat {
    /// Sends one `PING`.
    pub(super) async fn ping(&mut self) -> Result<(), ClientError> {
        let mut out = Vec::new();
        Command::Ping.encode(&mut out);
        self.write
            .write_all(&out)
            .await
            .map_err(|err| ClientError::Transport(err.to_string().into()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn glob_characters_in_a_prefix_match_only_themselves() {
        assert_eq!(glob_escape(b"a*b?[c]\\d/"), b"a\\*b\\?\\[c\\]\\\\d/");
    }

    #[test]
    fn every_command_encodes_as_itself_and_nothing_else() {
        let secret = Secret::new("pw");
        let keys = [b"a".to_vec(), b"b".to_vec()];
        let all = [
            (
                Command::Auth {
                    username: Some("u"),
                    password: &secret,
                },
                "AUTH",
            ),
            (Command::Select(2), "SELECT"),
            (
                Command::Scan {
                    cursor: 0,
                    pattern: b"p*",
                },
                "SCAN",
            ),
            (Command::MGet(&keys), "MGET"),
            (Command::Subscribe("c"), "SUBSCRIBE"),
            (Command::PSubscribe(b"p*"), "PSUBSCRIBE"),
            (Command::Ping, "PING"),
        ];
        for (command, name) in all {
            let mut out = Vec::new();
            command.encode(&mut out);
            let text = String::from_utf8_lossy(&out).into_owned();
            assert_eq!(command.name(), name);
            assert!(
                text.split("\r\n").nth(2) == Some(name),
                "{name} encodes as {text:?}"
            );
        }
    }
}
