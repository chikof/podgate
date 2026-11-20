//! On-demand TLS: before the handshake of a connection starts, learn its SNI and, when the
//! host belongs to an `on_demand` app and has no certificate, wait for one.
//!
//! The hook reads the ClientHello (rustls' `Acceptor` parses it, so no TLS parsing lives here),
//! then puts every byte back with `Stream::rewind` so the handshake sees the connection
//! untouched. It never fails a connection: whatever it cannot read or wait for, the handshake
//! decides. A host that is not an `on_demand` app's gets no wait, so the handshake fails at
//! once for unknown names.

use std::time::Duration;

use async_trait::async_trait;
use pingora::listeners::PreTlsProcess;
use pingora::protocols::l4::stream::Stream;
use rustls::server::Acceptor;
use tokio::io::AsyncReadExt;
use tokio::time::{Instant, sleep, timeout};

use super::{Acme, ON_DEMAND_WAIT};
use crate::host;

/// Longest a client may take to send its ClientHello before the hook gives up reading it.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// A ClientHello larger than a TLS record cannot be one.
const MAX_HELLO: usize = 17 * 1024;
/// How often a waiting handshake looks at the live table.
const POLL: Duration = Duration::from_millis(100);

#[async_trait]
impl PreTlsProcess for Acme {
    async fn process(&self, stream: &mut Stream) -> pingora::Result<()> {
        if !self.shared.table.load().acme().on_demand_enabled() {
            return Ok(());
        }
        if let Some(name) = peek_server_name(stream).await {
            self.await_certificate(&host::normalize(&name)).await;
        }
        Ok(())
    }
}

impl Acme {
    /// Waits, bounded, until the live table has a certificate for `host` (normalized), after
    /// asking for one. Returns at once when it has one, when `host` is not an `on_demand`
    /// app's, or when too many handshakes are already waiting.
    async fn await_certificate(&self, host: &str) {
        let table = self.shared.table.load();
        let plan = table.acme();
        if plan.settings().is_none() {
            return;
        }
        if table.certificates().lookup(host).is_some() || !plan.is_on_demand(host) {
            return;
        }
        let Ok(_permit) = self.shared.waiters.try_acquire() else {
            return;
        };
        self.request(host);
        drop(table);
        let deadline = Instant::now() + ON_DEMAND_WAIT;
        while Instant::now() < deadline {
            sleep(POLL).await;
            let table = self.shared.table.load();
            if table.certificates().lookup(host).is_some() {
                self.forget(host);
                return;
            }
            if !table.acme().is_on_demand(host) {
                return;
            }
        }
    }
}

/// The SNI of the connection's ClientHello, normalized by the caller; the stream is left as it
/// was.
async fn peek_server_name(stream: &mut Stream) -> Option<String> {
    let mut seen = Vec::new();
    let name = timeout(HELLO_TIMEOUT, read_hello(stream, &mut seen))
        .await
        .ok()
        .flatten();
    stream.rewind(&seen);
    name
}

/// Reads records into `seen` until rustls has a whole ClientHello. `None` when the connection
/// ends, errors or sends something that is not a ClientHello.
async fn read_hello(stream: &mut Stream, seen: &mut Vec<u8>) -> Option<String> {
    let mut acceptor = Acceptor::default();
    let mut chunk = [0_u8; 2048];
    while seen.len() < MAX_HELLO {
        let read = stream
            .read(&mut chunk)
            .await
            .ok()
            .filter(|read| *read > 0)?;
        seen.extend_from_slice(&chunk[..read]);
        let mut rest = &chunk[..read];
        while !rest.is_empty() {
            acceptor.read_tls(&mut rest).ok().filter(|used| *used > 0)?;
            if let Some(accepted) = acceptor.accept().ok()? {
                return accepted.client_hello().server_name().map(str::to_owned);
            }
        }
    }
    None
}
