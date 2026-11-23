//! The hub: one task per peer that pulls and stores, and the listener that serves the view.
//!
//! The view reads the fleet and sends nothing to any peer; a peer's task writes only its own
//! slot. One slow, dead or hostile peer therefore delays no other.

use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use http::Method;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::config::{Peer, PeersFile, Pull};
use crate::failure::Failure;
use crate::fleet::Fleet;
use crate::pull::{Limits, pull};
use crate::serve::{Handler, Reply, Request, serve};
use crate::view::{self, Query};

/// The longest wait after failed pulls.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// A running hub. Dropping it stops every task.
#[derive(Debug)]
pub struct Hub {
    addr: SocketAddr,
    fleet: Arc<Fleet>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Hub {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Hub {
    /// Binds the view listener and starts pulling every peer at once.
    ///
    /// # Errors
    ///
    /// Fails when the view address cannot be bound.
    pub async fn start(file: PeersFile) -> io::Result<Self> {
        let listener = TcpListener::bind(file.view.addr).await?;
        let addr = listener.local_addr()?;
        let fleet = Arc::new(Fleet::new(file.peers.iter().map(|peer| peer.name.clone())));
        let mut tasks = Vec::with_capacity(file.peers.len() + 1);
        for (index, peer) in file.peers.into_iter().enumerate() {
            tasks.push(tokio::spawn(peer_loop(
                index,
                peer,
                file.pull,
                Arc::clone(&fleet),
            )));
        }
        let handler = Arc::new(ViewHandler {
            fleet: Arc::clone(&fleet),
            stale_after: file.pull.stale_after,
        });
        tasks.push(tokio::spawn(serve(
            listener,
            file.view.tls,
            file.view.max_connections,
            handler,
        )));
        Ok(Self { addr, fleet, tasks })
    }

    /// Where the view listens.
    #[must_use]
    pub fn view_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The combined state.
    #[must_use]
    pub fn fleet(&self) -> &Arc<Fleet> {
        &self.fleet
    }
}

/// The wait before the next pull of a peer that failed `failures` times in a row: `poll`,
/// doubled per failure up to [`MAX_BACKOFF`], never below `poll`, then moved by `jitter_permille`
/// (at most 100, either way).
#[must_use]
pub fn next_delay(poll: Duration, failures: u32, jitter_permille: i64) -> Duration {
    let doubled = poll.saturating_mul(1_u32 << failures.min(10));
    let base = doubled.min(MAX_BACKOFF.max(poll));
    let millis = i64::try_from(base.as_millis()).unwrap_or(i64::MAX);
    let moved = millis + millis / 1000 * jitter_permille.clamp(-100, 100);
    Duration::from_millis(u64::try_from(moved).unwrap_or(0))
}

async fn peer_loop(index: usize, peer: Peer, settings: Pull, fleet: Arc<Fleet>) {
    let limits = Limits {
        timeout: settings.timeout,
        max_bytes: settings.max_bytes,
        max_entries: settings.max_entries,
    };
    let mut failures: u32 = 0;
    let mut round: u64 = 0;
    loop {
        let result = pull(&peer, &limits).await;
        let now = SystemTime::now();
        match result {
            Ok(pulled) => {
                if failures > 0 || round == 0 {
                    tracing::info!(cluster = %peer.name, entries = pulled.entries.len(), "cluster is fresh");
                }
                fleet.succeed(index, pulled, now);
                failures = 0;
            }
            Err(failure) => {
                note(&peer, failure, failures);
                fleet.fail(index, failure, now);
                failures = failures.saturating_add(1);
            }
        }
        round += 1;
        let jitter =
            i64::try_from(RandomState::new().hash_one((index, round)) % 201).unwrap_or(100) - 100;
        tokio::time::sleep(next_delay(settings.poll, failures, jitter)).await;
    }
}

/// Logs the first failure of a streak only: state changes, not every poll.
fn note(peer: &Peer, failure: Failure, earlier_failures: u32) {
    if earlier_failures == 0 {
        tracing::warn!(
            cluster = %peer.name,
            class = failure.class.as_str(),
            status = failure.http_status,
            "cluster is stale"
        );
    }
}

struct ViewHandler {
    fleet: Arc<Fleet>,
    stale_after: Duration,
}

impl Handler for ViewHandler {
    async fn handle(&self, request: Request) -> Reply {
        let known = matches!(request.path.as_str(), "/v1/clusters" | "/v1/catalog");
        if !known {
            return Reply::not_found();
        }
        if request.method != Method::GET {
            return Reply::method_not_allowed();
        }
        let now = SystemTime::now();
        let fleet = self.fleet.snapshot();
        match request.path.as_str() {
            "/v1/clusters" => {
                if let Err(reply) = crate::serve::Params::parse(request.query.as_deref(), &[]) {
                    return reply;
                }
                Reply::ok(view::clusters(&fleet, now, self.stale_after))
            }
            _ => match Query::parse(request.query.as_deref()) {
                Ok(query) => Reply::ok(view::catalog(&fleet, &query, now, self.stale_after)),
                Err(reply) => reply,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn federation_backoff_bounds() {
        let poll = Duration::from_secs(30);
        let mut previous = Duration::ZERO;
        for failures in 0..30 {
            let plain = next_delay(poll, failures, 0);
            assert!(plain >= previous, "never shrinks");
            assert!(plain >= poll && plain <= MAX_BACKOFF);
            for jitter in [-100, 0, 100] {
                let moved = next_delay(poll, failures, jitter);
                assert!(moved.as_millis() >= plain.as_millis() * 9 / 10 - 1);
                assert!(moved.as_millis() <= plain.as_millis() * 11 / 10 + 1);
            }
            previous = plain;
        }
        assert_eq!(next_delay(poll, 0, 0), poll);
        assert_eq!(next_delay(poll, 1, 0), Duration::from_secs(60));
        assert_eq!(
            next_delay(Duration::from_secs(3600), 5, 0),
            Duration::from_secs(3600),
            "never below poll"
        );
    }
}
