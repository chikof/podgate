//! The reader of one prefix: read it whole, follow it with a watch, and read it whole again when
//! the watch ends, the server compacted the history it needs, or `resync_secs` have passed.
//!
//! The full read is the truth and the watch only makes changes show sooner: a watch that dies in
//! some way nobody notices (a half-open connection, a missed event) is repaired by the next full
//! read, at the latest after `resync_secs`. The watch always starts at the revision of the read
//! plus one, so no change falls between the two.
//!
//! While etcd cannot be read, the reader reports an [`Msg::Outage`] and retries with growing
//! delays; the state it sent before stays in force.

use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::client::{Change, Client, ClientError, Notice};
use crate::push::Backoff;

const MIN_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// What a reader tells the source.
#[derive(Debug)]
pub(super) enum Msg {
    /// Every key and value under the prefix: replaces what the source holds for it.
    Full {
        prefix: usize,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    },
    /// Keys that changed since, in order.
    Changes { prefix: usize, changes: Vec<Change> },
    /// The prefix cannot be read.
    Outage { prefix: usize, why: Box<str> },
}

/// How a watch ended.
enum Ended {
    /// `resync_secs` passed.
    Resync,
    /// The server compacted the history the watch needs.
    Compacted,
    /// The stream closed or failed.
    Broken(Box<str>),
}

/// Reads and follows `path` until the task is aborted or the source stops listening.
pub(super) async fn run(
    client: Client,
    prefix: usize,
    path: Box<str>,
    watch: bool,
    resync: Duration,
    updates: Sender<Msg>,
) {
    let mut backoff = Backoff::new(MIN_RETRY, MAX_RETRY);
    let mut failing = false;
    loop {
        let ranged = match client.range(&path).await {
            Ok(ranged) => ranged,
            Err(err) => {
                if !failing {
                    warn!(prefix = %path, error = %err, "cannot read the prefix; the last state stays in force");
                }
                failing = true;
                let why = format!("prefix {path:?}: {err}").into();
                if updates.send(Msg::Outage { prefix, why }).await.is_err() {
                    return;
                }
                tokio::time::sleep(backoff.next_delay()).await;
                continue;
            }
        };
        if failing {
            debug!(prefix = %path, "the prefix can be read again");
        }
        failing = false;
        backoff.reset();
        let deadline = Instant::now() + resync;
        let from = ranged.revision.saturating_add(1);
        let full = Msg::Full {
            prefix,
            entries: ranged.entries,
        };
        if updates.send(full).await.is_err() {
            return;
        }
        if !watch {
            tokio::time::sleep_until(deadline).await;
            continue;
        }
        match follow(&client, prefix, &path, from, deadline, &updates).await {
            None => return,
            Some(Ended::Resync) => {}
            Some(Ended::Compacted) => {
                debug!(prefix = %path, "etcd compacted the history the watch needs; reading the prefix again");
                tokio::time::sleep(MIN_RETRY).await;
            }
            Some(Ended::Broken(why)) => {
                debug!(prefix = %path, error = %why, "the watch ended; reading the prefix again");
                tokio::time::sleep(backoff.next_delay()).await;
            }
        }
    }
}

/// Follows the watch until it ends. `None` when the source stopped listening.
async fn follow(
    client: &Client,
    prefix: usize,
    path: &str,
    from: u64,
    deadline: Instant,
    updates: &Sender<Msg>,
) -> Option<Ended> {
    let mut stream = match tokio::time::timeout_at(deadline, client.watch(path, from)).await {
        Err(_) => return Some(Ended::Resync),
        Ok(Err(err)) => return Some(Ended::Broken(err.to_string().into())),
        Ok(Ok(stream)) => stream,
    };
    loop {
        let notice = match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => return Some(Ended::Resync),
            Ok(Err(err)) => return Some(Ended::Broken(err.to_string().into())),
            Ok(Ok(None)) => return Some(Ended::Broken("the server closed the stream".into())),
            Ok(Ok(Some(notice))) => notice,
        };
        match notice {
            Notice::Created | Notice::Progress => {}
            Notice::Changes(changes) => {
                if updates
                    .send(Msg::Changes { prefix, changes })
                    .await
                    .is_err()
                {
                    return None;
                }
            }
            Notice::Compacted => return Some(Ended::Compacted),
            Notice::Canceled(why) => {
                return Some(Ended::Broken(ClientError::Watch(why).to_string().into()));
            }
        }
    }
}
