//! The session table of one UDP entry point: client address to session, with a fixed capacity
//! the caller enforces and an eviction order that protects the clients that keep talking.
//!
//! The table is plain data. Time comes in as milliseconds on the caller's clock, so tests drive
//! it with numbers; the handle `H` of a session is whatever must drop with it (the socket, the
//! reservations), so removing a session by any path releases everything.
//!
//! UDP sources are unauthenticated, and an upstream such as DNS answers every source, so an
//! upstream reply proves nothing about a client address. What a spoofer cannot cheaply do is keep
//! a conversation going: a session whose client has sent only one datagram is *single*, and
//! single sessions are kept in creation order. A full table gives up the oldest single session
//! for a new client, answered or not. A session whose client has sent two or more datagrams is
//! never given up for a newcomer, so spoofed one-datagram sources cannot push out clients that
//! keep sending; they can only fill the single part of the table.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::stats::Close;

/// What the socket loop and the session's reply task both see of a session.
#[derive(Debug)]
pub(super) struct Shared {
    last_seen_ms: AtomicU64,
    client_datagrams: AtomicU32,
    first_bytes: u64,
    returned_bytes: AtomicU64,
}

impl Shared {
    /// A session whose client just sent its first datagram of `first_bytes` at `now_ms`.
    pub(super) fn new(first_bytes: usize, now_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            last_seen_ms: AtomicU64::new(now_ms),
            client_datagrams: AtomicU32::new(1),
            first_bytes: first_bytes as u64,
            returned_bytes: AtomicU64::new(0),
        })
    }

    /// The client sent another datagram.
    pub(super) fn client_sent(&self, now_ms: u64) {
        self.client_datagrams.fetch_add(1, Ordering::Relaxed);
        self.last_seen_ms.fetch_max(now_ms, Ordering::Relaxed);
    }

    /// The upstream sent a datagram on the session.
    pub(super) fn upstream_sent(&self, now_ms: u64) {
        self.last_seen_ms.fetch_max(now_ms, Ordering::Relaxed);
    }

    /// Whether a reply of `len` bytes may go to the client. Until the client has sent a second
    /// datagram, the bytes returned stay within `ratio` times its first datagram; afterwards, and
    /// without a ratio, everything passes. Counts the bytes it lets through.
    pub(super) fn allow_reply(&self, len: usize, ratio: Option<u32>) -> bool {
        let Some(ratio) = ratio else { return true };
        if self.client_datagrams.load(Ordering::Relaxed) >= 2 {
            return true;
        }
        let limit = self.first_bytes.saturating_mul(u64::from(ratio));
        self.returned_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |sent| {
                sent.checked_add(len as u64).filter(|total| *total <= limit)
            })
            .is_ok()
    }

    /// Milliseconds since either side last sent a datagram.
    pub(super) fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_seen_ms.load(Ordering::Relaxed))
    }

    /// Whether the client has sent only the datagram that opened the session.
    fn is_single(&self) -> bool {
        self.client_datagrams.load(Ordering::Relaxed) == 1
    }
}

struct Entry<H> {
    id: u64,
    shared: Arc<Shared>,
    handle: H,
}

/// The sessions of one entry point.
pub(super) struct Table<H> {
    sessions: HashMap<SocketAddr, Entry<H>>,
    /// Creation order of the sessions. A single session's client has sent nothing since it
    /// opened, so creation order is its least recently used order. Entries go stale when a
    /// client sends a second datagram or the session is removed; they are skipped when popped
    /// and swept when the queue outgrows the table, so it stays within a small multiple of it.
    singles: VecDeque<(SocketAddr, u64)>,
    next_id: u64,
}

impl<H> Table<H> {
    pub(super) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            singles: VecDeque::new(),
            next_id: 0,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.sessions.len()
    }

    pub(super) fn get(&self, client: &SocketAddr) -> Option<(&Arc<Shared>, &H)> {
        let entry = self.sessions.get(client)?;
        Some((&entry.shared, &entry.handle))
    }

    /// Adds the session of `client`. The caller checked the capacity and that `client` has no
    /// session; a session already there is replaced and dropped.
    pub(super) fn insert(&mut self, client: SocketAddr, shared: Arc<Shared>, handle: H) {
        self.next_id += 1;
        let id = self.next_id;
        self.singles.push_back((client, id));
        self.sessions.insert(client, Entry { id, shared, handle });
        if self.singles.len() > 2 * self.sessions.len() + 16 {
            let sessions = &self.sessions;
            self.singles
                .retain(|(addr, id)| Self::is_live_single(sessions, addr, *id));
        }
    }

    fn is_live_single(
        sessions: &HashMap<SocketAddr, Entry<H>>,
        addr: &SocketAddr,
        id: u64,
    ) -> bool {
        sessions
            .get(addr)
            .is_some_and(|entry| entry.id == id && entry.shared.is_single())
    }

    /// Removes the session of `client`.
    pub(super) fn remove(&mut self, client: &SocketAddr) -> Option<H> {
        self.sessions.remove(client).map(|entry| entry.handle)
    }

    /// Removes the oldest session whose client has sent only one datagram, `None` when every
    /// client has sent two or more.
    pub(super) fn evict_single(&mut self) -> Option<H> {
        while let Some((addr, id)) = self.singles.pop_front() {
            if Self::is_live_single(&self.sessions, &addr, id) {
                return self.remove(&addr);
            }
        }
        None
    }

    /// Removes every session `verdict` closes and reports each reason to `closed`.
    pub(super) fn close_where(
        &mut self,
        mut verdict: impl FnMut(&Arc<Shared>, &H) -> Option<Close>,
        mut closed: impl FnMut(Close),
    ) {
        self.sessions
            .retain(|_, entry| match verdict(&entry.shared, &entry.handle) {
                Some(reason) => {
                    closed(reason);
                    false
                }
                None => true,
            });
    }

    #[cfg(test)]
    fn queued(&self) -> usize {
        self.singles.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn client(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    fn open(table: &mut Table<u16>, port: u16, now_ms: u64) -> Arc<Shared> {
        let shared = Shared::new(10, now_ms);
        table.insert(client(port), Arc::clone(&shared), port);
        shared
    }

    #[test]
    fn a_full_table_gives_up_the_oldest_single_session() {
        let mut table = Table::new();
        for port in 1..=3 {
            open(&mut table, port, 0);
        }
        assert_eq!(table.evict_single(), Some(1));
        assert_eq!(table.evict_single(), Some(2));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn an_upstream_that_answers_every_source_does_not_protect_a_session() {
        let mut table = Table::new();
        let first = open(&mut table, 1, 0);
        open(&mut table, 2, 0);
        first.upstream_sent(5);
        assert_eq!(
            table.evict_single(),
            Some(1),
            "answered, and still the oldest single"
        );
        assert_eq!(table.evict_single(), Some(2));
    }

    #[test]
    fn a_client_that_sent_two_datagrams_is_never_given_up_for_a_newcomer() {
        let mut table = Table::new();
        let talker = open(&mut table, 1, 0);
        open(&mut table, 2, 0);
        talker.client_sent(5);
        assert_eq!(table.evict_single(), Some(2));
        assert_eq!(
            table.evict_single(),
            None,
            "only the talking client is left"
        );
        assert!(table.get(&client(1)).is_some());
    }

    #[test]
    fn a_removed_and_recreated_client_is_not_evicted_by_its_old_entry() {
        let mut table = Table::new();
        open(&mut table, 1, 0);
        open(&mut table, 2, 0);
        assert_eq!(table.remove(&client(1)), Some(1));
        let again = open(&mut table, 1, 3);
        again.client_sent(4);
        assert_eq!(table.evict_single(), Some(2));
        assert_eq!(table.evict_single(), None);
    }

    #[test]
    fn the_queue_stays_near_the_size_of_the_table() {
        let mut table = Table::new();
        for round in 0..10_000u16 {
            let shared = open(&mut table, round % 8 + 1, 0);
            shared.client_sent(0);
            if table.len() > 4 {
                table.remove(&client(round % 8 + 1));
            }
        }
        assert!(table.queued() <= 2 * table.len() + 17, "{}", table.queued());
    }

    #[test]
    fn idle_sessions_close_and_the_rest_stay() {
        let mut table = Table::new();
        let stale = open(&mut table, 1, 0);
        let fresh = open(&mut table, 2, 0);
        stale.client_sent(100);
        fresh.client_sent(900);
        let mut closed = Vec::new();
        table.close_where(
            |shared, _| (shared.idle_ms(1_000) > 500).then_some(Close::Expired),
            |reason| closed.push(reason),
        );
        assert_eq!(closed, [Close::Expired]);
        assert!(table.get(&client(1)).is_none() && table.get(&client(2)).is_some());
    }

    #[test]
    fn replies_before_the_second_datagram_stay_within_the_ratio() {
        let shared = Shared::new(10, 0);
        assert!(shared.allow_reply(10, Some(3)));
        assert!(shared.allow_reply(20, Some(3)));
        assert!(
            !shared.allow_reply(1, Some(3)),
            "31 bytes for a 10 byte query"
        );
        shared.client_sent(1);
        assert!(
            shared.allow_reply(1_000, Some(3)),
            "a second datagram lifts the limit"
        );
        assert!(Shared::new(10, 0).allow_reply(1_000, None));
    }

    #[test]
    fn a_dropped_reply_does_not_use_up_the_allowance() {
        let shared = Shared::new(10, 0);
        assert!(!shared.allow_reply(31, Some(3)));
        assert!(shared.allow_reply(30, Some(3)));
    }
}
