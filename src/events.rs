//! The event feed: how podgate tells the control plane what happened, since it never opens a
//! connection to it. See `docs/architecture.md` (`### Event feed`).
//!
//! A feature emits with [`EventFeed::emit`]; the admin API serves the feed with
//! [`EventFeed::poll`] (`GET /v1/events`). To add an event kind, add a variant to [`EventKind`]
//! and call `emit` where it happens.
//!
//! Events live in a bounded in-memory ring of [`RING_CAPACITY`]. A reader that fell further
//! behind than the ring is told so ([`Gone`]) and must resync. Sequence numbers start at `1` and
//! restart with the process; [`EventFeed::boot_id`] changes with them, so a reader can tell a
//! restart from a quiet feed.

use std::collections::VecDeque;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::Serialize;
use thiserror::Error;
use tokio::sync::watch;

use crate::acme::PrivateKeyPem;

/// How many events the ring keeps.
pub const RING_CAPACITY: usize = 4096;

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    /// A `draining` revision has no request in flight any more. Emitted once per draining
    /// period.
    RevisionDrained {
        /// The app the revision belongs to.
        app: Box<str>,
        /// The drained revision.
        revision: Box<str>,
    },
    /// A request reached an app that is asleep: start it. Emitted once per wake
    /// cycle, however many requests wait.
    WakeRequested {
        /// The app to wake.
        app: Box<str>,
    },
    /// An app with `scale_to_zero` had no request for `idle_secs`. Emitted once per idle period.
    AppIdle {
        /// The idle app.
        app: Box<str>,
    },
    /// A 5xx spike in the apps a snapshot changed restored the previous snapshot.
    ConfigReverted {
        /// The version that was live and got replaced; the live version stays at this number.
        from_version: u64,
        /// The version of the snapshot that is serving again.
        to_version: u64,
    },
    /// A `5xx` spike called for a revert, but the previous snapshot no longer compiles (for
    /// example a certificate expired meanwhile). The current table stays live and the change
    /// is no longer watched.
    ConfigRevertFailed {
        /// The version that is live and could not be reverted.
        from_version: u64,
        /// The version of the snapshot that could not be restored.
        to_version: u64,
        /// Why the previous snapshot does not compile.
        error: Box<str>,
    },
    /// The canary of an app breached its `max_error_permille` and was pulled back to
    /// a share of `0`. Emitted once per canary; only a change to its policy or to its app's
    /// serving set gives it traffic again.
    CanaryRegressed {
        /// The app.
        app: Box<str>,
        /// The canary revision.
        revision: Box<str>,
        /// Its `5xx` per thousand requests over the judged window.
        error_permille: u64,
    },
    /// The issuer node needs a challenge answered: for HTTP-01 push the answer back in the
    /// snapshot's `acme.challenges`, for DNS-01 publish the TXT record and push the
    /// confirmation back in `acme.dns_ready`, for TLS-ALPN-01 push `{name,
    /// key_authorization}` back in `acme.challenges`.
    AcmeChallenge {
        /// What to publish.
        #[serde(flatten)]
        proof: ChallengeProof,
    },
    /// A DNS-01 challenge is over, validated or not: remove its TXT record.
    AcmeChallengeDone {
        /// The record that can go.
        #[serde(flatten)]
        proof: ChallengeProof,
    },
    /// The issuer node obtained a certificate: store it and push it back in the snapshot's
    /// `certificates`.
    CertificateIssued {
        /// The names the certificate is valid for.
        hosts: Box<[Box<str>]>,
        /// The certificate chain, leaf first, PEM.
        cert_pem: Box<str>,
        /// The private key, PKCS#8 PEM.
        key_pem: PrivateKeyPem,
    },
    /// A `circuit_breaker` middleware opened its circuit: it answers without an
    /// upstream until its fallback is over. Emitted again when a circuit re-opens during recovery.
    CircuitOpened {
        /// The app that declares the middleware.
        app: Box<str>,
        /// The middleware's name.
        middleware: Box<str>,
    },
    /// A `circuit_breaker` middleware finished its recovery and passes all traffic again.
    CircuitClosed {
        /// The app that declares the middleware.
        app: Box<str>,
        /// The middleware's name.
        middleware: Box<str>,
    },
    /// A TLS handshake named an `on_demand` host without a certificate. Emitted once per host per
    /// pending period, by any node. Approve it by listing the host in `acme.requested_hosts`
    ///; the issuer orders nothing on demand until then.
    CertificateRequested {
        /// The host named by the handshake's SNI.
        host: Box<str>,
    },
}

/// What an ACME challenge asks the control plane to publish. Serialized inline in the event,
/// next to `kind`, as `{"type": "http-01", ...}`, `{"type": "dns-01", ...}` or
/// `{"type": "tls-alpn-01", ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum ChallengeProof {
    /// Serve `key_authorization` at `/.well-known/acme-challenge/<token>`.
    #[serde(rename = "http-01")]
    Http01 {
        /// The challenge token.
        token: Box<str>,
        /// The key authorization the token must answer with.
        key_authorization: Box<str>,
    },
    /// Publish the TXT record `value` at `name`. Two challenges of one order can share a name
    /// (an apex and its wildcard); the values differ, and both records must exist.
    #[serde(rename = "dns-01")]
    Dns01 {
        /// `_acme-challenge.<domain>`.
        name: Box<str>,
        /// base64url of the SHA-256 of the key authorization.
        value: Box<str>,
    },
    /// Answer the TLS-ALPN-01 challenge of `name`: push `{name, key_authorization}`
    /// back in `acme.challenges`. Every node then answers an `acme-tls/1` handshake for `name`
    /// with a challenge certificate derived from `key_authorization`.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01 {
        /// The host being proven.
        name: Box<str>,
        /// The key authorization the challenge certificate commits to.
        key_authorization: Box<str>,
    },
}

/// One entry of the feed: a sequence number and what happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    /// Position in the feed, from `1`, strictly increasing within one boot.
    pub seq: u64,
    /// What happened. Serialized inline: `{"seq": 1, "kind": "revision_drained", ...}`.
    #[serde(flatten)]
    pub kind: EventKind,
}

/// The reader asked for events the ring no longer holds.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("events after {after} are no longer retained; the oldest retained is {oldest}")]
pub struct Gone {
    /// The sequence number the reader resumed from.
    pub after: u64,
    /// Sequence number of the oldest event still retained.
    pub oldest: u64,
}

#[derive(Debug)]
struct Ring {
    next_seq: u64,
    events: VecDeque<Event>,
}

#[derive(Debug)]
struct Inner {
    boot_id: Box<str>,
    ring: Mutex<Ring>,
    // Holds the newest sequence number; readers wait on it without missing a wake-up.
    latest: watch::Sender<u64>,
}

/// Handle on the process-wide event feed. Cheap to clone; every clone is the same feed.
#[derive(Debug, Clone)]
pub struct EventFeed {
    inner: Arc<Inner>,
}

impl Default for EventFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl EventFeed {
    /// An empty feed with a fresh random [`Self::boot_id`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                boot_id: random_id().into_boxed_str(),
                ring: Mutex::new(Ring {
                    next_seq: 1,
                    events: VecDeque::with_capacity(RING_CAPACITY),
                }),
                latest: watch::Sender::new(0),
            }),
        }
    }

    /// Identifies this process lifetime: sequence numbers are only comparable within one id.
    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.inner.boot_id
    }

    /// Appends an event, dropping the oldest when the ring is full, and returns its sequence
    /// number. Wakes every reader blocked in [`Self::poll`].
    pub fn emit(&self, kind: EventKind) -> u64 {
        let mut ring = self
            .inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let seq = ring.next_seq;
        ring.next_seq += 1;
        if ring.events.len() == RING_CAPACITY {
            ring.events.pop_front();
        }
        ring.events.push_back(Event { seq, kind });
        // Inside the lock, so readers see sequence numbers in order.
        self.inner.latest.send_replace(seq);
        seq
    }

    /// The events with a sequence number greater than `after`, oldest first. When there are
    /// none, waits up to `timeout` for the first one and returns an empty list on expiry.
    ///
    /// `after` is the last sequence number the reader has seen (`0` for none). A number beyond
    /// the newest event, as a reader holds after a restart, is not an error: the call waits and
    /// returns what arrives later, so the reader must compare [`Self::boot_id`].
    ///
    /// # Errors
    ///
    /// [`Gone`] when events right after `after` were already dropped from the ring.
    pub async fn poll(&self, after: u64, timeout: Duration) -> Result<Vec<Event>, Gone> {
        let mut latest = self.inner.latest.subscribe();
        let ready = self.read(after)?;
        if !ready.is_empty() || timeout.is_zero() {
            return Ok(ready);
        }
        // Expiry and wake-up both lead to a fresh read, so the outcome is not needed here.
        let waited = tokio::time::timeout(timeout, latest.wait_for(|newest| *newest > after)).await;
        drop(waited);
        self.read(after)
    }

    fn read(&self, after: u64) -> Result<Vec<Event>, Gone> {
        let ring = self
            .inner
            .ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let oldest = ring.events.front().map_or(ring.next_seq, |event| event.seq);
        if oldest > after.saturating_add(1) {
            return Err(Gone { after, oldest });
        }
        let skip = usize::try_from(after.saturating_add(1) - oldest).unwrap_or(usize::MAX);
        Ok(ring.events.iter().skip(skip).cloned().collect())
    }
}

/// 128 random bits as hex, from the standard library's per-process hash keys (seeded by the OS),
/// so no extra dependency is needed for an identifier that only has to differ between boots.
fn random_id() -> String {
    let word = || RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", word(), word())
}

#[cfg(test)]
mod test {
    use super::*;

    fn drained(n: u64) -> EventKind {
        EventKind::RevisionDrained {
            app: "a".into(),
            revision: format!("r{n}").into(),
        }
    }

    #[tokio::test]
    async fn events_ring_numbers_events_from_one() {
        let feed = EventFeed::new();
        assert_eq!(feed.emit(drained(1)), 1);
        assert_eq!(feed.emit(drained(2)), 2);
        let events = feed.poll(0, Duration::ZERO).await.expect("retained");
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        let events = feed.poll(1, Duration::ZERO).await.expect("retained");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, drained(2));
    }

    #[tokio::test]
    async fn events_ring_overflow_410() {
        let feed = EventFeed::new();
        let total = RING_CAPACITY as u64 + 10;
        for n in 1..=total {
            feed.emit(drained(n));
        }
        // 1..=10 were dropped; resuming after 10 still has everything it needs.
        let events = feed.poll(10, Duration::ZERO).await.expect("retained");
        assert_eq!(events.len(), RING_CAPACITY);
        assert_eq!(events[0].seq, 11);
        // Resuming after 9 misses event 10.
        assert_eq!(
            feed.poll(9, Duration::ZERO).await,
            Err(Gone {
                after: 9,
                oldest: 11
            })
        );
        assert!(feed.poll(0, Duration::ZERO).await.is_err());
    }

    #[test]
    fn acme_challenge_events_carry_their_type_inline() {
        let http = EventKind::AcmeChallenge {
            proof: ChallengeProof::Http01 {
                token: "tok".into(),
                key_authorization: "tok.thumb".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&http).expect("serializes"),
            serde_json::json!({
                "kind": "acme_challenge", "type": "http-01",
                "token": "tok", "key_authorization": "tok.thumb"
            })
        );
        let done = EventKind::AcmeChallengeDone {
            proof: ChallengeProof::Dns01 {
                name: "_acme-challenge.a.test".into(),
                value: "v".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&done).expect("serializes"),
            serde_json::json!({
                "kind": "acme_challenge_done", "type": "dns-01",
                "name": "_acme-challenge.a.test", "value": "v"
            })
        );
        let alpn = EventKind::AcmeChallenge {
            proof: ChallengeProof::TlsAlpn01 {
                name: "a.test".into(),
                key_authorization: "tok.thumb".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(&alpn).expect("serializes"),
            serde_json::json!({
                "kind": "acme_challenge", "type": "tls-alpn-01",
                "name": "a.test", "key_authorization": "tok.thumb"
            })
        );
    }

    #[tokio::test]
    async fn events_ring_after_the_newest_waits_then_returns_empty() {
        let feed = EventFeed::new();
        feed.emit(drained(1));
        let events = feed
            .poll(5, Duration::from_millis(20))
            .await
            .expect("not gone");
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn events_ring_poll_wakes_on_emit() {
        let feed = EventFeed::new();
        let reader = tokio::spawn({
            let feed = feed.clone();
            async move { feed.poll(0, Duration::from_secs(10)).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        feed.emit(drained(1));
        let events = reader.await.expect("reader ends").expect("not gone");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn events_ring_boot_ids_differ() {
        let (one, two) = (EventFeed::new(), EventFeed::new());
        assert_eq!(one.boot_id().len(), 32);
        assert_ne!(one.boot_id(), two.boot_id());
    }

    #[test]
    fn events_ring_serializes_the_kind_inline() {
        let event = Event {
            seq: 7,
            kind: drained(1),
        };
        assert_eq!(
            serde_json::to_string(&event).expect("serializes"),
            r#"{"seq":7,"kind":"revision_drained","app":"a","revision":"r1"}"#
        );
    }
}
