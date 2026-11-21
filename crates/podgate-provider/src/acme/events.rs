//! Reading podgate's event feed, and the loop of the broker.
//!
//! The feed is `GET /v1/events?after=<seq>&timeout_secs=<n>` on the admin socket
//! (`docs/architecture.md`, `### Event feed`). The broker long-polls it with the sequence number
//! it stored:
//!
//! - `200 {boot_id, events}` is a batch. The events are applied in order, then the cursor moves.
//!   A `boot_id` other than the stored one means podgate restarted: its sequence numbers start
//!   again, its orders are gone, so the broker forgets the position and the stale answers and
//!   polls from `0`.
//! - `410 {boot_id, oldest}` means the feed no longer holds the events after the cursor (the ring
//!   keeps 4096). The broker continues from `oldest - 1`; what was lost is lost, and the issuer
//!   orders again after its ten minutes.
//! - `408` and errors poll again, with the push client's backoff for errors.
//!
//! Event bodies carry private keys (`certificate_issued`). They are read into a `serde_json`
//! value and picked apart by hand, because a serde error repeats the value it could not parse.
//! Nothing in this module logs a body, a key or a key authorization.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{error, info, warn};

use super::{Broker, BrokerError, BrokerView, Claims, Secret, unix_ms};
use crate::push::{AdminClient, Answer, Backoff, ClientError, Tuning};
use crate::trust::HostPattern;

/// Housekeeping that runs even when nothing else wakes the loop.
const TICK: Duration = Duration::from_secs(60);

/// What an ACME challenge asks the control plane to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// Serve `key_authorization` at `/.well-known/acme-challenge/<token>`.
    Http01 {
        /// The token.
        token: Box<str>,
        /// The answer.
        key_authorization: Box<str>,
    },
    /// Publish the TXT record `value` at `name`.
    Dns01 {
        /// `_acme-challenge.<domain>`.
        name: Box<str>,
        /// The record value.
        value: Box<str>,
    },
    /// Answer an `acme-tls/1` handshake for `name`.
    TlsAlpn01 {
        /// The host being proven.
        name: Box<str>,
        /// The answer.
        key_authorization: Box<str>,
    },
}

/// The events the broker acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A challenge to answer.
    Challenge(Proof),
    /// A DNS-01 record can be removed (podgate says so for DNS-01 only).
    ChallengeDone(Proof),
    /// A certificate was issued.
    Issued {
        /// Its names.
        hosts: Vec<Box<str>>,
        /// The chain.
        cert_pem: String,
        /// The private key.
        key_pem: Secret,
    },
    /// A handshake wants a certificate for `host`.
    Requested {
        /// The SNI.
        host: Box<str>,
    },
}

/// One entry of the feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Its sequence number.
    pub seq: u64,
    /// `Ok(None)`: a kind the broker does not act on. `Err`: a kind it does act on, with a field
    /// missing or wrong (the message names the field, never the value).
    pub event: Result<Option<Event>, Box<str>>,
}

/// The answer of one poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feed {
    /// Events after the cursor, oldest first.
    Batch {
        /// podgate's `boot_id`.
        boot_id: Box<str>,
        /// The events.
        items: Vec<Item>,
        /// The highest sequence number in the batch, `0` when it is empty.
        last_seq: u64,
    },
    /// The cursor is older than the feed.
    Gone {
        /// podgate's `boot_id`, when the answer names it.
        boot_id: Option<Box<str>>,
        /// The oldest sequence number the feed still holds.
        oldest: u64,
    },
    /// The poll outlasted the admin timeout and consumed nothing.
    Timeout,
}

/// An answer the broker cannot read.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct FeedError(pub Box<str>);

fn text<'a>(object: &'a Value, field: &str, kind: &str) -> Result<&'a str, FeedError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| FeedError(format!("{kind}: `{field}` is missing or not a string").into()))
}

fn proof(object: &Value, kind: &str) -> Result<Option<Proof>, FeedError> {
    Ok(match text(object, "type", kind)? {
        "http-01" => Some(Proof::Http01 {
            token: text(object, "token", kind)?.into(),
            key_authorization: text(object, "key_authorization", kind)?.into(),
        }),
        "dns-01" => Some(Proof::Dns01 {
            name: text(object, "name", kind)?.into(),
            value: text(object, "value", kind)?.into(),
        }),
        "tls-alpn-01" => Some(Proof::TlsAlpn01 {
            name: text(object, "name", kind)?.into(),
            key_authorization: text(object, "key_authorization", kind)?.into(),
        }),
        _ => None,
    })
}

fn issued(object: &Value) -> Result<Event, FeedError> {
    const KIND: &str = "certificate_issued";
    let hosts: Vec<Box<str>> = object
        .get("hosts")
        .and_then(Value::as_array)
        .filter(|hosts| !hosts.is_empty())
        .and_then(|hosts| {
            hosts
                .iter()
                .map(|host| host.as_str().map(Box::from))
                .collect()
        })
        .ok_or_else(|| {
            FeedError(format!("{KIND}: `hosts` is not a non-empty list of strings").into())
        })?;
    if hosts.iter().any(|host| HostPattern::parse(host).is_err()) {
        return Err(FeedError(
            format!("{KIND}: `hosts` holds a name that is not a host").into(),
        ));
    }
    let cert_pem = text(object, "cert_pem", KIND)?;
    let key_pem = text(object, "key_pem", KIND)?;
    if !cert_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(FeedError(
            format!("{KIND}: `cert_pem` holds no certificate").into(),
        ));
    }
    if !key_pem.contains("PRIVATE KEY-----") {
        return Err(FeedError(
            format!("{KIND}: `key_pem` holds no private key").into(),
        ));
    }
    Ok(Event::Issued {
        hosts,
        cert_pem: cert_pem.to_owned(),
        key_pem: Secret::new(key_pem),
    })
}

fn item(object: &Value) -> Option<Item> {
    let seq = object.get("seq").and_then(Value::as_u64)?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let event = match kind {
        "acme_challenge" => proof(object, kind).map(|proof| proof.map(Event::Challenge)),
        "acme_challenge_done" => proof(object, kind).map(|proof| proof.map(Event::ChallengeDone)),
        "certificate_issued" => issued(object).map(Some),
        "certificate_requested" => {
            text(object, "host", kind).map(|host| Some(Event::Requested { host: host.into() }))
        }
        _ => Ok(None),
    };
    Some(Item {
        seq,
        event: event.map_err(|err| err.0),
    })
}

impl Feed {
    /// Reads the answer of one poll.
    ///
    /// # Errors
    ///
    /// [`FeedError`] for a status the feed does not document or a body that is not what it
    /// documents. The message never repeats the body.
    pub fn parse(answer: &Answer) -> Result<Self, FeedError> {
        let bad = |why: &str| {
            FeedError(format!("the event feed answered {}: {why}", answer.status).into())
        };
        match answer.status {
            200 => {
                let body = answer.json().ok_or_else(|| bad("the body is not JSON"))?;
                let boot_id = body
                    .get("boot_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("`boot_id` is missing"))?;
                let events = body
                    .get("events")
                    .and_then(Value::as_array)
                    .ok_or_else(|| bad("`events` is missing"))?;
                let items = events
                    .iter()
                    .map(|event| item(event).ok_or_else(|| bad("an event has no `seq`")))
                    .collect::<Result<Vec<_>, _>>()?;
                let last_seq = items.iter().map(|item| item.seq).max().unwrap_or(0);
                Ok(Self::Batch {
                    boot_id: boot_id.into(),
                    items,
                    last_seq,
                })
            }
            410 => {
                let body = answer.json().ok_or_else(|| bad("the body is not JSON"))?;
                let oldest = body
                    .get("oldest")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| bad("`oldest` is missing"))?;
                Ok(Self::Gone {
                    boot_id: body.get("boot_id").and_then(Value::as_str).map(Into::into),
                    oldest,
                })
            }
            408 => Ok(Self::Timeout),
            _ => Err(bad("not a documented status")),
        }
    }
}

/// A DNS-01 record the solver must publish and confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsChallenge {
    /// `_acme-challenge.<domain>`.
    pub name: Box<str>,
    /// The TXT value.
    pub value: Box<str>,
}

/// A solver that could not publish a record.
#[derive(Debug, Error)]
#[error("{0}")]
pub struct SolveError(pub Box<str>);

/// A boxed future, for the object-safe solver.
pub type SolverFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Publishes DNS-01 TXT records. The broker hands it each `dns-01` challenge and
/// puts the record into `acme.dns_ready` only after `present` returned `Ok`, which means the
/// record is visible on the zone's authoritative servers.
pub trait Solver: Send + Sync + 'static {
    /// Publishes the record and waits until it is visible. `claims` tells which app claims
    /// which host, for the solver's own trust check.
    fn present(
        &self,
        challenge: DnsChallenge,
        claims: Arc<Claims>,
    ) -> SolverFuture<Result<(), SolveError>>;

    /// Removes the record after `acme_challenge_done`. Failures are the solver's to log.
    fn cleanup(&self, challenge: DnsChallenge) -> SolverFuture<()>;
}

/// No DNS solver is configured: DNS-01 challenges are reported and never answered.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSolver;

impl Solver for NoSolver {
    fn present(&self, _: DnsChallenge, _: Arc<Claims>) -> SolverFuture<Result<(), SolveError>> {
        Box::pin(async { Err(SolveError("no_solver: no DNS solver is configured".into())) })
    }

    fn cleanup(&self, _: DnsChallenge) -> SolverFuture<()> {
        Box::pin(async {})
    }
}

type Poll = Pin<Box<dyn Future<Output = Result<Answer, ClientError>> + Send>>;

async fn next_poll(poll: &mut Option<Poll>) -> Result<Answer, ClientError> {
    match poll {
        Some(poll) => poll.await,
        None => std::future::pending().await,
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

fn publish(view: &watch::Sender<Arc<BrokerView>>, broker: &Broker) {
    let next = broker.view(unix_ms());
    view.send_if_modified(|current| {
        let changed = **current != next;
        if changed {
            *current = Arc::new(next);
        }
        changed
    });
}

/// Runs the broker until the engine drops its end, or the state directory fails.
pub(super) async fn run(
    mut broker: Broker,
    client: AdminClient,
    tuning: Tuning,
    solver: Arc<dyn Solver>,
    claims: watch::Receiver<Option<Arc<Claims>>>,
    view: watch::Sender<Arc<BrokerView>>,
) -> Result<(), BrokerError> {
    let outcome = drive(&mut broker, &client, tuning, &solver, claims, &view).await;
    if let Err(err) = &outcome {
        // What was persisted before the failure is still worth serving; nothing else is added.
        publish(&view, &broker);
        error!(error = %err, cause = %source_of(err), "the ACME broker stopped; the last pushed state stays");
    }
    outcome
}

fn source_of(err: &BrokerError) -> String {
    let mut parts = Vec::new();
    let mut current = std::error::Error::source(err);
    while let Some(cause) = current {
        parts.push(cause.to_string());
        current = cause.source();
    }
    parts.join(": ")
}

async fn drive(
    broker: &mut Broker,
    client: &AdminClient,
    tuning: Tuning,
    solver: &Arc<dyn Solver>,
    mut claims_rx: watch::Receiver<Option<Arc<Claims>>>,
    view: &watch::Sender<Arc<BrokerView>>,
) -> Result<(), BrokerError> {
    let mut backoff = Backoff::new(tuning.backoff_min, tuning.backoff_max);
    let mut solving: JoinSet<(DnsChallenge, Result<(), SolveError>)> = JoinSet::new();
    let mut poll: Option<Poll> = None;
    let mut not_before = Instant::now();
    let mut claims: Option<Arc<Claims>> = None;
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        if poll.is_none() && Instant::now() >= not_before {
            let client = client.clone();
            let after = broker.cursor().after;
            let wait = tuning.event_poll;
            poll = Some(Box::pin(async move { client.events(after, wait).await }));
        }
        let now = unix_ms();
        let wake = broker
            .next_wake(now)
            .map(|at| Instant::now() + Duration::from_millis(at.saturating_sub(now)));
        let retry = poll.is_none().then_some(not_before);
        tokio::select! {
            answer = next_poll(&mut poll) => {
                poll = None;
                match answer {
                    Err(err) => {
                        let delay = backoff.next_delay();
                        warn!(error = %err, retry_in_ms = delay.as_millis(), "the event feed is unreachable");
                        not_before = Instant::now() + delay;
                    }
                    Ok(answer) => match Feed::parse(&answer) {
                        Err(err) => {
                            let delay = backoff.next_delay();
                            warn!(error = %err, retry_in_ms = delay.as_millis(), "the event feed answer is unusable");
                            not_before = Instant::now() + delay;
                        }
                        Ok(feed) => {
                            backoff.reset();
                            handle_feed(broker, feed, claims.as_deref(), &mut solving, solver)?;
                        }
                    },
                }
            }
            changed = claims_rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                claims = claims_rx.borrow_and_update().clone();
                if let Some(claims) = &claims {
                    broker.claims_changed(claims, unix_ms())?;
                }
            }
            Some(done) = solving.join_next(), if !solving.is_empty() => {
                if let Ok((challenge, outcome)) = done {
                    match outcome {
                        Ok(()) => {
                            if broker.dns_visible(&challenge) {
                                info!(name = %challenge.name, "DNS-01 record is visible; confirming it to podgate");
                            }
                        }
                        Err(why) => warn!(name = %challenge.name, "DNS-01 record not published: {why}"),
                    }
                }
            }
            () = sleep_until(wake) => broker.tick(unix_ms())?,
            _ = tick.tick() => broker.tick(unix_ms())?,
            () = sleep_until(retry) => {}
        }
        publish(view, broker);
    }
}

fn handle_feed(
    broker: &mut Broker,
    feed: Feed,
    claims: Option<&Claims>,
    solving: &mut JoinSet<(DnsChallenge, Result<(), SolveError>)>,
    solver: &Arc<dyn Solver>,
) -> Result<(), BrokerError> {
    match feed {
        Feed::Timeout => {}
        Feed::Gone { boot_id, oldest } => {
            if let Some(boot_id) =
                boot_id.filter(|boot| broker.cursor().boot_id.as_deref() != Some(boot))
            {
                warn!("podgate restarted; polling its event feed from the start");
                broker.restarted(&boot_id)?;
            } else {
                warn!(
                    oldest,
                    "the event feed no longer holds the events after the cursor; continuing from its oldest"
                );
                broker.lost_events(oldest)?;
            }
        }
        Feed::Batch {
            boot_id,
            items,
            last_seq,
        } => {
            match broker.cursor().boot_id.as_deref() {
                None => broker.adopt_boot(&boot_id)?,
                Some(known) if known != &*boot_id => {
                    warn!("podgate restarted; polling its event feed from the start");
                    broker.restarted(&boot_id)?;
                    return Ok(());
                }
                Some(_) => {}
            }
            if items.is_empty() {
                return Ok(());
            }
            let applied = broker.apply(&items, last_seq, claims, unix_ms())?;
            let known = Arc::new(claims.cloned().unwrap_or_default());
            for challenge in applied.solve {
                let present = solver.present(challenge.clone(), Arc::clone(&known));
                solving.spawn(async move { (challenge, present.await) });
            }
            for challenge in applied.cleanup {
                tokio::spawn(solver.cleanup(challenge));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn answer(status: u16, body: &Value) -> Answer {
        Answer {
            status,
            headers: Vec::new(),
            body: body.to_string().into_bytes(),
        }
    }

    #[test]
    fn a_batch_is_read_in_order_and_unknown_kinds_are_skipped() {
        let body = serde_json::json!({
            "boot_id": "b1",
            "events": [
                {"seq": 4, "kind": "acme_challenge", "type": "http-01", "token": "t", "key_authorization": "k"},
                {"seq": 5, "kind": "revision_drained", "app": "a", "revision": "r"},
                {"seq": 6, "kind": "certificate_requested", "host": "x.test"},
            ],
        });
        let Ok(Feed::Batch {
            boot_id,
            items,
            last_seq,
        }) = Feed::parse(&answer(200, &body))
        else {
            panic!("a batch");
        };
        assert_eq!((&*boot_id, last_seq), ("b1", 6));
        assert!(matches!(
            items[0].event,
            Ok(Some(Event::Challenge(Proof::Http01 { .. })))
        ));
        assert_eq!(items[1].event, Ok(None));
        assert!(matches!(items[2].event, Ok(Some(Event::Requested { .. }))));
    }

    #[test]
    fn a_malformed_event_names_the_field_and_never_the_value() {
        let body = serde_json::json!({
            "boot_id": "b1",
            "events": [{"seq": 1, "kind": "certificate_issued", "hosts": ["a.test"],
                        "cert_pem": 7, "key_pem": "SECRET-KEY-MATERIAL"}],
        });
        let Ok(Feed::Batch { items, .. }) = Feed::parse(&answer(200, &body)) else {
            panic!("a batch");
        };
        let Err(problem) = &items[0].event else {
            panic!("malformed");
        };
        assert!(
            problem.contains("cert_pem") && !problem.contains("SECRET"),
            "{problem}"
        );
        // A key that is not a key is refused whole, without echoing it.
        let wrong = serde_json::json!({
            "boot_id": "b1",
            "events": [{"seq": 1, "kind": "certificate_issued", "hosts": ["a.test"],
                        "cert_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", "key_pem": "SECRET"}],
        });
        let Ok(Feed::Batch { items, .. }) = Feed::parse(&answer(200, &wrong)) else {
            panic!("a batch");
        };
        let Err(problem) = &items[0].event else {
            panic!("refused");
        };
        assert!(!problem.contains("SECRET"), "{problem}");
    }

    #[test]
    fn gone_timeout_and_undocumented_statuses() {
        let gone = serde_json::json!({"error": "x", "boot_id": "b2", "oldest": 40});
        assert_eq!(
            Feed::parse(&answer(410, &gone)),
            Ok(Feed::Gone {
                boot_id: Some("b2".into()),
                oldest: 40
            })
        );
        assert_eq!(Feed::parse(&answer(408, &Value::Null)), Ok(Feed::Timeout));
        assert!(Feed::parse(&answer(500, &serde_json::json!({"error": "boom"}))).is_err());
        assert!(Feed::parse(&answer(200, &serde_json::json!({"events": []}))).is_err());
    }
}
