//! DNS-01: wildcard certificates, and certificates for hosts that cannot answer
//! HTTP-01, without a DNS credential in podgate.
//!
//! podgate never talks to a DNS provider. The issuer computes the TXT record, asks the control
//! plane to publish it (`acme_challenge {type: "dns-01", name, value}`), and tells the CA to
//! validate only after the control plane confirmed the record in the snapshot
//! (`acme.dns_ready`). The CA spends its single validation attempt on the first query, so
//! answering early would burn the authorization and the order.
//!
//! This module holds the compile-time rules (operator zone allowlist, wildcard needs DNS-01),
//! the bounds on pending challenges, and the wait for the control plane's confirmation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::{Instant, sleep};

use crate::compile::{Invalid, Rejected};
use crate::entry::CompileContext;
use crate::events::{ChallengeProof, EventFeed, EventKind};
use crate::host::HostPattern;
use crate::table::TableHandle;
use podgate_model::{ChallengeKind, Snapshot, TlsMode};

/// The label every DNS-01 record name starts with.
const PREFIX: &str = "_acme-challenge.";
/// How long an order waits for the control plane to confirm its records before it is abandoned.
pub(super) const READY_WAIT: Duration = Duration::from_secs(600);
/// Records in `acme.dns_ready` a snapshot may list.
pub(super) const MAX_DNS_READY: usize = 1024;
/// Pending DNS-01 challenges on one node.
const MAX_PENDING_NODE: usize = 100;
/// Pending DNS-01 challenges of one app, and the most hosts a `dns-01` app may claim: one
/// challenge per host, so an order never needs more.
const MAX_PENDING_APP: usize = 4;
/// How often the wait looks at the live table.
const POLL: Duration = Duration::from_millis(100);

/// Parses `ACME_DNS_ZONES`: comma separated exact DNS names, lowercased, a trailing dot
/// dropped, duplicates removed.
///
/// # Errors
///
/// A message when the list names no zone, or names something that is not an exact host name
/// (a wildcard, an empty label, a character outside `a-z 0-9 - _`).
pub(crate) fn parse_zones(raw: &str) -> Result<Vec<Box<str>>, String> {
    let mut zones: Vec<Box<str>> = Vec::new();
    for item in raw
        .split(',')
        .map(str::trim)
        .filter(|zone| !zone.is_empty())
    {
        let zone = item.strip_suffix('.').unwrap_or(item);
        match HostPattern::parse(zone) {
            Ok(HostPattern::Exact(name)) => {
                if !zones.contains(&name) {
                    zones.push(name);
                }
            }
            _ => return Err(format!("{item:?} is not a DNS zone name like example.com")),
        }
    }
    if zones.is_empty() {
        return Err("is empty".to_owned());
    }
    Ok(zones)
}

/// Whether `host` is one of `zones` or lies under one.
fn in_zone(zones: &[Box<str>], host: &str) -> bool {
    zones.iter().any(|zone| {
        host == &**zone
            || host
                .strip_suffix(&**zone)
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// The TXT record name that proves `domain`.
pub(super) fn txt_name(domain: &str) -> String {
    format!("{PREFIX}{domain}")
}

/// A record name as compared: lowercase, no trailing dot.
pub(super) fn normalize_name(name: &str) -> Box<str> {
    name.strip_suffix('.')
        .unwrap_or(name)
        .to_ascii_lowercase()
        .into()
}

/// Whether `name` and `value` can be a DNS-01 record: `_acme-challenge.<host>` and a base64url
/// SHA-256 digest.
pub(super) fn check_record(name: &str, value: &str) -> Result<(), String> {
    let normalized = normalize_name(name);
    let domain = normalized
        .strip_prefix(PREFIX)
        .ok_or_else(|| format!("name {name:?} does not start with {PREFIX}"))?;
    if !matches!(HostPattern::parse(domain), Ok(HostPattern::Exact(_))) {
        return Err(format!("name {name:?} is not {PREFIX}<host name>"));
    }
    let value_ok = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !value_ok {
        return Err(format!("value of {name:?} is not base64url"));
    }
    Ok(())
}

/// The compile rules of the `challenge` field of `tls`, over the literal host claims of every
/// app (`claims[i]` for `snapshot.apps[i]`):
///
/// - `dns01_not_enabled`: `dns-01` while `ACME_DNS_ZONES` is unset.
/// - `dns01_zone_not_allowed`: a host outside every listed zone.
/// - `dns01_needs_acme_mode`: `dns-01` on an `on_demand` app, whose certificates come at the
///   handshake, far sooner than the control plane can publish a record.
/// - `dns01_too_many_hosts`: more hosts than [`MAX_PENDING_APP`], so the order could never hold
///   its challenges.
/// - `wildcard_needs_dns01`: with ACME settings present, an `acme` app claims a wildcard that no
///   certificate of the snapshot covers and cannot prove over HTTP-01, so it would silently get
///   no certificate.
pub(crate) fn reject(
    snapshot: &Snapshot,
    claims: &[Vec<HostPattern>],
    context: &CompileContext,
) -> Vec<Rejected> {
    let supplied: HashSet<Box<str>> = snapshot
        .certificates
        .iter()
        .flat_map(|certificate| &certificate.hosts)
        .map(|host| normalize_name(host))
        .collect();
    let mut rejected = Vec::new();
    for (app, patterns) in snapshot.apps.iter().zip(claims) {
        let mut problem = |invalid: Invalid| {
            rejected.push(Rejected::new(app, "tls.challenge", invalid));
        };
        let mut hosts: Vec<String> = Vec::new();
        for pattern in patterns {
            let shown = match pattern {
                HostPattern::Exact(name) => name.to_string(),
                HostPattern::Wildcard(base) => format!("*.{base}"),
            };
            if !hosts.contains(&shown) {
                hosts.push(shown);
            }
        }
        match app.tls.challenge {
            ChallengeKind::Dns01 => {
                let zones = context.acme_dns_zones();
                if app.tls.mode != TlsMode::Acme {
                    problem(Invalid::new(
                        "dns01_needs_acme_mode",
                        "challenge dns-01 needs tls.mode acme: an on_demand certificate is wanted at the handshake, before a DNS record can be published",
                    ));
                }
                if zones.is_empty() {
                    problem(Invalid::new(
                        "dns01_not_enabled",
                        "challenge dns-01 is off on this node: the operator lists the allowed zones in ACME_DNS_ZONES",
                    ));
                } else {
                    for host in &hosts {
                        let domain = host.strip_prefix("*.").unwrap_or(host);
                        if !in_zone(zones, domain) {
                            problem(
                                Invalid::new(
                                    "dns01_zone_not_allowed",
                                    format!("host {host} is outside every zone in ACME_DNS_ZONES"),
                                )
                                .with("host", host.as_str()),
                            );
                        }
                    }
                }
                if hosts.len() > MAX_PENDING_APP {
                    problem(Invalid::new(
                        "dns01_too_many_hosts",
                        format!(
                            "challenge dns-01 allows at most {MAX_PENDING_APP} hosts per app, found {}",
                            hosts.len()
                        ),
                    ));
                }
            }
            ChallengeKind::Http01 => {
                if snapshot.acme.is_none() || app.tls.mode != TlsMode::Acme {
                    continue;
                }
                for host in hosts.iter().filter(|host| host.starts_with("*.")) {
                    if !supplied.contains(&*normalize_name(host)) {
                        problem(
                            Invalid::new(
                                "wildcard_needs_dns01",
                                format!(
                                    "wildcard {host} cannot be proven over http-01: set tls.challenge to dns-01, or supply a certificate for it"
                                ),
                            )
                            .with("host", host.as_str()),
                        );
                    }
                }
            }
        }
    }
    rejected
}

/// Pending DNS-01 challenges, per node and per app. A challenge counts from the moment it is
/// announced until its order ends.
#[derive(Debug, Default)]
pub(super) struct Ledger {
    pending: Mutex<HashMap<Box<str>, usize>>,
}

impl Ledger {
    /// Counts one more pending challenge of `app`; `false` when the node or the app is at its
    /// limit, and nothing was counted.
    fn reserve(&self, app: &str) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let total: usize = pending.values().sum();
        let own = pending.get(app).copied().unwrap_or(0);
        if total >= MAX_PENDING_NODE || own >= MAX_PENDING_APP {
            return false;
        }
        *pending.entry(app.into()).or_insert(0) += 1;
        true
    }

    fn release(&self, app: &str, count: usize) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(own) = pending.get_mut(app) {
            *own = own.saturating_sub(count);
            if *own == 0 {
                pending.remove(app);
            }
        }
    }
}

/// One DNS-01 record an order asked the control plane to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub(super) name: Box<str>,
    pub(super) value: Box<str>,
}

/// The records of one order. It announces them, and however the order ends (success, failure,
/// timeout, cancellation) tells the control plane they can go (`acme_challenge_done`), so a
/// finished or abandoned order never leaves a record behind.
#[derive(Debug)]
pub(super) struct Round {
    ledger: Arc<Ledger>,
    events: EventFeed,
    app: Box<str>,
    records: Vec<Record>,
}

impl Round {
    pub(super) fn new(ledger: Arc<Ledger>, events: EventFeed, app: Box<str>) -> Self {
        Self {
            ledger,
            events,
            app,
            records: Vec::new(),
        }
    }

    /// Emits `acme_challenge {type: "dns-01"}` for the record proving `domain` (a base domain,
    /// without `*.`). `false` when the node or the app has too many pending challenges: nothing
    /// was emitted.
    pub(super) fn announce(&mut self, domain: &str, value: String) -> bool {
        if !self.ledger.reserve(&self.app) {
            return false;
        }
        let record = Record {
            name: txt_name(&normalize_name(domain)).into(),
            value: value.into(),
        };
        self.events.emit(EventKind::AcmeChallenge {
            proof: ChallengeProof::Dns01 {
                name: record.name.clone(),
                value: record.value.clone(),
            },
        });
        self.records.push(record);
        true
    }

    /// The records announced so far.
    pub(super) fn records(&self) -> &[Record] {
        &self.records
    }

    /// Emits `acme_challenge_done` for every announced record and frees their slots. Does
    /// nothing the second time.
    pub(super) fn finish(&mut self) {
        for record in self.records.drain(..) {
            self.events.emit(EventKind::AcmeChallengeDone {
                proof: ChallengeProof::Dns01 {
                    name: record.name,
                    value: record.value,
                },
            });
            self.ledger.release(&self.app, 1);
        }
    }
}

impl Drop for Round {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Why the wait for the control plane's confirmation ended without it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NotReady {
    /// The snapshot no longer has ACME settings.
    Cancelled,
    /// `wait` passed.
    Expired,
}

/// Waits until the live table lists every record in `acme.dns_ready`, which is the control
/// plane's confirmation that the record is visible on the zone's authoritative servers. Reads
/// the table of this node, so a table that lost its ACME settings cancels the wait.
pub(super) async fn await_ready(
    table: &TableHandle,
    records: &[Record],
    wait: Duration,
) -> Result<(), NotReady> {
    let deadline = Instant::now() + wait;
    loop {
        {
            let table = table.load();
            let plan = table.acme();
            if plan.settings().is_none() {
                return Err(NotReady::Cancelled);
            }
            if records
                .iter()
                .all(|record| plan.dns_ready(&record.name, &record.value))
            {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(NotReady::Expired);
        }
        sleep(POLL).await;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dns01_zones_are_normalized_and_validated() {
        assert_eq!(
            parse_zones("Example.com, a.example.org.,example.com"),
            Ok(vec!["example.com".into(), "a.example.org".into()])
        );
        for bad in ["", " , ", "*.example.com", "a b", "a..b"] {
            assert!(parse_zones(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dns01_zone_covers_itself_and_its_subdomains_only() {
        let zones = [Box::<str>::from("example.com")];
        assert!(in_zone(&zones, "example.com"));
        assert!(in_zone(&zones, "a.b.example.com"));
        assert!(!in_zone(&zones, "badexample.com"));
        assert!(!in_zone(&zones, "example.com.evil.test"));
        assert!(!in_zone(&zones, "com"));
    }

    fn live(ready: &str) -> TableHandle {
        let snapshot: Snapshot = serde_json::from_str(&format!(
            r#"{{"version": 1, "tenants": [], "apps": [],
            "acme": {{"issuer_node": "n1", "directory_url": "https://ca.test/dir",
                      "dns_ready": [{ready}]}}}}"#
        ))
        .expect("valid snapshot json");
        let table = TableHandle::new();
        table.apply(&snapshot).expect("applies");
        table
    }

    fn record() -> Record {
        Record {
            name: "_acme-challenge.a.test".into(),
            value: "v1".into(),
        }
    }

    #[tokio::test]
    async fn dns01_unconfirmed_times_out() {
        let table = live("");
        let started = Instant::now();
        let waited = await_ready(&table, &[record()], Duration::from_millis(300)).await;
        assert_eq!(waited, Err(NotReady::Expired));
        assert!(started.elapsed() >= Duration::from_millis(300));
        let wrong_value = live(r#"{"name": "_acme-challenge.a.test", "value": "v2"}"#);
        let waited = await_ready(&wrong_value, &[record()], Duration::from_millis(200)).await;
        assert_eq!(
            waited,
            Err(NotReady::Expired),
            "the value is part of the key"
        );
    }

    #[tokio::test]
    async fn dns01_wait_ends_when_the_table_confirms() {
        let confirmed = live(r#"{"name": "_acme-challenge.a.test", "value": "v1"}"#);
        assert_eq!(
            await_ready(&confirmed, &[record()], Duration::ZERO).await,
            Ok(())
        );
        let empty = TableHandle::new();
        assert_eq!(
            await_ready(&empty, &[record()], Duration::from_secs(5)).await,
            Err(NotReady::Cancelled)
        );
    }

    #[test]
    fn dns01_records_are_checked() {
        let digest = "A".repeat(43);
        assert_eq!(check_record("_acme-challenge.a.test", &digest), Ok(()));
        assert_eq!(check_record("_ACME-Challenge.A.test.", &digest), Ok(()));
        for (name, value) in [
            ("a.test", digest.as_str()),
            ("_acme-challenge.", digest.as_str()),
            ("_acme-challenge.*.a.test", digest.as_str()),
            ("_acme-challenge.a.test", ""),
            ("_acme-challenge.a.test", "not base64!"),
        ] {
            assert!(check_record(name, value).is_err(), "{name} {value}");
        }
    }

    #[test]
    fn dns01_pending_challenges_bounded() {
        let ledger = Arc::new(Ledger::default());
        for _ in 0..MAX_PENDING_APP {
            assert!(ledger.reserve("a"));
        }
        assert!(!ledger.reserve("a"), "an app holds at most four");
        ledger.release("a", 1);
        assert!(ledger.reserve("a"));
        ledger.release("a", MAX_PENDING_APP);
        for app in 0..MAX_PENDING_NODE / MAX_PENDING_APP {
            for _ in 0..MAX_PENDING_APP {
                assert!(ledger.reserve(&format!("app{app}")));
            }
        }
        assert!(!ledger.reserve("another"), "a node holds at most 100");
    }

    #[tokio::test]
    async fn dns01_round_announces_and_always_says_done() {
        let events = EventFeed::new();
        let ledger = Arc::new(Ledger::default());
        {
            let mut round = Round::new(Arc::clone(&ledger), events.clone(), "a".into());
            assert!(round.announce("Example.com", "v1".into()));
            assert!(round.announce("example.com", "v2".into()));
            assert_eq!(round.records().len(), 2);
            assert_eq!(&*round.records()[0].name, "_acme-challenge.example.com");
        }
        let kinds: Vec<String> = events
            .poll(0, Duration::ZERO)
            .await
            .expect("retained")
            .iter()
            .map(|event| serde_json::to_value(&event.kind).expect("serializes")["kind"].to_string())
            .collect();
        assert_eq!(
            kinds,
            [
                "\"acme_challenge\"",
                "\"acme_challenge\"",
                "\"acme_challenge_done\"",
                "\"acme_challenge_done\""
            ]
        );
        assert!(ledger.reserve("a"), "slots are free again");
    }
}
