//! Certificates without a single owner: HA ACME with ARI renewal, and on-demand TLS.
//!
//! podgate keeps no state on disk and never calls the control plane. Everything below runs on
//! the snapshot the control plane pushes and the events podgate emits:
//!
//! 1. **One issuer.** Only the node whose `NODE_NAME` equals `Snapshot.acme.issuer_node` orders
//!    certificates ([`Acme`] as a background service). Every node serves HTTP-01 answers.
//! 2. **Challenge round trip.** For a host without a certificate the issuer opens an order and
//!    emits `acme_challenge {token, key_authorization}`. The control plane pushes a snapshot
//!    with the answer in `acme.challenges`; every node then serves
//!    `GET /.well-known/acme-challenge/<token>` on the plain HTTP listener ([`serve_challenge`],
//!    before routing). The issuer waits until its own table holds the token, tells the CA, and
//!    emits `certificate_issued {hosts, cert_pem, key_pem}`. The control plane stores the
//!    certificate and pushes it back in `Snapshot.certificates`, which is the only place the
//!    TLS listener reads certificates from.
//! 3. **Renewal.** The issuer asks the CA for each served certificate's ARI window (RFC 9773)
//!    and renews at a random point inside it, replacing the old certificate; without ARI it
//!    renews at two thirds of the lifetime. Renewing is the same round trip as issuing.
//! 4. **On demand.** A TLS handshake for a host of an `on_demand` app that has no certificate
//!    waits, bounded, for one (the pre-TLS hook on [`Acme`]). Every node, the issuer too, emits
//!    `certificate_requested {host}` once per pending period; the control plane approves by
//!    listing the host in `acme.requested_hosts`, and only then does the issuer order it. A
//!    client can therefore never make podgate spend the CA's rate limits. A host of no app never
//!    waits and never gets a certificate.
//!
//! Pingora's rustls backend has no async certificate callback (`certificate_callback` is
//! OpenSSL-only) and rustls' `ResolvesServerCert` is synchronous, so the wait happens before
//! the handshake starts: [`Acme`] is installed as Pingora's pre-TLS hook, reads the ClientHello
//! to learn the SNI, waits, and hands the bytes back to the handshake.

mod handshake;
mod http01;
mod issuer;
mod plan;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::sync::Semaphore;

use crate::events::{EventFeed, EventKind};
use crate::snapshot;
use crate::table::TableHandle;

pub use http01::serve_challenge;
pub use plan::{CertInfo, Plan, PlanError};

/// How long an on-demand handshake waits for a certificate before it fails.
const ON_DEMAND_WAIT: Duration = Duration::from_secs(30);
/// Handshakes waiting for an on-demand certificate at once; further ones fail at once.
const MAX_WAITERS: usize = 256;
/// Hosts with a pending `certificate_requested` at once; further ones are not announced.
const MAX_ANNOUNCED: usize = 256;
/// How long a host's `certificate_requested` stays pending: no second event for it meanwhile.
const PENDING_PERIOD: Duration = Duration::from_secs(600);

/// A private key in PEM. Serializes as the plain string; `Debug` hides it, so it cannot leak
/// through a log line.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PrivateKeyPem(Box<str>);

impl PrivateKeyPem {
    /// Wraps the PEM text.
    #[must_use]
    pub fn new(pem: impl Into<Box<str>>) -> Self {
        Self(pem.into())
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyPem([redacted])")
    }
}

#[derive(Debug)]
struct Shared {
    node: Option<Box<str>>,
    table: TableHandle,
    events: EventFeed,
    ca_file: Option<PathBuf>,
    /// Hosts whose `certificate_requested` is pending, and when it was emitted.
    announced: Mutex<HashMap<Box<str>, Instant>>,
    waiters: Semaphore,
}

/// The ACME machinery of one node. Cheap to clone; every clone is the same node.
///
/// Run one clone as a Pingora background service (it only acts when this node is the issuer)
/// and install another as the listener's pre-TLS hook.
#[derive(Debug, Clone)]
pub struct Acme {
    shared: Arc<Shared>,
}

impl Acme {
    /// The ACME machinery of the node called `node` (`NODE_NAME`; `None` never issues), reading
    /// snapshots from `table` and reporting through `events`. `ca_file` is a PEM root to trust
    /// for the ACME server instead of the platform's roots.
    #[must_use]
    pub fn new(
        table: TableHandle,
        events: EventFeed,
        node: Option<Box<str>>,
        ca_file: Option<PathBuf>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                node,
                table,
                events,
                ca_file,
                announced: Mutex::new(HashMap::new()),
                waiters: Semaphore::new(MAX_WAITERS),
            }),
        }
    }

    fn is_issuer(&self, settings: &snapshot::Acme) -> bool {
        self.shared.node.as_deref() == Some(&*settings.issuer_node)
    }

    /// Tells the control plane that a handshake wants a certificate for `host`, once per
    /// pending period: until the certificate shows up (see [`Self::forget`]) or
    /// [`PENDING_PERIOD`] passes, however many handshakes ask. Every node does this, the
    /// issuer too; ordering waits for the control plane to list the host in
    /// `acme.requested_hosts`, so no client can make the issuer order on its own.
    fn request(&self, host: &str) {
        let now = Instant::now();
        let mut announced = lock(&self.shared.announced);
        announced.retain(|_, at| now.duration_since(*at) < PENDING_PERIOD);
        if announced.len() < MAX_ANNOUNCED && !announced.contains_key(host) {
            announced.insert(host.into(), now);
            drop(announced);
            self.shared
                .events
                .emit(EventKind::CertificateRequested { host: host.into() });
        }
    }

    /// Ends the pending period of `host`: its certificate arrived.
    fn forget(&self, host: &str) {
        lock(&self.shared.announced).remove(host);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
