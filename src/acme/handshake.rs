//! On-demand TLS: before the handshake of a connection starts, when the host belongs to an
//! `on_demand` app and has no certificate, wait for one.
//!
//! The pre-TLS hook that learns the SNI from the ClientHello is [`crate::tls::PreHandshake`]; it
//! calls [`Acme::await_certificate`] with the name. The wait never fails a connection: whatever
//! it cannot wait for, the handshake decides. A host that is not an `on_demand` app's gets no
//! wait, so the handshake fails at once for unknown names.

use tokio::time::{Instant, sleep};

use super::{Acme, ON_DEMAND_WAIT};

/// How often a waiting handshake looks at the live table.
const POLL: std::time::Duration = std::time::Duration::from_millis(100);

impl Acme {
    /// Waits, bounded, until the live table has a certificate for `host` (normalized), after
    /// asking for one. Returns at once when it has one, when `host` is not an `on_demand`
    /// app's, or when too many handshakes are already waiting.
    pub(crate) async fn await_certificate(&self, host: &str) {
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
