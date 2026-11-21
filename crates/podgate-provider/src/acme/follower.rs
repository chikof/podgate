//! A follower provider, and the read-only view `print` and `check` use.
//!
//! A cluster runs one broker, beside the issuer's podgate. The other nodes' providers run in
//! `mode = "follower"` on the same `state_dir` (a shared volume): they read the certificates and
//! the HTTP-01 and TLS-ALPN-01 answers the broker keeps there and push them to their own podgate,
//! so every node serves the same certificates and answers the CA's challenge on whichever node
//! it reaches. A follower never writes the directory, never reads an event feed, and puts neither
//! the account key nor an EAB key into its snapshot: only the issuer's podgate uses them.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use super::settings::AcmeSettings;
use super::store::{Store, StoreError};
use super::{
    Base, BrokerError, BrokerView, CHALLENGES, Held, account_key, base_of, certificate_of,
};

/// How often a follower looks at the directory.
const POLL: Duration = Duration::from_secs(1);

pub(super) fn load(settings: &AcmeSettings) -> Result<BrokerView, StoreError> {
    load_with(settings, false)
}

/// Reads the directory without changing it. `secrets` puts the account key and the EAB key in
/// the view (`print` and `check` of a broker, which redact them before showing anything).
pub(super) fn load_with(settings: &AcmeSettings, secrets: bool) -> Result<BrokerView, StoreError> {
    let store = Store::open_existing(&settings.state_dir)?;
    let (certs, held) = match &store {
        Some(store) => (
            store.certs()?,
            store
                .read_json::<Vec<Held>>(CHALLENGES)?
                .unwrap_or_default(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    let base = if secrets {
        base_of(settings, account_key(settings, store.as_ref(), false)?)?
    } else {
        Base {
            issuer_node: settings.issuer_node.clone(),
            directory_url: settings.directory_url.clone(),
            contact: settings.contact.clone(),
            eab: None,
            account_key: None,
        }
    };
    let mut certificates: Vec<_> = certs.iter().map(certificate_of).collect();
    certificates.sort_by(|a, b| a.hosts.cmp(&b.hosts));
    let mut challenges: Vec<_> = held.iter().map(Held::challenge).collect();
    challenges.sort_by(|a, b| {
        (&a.token, &a.name, &a.key_authorization).cmp(&(&b.token, &b.name, &b.key_authorization))
    });
    Ok(BrokerView {
        base: Some(base),
        certificates,
        challenges,
        ..BrokerView::default()
    })
}

/// Follows the directory until the engine drops the view.
pub(super) async fn run(
    settings: AcmeSettings,
    view: watch::Sender<Arc<BrokerView>>,
) -> Result<(), BrokerError> {
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut last_error: Option<String> = None;
    loop {
        tick.tick().await;
        if view.is_closed() {
            return Ok(());
        }
        match load(&settings) {
            Ok(next) => {
                last_error = None;
                view.send_if_modified(|current| {
                    let changed = **current != next;
                    if changed {
                        *current = Arc::new(next);
                    }
                    changed
                });
            }
            Err(err) => {
                // The broker replaces files while this reads: the next look will see a whole
                // state. The previous view stays meanwhile.
                let shown = format!("{err}");
                if last_error.as_deref() != Some(shown.as_str()) {
                    tracing::warn!(
                        "cannot read the shared ACME directory, keeping the last view: {shown}"
                    );
                    last_error = Some(shown);
                }
            }
        }
    }
}
