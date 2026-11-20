//! TCP and UDP routing (layer 4). The model is in [`podgate_model::Tcp`] and
//! [`podgate_model::Udp`]; the runtime is not built. Pingora has no UDP support and no L4
//! router, so these will run as podgate's own services on tokio; their specs read
//! `pingora-core` before promising what TCP gives for free.
//!
//! Until then [`reject`] refuses a snapshot that carries any L4 router or service with
//! `l4_not_built`, so nothing is silently left unrouted.

mod tcp;
mod udp;

use crate::compile::Invalid;
use podgate_model::App;

/// The refusal for an app that declares L4 routers or services, `None` when it declares none.
#[must_use]
pub fn reject(app: &App) -> Option<Invalid> {
    let tcp = app.tcp.as_ref().is_some_and(|tcp| {
        !(tcp.routers.is_empty() && tcp.services.is_empty() && tcp.middlewares.is_empty())
    });
    let udp = app
        .udp
        .as_ref()
        .is_some_and(|udp| !(udp.routers.is_empty() && udp.services.is_empty()));
    (tcp || udp).then(|| {
        Invalid::new(
            "l4_not_built",
            "TCP and UDP routers and services are planned and not built yet",
        )
    })
}
