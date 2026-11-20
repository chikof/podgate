//! `hrw`: highest random weight (rendezvous hashing) of the client address. Every server scores
//! the client with a keyed hash of the client and the server's address, scaled by its weight
//! (`weight / -ln(u)` for a uniform `u`, so a server of weight 3 wins three times as many
//! clients as one of weight 1), and the best allowed score wins. Removing a server moves only
//! the clients it won; an unavailable server hands each of its clients to that client's second
//! best. The client is the one `ip_hash` uses; a request without one goes to a random available
//! server. A pick costs one hash and one logarithm per server. A server of weight `0` receives
//! nothing.

use super::PickCx;
use super::ip_hash::digest;
use super::ring::{check_weights, fallback};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The rendezvous balancer.
#[derive(Debug, Default)]
pub struct Hrw;

/// The score of a server of `weight` for a client: `hash` read as a number strictly between `0`
/// and `1`.
fn score(hash: u64, weight: u32) -> f64 {
    let top = u32::try_from(hash >> 32).unwrap_or(u32::MAX);
    let unit = (f64::from(top) + 0.5) / 4_294_967_296.0;
    f64::from(weight) / -unit.ln()
}

impl Hrw {
    pub(super) fn compile(servers: &[Server]) -> Result<Self, Invalid> {
        check_weights("hrw", servers)?;
        Ok(Self)
    }

    pub(super) fn pick(
        &self,
        cx: PickCx<'_>,
        servers: &[Server],
        shared: &ServiceState,
    ) -> Option<usize> {
        let Some(client) = cx.client else {
            return fallback(cx, servers, shared);
        };
        let key = digest(client, shared);
        servers
            .iter()
            .enumerate()
            .filter(|(_, server)| server.weight > 0 && cx.allows(server))
            .map(|(index, server)| {
                (
                    index,
                    score(shared.keyed_hash((key, server.addr)), server.weight),
                )
            })
            .fold(None::<(usize, f64)>, |best, (index, score)| match best {
                Some((_, most)) if most >= score => best,
                _ => Some((index, score)),
            })
            .map(|(index, _)| index)
    }
}
