//! What `ip_hash`, `uri_hash`, `header_hash` and `hrw` share: the consistent-hash ring (ketama
//! through `pingora-ketama`), the fallback for a request that has nothing to hash, and the
//! weights rules.
//!
//! A server owns `weight / gcd` times 160 points on the ring, so a server of weight 3 gets three
//! times the keys of weight 1, and the ring is built once per compiled service. A pick hashes the
//! key with the service's secret ([`ServiceState::keyed_hash`]), finds the first point at or
//! after it and walks on to the next point while the server there is not allowed
//! ([`PickCx::allows`]: unhealthy, ejected or already tried). Walking to the next point moves only
//! the keys of the server that is out, and they return to it when it recovers. The digest is
//! secret-keyed because ketama's own hash (CRC-32) is not: with it a client could pick paths or
//! header values that all land on one server of the app.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use pingora_ketama::{Bucket, Continuum, DEFAULT_POINT_MULTIPLE};

use super::{PickCx, below, weighted_round_robin::gcd};
use crate::compile::Invalid;
use crate::service::{Server, ServiceState};

/// The most weight a ring may hold, after dividing the weights by their greatest common divisor:
/// 256 servers of weight 1 (the most a service declares) fill it. A ring of 256 weight units has
/// 40 960 points, 320 KiB, and building it costs about twice that for a moment.
const MAX_WEIGHT: u64 = 256;

/// The most ring points one tenant's hash services may hold together, over every app and every
/// revision it declares (a service declared in three revisions is compiled, and counted, three
/// times). 1 048 576 points are 8 MiB (8 bytes a point): about 25 services of the most weight
/// a service may have, or 2 000 services of three servers.
const MAX_TENANT_POINTS: u64 = 1_048_576;

/// The most ring points one snapshot may hold in all: 32 MiB, the memory a push can make the
/// proxy build however many tenants it names.
const MAX_SNAPSHOT_POINTS: u64 = 4_194_304;

/// The ring points the services compiled so far for one snapshot hold, per tenant and in all.
/// The compile pass charges every hash service as it is built, so a snapshot that asks for more
/// than the caps is refused after at most one service over them, never after building them all.
#[derive(Debug, Default)]
pub(crate) struct RingBudget {
    total: u64,
    tenants: HashMap<Box<str>, u64>,
    refused: bool,
}

impl RingBudget {
    /// Whether a charge was refused: the snapshot is rejected and building more rings is waste.
    pub(crate) fn refused(&self) -> bool {
        self.refused
    }

    /// Charges a service of `tenant` that holds `points` ring points.
    ///
    /// # Errors
    ///
    /// `invalid_service`, naming the tenant, the points asked and the cap, when the tenant's
    /// hash services or the snapshot's together would hold more than the caps.
    pub(crate) fn charge(&mut self, tenant: &str, points: u64) -> Result<(), Invalid> {
        if points == 0 {
            return Ok(());
        }
        let asked = self
            .tenants
            .get(tenant)
            .copied()
            .unwrap_or(0)
            .saturating_add(points);
        let total = self.total.saturating_add(points);
        let refusal = if asked > MAX_TENANT_POINTS {
            Some(format!(
                "tenant {tenant}: its hash services ask for {asked} ring points, at most \
                 {MAX_TENANT_POINTS} are allowed; lower the weights or the servers of hash services"
            ))
        } else if total > MAX_SNAPSHOT_POINTS {
            Some(format!(
                "tenant {tenant}: the snapshot's hash services ask for {total} ring points, at \
                 most {MAX_SNAPSHOT_POINTS} are allowed in all"
            ))
        } else {
            None
        };
        if let Some(why) = refusal {
            self.refused = true;
            return Err(Invalid::new("invalid_service", why));
        }
        self.total = total;
        self.tenants.insert(tenant.into(), asked);
        Ok(())
    }
}

/// The ring of one compiled service.
pub(super) struct Ring {
    continuum: Continuum,
    /// The points on the ring: a walk never takes more steps than this.
    points: usize,
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ring")
            .field("points", &self.points)
            .finish_non_exhaustive()
    }
}

/// The weights of `servers`, merged by address, divided by their greatest common divisor, and
/// without the servers of weight `0`, which receive nothing.
///
/// # Errors
///
/// `invalid_service` when every weight is `0` or the weights add up to more than [`MAX_WEIGHT`].
fn weights(algorithm: &str, servers: &[Server]) -> Result<Vec<(SocketAddr, u32)>, Invalid> {
    check_weights(algorithm, servers)?;
    let divisor = servers
        .iter()
        .fold(0, |divisor, server| gcd(divisor, u64::from(server.weight)));
    let mut merged: Vec<(SocketAddr, u32)> = Vec::with_capacity(servers.len());
    for server in servers.iter().filter(|server| server.weight > 0) {
        let share = u64::from(server.weight)
            .checked_div(divisor)
            .and_then(|share| u32::try_from(share).ok())
            .unwrap_or(u32::MAX);
        match merged.iter_mut().find(|(addr, _)| *addr == server.addr) {
            Some((_, weight)) => *weight = weight.saturating_add(share),
            None => merged.push((server.addr, share)),
        }
    }
    let total: u64 = merged.iter().map(|(_, weight)| u64::from(*weight)).sum();
    if total > MAX_WEIGHT {
        return Err(Invalid::new(
            "invalid_service",
            format!(
                "{algorithm}: the weights add up to {total} after dividing by their common \
                 divisor, which is more than {MAX_WEIGHT}; scale them down"
            ),
        ));
    }
    Ok(merged)
}

/// Checks the weights of `servers` for an algorithm that picks by them without a ring (`hrw`):
/// the rules of [`Ring::compile`] without building anything.
///
/// # Errors
///
/// `invalid_service` when every server has weight `0`.
pub(super) fn check_weights(algorithm: &str, servers: &[Server]) -> Result<(), Invalid> {
    if servers.is_empty() || servers.iter().any(|server| server.weight > 0) {
        Ok(())
    } else {
        Err(Invalid::new(
            "invalid_service",
            format!("{algorithm}: every server has weight 0, so none could receive a request"),
        ))
    }
}

impl Ring {
    /// The ring of `servers` for `algorithm` (named in the error messages).
    ///
    /// # Errors
    ///
    /// `invalid_service` when the weights are all `0` or add up to too much.
    pub(super) fn compile(algorithm: &str, servers: &[Server]) -> Result<Self, Invalid> {
        if servers.is_empty() {
            return Ok(Self {
                continuum: Continuum::new(&[]),
                points: 0,
            });
        }
        let weights = weights(algorithm, servers)?;
        let total: u64 = weights.iter().map(|(_, weight)| u64::from(*weight)).sum();
        let buckets: Vec<Bucket> = weights
            .iter()
            .map(|(addr, weight)| Bucket::new(*addr, *weight))
            .collect();
        Ok(Self {
            continuum: Continuum::new(&buckets),
            points: usize::try_from(total * u64::from(DEFAULT_POINT_MULTIPLE)).unwrap_or(0),
        })
    }

    /// The points on the ring, what [`RingBudget`] charges.
    pub(super) fn points(&self) -> u64 {
        u64::try_from(self.points).unwrap_or(u64::MAX)
    }

    /// The index in `servers` of the first server at or after the point `digest` hashes to that
    /// `cx` allows; `None` when none is left. `servers` must be the list the ring was built from.
    pub(super) fn pick(&self, digest: u64, cx: PickCx<'_>, servers: &[Server]) -> Option<usize> {
        let key = digest.to_le_bytes();
        let mut checked = false;
        for addr in self.continuum.node_iter(&key).take(self.points) {
            let Some(index) = servers.iter().position(|server| server.addr == *addr) else {
                continue;
            };
            if servers.get(index).is_some_and(|server| cx.allows(server)) {
                return Some(index);
            }
            // The first refusal is the only moment to ask whether anyone is left: a walk around
            // the whole ring costs a request its time, and a service whose servers are all down
            // must not make every request pay it.
            if !checked {
                checked = true;
                if !servers
                    .iter()
                    .any(|server| server.weight > 0 && cx.allows(server))
                {
                    return None;
                }
            }
        }
        None
    }
}

/// A random allowed server with a weight above `0`, for a request that has nothing to hash.
pub(super) fn fallback(cx: PickCx<'_>, servers: &[Server], shared: &ServiceState) -> Option<usize> {
    let takes = |server: &Server| server.weight > 0 && cx.allows(server);
    let allowed = servers.iter().filter(|server| takes(server)).count();
    if allowed == 0 {
        return None;
    }
    let nth = below(shared.random(), allowed);
    servers
        .iter()
        .enumerate()
        .filter(|(_, server)| takes(server))
        .nth(nth)
        .map(|(index, _)| index)
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;

    use pingora::http::RequestHeader;
    use serde_json::{Value, json};

    use super::super::test_support::{servers, weighted};
    use super::*;
    use crate::service::lb::Balancer;

    const HASHING: [&str; 4] = ["ip_hash", "uri_hash", "header_hash", "hrw"];

    fn compile(name: &str, servers: &[Server]) -> Balancer {
        let algorithm: Value = match name {
            "header_hash" => json!({ "type": "header_hash", "header": "x-key" }),
            other => json!(other),
        };
        Balancer::compile(Some(&algorithm), servers).expect("compiles")
    }

    /// The request of key `n`: its path, its `x-key` header and its client address.
    fn key(n: u32) -> (RequestHeader, IpAddr) {
        let mut request =
            RequestHeader::build("GET", format!("/p/{n}").as_bytes(), None).expect("request");
        request
            .insert_header("x-key", format!("k{n}"))
            .expect("header");
        let [_, a, b, c] = n.to_be_bytes();
        (request, [10, a, b, c].into())
    }

    fn pick(
        balancer: &Balancer,
        servers: &[Server],
        shared: &ServiceState,
        n: u32,
    ) -> Option<usize> {
        let (request, client) = key(n);
        let cx = PickCx::new(&request).with_client(Some(client));
        balancer.pick(cx, servers, shared)
    }

    fn picks(balancer: &Balancer, servers: &[Server], shared: &ServiceState) -> Vec<Option<usize>> {
        picks_of(balancer, servers, shared, 2000)
    }

    fn picks_of(
        balancer: &Balancer,
        servers: &[Server],
        shared: &ServiceState,
        count: u32,
    ) -> Vec<Option<usize>> {
        (0..count)
            .map(|n| pick(balancer, servers, shared, n))
            .collect()
    }

    #[test]
    fn hash_minimal_disruption_on_removal() {
        const N: usize = 10;
        let shared = ServiceState::default();
        for name in HASHING {
            let all = servers(10);
            let fewer = servers(9);
            let before = picks(&compile(name, &all), &all, &shared);
            let after = picks(&compile(name, &fewer), &fewer, &shared);
            let mut kept = 0;
            for (old, new) in before.iter().zip(&after) {
                if *old == Some(N - 1) {
                    assert_ne!(*new, Some(N - 1), "{name}");
                } else {
                    // A key that did not live on the removed server stays where it was.
                    assert_eq!(old, new, "{name}");
                    kept += 1;
                }
            }
            assert!(kept * N >= before.len() * (N - 2), "{name}: kept {kept}");
            // Each server holds a share of the keys: the ring is not lopsided.
            for index in 0..N {
                let held = before.iter().filter(|pick| **pick == Some(index)).count();
                assert!(
                    (100..=320).contains(&held),
                    "{name}: server {index} holds {held}"
                );
            }
        }
    }

    #[test]
    fn hash_skips_unhealthy_and_returns() {
        let shared = ServiceState::default();
        for name in HASHING {
            let up = servers(8);
            let balancer = compile(name, &up);
            let before = picks(&balancer, &up, &shared);
            let down = up.first().expect("a server");
            down.state.healthy.store(false, Ordering::Relaxed);
            let during = picks(&balancer, &up, &shared);
            for (old, new) in before.iter().zip(&during) {
                if *old == Some(0) {
                    assert!(new.is_some() && *new != Some(0), "{name}: {new:?}");
                } else {
                    assert_eq!(old, new, "{name}: a key of a healthy server moved");
                }
            }
            down.state.healthy.store(true, Ordering::Relaxed);
            assert_eq!(before, picks(&balancer, &up, &shared), "{name}");
        }
    }

    #[test]
    fn hash_finds_nothing_when_every_server_is_out() {
        let shared = ServiceState::default();
        for name in HASHING {
            let up = servers(8);
            for server in &up {
                server.state.healthy.store(false, Ordering::Relaxed);
            }
            let balancer = compile(name, &up);
            assert_eq!(pick(&balancer, &up, &shared, 1), None, "{name}");
        }
    }

    #[test]
    fn hash_follows_the_retry_exclusion() {
        let shared = ServiceState::default();
        for name in HASHING {
            let up = servers(8);
            let balancer = compile(name, &up);
            let (request, client) = key(77);
            let first = balancer
                .pick(
                    PickCx::new(&request).with_client(Some(client)),
                    &up,
                    &shared,
                )
                .expect("a server");
            let tried = [up[first].addr];
            let cx = PickCx {
                request: &request,
                excluded: &tried,
                client: Some(client),
            };
            let second = balancer.pick(cx, &up, &shared).expect("another server");
            assert_ne!(first, second, "{name}");
        }
    }

    #[test]
    fn hrw_respects_weights() {
        let up = weighted(&[1, 3]);
        let shared = ServiceState::default();
        let balancer = compile("hrw", &up);
        let picks = picks_of(&balancer, &up, &shared, 50_000);
        let light = picks.iter().filter(|pick| **pick == Some(0)).count();
        let heavy = picks.iter().filter(|pick| **pick == Some(1)).count();
        assert_eq!(light + heavy, picks.len());
        let ratio = heavy as f64 / light as f64;
        assert!((2.6..=3.5).contains(&ratio), "{light} against {heavy}");
    }

    #[test]
    fn ring_respects_weights_and_skips_weight_zero() {
        let up = weighted(&[1, 3, 0]);
        let shared = ServiceState::default();
        for name in ["ip_hash", "uri_hash", "header_hash", "hrw"] {
            let balancer = compile(name, &up);
            let picks = picks_of(&balancer, &up, &shared, 50_000);
            let count = |index| picks.iter().filter(|pick| **pick == Some(index)).count();
            assert_eq!(count(2), 0, "{name}: weight 0 receives nothing");
            let ratio = count(1) as f64 / count(0) as f64;
            assert!((2.2..=4.0).contains(&ratio), "{name}: {ratio}");
        }
    }

    #[test]
    fn hash_weights_are_checked() {
        for name in HASHING {
            let all_zero = weighted(&[0, 0]);
            let algorithm = match name {
                "header_hash" => json!({ "type": "header_hash", "header": "x-key" }),
                other => json!(other),
            };
            let err = Balancer::compile(Some(&algorithm), &all_zero).expect_err("refused");
            assert_eq!(err.code, "invalid_service", "{name}");
        }
        // Weights are divided by their common divisor first, so 1000 and 3000 are fine and
        // 1 and 2000 are not.
        assert!(Ring::compile("ip_hash", &weighted(&[1000, 3000])).is_ok());
        let err = Ring::compile("ip_hash", &weighted(&[1, 2000])).expect_err("too much");
        assert_eq!(err.code, "invalid_service");
    }

    #[test]
    fn ip_hash_groups_an_ipv6_client_by_its_prefix_and_keys_the_hash() {
        let up = servers(8);
        let balancer = compile("ip_hash", &up);
        let shared = ServiceState::default();
        let (request, _) = key(1);
        let at = |client: &str| {
            let cx = PickCx::new(&request).with_client(Some(client.parse().expect("address")));
            balancer.pick(cx, &up, &shared)
        };
        assert_eq!(at("2001:db8:1:2::1"), at("2001:db8:1:2:ffff::9"));
        let moved = (0..64)
            .filter(|n| at(&format!("2001:db8:1:{n}::1")) != at("2001:db8:1:0::1"))
            .count();
        assert!(moved > 0, "other prefixes spread out");

        // The key is the service's secret: another service maps the same clients differently.
        let other = ServiceState::default();
        let differing = (0..200)
            .filter(|n| pick(&balancer, &up, &shared, *n) != pick(&balancer, &up, &other, *n))
            .count();
        assert!(
            differing > 100,
            "{differing} of 200 keys differ between secrets"
        );
    }

    #[test]
    fn hash_without_a_key_falls_back_to_a_random_server() {
        let up = servers(4);
        let shared = ServiceState::default();
        let request = RequestHeader::build("GET", b"/", None).expect("request");
        for name in ["ip_hash", "hrw", "header_hash"] {
            let balancer = compile(name, &up);
            let mut seen = [0_u32; 4];
            for _ in 0..400 {
                let index = balancer
                    .pick(PickCx::new(&request), &up, &shared)
                    .expect("a server");
                seen[index] += 1;
            }
            assert!(seen.iter().all(|count| *count > 50), "{name}: {seen:?}");
        }
    }

    #[test]
    fn uri_hash_leaves_the_query_out_unless_asked() {
        let up = servers(8);
        let shared = ServiceState::default();
        let plain = Balancer::compile(Some(&json!("uri_hash")), &up).expect("uri_hash");
        let queried = Balancer::compile(
            Some(&json!({ "type": "uri_hash", "include_query": true })),
            &up,
        )
        .expect("uri_hash");
        let request =
            |target: String| RequestHeader::build("GET", target.as_bytes(), None).expect("request");
        let (mut same, mut differ) = (0, 0);
        for n in 0..100 {
            let bare = request(format!("/p/{n}"));
            let with = request(format!("/p/{n}?v=1"));
            let pick = |balancer: &Balancer, request: &RequestHeader| {
                balancer.pick(PickCx::new(request), &up, &shared)
            };
            assert_eq!(pick(&plain, &bare), pick(&plain, &with));
            if pick(&queried, &bare) == pick(&queried, &with) {
                same += 1;
            } else {
                differ += 1;
            }
        }
        assert!(
            differ > same,
            "the query is hashed: {differ} differ, {same} same"
        );
    }

    #[test]
    fn ring_points_follow_the_weights_and_the_budget_refuses_past_its_caps() {
        let ring = Ring::compile("ip_hash", &weighted(&[255, 1])).expect("at the cap");
        assert_eq!(ring.points(), 256 * 160);
        assert!(Ring::compile("ip_hash", &weighted(&[256, 1])).is_err());
        assert_eq!(Ring::compile("ip_hash", &[]).expect("empty").points(), 0);

        let mut budget = RingBudget::default();
        let service = 256 * 160;
        for _ in 0..25 {
            assert!(budget.charge("t1", service).is_ok());
        }
        let err = budget.charge("t1", service).expect_err("26th service");
        assert!(
            err.message.contains("tenant t1") && err.message.contains("1064960"),
            "{}",
            err.message
        );
        assert!(budget.refused());
        let mut spread = RingBudget::default();
        for tenant in ["a", "b", "c", "d"] {
            for _ in 0..25 {
                assert!(spread.charge(tenant, service).is_ok());
            }
        }
        assert!(spread.charge("e", service).is_ok());
        assert!(spread.charge("e", service).is_ok());
        assert!(spread.charge("e", service).is_err(), "the snapshot's cap");
        assert!(RingBudget::default().charge("t", 0).is_ok());
    }
}
