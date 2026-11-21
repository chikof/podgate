//! Which zone a challenge name belongs to, and whose name it is.
//!
//! Both checks run before anything is published. A name outside every configured zone is
//! `no_solver`, never guessed. A name whose base domain no tenant of the requesting app owns is
//! `foreign_name`: a solver that published whatever it is asked would let a tenant write TXT
//! records into the operator's DNS.

use super::DnsError;
use crate::acme::Claims;
use crate::trust::{HostPattern, Trust};

/// Every ACME challenge name starts with this label.
const PREFIX: &str = "_acme-challenge.";

/// `name` in the form zones are compared in: lowercase, no trailing dot.
pub(super) fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The domain a challenge name proves: `example.com` for `_acme-challenge.example.com`.
pub(super) fn base_domain(name: &str) -> Option<&str> {
    name.strip_prefix(PREFIX).filter(|base| !base.is_empty())
}

/// The index of the zone with the longest name that `name` equals or lies under. `names` are
/// the zones' normalized names.
pub(super) fn longest_suffix<'a>(
    names: impl IntoIterator<Item = &'a str>,
    name: &str,
) -> Option<usize> {
    names
        .into_iter()
        .enumerate()
        .filter(|(_, zone)| {
            name == *zone
                || name
                    .strip_suffix(zone)
                    .is_some_and(|head| head.ends_with('.'))
        })
        .max_by_key(|(_, zone)| zone.len())
        .map(|(at, _)| at)
}

/// Whether the app that wants a certificate for `base` belongs to a tenant that owns it.
///
/// The challenge carries no app, so the apps of `claims` are searched: one must claim `base` or
/// `*.base` (the two hosts whose challenge is `_acme-challenge.<base>`) and its tenant's
/// configured `hosts` must cover the claim, the rule the merge applied to the app.
pub(super) fn check_owner(
    trust: &Trust,
    claims: &Claims,
    name: &str,
    base: &str,
) -> Result<(), DnsError> {
    let foreign = |why: &str| DnsError::ForeignName {
        name: name.into(),
        why: why.into(),
    };
    let Ok(exact @ HostPattern::Exact(_)) = HostPattern::parse(base) else {
        return Err(foreign("the challenge name does not name a host"));
    };
    let wildcard = HostPattern::Wildcard(base.into());
    let mut claimed = false;
    for app in &claims.apps {
        for pattern in app
            .hosts
            .iter()
            .filter(|pattern| **pattern == exact || **pattern == wildcard)
        {
            claimed = true;
            let allowed = trust
                .lookup(&app.tenant)
                .and_then(|tenant| trust.check_host(tenant, pattern));
            if allowed.is_ok() {
                return Ok(());
            }
        }
    }
    Err(foreign(if claimed {
        "the tenant of the app that claims it does not own the domain"
    } else {
        "no app claims the domain"
    }))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn the_longest_zone_wins_and_labels_must_align() {
        let zones = ["example.com", "dev.example.com", "ample.com"];
        let pick = |name| longest_suffix(zones, name);
        assert_eq!(pick("_acme-challenge.dev.example.com"), Some(1));
        assert_eq!(pick("_acme-challenge.example.com"), Some(0));
        assert_eq!(pick("example.com"), Some(0));
        assert_eq!(pick("notexample.com"), None);
        assert_eq!(pick("_acme-challenge.example.org"), None);
    }

    #[test]
    fn the_base_domain_is_what_follows_the_challenge_label() {
        assert_eq!(base_domain("_acme-challenge.a.test"), Some("a.test"));
        assert_eq!(base_domain("_acme-challenge."), None);
        assert_eq!(base_domain("a.test"), None);
        assert_eq!(normalize("A.Test."), "a.test");
    }
}
