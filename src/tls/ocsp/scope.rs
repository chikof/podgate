//! Whose address policy a certificate's responder fetch is held to.
//!
//! A snapshot certificate carries no tenant, and the responder URL inside it is text the
//! certificate's supplier chose. The tenant is therefore derived from the table: the tenants of
//! every app that claims a host the certificate covers. The fetch must pass the policy of each
//! of them, so a certificate shared by two tenants is held to the stricter one. The one
//! certificate that is not tenant-owned is the `default: true` certificate, which the operator
//! sets for names no app owns: it gets the operator's scope, the policy's `default` entry. A
//! certificate that is neither default nor claimed by any app has no owner to hold to, so it is
//! not fetched (`unowned`).

use crate::host::{HostPattern, overlaps};
use crate::table::RoutingTable;

/// The tenant id the operator scope is checked as. The policy has no entry for it, so it gets
/// the `default` entry, which is what the operator wrote for everything not listed.
pub(super) const OPERATOR: &str = "";

/// Whose policy applies to one certificate's fetches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// The operator's own certificate (`default: true`).
    Operator,
    /// A certificate whose hosts these tenants' apps claim: every one must permit the address.
    Tenants(Box<[Box<str>]>),
    /// No app claims the certificate's hosts and it is not the default: not fetched.
    Unowned,
}

impl Scope {
    /// The scope of a certificate declared for `hosts` in `table`.
    #[must_use]
    pub fn of(table: &RoutingTable, hosts: &[Box<str>], default: bool) -> Self {
        if default {
            return Self::Operator;
        }
        let covered: Vec<HostPattern> = hosts
            .iter()
            .filter_map(|host| HostPattern::parse(host).ok())
            .collect();
        let mut tenants: Vec<Box<str>> = Vec::new();
        for app in table.apps() {
            let claims = app
                .hosts()
                .iter()
                .filter_map(|host| HostPattern::parse(host).ok())
                .any(|claim| covered.iter().any(|cover| overlaps(&claim, cover)));
            if claims && !tenants.iter().any(|known| **known == *app.tenant()) {
                tenants.push(app.tenant().into());
            }
        }
        if tenants.is_empty() {
            Self::Unowned
        } else {
            Self::Tenants(tenants.into())
        }
    }

    /// The tenant ids to check an address against; `None` for [`Self::Unowned`].
    #[must_use]
    pub fn tenants(&self) -> Option<Vec<&str>> {
        match self {
            Self::Operator => Some(vec![OPERATOR]),
            Self::Tenants(list) => Some(list.iter().map(AsRef::as_ref).collect()),
            Self::Unowned => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn exact(name: &str) -> HostPattern {
        HostPattern::parse(name).expect("host")
    }

    #[test]
    fn patterns_overlap_by_one_label() {
        assert!(overlaps(&exact("a.test"), &exact("a.test")));
        assert!(!overlaps(&exact("a.test"), &exact("b.test")));
        assert!(overlaps(&exact("x.a.test"), &exact("*.a.test")));
        assert!(overlaps(&exact("*.a.test"), &exact("x.a.test")));
        assert!(!overlaps(&exact("a.test"), &exact("*.a.test")));
        assert!(!overlaps(&exact("x.y.a.test"), &exact("*.a.test")));
        assert!(overlaps(&exact("*.a.test"), &exact("*.a.test")));
        assert!(!overlaps(&exact("*.a.test"), &exact("*.b.test")));
    }
}
