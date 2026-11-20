//! A set of [`Cidr`] blocks with a binary-search lookup: the type `ip_allow_list` and the L4
//! allow list share. It knows nothing about HTTP or sessions.
//!
//! The blocks are merged into sorted, disjoint address ranges per family, so a lookup is one
//! binary search however many blocks overlap, and "does this set cover that block" is one search
//! too. Addresses are normalized before a lookup: an IPv4-mapped IPv6 address is looked up as
//! the IPv4 address, so an IPv4 range cannot be bypassed by writing the address in IPv6.

use std::net::IpAddr;

use ipnet::IpNet;

use super::{Cidr, normalize};

/// Sorted, disjoint, non-adjacent inclusive ranges of one address family.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Ranges(Vec<(u128, u128)>);

impl Ranges {
    fn from_unsorted(mut ranges: Vec<(u128, u128)>) -> Self {
        ranges.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some((_, last_end)) if start <= last_end.saturating_add(1) => {
                    *last_end = (*last_end).max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        Self(merged)
    }

    /// Whether `start..=end` lies inside one merged range, which is where every address of it
    /// is in the set (adjacent ranges are merged, so none can straddle two).
    fn covers(&self, start: u128, end: u128) -> bool {
        let after = self.0.partition_point(|(from, _)| *from <= start);
        after > 0 && self.0.get(after - 1).is_some_and(|(_, to)| *to >= end)
    }
}

/// The set of addresses in some of a list of blocks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CidrSet {
    v4: Ranges,
    v6: Ranges,
    blocks: Box<[Cidr]>,
}

/// The first and last address of a block as integers of its family.
fn span(net: &IpNet) -> (u128, u128) {
    match net {
        IpNet::V4(v4) => (
            u128::from(u32::from(v4.network())),
            u128::from(u32::from(v4.broadcast())),
        ),
        IpNet::V6(v6) => (u128::from(v6.network()), u128::from(v6.broadcast())),
    }
}

fn point(addr: IpAddr) -> (bool, u128) {
    match addr {
        IpAddr::V4(v4) => (true, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (false, u128::from(v6)),
    }
}

impl CidrSet {
    /// The set of every address in any of `blocks`. An empty list is the empty set.
    #[must_use]
    pub fn new(blocks: impl IntoIterator<Item = Cidr>) -> Self {
        let blocks: Box<[Cidr]> = blocks.into_iter().collect();
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for block in &blocks {
            match block.0 {
                IpNet::V4(_) => v4.push(span(&block.0)),
                IpNet::V6(_) => v6.push(span(&block.0)),
            }
        }
        Self {
            v4: Ranges::from_unsorted(v4),
            v6: Ranges::from_unsorted(v6),
            blocks,
        }
    }

    /// Whether `addr` is in some block. An IPv4-mapped IPv6 address is looked up as IPv4.
    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        let (v4, value) = point(normalize(addr));
        let ranges = if v4 { &self.v4 } else { &self.v6 };
        ranges.covers(value, value)
    }

    /// Whether every address of `block` is in the set, however many blocks it takes to cover it.
    #[must_use]
    pub fn covers(&self, block: &Cidr) -> bool {
        let (start, end) = span(&block.0);
        let ranges = match block.0 {
            IpNet::V4(_) => &self.v4,
            IpNet::V6(_) => &self.v6,
        };
        ranges.covers(start, end)
    }

    /// Whether every address of `other` is in this set: no block of `other` lets in an address
    /// this set does not.
    #[must_use]
    pub fn covers_all(&self, other: &Self) -> bool {
        other.blocks.iter().all(|block| self.covers(block))
    }

    /// The blocks the set was built from, in the order given.
    #[must_use]
    pub fn blocks(&self) -> &[Cidr] {
        &self.blocks
    }

    /// Whether the set has no block.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn set(blocks: &[&str]) -> CidrSet {
        CidrSet::new(blocks.iter().map(|text| text.parse().expect("block")))
    }

    #[test]
    fn cidr_set_contains() {
        let set = set(&[
            "10.0.0.0/8",
            "192.168.1.5",
            "2001:db8::/32",
            "fd00::1",
            "10.1.0.0/16",
        ]);
        for inside in [
            "10.0.0.0",
            "10.255.255.255",
            "10.1.2.3",
            "192.168.1.5",
            "2001:db8::1",
            "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
            "fd00::1",
        ] {
            assert!(set.contains(ip(inside)), "{inside}");
        }
        for outside in [
            "9.255.255.255",
            "11.0.0.0",
            "192.168.1.4",
            "192.168.1.6",
            "2001:db9::",
            "2001:db7:ffff::",
            "fd00::2",
            "::1",
        ] {
            assert!(!set.contains(ip(outside)), "{outside}");
        }
        assert!(!CidrSet::default().contains(ip("10.0.0.1")));
        assert!(CidrSet::default().is_empty());
        let everyone = self::set(&["0.0.0.0/0", "::/0"]);
        assert!(everyone.contains(ip("203.0.113.9")) && everyone.contains(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_set_normalizes() {
        let set = set(&["10.0.0.0/8", "::ffff:192.0.2.0/120", "2001:db8::/32"]);
        assert!(
            set.contains(ip("::ffff:10.9.9.9")),
            "mapped address, IPv4 block"
        );
        assert!(set.contains(ip("192.0.2.77")), "IPv4 address, mapped block");
        assert!(set.contains(ip("::ffff:192.0.2.77")));
        assert!(!set.contains(ip("::ffff:11.0.0.1")));
        assert!(
            !set.contains(ip("::a00:1")),
            "an IPv4-compatible address is not IPv4"
        );
        assert_eq!(set.blocks().len(), 3);
        assert_eq!(set.blocks()[1].to_string(), "192.0.2.0/24");
    }

    #[test]
    fn cidr_set_covers_blocks_across_adjacent_ranges() {
        let set = set(&["10.0.0.0/25", "10.0.0.128/25", "2001:db8::/33"]);
        let block = |text: &str| text.parse::<Cidr>().expect("block");
        assert!(
            set.covers(&block("10.0.0.0/24")),
            "two halves cover the whole"
        );
        assert!(set.covers(&block("10.0.0.64/26")));
        assert!(!set.covers(&block("10.0.0.0/23")));
        assert!(!set.covers(&block("10.0.1.0/24")));
        assert!(set.covers(&block("2001:db8:1::/48")));
        assert!(!set.covers(&block("2001:db8::/32")));
        assert!(!set.covers(&block("::ffff:0:0/96")));
        assert!(self::set(&["10.0.0.0/8"]).covers_all(&self::set(&["10.1.0.0/16", "10.2.3.4"])));
        assert!(!self::set(&["10.1.0.0/16"]).covers_all(&self::set(&["10.1.0.0/16", "10.2.3.4"])));
        assert!(set.covers_all(&CidrSet::default()));
    }
}
