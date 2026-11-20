//! The index that finds the routers able to match a request.
//!
//! Routers with literal hosts are found by hash lookup of the exact host and of the wildcard
//! above it. Fallbacks (`host_regexp` or no host) sit in one short list. A request sees the
//! literal buckets first and then the fallbacks its host is open to; see the module docs of
//! [`crate::router`] for the rules that make that safe across tenants.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::{Key, Matched, Tier, View};
use crate::host::HostPattern;
use crate::table::CompiledApp;

/// A router by position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ref {
    app: u32,
    router: u32,
}

/// How a candidate was found, which decides its host rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via<'a> {
    /// The request host equals this exact name.
    Exact(&'a str),
    /// The request host is one label under this wildcard base.
    Wildcard(&'a str),
    /// A fallback with a `host_regexp`.
    Regexp,
    /// A fallback with no host constraint.
    Hostless,
}

impl Via<'_> {
    pub(super) fn rank(&self) -> u8 {
        match self {
            Self::Exact(_) => 3,
            Self::Wildcard(_) => 2,
            Self::Regexp => 1,
            Self::Hostless => 0,
        }
    }

    /// The declared host pattern that matched (`a.test` or `*.a.test`), `None` for a fallback.
    #[must_use]
    pub fn pattern(&self) -> Option<String> {
        match self {
            Self::Exact(name) => Some((*name).to_owned()),
            Self::Wildcard(base) => Some(format!("*.{base}")),
            Self::Regexp | Self::Hostless => None,
        }
    }

    /// `exact`, `wildcard`, `regexp` or `none`.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Exact(_) => "exact",
            Self::Wildcard(_) => "wildcard",
            Self::Regexp => "regexp",
            Self::Hostless => "none",
        }
    }
}

/// One router that matches a request, with its order.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'v> {
    /// Where it is.
    pub matched: Matched,
    /// Its order; larger wins.
    pub key: Key,
    /// How it was found.
    pub via: Via<'v>,
}

/// Routers of all apps, by host.
#[derive(Debug, Default)]
pub struct Index {
    exact: HashMap<Box<str>, Vec<Ref>>,
    wildcard: HashMap<Box<str>, Vec<Ref>>,
    fallback: Vec<Ref>,
}

fn position(index: usize) -> u32 {
    u32::try_from(index).unwrap_or(u32::MAX)
}

impl Index {
    /// Indexes the routers of `apps`.
    #[must_use]
    pub fn build(apps: &[CompiledApp]) -> Self {
        let mut index = Self::default();
        for (app_index, app) in apps.iter().enumerate() {
            for (router_index, router) in app.routers().iter().enumerate() {
                let at = Ref {
                    app: position(app_index),
                    router: position(router_index),
                };
                if router.tier() != Tier::Literal {
                    index.fallback.push(at);
                    continue;
                }
                for pattern in router.patterns() {
                    let bucket = match pattern {
                        HostPattern::Exact(name) => index.exact.entry(name.clone()).or_default(),
                        HostPattern::Wildcard(base) => {
                            index.wildcard.entry(base.clone()).or_default()
                        }
                    };
                    if bucket.last() != Some(&at) {
                        bucket.push(at);
                    }
                }
            }
        }
        index
    }

    /// The routers with a literal claim on `host`: its exact bucket, then the wildcard above it.
    fn literal<'a>(&'a self, host: &str) -> impl Iterator<Item = &'a Ref> + use<'a> {
        let exact = self.exact.get(host);
        let wildcard = host
            .split_once('.')
            .and_then(|(_, base)| self.wildcard.get(base));
        exact.into_iter().chain(wildcard).flatten()
    }

    /// The tenant that claims `host` with a literal host, if any. A compiled table has at most
    /// one: two tenants never share a literal claim, or a claim under the other's wildcard.
    #[must_use]
    pub fn claimant<'a>(&self, apps: &'a [CompiledApp], host: &str) -> Option<&'a str> {
        self.literal(host)
            .find_map(|at| apps.get(at.app as usize).map(CompiledApp::tenant))
    }

    /// The apps whose routers may serve `host`: those with a literal claim on it (exact name or
    /// wildcard) and every app with a fallback router. A superset of what a match can pick.
    pub fn may_serve<'a>(
        &'a self,
        apps: &'a [CompiledApp],
        host: &str,
    ) -> impl Iterator<Item = &'a CompiledApp> {
        self.literal(host)
            .chain(self.fallback.iter())
            .filter_map(|at| apps.get(at.app as usize))
    }

    /// Calls `found` for every router that matches `view` and may serve it, in no order.
    pub fn scan<'v>(
        &self,
        apps: &[CompiledApp],
        view: &View<'v>,
        found: &mut impl FnMut(Candidate<'v>),
    ) {
        let mut check = |at: &Ref, via: Via<'v>| {
            let Some(app) = apps.get(at.app as usize) else {
                return;
            };
            let Some(router) = app.routers().get(at.router as usize) else {
                return;
            };
            if router.listens_on(view.entry_point) && router.matcher().matches(view) {
                found(Candidate {
                    matched: Matched {
                        app: at.app as usize,
                        router: at.router as usize,
                    },
                    key: router.key(&via),
                    via,
                });
            }
        };
        for at in self.exact.get(view.host).into_iter().flatten() {
            check(at, Via::Exact(view.host));
        }
        if let Some((base, refs)) = view
            .host
            .split_once('.')
            .and_then(|(_, base)| self.wildcard.get(base).map(|refs| (base, refs)))
        {
            for at in refs {
                check(at, Via::Wildcard(base));
            }
        }
        if self.fallback.is_empty() {
            return;
        }
        let claimant = self.claimant(apps, view.host);
        for at in &self.fallback {
            let Some(app) = apps.get(at.app as usize) else {
                continue;
            };
            let Some(router) = app.routers().get(at.router as usize) else {
                continue;
            };
            let open =
                router.is_unrestricted() || claimant.is_none_or(|tenant| tenant == app.tenant());
            if !open {
                continue;
            }
            let via = if router.tier() == Tier::Regexp {
                Via::Regexp
            } else {
                Via::Hostless
            };
            check(at, via);
        }
    }

    /// The router that wins for `view`, if any matches.
    #[must_use]
    pub fn find(&self, apps: &[CompiledApp], view: &View<'_>) -> Option<Matched> {
        let mut best: Option<(Candidate<'_>, (&str, &str))> = None;
        self.scan(apps, view, &mut |candidate| {
            let names = names(apps, candidate.matched);
            let wins = best.as_ref().is_none_or(|(held, held_names)| {
                candidate.key.cmp_with(names, held.key, *held_names) == Ordering::Greater
            });
            if wins {
                best = Some((candidate, names));
            }
        });
        best.map(|(candidate, _)| candidate.matched)
    }

    /// Every router that matches `view`, best first: what explain shows.
    #[must_use]
    pub fn find_all<'v>(&self, apps: &[CompiledApp], view: &View<'v>) -> Vec<Candidate<'v>> {
        let mut all = Vec::new();
        self.scan(apps, view, &mut |candidate| all.push(candidate));
        all.sort_by(|a, b| {
            b.key
                .cmp_with(names(apps, b.matched), a.key, names(apps, a.matched))
        });
        all
    }

    /// The declared wildcard nearest to `host`, for explaining a miss: the wildcard whose base
    /// is the longest suffix of `host`, the whole host counting as a suffix of itself, so
    /// `p.q.a.test` and `a.test` are both nearest to `*.a.test`.
    #[must_use]
    pub fn nearest_wildcard(&self, host: &str) -> Option<String> {
        let mut suffix = host;
        loop {
            if self.wildcard.contains_key(suffix) {
                return Some(format!("*.{suffix}"));
            }
            suffix = suffix.split_once('.')?.1;
        }
    }
}

fn names(apps: &[CompiledApp], matched: Matched) -> (&str, &str) {
    apps.get(matched.app).map_or(("", ""), |app| {
        (
            app.id(),
            app.routers()
                .get(matched.router)
                .map_or("", |router| router.name()),
        )
    })
}
