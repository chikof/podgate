//! Per-tenant resource budgets: how many requests a tenant may have in flight and how many bytes
//! of proxy memory it may buffer.
//!
//! [`Budgets`] is the registry, keyed by tenant id. It outlives snapshot swaps, so a tenant's
//! usage carries across a deploy; the limits are refreshed from the live table each time a
//! request looks the tenant up ([`Budgets::tenant`]).
//!
//! Both resources are charged before they are used and released by an RAII guard:
//!
//! - [`TenantBudget::admit`] takes an in-flight slot, held by an [`TenantSlot`].
//! - [`TenantBudget::reserve`] takes buffer bytes, held by a [`BufferGuard`]. A caller reserves
//!   *before* it allocates, so usage can never exceed the limit, not even briefly.
//!
//! A charge that does not fit fails. The caller decides what that means: admission answers
//! `503`, compression serves the response uncompressed.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::error::AppError;
use crate::snapshot::Budget;
use crate::table::RoutingTable;

/// The budget and the live usage of one tenant.
#[derive(Debug)]
pub struct TenantBudget {
    max_inflight: AtomicU32,
    max_buffer_bytes: AtomicU64,
    inflight: AtomicU32,
    buffered: AtomicU64,
    peak_buffered: AtomicU64,
    rejected: AtomicU64,
    degraded: AtomicU64,
}

impl TenantBudget {
    fn new(limits: Budget) -> Self {
        Self {
            max_inflight: AtomicU32::new(limits.max_inflight),
            max_buffer_bytes: AtomicU64::new(limits.max_buffer_bytes),
            inflight: AtomicU32::new(0),
            buffered: AtomicU64::new(0),
            peak_buffered: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            degraded: AtomicU64::new(0),
        }
    }

    fn set_limits(&self, limits: Budget) {
        self.max_inflight
            .store(limits.max_inflight, Ordering::Relaxed);
        self.max_buffer_bytes
            .store(limits.max_buffer_bytes, Ordering::Relaxed);
    }

    /// Takes an in-flight slot, or returns `None` when the tenant is at `max_inflight`. The slot
    /// is returned when the guard drops.
    #[must_use]
    pub fn admit(self: &Arc<Self>) -> Option<TenantSlot> {
        let limit = self.max_inflight.load(Ordering::Relaxed);
        let taken = self
            .inflight
            .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                (now < limit).then_some(now + 1)
            });
        if taken.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(TenantSlot {
            tenant: Arc::clone(self),
        })
    }

    /// Charges `bytes` of buffer memory, or returns `None` when that would pass
    /// `max_buffer_bytes`. Call it before allocating; the charge ends when the guard drops.
    #[must_use]
    pub fn reserve(self: &Arc<Self>, bytes: u64) -> Option<BufferGuard> {
        let limit = self.max_buffer_bytes.load(Ordering::Relaxed);
        let charged = self
            .buffered
            .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                now.checked_add(bytes).filter(|total| *total <= limit)
            });
        match charged {
            Ok(before) => {
                self.peak_buffered
                    .fetch_max(before + bytes, Ordering::Relaxed);
                Some(BufferGuard {
                    tenant: Arc::clone(self),
                    bytes,
                })
            }
            Err(_) => {
                self.degraded.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Requests in flight now.
    #[must_use]
    pub fn inflight(&self) -> u32 {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Buffer bytes charged now.
    #[must_use]
    pub fn buffered(&self) -> u64 {
        self.buffered.load(Ordering::Relaxed)
    }

    /// The most buffer bytes ever charged at once since this process started.
    #[must_use]
    pub fn peak_buffered(&self) -> u64 {
        self.peak_buffered.load(Ordering::Relaxed)
    }
}

/// One in-flight slot of a tenant. Dropping it frees the slot.
#[derive(Debug)]
pub struct TenantSlot {
    tenant: Arc<TenantBudget>,
}

impl TenantSlot {
    /// The tenant this slot is charged to.
    #[must_use]
    pub fn tenant(&self) -> &Arc<TenantBudget> {
        &self.tenant
    }
}

impl Drop for TenantSlot {
    fn drop(&mut self) {
        self.tenant.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Buffer bytes charged to a tenant. Dropping it releases them.
#[derive(Debug)]
pub struct BufferGuard {
    tenant: Arc<TenantBudget>,
    bytes: u64,
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        self.tenant.buffered.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Registry of every tenant's [`TenantBudget`]. Cheap to clone; every clone shares the registry.
///
/// Entries are created on first use and never removed: a tenant that leaves the snapshot costs
/// one small entry until restart. [`Self::render`] hides such an entry once it is idle.
#[derive(Debug, Clone, Default)]
pub struct Budgets {
    tenants: Arc<Mutex<HashMap<Box<str>, Arc<TenantBudget>>>>,
}

impl Budgets {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The budget of tenant `id`, created on first use and set to `limits` (the limits of the
    /// table the caller is serving from) on every call.
    #[must_use]
    pub fn tenant(&self, id: &str, limits: Budget) -> Arc<TenantBudget> {
        let mut tenants = self.tenants.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = tenants.get(id) {
            existing.set_limits(limits);
            return Arc::clone(existing);
        }
        let created = Arc::new(TenantBudget::new(limits));
        tenants.insert(id.into(), Arc::clone(&created));
        created
    }

    /// Prometheus text exposition of every tenant's usage. Tenants the `live` table no longer
    /// declares are listed only while they still hold something.
    #[must_use]
    pub fn render(&self, live: &RoutingTable) -> String {
        let mut rows: Vec<(Box<str>, Arc<TenantBudget>)> = {
            let tenants = self.tenants.lock().unwrap_or_else(PoisonError::into_inner);
            tenants
                .iter()
                .filter(|(id, tenant)| {
                    live.tenant_budget(id).is_some()
                        || tenant.inflight() > 0
                        || tenant.buffered() > 0
                })
                .map(|(id, tenant)| (id.clone(), Arc::clone(tenant)))
                .collect()
        };
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        let mut out = String::new();
        let families = [
            Family {
                name: "podgate_tenant_buffer_bytes",
                kind: "gauge",
                help: "Proxy buffer bytes charged to the tenant now.",
                value: TenantBudget::buffered,
            },
            Family {
                name: "podgate_tenant_buffer_bytes_peak",
                kind: "gauge",
                help: "Most buffer bytes charged to the tenant at once since start.",
                value: TenantBudget::peak_buffered,
            },
            Family {
                name: "podgate_tenant_inflight",
                kind: "gauge",
                help: "Requests the tenant has in flight now.",
                value: |tenant| u64::from(tenant.inflight()),
            },
            Family {
                name: "podgate_tenant_inflight_rejected_total",
                kind: "counter",
                help: "Requests refused with 503 because the tenant was at max_inflight.",
                value: |tenant| tenant.rejected.load(Ordering::Relaxed),
            },
            Family {
                name: "podgate_tenant_compression_skipped_total",
                kind: "counter",
                help: "Responses served uncompressed because the buffer budget was full.",
                value: |tenant| tenant.degraded.load(Ordering::Relaxed),
            },
        ];
        for Family {
            name,
            kind,
            help,
            value,
        } in families
        {
            // Writing to a `String` cannot fail.
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (id, tenant) in &rows {
                let _ = writeln!(
                    out,
                    "{name}{{tenant=\"{}\"}} {}",
                    Escaped(id),
                    value(tenant)
                );
            }
        }
        out
    }
}

/// One metric family of the exposition: its header lines and how to read a tenant's sample.
struct Family {
    name: &'static str,
    kind: &'static str,
    help: &'static str,
    value: fn(&TenantBudget) -> u64,
}

/// A label value with `\`, `"` and newline escaped, as the exposition format requires.
struct Escaped<'a>(&'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in self.0.chars() {
            match ch {
                '\\' => f.write_str("\\\\")?,
                '"' => f.write_str("\\\"")?,
                '\n' => f.write_str("\\n")?,
                other => f.write_char(other)?,
            }
        }
        Ok(())
    }
}

/// Admits a request to the app at index `app` of `table`: takes an in-flight slot of its tenant.
///
/// # Errors
///
/// [`AppError::Overloaded`] (`503`, `retry-after: 1`) when the tenant is at `max_inflight`.
/// An app index the table does not know, or a tenant it does not declare, is let through: a
/// compiled table has neither.
pub fn admit(
    budgets: &Budgets,
    table: &RoutingTable,
    app: usize,
) -> Result<Option<TenantSlot>, AppError> {
    let Some(tenant) = table.app(app).map(|app| app.tenant()) else {
        return Ok(None);
    };
    let Some(limits) = table.tenant_budget(tenant) else {
        return Ok(None);
    };
    budgets
        .tenant(tenant, limits)
        .admit()
        .map(Some)
        .ok_or(AppError::Overloaded)
}

#[cfg(test)]
mod test {
    use super::*;

    fn tenant(max_inflight: u32, max_buffer_bytes: u64) -> Arc<TenantBudget> {
        Budgets::new().tenant(
            "t1",
            Budget {
                max_inflight,
                max_buffer_bytes,
            },
        )
    }

    #[test]
    fn budget_guard_releases_inflight_slots() {
        let tenant = tenant(2, 0);
        let first = tenant.admit().expect("first slot");
        let _second = tenant.admit().expect("second slot");
        assert!(tenant.admit().is_none(), "third slot is over the cap");
        assert_eq!(tenant.inflight(), 2);

        drop(first);
        assert_eq!(tenant.inflight(), 1);
        assert!(tenant.admit().is_some(), "a freed slot is reusable");
    }

    #[test]
    fn budget_guard_charges_before_it_allocates() {
        let tenant = tenant(0, 100);
        let first = tenant.reserve(60).expect("fits");
        assert!(tenant.reserve(41).is_none(), "60 + 41 is over 100");
        assert_eq!(tenant.buffered(), 60, "a refused charge leaves no trace");
        let second = tenant.reserve(40).expect("exactly the rest fits");
        assert_eq!((tenant.buffered(), tenant.peak_buffered()), (100, 100));

        drop(first);
        drop(second);
        assert_eq!(tenant.buffered(), 0);
        assert_eq!(tenant.peak_buffered(), 100, "the peak survives the release");
    }

    #[test]
    fn budget_guard_refuses_overflowing_charges() {
        let tenant = tenant(0, u64::MAX);
        let _held = tenant.reserve(u64::MAX).expect("fits exactly");
        assert!(tenant.reserve(1).is_none());
    }

    #[test]
    fn budget_guard_tenants_survive_limit_changes() {
        let budgets = Budgets::new();
        let limits = |max_inflight| Budget {
            max_inflight,
            max_buffer_bytes: 0,
        };
        let before = budgets.tenant("t1", limits(1));
        let held = before.admit().expect("slot");

        let after = budgets.tenant("t1", limits(1));
        assert!(Arc::ptr_eq(&before, &after), "same tenant, same counters");
        assert!(after.admit().is_none(), "usage carries across a swap");

        let raised = budgets.tenant("t1", limits(2));
        assert!(raised.admit().is_some(), "new limits apply at once");
        drop(held);
    }

    #[test]
    fn budget_guard_never_passes_the_limit_under_contention() {
        let tenant = tenant(0, 1000);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let tenant = Arc::clone(&tenant);
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        if let Some(guard) = tenant.reserve(300) {
                            assert!(tenant.buffered() <= 1000);
                            drop(guard);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("worker finished");
        }
        assert_eq!(tenant.buffered(), 0);
        assert!(tenant.peak_buffered() <= 1000);
    }

    #[test]
    fn budget_guard_render_lists_live_tenants_and_escapes_labels() {
        use crate::snapshot::{Snapshot, Tenant};
        let snapshot = Snapshot {
            version: 1,
            tenants: vec![Tenant {
                id: "a\"b".into(),
                weight: 1,
                budget: Budget {
                    max_inflight: 1,
                    max_buffer_bytes: 10,
                },
            }],
            ..Snapshot::default()
        };
        let table = RoutingTable::compile(&snapshot).expect("compiles");
        let budgets = Budgets::new();
        let live = budgets.tenant("a\"b", table.tenant_budget("a\"b").expect("declared"));
        let _gone = budgets.tenant("gone", table.tenant_budget("a\"b").expect("declared"));
        let _held = live.reserve(7).expect("fits");

        let text = budgets.render(&table);
        assert!(
            text.contains("podgate_tenant_buffer_bytes{tenant=\"a\\\"b\"} 7\n"),
            "{text}"
        );
        assert!(text.contains("podgate_tenant_buffer_bytes_peak{tenant=\"a\\\"b\"} 7\n"));
        assert!(
            !text.contains("gone"),
            "an idle tenant the table dropped is hidden"
        );
    }
}
