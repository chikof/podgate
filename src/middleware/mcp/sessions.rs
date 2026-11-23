//! The session table of the MCP gateway.
//!
//! A session starts with the client's `initialize` and is named by the `Mcp-Session-Id` the
//! gateway returns. It is bound to the tenant and to the one `mcp_gateway` stage that issued it,
//! and it keeps the session each registered server issued to the gateway for it.
//!
//! The table is bounded and a tenant is bounded alone: at most [`MAX_PER_TENANT`] sessions each,
//! and a tenant that opens more evicts its own least recently used session, never another
//! tenant's. A session unused for [`IDLE`] is gone. Time is a parameter so a test can pass a
//! clock instead of sleeping.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::server::Up;

/// The most live sessions of one tenant.
pub(super) const MAX_PER_TENANT: usize = 1024;

/// How long a session may sit unused.
pub(super) const IDLE: Duration = Duration::from_secs(30 * 60);

/// The session one server issued, once opened; locked while it is being opened.
pub(super) type Cell = Arc<tokio::sync::Mutex<Option<Up>>>;

/// The sessions the registered servers issued to the gateway for one client session, one cell per
/// server. A cell is empty until the first request that needs the server, which opens the
/// session under the cell's lock: concurrent requests of one client session open it once.
#[derive(Debug, Default)]
pub(super) struct Upstreams {
    cells: Mutex<HashMap<Box<str>, Cell>>,
}

impl Upstreams {
    /// The cell of `server`.
    pub(super) fn cell(&self, server: &str) -> Cell {
        let mut cells = self.cells.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(cells.entry(server.into()).or_default())
    }
}

/// A session found in the table.
#[derive(Debug, Clone)]
pub(super) struct Handle {
    /// The id the client sent.
    pub(super) id: Box<str>,
    /// The servers' sessions.
    pub(super) upstreams: Arc<Upstreams>,
}

#[derive(Debug)]
struct Entry {
    app: Box<str>,
    fingerprint: u64,
    last_used: Instant,
    upstreams: Arc<Upstreams>,
}

impl Entry {
    fn expired(&self, now: Instant, idle: Duration) -> bool {
        now.saturating_duration_since(self.last_used) > idle
    }
}

#[derive(Debug)]
struct Table {
    tenants: HashMap<Box<str>, HashMap<Box<str>, Entry>>,
    swept: Instant,
}

/// What bounds the table.
#[derive(Debug, Clone, Copy)]
struct Limits {
    per_tenant: usize,
    idle: Duration,
}

/// The sessions of every `mcp_gateway` stage of the process. Cheap to clone; clones share the
/// table.
#[derive(Debug, Clone)]
pub struct Sessions {
    table: Arc<Mutex<Table>>,
    limits: Limits,
}

impl Default for Sessions {
    fn default() -> Self {
        Self::with_limits(MAX_PER_TENANT, IDLE)
    }
}

impl Sessions {
    /// An empty table with the process limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with_limits(per_tenant: usize, idle: Duration) -> Self {
        Self {
            table: Arc::new(Mutex::new(Table {
                tenants: HashMap::new(),
                swept: Instant::now(),
            })),
            limits: Limits { per_tenant, idle },
        }
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a session of `tenant` for the stage `app` with `fingerprint`. A tenant at its limit
    /// loses its least recently used session. `None` when the system has no randomness for an
    /// id.
    pub(super) fn open(
        &self,
        tenant: &str,
        app: &str,
        fingerprint: u64,
        now: Instant,
    ) -> Option<Handle> {
        let id = new_id()?;
        let upstreams = Arc::new(Upstreams::default());
        let mut table = self.table();
        let idle = self.limits.idle;
        if now.saturating_duration_since(table.swept) > idle / 2 {
            table.swept = now;
            table.tenants.retain(|_, sessions| {
                sessions.retain(|_, entry| !entry.expired(now, idle));
                !sessions.is_empty()
            });
        }
        let sessions = table.tenants.entry(tenant.into()).or_default();
        sessions.retain(|_, entry| !entry.expired(now, idle));
        while sessions.len() >= self.limits.per_tenant {
            let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            sessions.remove(&oldest);
        }
        sessions.insert(
            id.clone(),
            Entry {
                app: app.into(),
                fingerprint,
                last_used: now,
                upstreams: Arc::clone(&upstreams),
            },
        );
        Some(Handle { id, upstreams })
    }

    /// The session `id` of `tenant`, if it is live and was opened by the stage `app` with
    /// `fingerprint`; a use renews it.
    pub(super) fn lookup(
        &self,
        tenant: &str,
        id: &str,
        app: &str,
        fingerprint: u64,
        now: Instant,
    ) -> Option<Handle> {
        let mut table = self.table();
        let sessions = table.tenants.get_mut(tenant)?;
        let entry = sessions.get_mut(id)?;
        if entry.expired(now, self.limits.idle) {
            sessions.remove(id);
            return None;
        }
        if &*entry.app != app || entry.fingerprint != fingerprint {
            return None;
        }
        entry.last_used = now;
        Some(Handle {
            id: id.into(),
            upstreams: Arc::clone(&entry.upstreams),
        })
    }

    /// Ends the session `id` of `tenant` opened by the stage `app` with `fingerprint`. Whether
    /// there was one.
    pub(super) fn close(&self, tenant: &str, id: &str, app: &str, fingerprint: u64) -> bool {
        let mut table = self.table();
        let Some(sessions) = table.tenants.get_mut(tenant) else {
            return false;
        };
        let owned = sessions
            .get(id)
            .is_some_and(|entry| &*entry.app == app && entry.fingerprint == fingerprint);
        if owned {
            sessions.remove(id);
        }
        owned
    }

    /// The live sessions of `tenant`.
    #[cfg(test)]
    fn count(&self, tenant: &str) -> usize {
        self.table().tenants.get(tenant).map_or(0, HashMap::len)
    }
}

/// 128 random bits as 32 lower case hex digits: visible ASCII, as the transport requires.
fn new_id() -> Option<Box<str>> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).ok()?;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        id.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        id.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    Some(id.into())
}

#[cfg(test)]
mod test {
    use super::*;

    fn open(sessions: &Sessions, tenant: &str, now: Instant) -> Handle {
        sessions.open(tenant, "app", 7, now).expect("a session")
    }

    fn live(sessions: &Sessions, tenant: &str, handle: &Handle, now: Instant) -> bool {
        sessions.lookup(tenant, &handle.id, "app", 7, now).is_some()
    }

    #[test]
    fn mcp_sessions_bounded_by_cap_and_idle_expiry() {
        let sessions = Sessions::with_limits(3, Duration::from_secs(60));
        let start = Instant::now();
        let first = open(&sessions, "t1", start);
        let second = open(&sessions, "t1", start + Duration::from_secs(1));
        let third = open(&sessions, "t1", start + Duration::from_secs(2));
        // A use renews a session: the second is now the least recently used.
        assert!(live(
            &sessions,
            "t1",
            &first,
            start + Duration::from_secs(3)
        ));
        let fourth = open(&sessions, "t1", start + Duration::from_secs(4));
        assert_eq!(sessions.count("t1"), 3);
        assert!(!live(
            &sessions,
            "t1",
            &second,
            start + Duration::from_secs(5)
        ));
        for kept in [&first, &third, &fourth] {
            assert!(live(&sessions, "t1", kept, start + Duration::from_secs(5)));
        }
        // Idle expiry: a session idle for more than 60 s is gone, one used in between is not.
        let later = start + Duration::from_secs(64);
        assert!(live(&sessions, "t1", &fourth, later));
        assert!(!live(
            &sessions,
            "t1",
            &first,
            start + Duration::from_secs(66)
        ));
        // An expired session does not count against the cap.
        let late = later + Duration::from_secs(200);
        let fresh = open(&sessions, "t1", late);
        assert_eq!(sessions.count("t1"), 1);
        assert!(live(&sessions, "t1", &fresh, late));
    }

    #[test]
    fn mcp_sessions_isolated_in_table() {
        let sessions = Sessions::with_limits(2, Duration::from_secs(60));
        let now = Instant::now();
        let quiet = open(&sessions, "quiet", now);
        let flood: Vec<Handle> = (0..50).map(|_| open(&sessions, "loud", now)).collect();
        assert_eq!(sessions.count("loud"), 2);
        assert_eq!(sessions.count("quiet"), 1);
        assert!(live(&sessions, "quiet", &quiet, now));
        // An id is only good for its own tenant, app and declaration.
        let newest = flood.last().expect("a flood");
        assert!(live(&sessions, "loud", newest, now));
        assert!(!live(&sessions, "quiet", newest, now));
        assert!(
            sessions
                .lookup("loud", &newest.id, "other", 7, now)
                .is_none()
        );
        assert!(sessions.lookup("loud", &newest.id, "app", 8, now).is_none());
        assert!(!sessions.close("loud", &newest.id, "app", 8));
        assert!(!sessions.close("quiet", &newest.id, "app", 7));
        assert!(sessions.close("loud", &newest.id, "app", 7));
        assert!(!live(&sessions, "loud", newest, now));
    }

    #[test]
    fn mcp_sessions_ids_are_visible_ascii_and_distinct() {
        let sessions = Sessions::new();
        let now = Instant::now();
        let a = open(&sessions, "t", now);
        let b = open(&sessions, "t", now);
        assert_ne!(a.id, b.id);
        assert_eq!(a.id.len(), 32);
        assert!(a.id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)));
    }

    #[test]
    fn mcp_sessions_a_sweep_drops_idle_tenants() {
        let sessions = Sessions::with_limits(4, Duration::from_secs(60));
        let start = Instant::now();
        drop(open(&sessions, "gone", start));
        drop(open(&sessions, "here", start + Duration::from_secs(100)));
        assert_eq!(sessions.count("gone"), 0);
        assert_eq!(sessions.count("here"), 1);
    }
}
