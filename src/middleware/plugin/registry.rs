//! `PLUGINS_FILE`: the plugins a snapshot may name, parsed and validated at startup, and the
//! live state of each (its connection, circuit, calls in flight, supervision).
//!
//! ```json
//! {"headeradder": {
//!    "socket": "/run/podgate/plugins/headeradder.sock",
//!    "tenants": ["acme"],
//!    "managed": true,
//!    "command": "/opt/plugins/headeradder", "args": ["--verbose"], "env": {"LANG": "C"},
//!    "user": "plugin", "group": "plugin",
//!    "limits": {"memory_max_bytes": 268435456, "pids_max": 64, "cpu_percent": 100},
//!    "max_concurrent": 256}}
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use serde::Deserialize;

use super::client::Client;
use super::limits::{
    CIRCUIT_AFTER, CIRCUIT_FOR, Circuit, DEFAULT_MAX_CONCURRENT, MAX_CONCURRENT, Slots,
};
use super::supervisor::{self, Running};
use super::wire::Phase;

/// The longest plugin name.
const MAX_NAME: usize = 64;

/// The most tenants one entry may list.
const MAX_TENANTS: usize = 4096;

/// The most arguments and environment variables a managed plugin may be given.
const MAX_ARGS: usize = 256;

/// The smallest `memory_max_bytes`: below it nothing starts.
const MIN_MEMORY_MAX: u64 = 1 << 20;

/// The most `cpu_percent`: 1024 cores.
const MAX_CPU_PERCENT: u32 = 102_400;

/// Why `PLUGINS_FILE` cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The file cannot be read.
    #[error("cannot read {path}: {source}")]
    Read {
        /// The file.
        path: String,
        /// The cause.
        source: std::io::Error,
    },
    /// The file is not the JSON object described above.
    #[error("{0}")]
    Parse(serde_json::Error),
    /// One entry is wrong.
    #[error("plugin {name:?}: {reason}")]
    Plugin {
        /// The entry's name.
        name: Box<str>,
        /// What is wrong.
        reason: Box<str>,
    },
}

fn bad(name: &str, reason: impl Into<Box<str>>) -> LoadError {
    LoadError::Plugin {
        name: name.into(),
        reason: reason.into(),
    }
}

/// A user or group, by number or by name.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Id {
    Number(u32),
    Name(String),
}

/// What the cgroup of a managed plugin is limited to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Limits {
    /// `memory.max`, in bytes.
    pub(super) memory_max_bytes: Option<u64>,
    /// `pids.max`.
    pub(super) pids_max: Option<u32>,
    /// `cpu.max`, as a percent of one core: 100 is one core, 250 two and a half.
    pub(super) cpu_percent: Option<u32>,
}

impl Limits {
    /// Whether the entry declares any limit.
    pub(super) fn any(&self) -> bool {
        self.memory_max_bytes.is_some() || self.pids_max.is_some() || self.cpu_percent.is_some()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    socket: PathBuf,
    #[serde(default)]
    tenants: Vec<String>,
    #[serde(default = "managed_by_default")]
    managed: bool,
    #[serde(default)]
    command: Option<PathBuf>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    user: Option<Id>,
    #[serde(default)]
    group: Option<Id>,
    #[serde(default)]
    limits: Limits,
    #[serde(default)]
    max_concurrent: Option<u32>,
}

fn managed_by_default() -> bool {
    true
}

/// How podgate starts a managed plugin.
#[derive(Debug)]
pub(super) struct Managed {
    pub(super) command: PathBuf,
    pub(super) args: Vec<String>,
    pub(super) env: BTreeMap<String, String>,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    pub(super) limits: Limits,
}

/// One entry of the file, validated.
#[derive(Debug)]
pub(super) struct Spec {
    /// The unix socket the plugin serves.
    pub(super) socket: PathBuf,
    /// The tenants that may use the plugin.
    pub(super) tenants: Box<[Box<str>]>,
    /// `Some` when podgate starts and supervises the plugin.
    pub(super) managed: Option<Managed>,
    /// Calls in flight at once.
    pub(super) max_concurrent: usize,
}

/// What a plugin said it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Described {
    /// The plugin's own name.
    pub(super) name: Box<str>,
    /// The phases it serves.
    pub(super) phases: Box<[Phase]>,
}

/// How a call ended, for the metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The plugin decided.
    Ok,
    /// The deadline passed.
    Timeout,
    /// The connection failed or nothing listens.
    Transport,
    /// The plugin answered something that cannot be used.
    Invalid,
    /// No room: the plugin or the tenant is at its calls in flight.
    Busy,
    /// The circuit is open or the plugin is starting: the call was not made.
    Unavailable,
    /// The tenant's buffer budget could not take the call.
    OverBudget,
    /// The call was over the cap: nothing was sent.
    CallTooLarge,
    /// A failed call that `fail_open` let the request survive.
    FailedOpen,
}

impl Outcome {
    const ALL: [Self; 9] = [
        Self::Ok,
        Self::Timeout,
        Self::Transport,
        Self::Invalid,
        Self::Busy,
        Self::Unavailable,
        Self::OverBudget,
        Self::CallTooLarge,
        Self::FailedOpen,
    ];

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Invalid => "invalid",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
            Self::OverBudget => "over_budget",
            Self::CallTooLarge => "call_too_large",
            Self::FailedOpen => "failed_open",
        }
    }
}

/// The plugins that are alive, for the metrics exposition.
static LIVE: Mutex<Vec<Weak<Entry>>> = Mutex::new(Vec::new());

/// A plugin: its entry in the file and everything that changes while it runs.
#[derive(Debug)]
pub(super) struct Entry {
    pub(super) name: Box<str>,
    pub(super) spec: Spec,
    pub(super) client: Client,
    pub(super) circuit: Circuit,
    pub(super) slots: Slots,
    described: Mutex<Option<Described>>,
    ready: AtomicBool,
    outcomes: [AtomicU64; Outcome::ALL.len()],
    restarts: AtomicU64,
    /// The process, while podgate runs it.
    pub(super) running: Mutex<Option<Running>>,
}

impl Entry {
    fn new(name: &str, spec: Spec) -> Arc<Self> {
        let entry = Arc::new(Self {
            name: name.into(),
            client: Client::new(&spec.socket),
            circuit: Circuit::new(CIRCUIT_AFTER, CIRCUIT_FOR),
            slots: Slots::new(spec.max_concurrent, &spec.tenants),
            spec,
            described: Mutex::new(None),
            ready: AtomicBool::new(false),
            outcomes: std::array::from_fn(|_| AtomicU64::new(0)),
            restarts: AtomicU64::new(0),
            running: Mutex::new(None),
        });
        LIVE.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::downgrade(&entry));
        entry
    }

    /// Whether `tenant` may use the plugin.
    pub(super) fn allows(&self, tenant: &str) -> bool {
        self.spec.tenants.iter().any(|listed| &**listed == tenant)
    }

    /// Whether the plugin serves `phase`, by its last `Describe`. `false` before there was one.
    pub(super) fn serves(&self, phase: Phase) -> bool {
        self.described
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|described| described.phases.contains(&phase))
    }

    /// Records a `Describe` and lets calls through: the plugin is up.
    pub(super) fn set_described(&self, described: Described) {
        *self
            .described
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(described);
        self.circuit.reset();
        self.ready.store(true, Ordering::Release);
    }

    /// Stops calls: the plugin is gone or starting, and its connection is not the next one's.
    pub(super) fn set_down(&self) {
        self.ready.store(false, Ordering::Release);
        self.client.reset();
    }

    /// Whether calls may be made: the plugin answered `Describe` since it last started.
    pub(super) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Counts one call's outcome.
    pub(super) fn count(&self, outcome: Outcome) {
        if let Some(counter) = self.outcomes.get(outcome as usize) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Counts one restart of the process.
    pub(super) fn count_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    /// The restarts counted so far.
    pub(super) fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Default)]
struct Inner {
    entries: BTreeMap<Box<str>, Arc<Entry>>,
    cgroup_root: Option<PathBuf>,
    max_timeout: Duration,
}

/// The plugins of `PLUGINS_FILE`. Cheap to clone; every clone shares the plugins.
///
/// The snapshot compiler checks a `plugin` middleware against it (the plugin exists and lists
/// the app's tenant); the middleware keeps the plugin it resolved and calls it.
#[derive(Debug, Clone, Default)]
pub struct Plugins(Arc<Inner>);

impl Plugins {
    /// Reads and validates `path`.
    ///
    /// `cgroup_root` is `PLUGINS_CGROUP_ROOT`; an entry that declares limits needs it.
    /// `request_timeout` is `REQUEST_TIMEOUT_SECS`, the longest a call may be given. Nothing is
    /// started or contacted.
    ///
    /// # Errors
    ///
    /// [`LoadError`] when the file cannot be read or parsed, or an entry is invalid (its name,
    /// an absolute path that is relative, a managed plugin without a command, limits without
    /// `cgroup_root` or on a plugin podgate does not start, a user or group that does not
    /// exist).
    pub fn load(
        path: &Path,
        cgroup_root: Option<&Path>,
        request_timeout: Duration,
    ) -> Result<Self, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::parse(&text, cgroup_root, request_timeout)
    }

    fn parse(
        text: &str,
        cgroup_root: Option<&Path>,
        request_timeout: Duration,
    ) -> Result<Self, LoadError> {
        let files: BTreeMap<String, File> = serde_json::from_str(text).map_err(LoadError::Parse)?;
        let mut entries = BTreeMap::new();
        for (name, file) in files {
            let spec = spec_of(&name, file, cgroup_root)?;
            entries.insert(Box::from(name.as_str()), Entry::new(&name, spec));
        }
        Ok(Self(Arc::new(Inner {
            entries,
            cgroup_root: cgroup_root.map(Path::to_owned),
            max_timeout: request_timeout,
        })))
    }

    /// Whether no plugin is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.entries.is_empty()
    }

    /// The plugin called `name`.
    pub(super) fn get(&self, name: &str) -> Option<&Arc<Entry>> {
        self.0.entries.get(name)
    }

    /// Every plugin, by name.
    pub(super) fn entries(&self) -> impl Iterator<Item = &Arc<Entry>> {
        self.0.entries.values()
    }

    /// `PLUGINS_CGROUP_ROOT`.
    pub(super) fn cgroup_root(&self) -> Option<&Path> {
        self.0.cgroup_root.as_deref()
    }

    /// The longest `timeout_ms` a middleware may set: `REQUEST_TIMEOUT_SECS`.
    pub(super) fn max_timeout(&self) -> Duration {
        self.0.max_timeout
    }

    /// Starts the managed plugins and waits until every plugin answers `Describe`, at most five
    /// seconds each. Call it once, before the server runs; [`Self::supervisor`] then keeps the
    /// managed ones running.
    ///
    /// # Errors
    ///
    /// [`supervisor::StartError`] naming the plugin that could not be started: its cgroup
    /// cannot be set up, it cannot be spawned, it never listens, or its `Describe` fails or
    /// names a protocol version this podgate does not speak.
    pub fn start(&self) -> Result<(), supervisor::StartError> {
        supervisor::start(self)
    }

    /// The background service that restarts managed plugins that exit and stops them at
    /// shutdown.
    #[must_use]
    pub fn supervisor(&self) -> supervisor::Supervisor {
        supervisor::Supervisor::new(self.clone())
    }
}

pub(super) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

/// The id of `name` in a passwd-style `table` (`/etc/passwd` or `/etc/group`), and the group
/// number that follows it in the line (the primary group, for a user).
fn lookup(table: &str, name: &str) -> Option<(u32, Option<u32>)> {
    let text = std::fs::read_to_string(table).ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        let _password = fields.next()?;
        let id = fields.next()?.parse().ok()?;
        let next = fields.next().and_then(|field| field.parse().ok());
        Some((id, next))
    })
}

fn id_of(name: &str, what: &str, table: &str, id: &Id) -> Result<(u32, Option<u32>), LoadError> {
    match id {
        Id::Number(number) => Ok((*number, None)),
        Id::Name(text) => lookup(table, text)
            .ok_or_else(|| bad(name, format!("{what} {text:?} is not in {table}"))),
    }
}

fn spec_of(name: &str, file: File, cgroup_root: Option<&Path>) -> Result<Spec, LoadError> {
    if !valid_name(name) {
        return Err(bad(
            name,
            format!("a name is 1 to {MAX_NAME} characters of a to z, 0 to 9, `-` and `_`"),
        ));
    }
    if !file.socket.is_absolute() {
        return Err(bad(name, "`socket` must be an absolute path"));
    }
    if file.tenants.len() > MAX_TENANTS {
        return Err(bad(name, format!("lists more than {MAX_TENANTS} tenants")));
    }
    let mut tenants: Vec<Box<str>> = Vec::with_capacity(file.tenants.len());
    for tenant in &file.tenants {
        if tenant.is_empty() {
            return Err(bad(name, "`tenants` has an empty tenant id"));
        }
        if !tenants.iter().any(|listed| **listed == **tenant) {
            tenants.push(tenant.as_str().into());
        }
    }
    let max_concurrent = file.max_concurrent.unwrap_or(DEFAULT_MAX_CONCURRENT);
    if !(1..=MAX_CONCURRENT).contains(&max_concurrent) {
        return Err(bad(
            name,
            format!("`max_concurrent` is in 1..={MAX_CONCURRENT}"),
        ));
    }
    let managed = if file.managed {
        let command = file
            .command
            .ok_or_else(|| bad(name, "a managed plugin needs a `command`"))?;
        if !command.is_absolute() {
            return Err(bad(name, "`command` must be an absolute path"));
        }
        if file.args.len() > MAX_ARGS || file.env.len() > MAX_ARGS {
            return Err(bad(
                name,
                format!("`args` and `env` hold at most {MAX_ARGS} entries each"),
            ));
        }
        if let Some(key) = file
            .env
            .keys()
            .find(|key| key.is_empty() || key.contains('=') || key.contains('\0'))
        {
            return Err(bad(name, format!("`env` has the invalid name {key:?}")));
        }
        if file.args.iter().any(|arg| arg.contains('\0'))
            || file.env.values().any(|value| value.contains('\0'))
        {
            return Err(bad(name, "`args` and `env` cannot hold a NUL"));
        }
        let limits = file.limits;
        if limits.any() && cgroup_root.is_none() {
            return Err(bad(
                name,
                "declares limits and PLUGINS_CGROUP_ROOT is not set: a limit would silently not apply",
            ));
        }
        if limits
            .memory_max_bytes
            .is_some_and(|bytes| bytes < MIN_MEMORY_MAX)
        {
            return Err(bad(name, "`limits.memory_max_bytes` is at least 1048576"));
        }
        if limits.pids_max == Some(0) {
            return Err(bad(name, "`limits.pids_max` is at least 1"));
        }
        if limits
            .cpu_percent
            .is_some_and(|percent| !(1..=MAX_CPU_PERCENT).contains(&percent))
        {
            return Err(bad(
                name,
                format!("`limits.cpu_percent` is in 1..={MAX_CPU_PERCENT}"),
            ));
        }
        let (uid, primary) = match &file.user {
            Some(id) => {
                let (uid, primary) = id_of(name, "user", "/etc/passwd", id)?;
                (Some(uid), primary)
            }
            None => (None, None),
        };
        let gid = match &file.group {
            Some(id) => Some(id_of(name, "group", "/etc/group", id)?.0),
            // A user without a group would keep podgate's: its own primary group is the default.
            None => match (uid, primary) {
                (Some(_), Some(primary)) => Some(primary),
                (Some(_), None) => {
                    return Err(bad(name, "`user` is a number: name its `group` too"));
                }
                (None, _) => None,
            },
        };
        if (uid.is_some() || gid.is_some()) && !rustix::process::geteuid().is_root() {
            return Err(bad(
                name,
                "sets `user` or `group` and podgate does not run as root",
            ));
        }
        Some(Managed {
            command,
            args: file.args,
            env: file.env,
            uid,
            gid,
            limits,
        })
    } else {
        if file.command.is_some()
            || !file.args.is_empty()
            || !file.env.is_empty()
            || file.user.is_some()
            || file.group.is_some()
            || file.limits.any()
        {
            return Err(bad(
                name,
                "`command`, `args`, `env`, `user`, `group` and `limits` are for a managed plugin: podgate does not start this one",
            ));
        }
        None
    };
    Ok(Spec {
        socket: file.socket,
        tenants: tenants.into_boxed_slice(),
        managed,
        max_concurrent: usize::try_from(max_concurrent).unwrap_or(usize::MAX),
    })
}

/// Appends `podgate_plugin_up`, `podgate_plugin_calls_total`, `podgate_plugin_in_flight` and
/// `podgate_plugin_restarts_total` for every plugin of this process to the exposition `out`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;

    use crate::budget::Escaped;

    let mut entries: Vec<Arc<Entry>> = LIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = writeln!(
        out,
        "# HELP podgate_plugin_up 1 while calls to the plugin are made: it answered Describe since it last started and its circuit is closed.\n# TYPE podgate_plugin_up gauge"
    );
    for entry in &entries {
        let _ = writeln!(
            out,
            "podgate_plugin_up{{plugin=\"{}\"}} {}",
            Escaped(&entry.name),
            u8::from(entry.is_ready() && !entry.circuit.is_open())
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_plugin_calls_total Plugin calls, by how they ended.\n# TYPE podgate_plugin_calls_total counter"
    );
    for entry in &entries {
        for outcome in Outcome::ALL {
            let count = entry
                .outcomes
                .get(outcome as usize)
                .map_or(0, |counter| counter.load(Ordering::Relaxed));
            let _ = writeln!(
                out,
                "podgate_plugin_calls_total{{plugin=\"{}\",outcome=\"{}\"}} {count}",
                Escaped(&entry.name),
                outcome.name()
            );
        }
    }
    let _ = writeln!(
        out,
        "# HELP podgate_plugin_in_flight Plugin calls in flight.\n# TYPE podgate_plugin_in_flight gauge"
    );
    for entry in &entries {
        let _ = writeln!(
            out,
            "podgate_plugin_in_flight{{plugin=\"{}\"}} {}",
            Escaped(&entry.name),
            entry.slots.in_flight()
        );
    }
    let _ = writeln!(
        out,
        "# HELP podgate_plugin_restarts_total Restarts of a managed plugin's process.\n# TYPE podgate_plugin_restarts_total counter"
    );
    for entry in entries.iter().filter(|entry| entry.spec.managed.is_some()) {
        let _ = writeln!(
            out,
            "podgate_plugin_restarts_total{{plugin=\"{}\"}} {}",
            Escaped(&entry.name),
            entry.restarts()
        );
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn parse(text: &str, cgroup: Option<&Path>) -> Result<Plugins, LoadError> {
        Plugins::parse(text, cgroup, Duration::from_secs(5))
    }

    fn reason(text: &str, cgroup: Option<&Path>) -> String {
        parse(text, cgroup).expect_err("refused").to_string()
    }

    #[test]
    fn an_unmanaged_plugin_is_a_socket_and_its_tenants() {
        let plugins = parse(
            r#"{"p": {"socket": "/run/p.sock", "managed": false, "tenants": ["a", "b", "a"]}}"#,
            None,
        )
        .expect("loads");
        let entry = plugins.get("p").expect("listed");
        assert_eq!(entry.spec.tenants.len(), 2);
        assert!(entry.allows("a") && !entry.allows("c"));
        assert!(entry.spec.managed.is_none());
        assert_eq!(entry.spec.max_concurrent, 256);
    }

    #[test]
    fn a_plugin_that_lists_no_tenant_is_usable_by_none() {
        let plugins = parse(r#"{"p": {"socket": "/s", "managed": false}}"#, None).expect("loads");
        assert!(!plugins.get("p").expect("listed").allows("a"));
    }

    #[test]
    fn a_bad_entry_is_refused_naming_the_plugin() {
        for (text, wanted) in [
            (
                r#"{"Bad Name": {"socket": "/s", "managed": false}}"#,
                "Bad Name",
            ),
            (r#"{"p": {"socket": "s", "managed": false}}"#, "absolute"),
            (r#"{"p": {"socket": "/s"}}"#, "needs a `command`"),
            (
                r#"{"p": {"socket": "/s", "command": "relative"}}"#,
                "absolute",
            ),
            (
                r#"{"p": {"socket": "/s", "managed": false, "command": "/bin/x"}}"#,
                "managed plugin",
            ),
            (
                r#"{"p": {"socket": "/s", "managed": false, "max_concurrent": 0}}"#,
                "max_concurrent",
            ),
            (
                r#"{"p": {"socket": "/s", "command": "/bin/x", "env": {"A=B": "1"}}}"#,
                "env",
            ),
        ] {
            let why = reason(text, None);
            assert!(why.contains("p") && why.contains(wanted), "{text}: {why}");
        }
        assert!(reason("not json", None).contains("expected"));
        assert!(reason(r#"{"p": {"socket": "/s", "extra": 1}}"#, None).contains("extra"));
    }

    #[test]
    fn limits_need_a_cgroup_root_and_sane_values() {
        let text = r#"{"p": {"socket": "/s", "command": "/bin/x", "limits": {"pids_max": 8}}}"#;
        let why = reason(text, None);
        assert!(
            why.contains("PLUGINS_CGROUP_ROOT") && why.contains("\"p\""),
            "{why}"
        );
        assert!(parse(text, Some(Path::new("/sys/fs/cgroup/x"))).is_ok());
        for limits in [
            r#"{"memory_max_bytes": 1024}"#,
            r#"{"pids_max": 0}"#,
            r#"{"cpu_percent": 0}"#,
            r#"{"cpu_percent": 999999999}"#,
        ] {
            let text =
                format!(r#"{{"p": {{"socket": "/s", "command": "/bin/x", "limits": {limits}}}}}"#);
            assert!(
                parse(&text, Some(Path::new("/c"))).is_err(),
                "{limits} is refused"
            );
        }
    }

    #[test]
    fn a_user_needs_a_group_to_go_with_it_and_root_to_apply_either() {
        let text = r#"{"p": {"socket": "/s", "command": "/bin/x", "user": 4242}}"#;
        let why = reason(text, None);
        assert!(why.contains("group") || why.contains("root"), "{why}");
        let missing = reason(
            r#"{"p": {"socket": "/s", "command": "/bin/x", "user": "no-such-user-here"}}"#,
            None,
        );
        assert!(missing.contains("no-such-user-here"), "{missing}");
    }

    #[test]
    fn names_are_lower_case_words() {
        assert!(valid_name("header-adder_2"));
        assert!(!valid_name(""));
        assert!(!valid_name("Upper"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(&"a".repeat(65)));
    }

    #[test]
    fn passwd_lines_give_an_id_and_the_next_number() {
        let dir = std::env::temp_dir().join(format!("podgate-passwd-{}", std::process::id()));
        std::fs::write(
            &dir,
            "root:x:0:0:r:/root:/bin/sh\nplug:x:1001:1002:p:/:/bin/false\n",
        )
        .expect("write");
        let table = dir.to_str().expect("utf-8 path");
        assert_eq!(lookup(table, "plug"), Some((1001, Some(1002))));
        assert_eq!(lookup(table, "nobody"), None);
        drop(std::fs::remove_file(&dir));
    }
}
