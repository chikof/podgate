//! Starting, watching, restarting and stopping the plugins of `PLUGINS_FILE` that podgate runs
//! itself (`managed: true`).
//!
//! # Starting a plugin
//!
//! The process gets a cleared environment plus the entry's `env`, `PODGATE_PLUGIN_SOCKET` (the
//! socket it must serve) and `PODGATE_PLUGIN_NAME`, the entry's `user` and `group` (through
//! `CommandExt::uid` and `gid`, so podgate must be root for them), and its own process group.
//! Its stdout and stderr go to podgate's log, tagged with the plugin's name, at most
//! [`LOG_LINES_PER_SEC`] lines a second and [`LOG_LINE_MAX`] bytes a line.
//!
//! With `PLUGINS_CGROUP_ROOT`, podgate creates `<root>/<plugin>/`, writes `memory.max` (and
//! `memory.swap.max`, so swap cannot hide the limit), `pids.max` and `cpu.max` from the entry,
//! and puts the plugin in it before the plugin's code runs. The process starts as
//! `sh -c 'read go && exec "$@"'` with a pipe for stdin; podgate writes the shell's pid into
//! `cgroup.procs` and then releases it with one line on the pipe. Only podgate writes the
//! file, so a plugin running as another user needs no write access to the cgroup. A podgate
//! that dies before the release leaves a shell that reads end of file and exits.
//!
//! # Keeping it running
//!
//! A plugin counts as up once it answers `Describe`, at most [`DESCRIBE_WITHIN`] after it
//! started; until then no call is made. One that exits (or does not describe itself in time) is
//! started again after a delay of one second that doubles on every failed start up to a
//! minute, and goes back to a second after the plugin stayed up [`STABLE_AFTER`].
//!
//! # Stopping it
//!
//! At shutdown a plugin gets `SIGTERM`, then `SIGKILL` after [`STOP_GRACE`]; its cgroup is
//! emptied with `cgroup.kill` and removed.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, LazyLock, mpsc};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::task::JoinSet;
use tokio::time::sleep;

use super::client::CallError;
use super::registry::{Described, Entry, Limits, Managed, Plugins};
use super::wire::{DescribeResponse, Phase};

/// How long a plugin has to answer `Describe` after it started.
pub(super) const DESCRIBE_WITHIN: Duration = Duration::from_secs(5);

/// The delay before the first restart; it doubles on every failed start.
const BACKOFF_MIN: Duration = Duration::from_secs(1);

/// The longest delay before a restart.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// How long a plugin must stay up for the next restart delay to be [`BACKOFF_MIN`] again.
const STABLE_AFTER: Duration = Duration::from_secs(30);

/// How long a plugin has to leave after `SIGTERM` before it gets `SIGKILL`.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// How often a running plugin is checked for having exited.
const WATCH_EVERY: Duration = Duration::from_millis(100);

/// The protocol version of `proto/podgate_plugin.proto`.
const PROTOCOL_VERSION: u32 = 1;

/// Lines of a plugin's output logged per second; the rest are counted and dropped.
const LOG_LINES_PER_SEC: u32 = 50;

/// Bytes of one logged line; the rest of a longer line is dropped.
const LOG_LINE_MAX: usize = 1024;

/// The period `cpu.max` is written for, in microseconds.
const CPU_PERIOD_US: u64 = 100_000;

/// A plugin that cannot be started. The message names the plugin.
#[derive(Debug, thiserror::Error)]
#[error("cannot start plugin {plugin:?}: {reason}")]
pub struct StartError {
    plugin: Box<str>,
    reason: String,
}

fn failed(entry: &Entry, reason: impl Into<String>) -> StartError {
    StartError {
        plugin: entry.name.clone(),
        reason: reason.into(),
    }
}

/// A plugin's cgroup.
#[derive(Debug)]
struct Cgroup {
    dir: PathBuf,
}

fn write_file(path: &Path, text: &str) -> std::io::Result<()> {
    fs::write(path, text)
}

impl Cgroup {
    /// Creates `<root>/<name>/` (emptying it of a previous run's processes) and writes the
    /// limits of `limits`; a limit the entry does not declare is reset to `max`.
    fn prepare(root: &Path, name: &str, limits: &Limits) -> Result<Self, String> {
        // Best effort: a delegated cgroup usually has the controllers enabled already.
        drop(write_file(
            &root.join("cgroup.subtree_control"),
            "+memory +pids +cpu",
        ));
        let dir = root.join(name);
        match fs::create_dir(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // A podgate that died took no plugin down with it: empty the cgroup.
                drop(write_file(&dir.join("cgroup.kill"), "1"));
                let until = Instant::now() + Duration::from_millis(500);
                while Instant::now() < until
                    && fs::read_to_string(dir.join("cgroup.procs"))
                        .is_ok_and(|procs| !procs.trim().is_empty())
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(err) => return Err(format!("cannot create the cgroup {}: {err}", dir.display())),
        }
        let set = |file: &str, value: String, required: bool| {
            let path = dir.join(file);
            match write_file(&path, &value) {
                Ok(()) => Ok(()),
                Err(err) if !required => {
                    tracing::debug!(file = %path.display(), %err, "cgroup file not written");
                    Ok(())
                }
                Err(err) => Err(format!(
                    "cannot write {value:?} to {}: {err} (is the controller enabled in {}'s cgroup.subtree_control?)",
                    path.display(),
                    root.display()
                )),
            }
        };
        let max = || "max".to_owned();
        set(
            "memory.max",
            limits
                .memory_max_bytes
                .map_or_else(max, |bytes| bytes.to_string()),
            limits.memory_max_bytes.is_some(),
        )?;
        // Swap would let a plugin that passes `memory.max` live on: the limit is the limit.
        set(
            "memory.swap.max",
            limits.memory_max_bytes.map_or_else(max, |_| "0".to_owned()),
            false,
        )?;
        set(
            "pids.max",
            limits.pids_max.map_or_else(max, |pids| pids.to_string()),
            limits.pids_max.is_some(),
        )?;
        set(
            "cpu.max",
            limits.cpu_percent.map_or_else(
                || format!("max {CPU_PERIOD_US}"),
                |percent| format!("{} {CPU_PERIOD_US}", u64::from(percent) * 1000),
            ),
            limits.cpu_percent.is_some(),
        )?;
        Ok(Self { dir })
    }

    /// Moves process `pid` into the cgroup.
    fn add(&self, pid: u32) -> std::io::Result<()> {
        write_file(&self.dir.join("cgroup.procs"), &pid.to_string())
    }

    /// Kills whatever is left in the cgroup and removes it.
    fn remove(&self) {
        drop(write_file(&self.dir.join("cgroup.kill"), "1"));
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until && fs::remove_dir(&self.dir).is_err() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A plugin's process, while podgate runs it.
#[derive(Debug)]
pub(super) struct Running {
    child: Child,
    cgroup: Option<Cgroup>,
    started: Instant,
}

impl Running {
    /// The process id, for the tests and the logs.
    pub(super) fn pid(&self) -> u32 {
        self.child.id()
    }
}

/// Copies lines of `stream` into the log as the plugin's, within the caps.
fn pump(plugin: Box<str>, stream: &'static str, mut source: impl Read + Send + 'static) {
    let spawned = std::thread::Builder::new()
        .name(format!("plugin-{plugin}-{stream}"))
        .spawn(move || {
            let mut window = Instant::now();
            let (mut logged, mut dropped) = (0_u32, 0_u64);
            let mut line: Vec<u8> = Vec::with_capacity(LOG_LINE_MAX);
            let mut chunk = [0_u8; 4096];
            let mut flush = |line: &mut Vec<u8>| {
                if window.elapsed() >= Duration::from_secs(1) {
                    if dropped > 0 {
                        tracing::warn!(%plugin, stream, dropped, "plugin output over the line cap was dropped");
                    }
                    window = Instant::now();
                    logged = 0;
                    dropped = 0;
                }
                if logged < LOG_LINES_PER_SEC {
                    logged += 1;
                    tracing::info!(%plugin, stream, "{}", String::from_utf8_lossy(line));
                } else {
                    dropped += 1;
                }
                line.clear();
            };
            loop {
                let read = match source.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                for byte in chunk.iter().take(read) {
                    if *byte == b'\n' {
                        flush(&mut line);
                    } else if line.len() < LOG_LINE_MAX {
                        line.push(*byte);
                    }
                }
            }
            if !line.is_empty() {
                flush(&mut line);
            }
        });
    if let Err(err) = spawned {
        tracing::warn!(%err, "cannot start the thread that copies a plugin's output");
    }
}

/// Starts the process of `entry`.
fn spawn(entry: &Entry, cgroup_root: Option<&Path>) -> Result<Running, StartError> {
    let Some(managed) = &entry.spec.managed else {
        return Err(failed(entry, "podgate does not run this plugin"));
    };
    // A socket left by a plugin that is gone would make the new one's bind fail.
    if fs::symlink_metadata(&entry.spec.socket)
        .is_ok_and(|meta| std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()))
    {
        drop(fs::remove_file(&entry.spec.socket));
    }
    let cgroup = cgroup_root
        .map(|root| Cgroup::prepare(root, &entry.name, &managed.limits))
        .transpose()
        .map_err(|reason| failed(entry, reason))?;
    let mut command = command_of(managed, cgroup.is_some());
    command
        .env_clear()
        .envs(&managed.env)
        .env("PODGATE_PLUGIN_SOCKET", &entry.spec.socket)
        .env("PODGATE_PLUGIN_NAME", &*entry.name)
        .stdin(if cgroup.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(uid) = managed.uid {
        command.uid(uid);
    }
    if let Some(gid) = managed.gid {
        command.gid(gid);
    }
    die_with_parent(&mut command);
    let mut child = on_spawner(move || command.spawn())
        .map_err(|reason| failed(entry, reason))?
        .map_err(|err| {
            failed(
                entry,
                format!("cannot run {}: {err}", managed.command.display()),
            )
        })?;
    if let Some(cgroup) = &cgroup {
        let released = cgroup.add(child.id()).map_err(|err| {
            format!(
                "cannot move process {} into {}: {err}",
                child.id(),
                cgroup.dir.display()
            )
        });
        let released = released.and_then(|()| match child.stdin.take() {
            Some(mut gate) => gate
                .write_all(b"\n")
                .map_err(|err| format!("cannot release the plugin's process: {err}")),
            None => Err("the plugin's process has no gate".to_owned()),
        });
        if let Err(reason) = released {
            drop(child.kill());
            drop(child.wait());
            cgroup.remove();
            return Err(failed(entry, reason));
        }
    }
    if let Some(out) = child.stdout.take() {
        pump(entry.name.clone(), "stdout", out);
    }
    if let Some(err) = child.stderr.take() {
        pump(entry.name.clone(), "stderr", err);
    }
    Ok(Running {
        child,
        cgroup,
        started: Instant::now(),
    })
}

type Job = Box<dyn FnOnce() + Send>;

/// The queue of the one thread every managed plugin is forked from; `None` when that thread
/// could not be started. Started by the first use, which is `Plugins::start` on the main thread.
static SPAWNER: LazyLock<Option<mpsc::Sender<Job>>> = LazyLock::new(|| {
    let (sender, jobs) = mpsc::channel::<Job>();
    std::thread::Builder::new()
        .name("plugin-spawner".to_owned())
        .spawn(move || {
            for job in jobs {
                job();
            }
        })
        .ok()
        .map(|_| sender)
});

/// Runs `job` on the spawner thread and returns what it returned.
///
/// `PR_SET_PDEATHSIG` fires when the thread that forked the child exits, not the process. A
/// tokio worker, the blocking pool (its threads leave after 10 idle seconds) or the short-lived
/// runtime that starts the plugins would kill a plugin for no reason. So every fork, the first
/// start and each restart, happens on one thread that is started once, never ends, and does
/// nothing but run these jobs one after the other.
fn on_spawner<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    let queue = SPAWNER
        .as_ref()
        .ok_or_else(|| "cannot start the thread that spawns plugins".to_owned())?;
    let (reply, answer) = mpsc::channel();
    queue
        .send(Box::new(move || drop(reply.send(job()))))
        .map_err(|_| "the thread that spawns plugins is gone".to_owned())?;
    answer
        .recv()
        .map_err(|_| "the thread that spawns plugins failed".to_owned())
}

/// Makes the kernel kill the process when the thread that forks it ends, so a podgate that is
/// killed (`SIGKILL`, the OOM killer, a crash) takes its managed plugins with it: fork only
/// from [`on_spawner`]. `SIGKILL` rather than `SIGTERM`: nobody is left to wait for a clean
/// stop, and a plugin must not be able to ignore it. Call it after `uid` and `gid`: std runs
/// the closures after the credential change, which clears the signal if it was set before. It
/// survives the `exec` of the `sh -c 'read go && exec "$@"'` wrapper into the plugin.
#[allow(
    unsafe_code,
    reason = "`pre_exec` is unsafe; the closure makes two plain syscalls, see SAFETY"
)]
fn die_with_parent(command: &mut Command) {
    let parent = rustix::process::getpid();
    // SAFETY: the closure runs between fork and exec and calls only `prctl` and `getppid`, plain
    // async-signal-safe syscall wrappers: no allocation, no locks, no access to shared state. When
    // the parent died before the `prctl` took effect the signal would never come, so a changed
    // `getppid` makes the closure fail, which ends the child before it execs (std reports the
    // error and `_exit`s; the error value is a plain errno, built without allocating).
    unsafe {
        command.pre_exec(move || {
            rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
                .map_err(std::io::Error::from)?;
            if rustix::process::getppid() == Some(parent) {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(
                    rustix::io::Errno::SRCH.raw_os_error(),
                ))
            }
        });
    }
}

fn command_of(managed: &Managed, in_cgroup: bool) -> Command {
    if in_cgroup {
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(r#"read go && exec "$@""#)
            .arg("podgate-plugin")
            .arg(&managed.command)
            .args(&managed.args);
        command
    } else {
        let mut command = Command::new(&managed.command);
        command.args(&managed.args);
        command
    }
}

/// Checks a plugin's `Describe` and, when it is fit, records it and lets calls through.
fn accept(entry: &Entry, described: &DescribeResponse) -> Result<(), String> {
    if described.protocol_version != PROTOCOL_VERSION {
        return Err(format!(
            "speaks protocol version {}; this podgate speaks {PROTOCOL_VERSION}",
            described.protocol_version
        ));
    }
    let phases: Vec<Phase> = described
        .phases
        .iter()
        .filter_map(|phase| Phase::try_from(*phase).ok())
        .filter(|phase| *phase != Phase::Unspecified)
        .collect();
    if phases.is_empty() {
        return Err("describes no phase it serves".to_owned());
    }
    entry.set_described(Described {
        name: described.name.as_str().into(),
        phases: phases.into_boxed_slice(),
    });
    Ok(())
}

/// Whether the process of `entry` has exited: its status when it has.
fn exited(entry: &Entry) -> Option<ExitStatus> {
    let mut running = entry
        .running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = running.as_mut()?.child.try_wait().ok().flatten()?;
    if let Some(gone) = running.take()
        && let Some(cgroup) = &gone.cgroup
    {
        drop(write_file(&cgroup.dir.join("cgroup.kill"), "1"));
    }
    Some(status)
}

/// Waits for `entry` to answer `Describe` and accepts it, at most [`DESCRIBE_WITHIN`].
async fn describe(entry: &Entry) -> Result<(), String> {
    let until = Instant::now() + DESCRIBE_WITHIN;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "did not answer Describe on {} within {}s",
                entry.spec.socket.display(),
                DESCRIBE_WITHIN.as_secs()
            ));
        }
        match entry.client.describe(left).await {
            Ok(described) => return accept(entry, &described),
            Err(CallError::Unreachable(_)) => {
                if let Some(status) = exited(entry)
                    && entry.spec.managed.is_some()
                {
                    return Err(format!("exited with {status} before it answered Describe"));
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(CallError::Timeout) => {
                return Err(format!(
                    "did not answer Describe on {} within {}s",
                    entry.spec.socket.display(),
                    DESCRIBE_WITHIN.as_secs()
                ));
            }
            Err(err) => return Err(format!("Describe failed: {err}")),
        }
    }
}

/// Starts `entry` if podgate runs it, and waits until it describes itself.
async fn bring_up(entry: &Entry, cgroup_root: Option<&Path>) -> Result<(), StartError> {
    entry.set_down();
    if entry.spec.managed.is_some() {
        let running = spawn(entry, cgroup_root)?;
        tracing::info!(plugin = %entry.name, pid = running.pid(), "plugin started");
        *entry
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(running);
    }
    describe(entry)
        .await
        .map_err(|reason| failed(entry, reason))
}

/// Ends the process of `entry` now and drops its cgroup. Nothing to wait for.
fn kill_now(entry: &Entry) {
    let running = entry
        .running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(mut running) = running {
        drop(running.child.kill());
        drop(running.child.wait());
        if let Some(cgroup) = &running.cgroup {
            cgroup.remove();
        }
    }
    entry.set_down();
}

/// Starts every plugin and waits for each to describe itself; see [`Plugins::start`].
pub(super) fn start(plugins: &Plugins) -> Result<(), StartError> {
    if plugins.is_empty() {
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| StartError {
            plugin: "".into(),
            reason: format!("cannot build the runtime that starts plugins: {err}"),
        })?;
    let outcome = runtime.block_on(async {
        let mut set = JoinSet::new();
        for entry in plugins.entries() {
            let entry = Arc::clone(entry);
            let root = plugins.cgroup_root().map(Path::to_owned);
            set.spawn(async move { bring_up(&entry, root.as_deref()).await });
        }
        let mut first = None;
        while let Some(done) = set.join_next().await {
            if let Ok(Err(err)) = done
                && first.is_none()
            {
                first = Some(err);
                set.abort_all();
            }
        }
        first
    });
    if let Some(err) = outcome {
        for entry in plugins.entries() {
            kill_now(entry);
        }
        return Err(err);
    }
    Ok(())
}

/// Signals process `pid` to terminate.
fn terminate(pid: u32) {
    if let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
}

/// Stops the process of `entry`: `SIGTERM`, `SIGKILL` after [`STOP_GRACE`].
async fn stop(entry: &Entry) {
    let pid = entry
        .running
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map(Running::pid);
    entry.set_down();
    if let Some(pid) = pid {
        terminate(pid);
        let until = Instant::now() + STOP_GRACE;
        while Instant::now() < until && exited(entry).is_none() {
            if entry
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    }
    kill_now(entry);
    tracing::info!(plugin = %entry.name, "plugin stopped");
}

/// Keeps one plugin running until `shutdown`.
async fn keep(entry: Arc<Entry>, cgroup_root: Option<PathBuf>, mut shutdown: ShutdownWatch) {
    let mut delay = BACKOFF_MIN;
    loop {
        let started = entry
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or_else(Instant::now, |running| running.started);
        // Up: wait for the process to leave, or for shutdown.
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    stop(&entry).await;
                    return;
                }
                () = sleep(WATCH_EVERY) => {}
            }
            if *shutdown.borrow() {
                stop(&entry).await;
                return;
            }
            if let Some(status) = exited(&entry) {
                entry.set_down();
                tracing::warn!(plugin = %entry.name, %status, "plugin exited");
                break;
            }
            if entry
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_none()
            {
                break;
            }
        }
        if started.elapsed() >= STABLE_AFTER {
            delay = BACKOFF_MIN;
        }
        // Down: start again after the delay, until one start works.
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = sleep(delay) => {}
            }
            if *shutdown.borrow() {
                return;
            }
            delay = (delay * 2).min(BACKOFF_MAX);
            match bring_up(&entry, cgroup_root.as_deref()).await {
                Ok(()) => {
                    entry.count_restart();
                    tracing::info!(plugin = %entry.name, "plugin is up again");
                    break;
                }
                Err(err) => {
                    tracing::error!(plugin = %entry.name, %err, "plugin failed to restart");
                    kill_now(&entry);
                }
            }
        }
    }
}

/// The background service that keeps managed plugins running and stops them at shutdown.
#[derive(Debug)]
pub struct Supervisor {
    plugins: Plugins,
}

impl Supervisor {
    pub(super) fn new(plugins: Plugins) -> Self {
        Self { plugins }
    }
}

#[async_trait]
impl BackgroundService for Supervisor {
    async fn start(&self, shutdown: ShutdownWatch) {
        let mut tasks = JoinSet::new();
        for entry in self
            .plugins
            .entries()
            .filter(|entry| entry.spec.managed.is_some())
        {
            tasks.spawn(keep(
                Arc::clone(entry),
                self.plugins.cgroup_root().map(Path::to_owned),
                shutdown.clone(),
            ));
        }
        while tasks.join_next().await.is_some() {}
    }
}
