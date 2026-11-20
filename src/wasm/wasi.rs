//! The `wasi_snapshot_preview1` functions a filter may import: harmless stubs, so proxy-wasm
//! modules built for `wasm32-wasip1` (the Rust and Go SDK default) load.
//!
//! Nothing here reaches the host beyond a clock read, entropy and a `tracing` event:
//!
//! | Import | Behaviour |
//! |---|---|
//! | `clock_time_get`, `clock_res_get` | real-time clock (id `0`) or time since the run started (ids `1` to `3`); other ids `EINVAL` |
//! | `random_get` | OS entropy |
//! | `proc_exit` | traps the guest, so the request answers `500` |
//! | `environ_sizes_get`, `environ_get`, `args_sizes_get`, `args_get` | empty |
//! | `sched_yield` | no-op |
//! | `fd_write` | fd `1` (info) and `2` (warn) go to `tracing` through the run's log budget; every other fd is `EBADF` |
//!
//! Every other WASI import, in particular all `sock_*`, `path_*` and the other `fd_*`
//! functions, is refused when the snapshot compiles (`wasm_forbidden_import`).

use std::time::{SystemTime, UNIX_EPOCH};

use wasmtime::{Caller, Linker};

use super::{HostState, emit, memory, region};

/// The import module of these functions.
pub(super) const MODULE: &str = "wasi_snapshot_preview1";

/// The functions [`link`] defines.
pub(super) const IMPORTS: [&str; 10] = [
    "clock_time_get",
    "clock_res_get",
    "random_get",
    "proc_exit",
    "environ_sizes_get",
    "environ_get",
    "args_sizes_get",
    "args_get",
    "sched_yield",
    "fd_write",
];

/// WASI `errno` values returned.
mod errno {
    pub(super) const SUCCESS: i32 = 0;
    pub(super) const BADF: i32 = 8;
    pub(super) const FAULT: i32 = 21;
    pub(super) const INVAL: i32 = 28;
    pub(super) const IO: i32 = 29;
}

/// Most `iovec`s one `fd_write` may pass (POSIX `IOV_MAX`).
const IOV_MAX: u32 = 1024;

pub(super) fn link(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    linker.func_wrap(MODULE, "clock_time_get", clock_time_get)?;
    linker.func_wrap(MODULE, "clock_res_get", clock_res_get)?;
    linker.func_wrap(MODULE, "random_get", random_get)?;
    linker.func_wrap(MODULE, "proc_exit", proc_exit)?;
    linker.func_wrap(MODULE, "environ_sizes_get", empty_sizes)?;
    linker.func_wrap(MODULE, "environ_get", empty_list)?;
    linker.func_wrap(MODULE, "args_sizes_get", empty_sizes)?;
    linker.func_wrap(MODULE, "args_get", empty_list)?;
    linker.func_wrap(MODULE, "sched_yield", sched_yield)?;
    linker.func_wrap(MODULE, "fd_write", fd_write)?;
    Ok(())
}

/// Copies `bytes` to guest memory at `at`; the WASI errno.
fn put(caller: &mut Caller<'_, HostState>, at: u32, bytes: &[u8]) -> i32 {
    let Some(memory) = memory(caller) else {
        return errno::FAULT;
    };
    let guest = memory.data_mut(&mut *caller);
    let target = usize::try_from(at)
        .ok()
        .and_then(|start| guest.get_mut(start..start.checked_add(bytes.len())?));
    match target {
        Some(target) => {
            target.copy_from_slice(bytes);
            errno::SUCCESS
        }
        None => errno::FAULT,
    }
}

fn clock_time_get(mut caller: Caller<'_, HostState>, id: u32, _precision: u64, out: u32) -> i32 {
    let nanos = match id {
        0 => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos()),
        1..=3 => caller.data().started.elapsed().as_nanos(),
        _ => return errno::INVAL,
    };
    let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
    put(&mut caller, out, &nanos.to_le_bytes())
}

fn clock_res_get(mut caller: Caller<'_, HostState>, id: u32, out: u32) -> i32 {
    if id > 3 {
        return errno::INVAL;
    }
    put(&mut caller, out, &1_u64.to_le_bytes())
}

fn random_get(mut caller: Caller<'_, HostState>, buf: u32, len: u32) -> i32 {
    let Some(memory) = memory(&mut caller) else {
        return errno::FAULT;
    };
    let guest = memory.data_mut(&mut caller);
    let target = usize::try_from(buf)
        .ok()
        .and_then(|start| guest.get_mut(start..start.checked_add(usize::try_from(len).ok()?)?));
    let Some(target) = target else {
        return errno::FAULT;
    };
    if getrandom::fill(target).is_ok() {
        errno::SUCCESS
    } else {
        errno::IO
    }
}

fn proc_exit(_caller: Caller<'_, HostState>, code: i32) -> wasmtime::Result<()> {
    Err(wasmtime::format_err!("the filter called proc_exit({code})"))
}

/// `environ_sizes_get` and `args_sizes_get`: zero entries in zero bytes.
fn empty_sizes(mut caller: Caller<'_, HostState>, count: u32, size: u32) -> i32 {
    let first = put(&mut caller, count, &0_u32.to_le_bytes());
    if first == errno::SUCCESS {
        put(&mut caller, size, &0_u32.to_le_bytes())
    } else {
        first
    }
}

/// `environ_get` and `args_get`: nothing to write.
fn empty_list(_caller: Caller<'_, HostState>, _pointers: u32, _buffer: u32) -> i32 {
    errno::SUCCESS
}

fn sched_yield() -> i32 {
    errno::SUCCESS
}

/// Up to `room` bytes of the `count` `iovec`s at `iovs`, and the bytes they hold in total. It
/// never copies more than `room`, whatever the guest passes. `None` when an `iovec` or a
/// buffer lies outside memory.
fn gather(guest: &[u8], iovs: u32, count: u32, room: usize) -> Option<(Vec<u8>, u32)> {
    let table = region(guest, iovs, count.checked_mul(8)?)?;
    let mut text = Vec::new();
    let mut total = 0_u32;
    for entry in table.as_chunks::<8>().0 {
        let ptr = u32::from_le_bytes(entry.get(..4)?.try_into().ok()?);
        let len = u32::from_le_bytes(entry.get(4..)?.try_into().ok()?);
        let chunk = region(guest, ptr, len)?;
        let left = room.saturating_sub(text.len());
        text.extend_from_slice(chunk.get(..chunk.len().min(left))?);
        total = total.checked_add(len)?;
    }
    Some((text, total))
}

fn fd_write(
    mut caller: Caller<'_, HostState>,
    fd: u32,
    iovs: u32,
    count: u32,
    written: u32,
) -> i32 {
    if fd != 1 && fd != 2 {
        return errno::BADF;
    }
    if count > IOV_MAX {
        return errno::INVAL;
    }
    let Some(memory) = memory(&mut caller) else {
        return errno::FAULT;
    };
    let total = {
        let (guest, state) = memory.data_and_store_mut(&mut caller);
        let Some((text, total)) = gather(guest, iovs, count, state.log_bytes_left) else {
            return errno::FAULT;
        };
        // stdout is info, stderr is warn.
        let cut = usize::try_from(total).is_ok_and(|total| total > text.len());
        emit(
            state,
            if fd == 1 { 2 } else { 3 },
            text.trim_ascii_end(),
            cut,
        );
        total
    };
    put(&mut caller, written, &total.to_le_bytes())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn gather_copies_at_most_the_room_from_a_1_mib_write() {
        let mut guest = vec![b'x'; (1 << 20) + 64];
        // One iovec at 0 describing the 1 MiB buffer that starts at 64.
        guest[..4].copy_from_slice(&64_u32.to_le_bytes());
        guest[4..8].copy_from_slice(&(1_u32 << 20).to_le_bytes());
        let (text, total) = gather(&guest, 0, 1, 4096).expect("in bounds");
        assert_eq!((text.len(), total), (4096, 1 << 20));
        let (text, _) = gather(&guest, 0, 1, 0).expect("in bounds");
        assert!(text.is_empty());
    }

    #[test]
    fn gather_refuses_buffers_outside_memory() {
        let mut guest = vec![0_u8; 16];
        guest[..4].copy_from_slice(&8_u32.to_le_bytes());
        guest[4..8].copy_from_slice(&64_u32.to_le_bytes());
        assert!(gather(&guest, 0, 1, 4096).is_none());
        assert!(gather(&guest, 12, 1, 4096).is_none(), "iovec past the end");
    }
}
