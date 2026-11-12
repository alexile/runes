//! The crate's only `unsafe` code: `getrlimit`/`setrlimit` calls and the
//! `pre_exec` hook that runs between `fork` and `exec`. The hook's input is
//! prepared before the fork; the hook itself calls `setrlimit` only, which
//! is async-signal-safe, and never allocates.

use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::resource::RawResource;
use crate::{Error, Resource, Rlimit};

/// Reads the calling process's limits for `resource`.
#[allow(
    unsafe_code,
    reason = "`getrlimit` is an FFI call writing through a pointer to a local"
)]
pub fn get(resource: Resource) -> Result<Rlimit, Error> {
    let mut raw = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `raw` is a valid, writable `struct rlimit` for the call's
    // duration, and `resource.raw()` is a valid resource constant.
    if unsafe { libc::getrlimit(resource.raw(), &raw mut raw) } != 0 {
        return Err(Error::Os {
            op: "getrlimit",
            resource,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(Rlimit::from_raw(raw))
}

/// Sets the calling process's limits for `resource`.
#[allow(
    unsafe_code,
    reason = "`setrlimit` is an FFI call reading through a pointer to a local"
)]
pub fn set(resource: Resource, limit: Rlimit) -> Result<(), Error> {
    let raw = limit.to_raw();
    // SAFETY: `raw` is a valid `struct rlimit` that outlives the call, and
    // `resource.raw()` is a valid resource constant.
    if unsafe { libc::setrlimit(resource.raw(), &raw const raw) } != 0 {
        return Err(Error::Os {
            op: "setrlimit",
            resource,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Installs a `pre_exec` hook that sets every limit in `raw` in the child.
/// The child fails to spawn (with the `setrlimit` error) if any call fails.
#[allow(
    unsafe_code,
    reason = "`CommandExt::pre_exec` is unsafe; the hook only calls async-signal-safe `setrlimit`"
)]
pub fn pre_exec(command: &mut Command, raw: Vec<(RawResource, libc::rlimit)>) {
    // SAFETY: the closure only calls `setrlimit` on data prepared before
    // the fork, borrowing it without allocating or taking locks — the only
    // kind of work that is sound between `fork` and `exec`.
    unsafe {
        command.pre_exec(move || {
            for (resource, limit) in &raw {
                if libc::setrlimit(*resource, limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}
