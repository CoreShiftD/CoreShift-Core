// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Low-level process management primitives.
//!
//! Safe wrappers around `fork`, `setsid`, `setpgid`, `dup2`, `prctl`,
//! and fd-range close — building blocks for double-fork supervisor patterns.

use crate::CoreError;
use crate::error::syscall_ret;

/// Result of a [`fork`] call.
pub enum ForkResult {
    /// Returned in the parent with the child's PID.
    Parent(i32),
    /// Returned in the child (PID = 0).
    Child,
}

/// Fork the current process.
///
/// # Safety
/// After `fork`, only async-signal-safe operations are safe in the child
/// before `exec`. Rust's allocator is not async-signal-safe; use this only
/// in the narrow pattern of fork → exec or fork → immediate `_exit`.
pub unsafe fn fork() -> Result<ForkResult, CoreError> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(CoreError::sys(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            "fork",
        ));
    }
    if pid == 0 {
        Ok(ForkResult::Child)
    } else {
        Ok(ForkResult::Parent(pid))
    }
}

/// Create a new session and set the calling process as leader.
pub fn setsid() -> Result<(), CoreError> {
    let ret = unsafe { libc::setsid() };
    if ret < 0 {
        return Err(CoreError::sys(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            "setsid",
        ));
    }
    Ok(())
}

/// Set the process group ID of `pid` to `pgid` (use 0 for self).
pub fn setpgid(pid: i32, pgid: i32) -> Result<(), CoreError> {
    syscall_ret(unsafe { libc::setpgid(pid, pgid) }, "setpgid")
}

/// Redirect stdin, stdout, and stderr to `/dev/null`.
///
/// # Safety
/// Uses `dup2` on file descriptors 0/1/2.
pub unsafe fn redirect_stdio_to_devnull() -> Result<(), CoreError> {
    let fd = unsafe {
        libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char,
                   libc::O_RDWR)
    };
    if fd < 0 {
        return Err(CoreError::sys(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            "open:/dev/null",
        ));
    }
    unsafe {
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
        if fd > 2 { libc::close(fd); }
    }
    Ok(())
}

/// Set the signal sent to this process when its parent dies (`PR_SET_PDEATHSIG`).
pub fn set_pdeathsig(sig: i32) -> Result<(), CoreError> {
    syscall_ret(
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig as libc::c_ulong, 0, 0, 0) },
        "prctl:PR_SET_PDEATHSIG",
    )
}

/// Drop process privileges to the given UID (`setresuid`).
///
/// Sets real, effective, and saved UID to `uid`.
pub fn setuid(uid: u32) -> Result<(), CoreError> {
    syscall_ret(
        unsafe { libc::setresuid(uid, uid, uid) },
        "setresuid",
    )
}

/// Drop process privileges to the given GID (`setresgid`).
///
/// Sets real, effective, and saved GID to `gid`.
pub fn setgid(gid: u32) -> Result<(), CoreError> {
    syscall_ret(
        unsafe { libc::setresgid(gid, gid, gid) },
        "setresgid",
    )
}

/// Close all file descriptors >= `start`.
///
/// Silently ignores `EBADF` (already closed or never open).
pub fn close_fds_from(start: i32) {
    for fd in start..1024 {
        unsafe { libc::close(fd) };
    }
}
