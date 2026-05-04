// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Ownership and UID lookup helpers.
//!
//! These helpers provide cheap ownership probes for filesystem paths and
//! `/proc/<pid>` directories before higher layers do more expensive work.

use crate::CoreError;
use crate::error::syscall_ret;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Filesystem identity derived from `stat(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStat {
    /// Owning UID from `st_uid`.
    pub uid: u32,
    /// Inode number from `st_ino`.
    pub inode: u64,
    /// Change time seconds from `st_ctime`.
    pub ctime_sec: i64,
    /// Change time nanoseconds from `st_ctime_nsec`.
    pub ctime_nsec: i64,
    /// Modification time seconds from `st_mtime`.
    pub mtime_sec: i64,
    /// Modification time nanoseconds from `st_mtime_nsec`.
    pub mtime_nsec: i64,
}

/// Return the owning UID for a filesystem path.
///
/// This performs a `stat(2)` call and returns the owner UID from the resulting
/// metadata. Missing files, permission errors, and invalid path bytes are
/// surfaced as [`CoreError`].
pub fn path_uid(path: impl AsRef<Path>) -> Result<u32, CoreError> {
    Ok(path_stat(path)?.uid)
}

/// Return identity metadata for a filesystem path, following symbolic links.
///
/// This performs a `stat(2)` call and captures the fields used by hot-path
/// procfs callers to detect identity changes cheaply without opening procfs
/// text files.
pub fn path_stat(path: impl AsRef<Path>) -> Result<PathStat, CoreError> {
    stat_path(path.as_ref(), "stat", true)
}

/// Return identity metadata for a filesystem path without following symbolic links.
pub fn path_lstat(path: impl AsRef<Path>) -> Result<PathStat, CoreError> {
    stat_path(path.as_ref(), "lstat", false)
}

/// Return the owning UID for `/proc/<pid>`.
///
/// This is a cheap ownership probe that can be useful before reading procfs
/// files such as `/proc/<pid>/cmdline` in hot paths. Processes may disappear
/// at any time, so callers should treat `ENOENT` as a normal race.
pub fn proc_uid(pid: i32) -> Result<u32, CoreError> {
    proc_uid_at("/proc", pid)
}

/// Return the owning UID for `/proc/<pid>` under an explicit procfs root.
///
/// This is a cheap ownership probe for tests, alternate proc mounts, or
/// callers that need to inspect a procfs tree other than the host `/proc`.
pub fn proc_uid_at(proc_root: impl AsRef<Path>, pid: i32) -> Result<u32, CoreError> {
    Ok(proc_stat_at(proc_root, pid)?.uid)
}

/// Return identity metadata for `/proc/<pid>`.
pub fn proc_stat(pid: i32) -> Result<PathStat, CoreError> {
    proc_stat_at("/proc", pid)
}

/// Return identity metadata for `/proc/<pid>` under an explicit procfs root.
pub fn proc_stat_at(proc_root: impl AsRef<Path>, pid: i32) -> Result<PathStat, CoreError> {
    let path = proc_root.as_ref().join(pid.to_string());
    stat_path(&path, "stat", true)
}

/// Return the effective UID of the current process.
#[inline(always)]
pub fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Change the owner of a path while leaving the group unchanged when `gid` is `None`.
pub fn chown_path(path: impl AsRef<Path>, uid: u32, gid: Option<u32>) -> Result<(), CoreError> {
    let path = CString::new(path.as_ref().as_os_str().as_bytes())
        .map_err(|_| CoreError::sys(libc::EINVAL, "chown"))?;
    let gid = gid.unwrap_or(u32::MAX);
    let ret = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    syscall_ret(ret, "chown")
}

fn stat_path(path: &Path, op: &'static str, follow_symlink: bool) -> Result<PathStat, CoreError> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| CoreError::sys(libc::EINVAL, op))?;
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let ret = if follow_symlink {
        unsafe { libc::stat(path.as_ptr(), &mut stat_buf) }
    } else {
        unsafe { libc::lstat(path.as_ptr(), &mut stat_buf) }
    };
    syscall_ret(ret, op)?;
    Ok(PathStat {
        uid: stat_buf.st_uid,
        inode: stat_buf.st_ino as u64,
        ctime_sec: stat_buf.st_ctime as i64,
        ctime_nsec: stat_buf.st_ctime_nsec as i64,
        mtime_sec: stat_buf.st_mtime as i64,
        mtime_nsec: stat_buf.st_mtime_nsec as i64,
    })
}
