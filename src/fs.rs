// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Filesystem-oriented low-level helpers.
//!
//! This module contains lightweight Linux and Android file probes and helpers
//! that are useful near the OS boundary, including path existence checks and
//! page-cache read-ahead hints.

use crate::CoreError;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::UNIX_EPOCH;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathFingerprint {
    pub len: u64,
    pub modified_ns: u128,
}

pub fn path_fingerprint(path: &Path) -> Result<PathFingerprint, CoreError> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        CoreError::sys(err.raw_os_error().unwrap_or(libc::EIO), "path_fingerprint")
    })?;
    let modified_ns = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    Ok(PathFingerprint {
        len: metadata.len(),
        modified_ns,
    })
}

/// Probe whether a filesystem path is accessible and exists.
///
/// NOTE: This follows symbolic links. It uses `libc::access` with `F_OK`
/// so the check is a single syscall with no Rust allocator involvement.
/// Returns `true` if the path is accessible or visible, `false` on any error
/// (including `ENOENT`, `EACCES`, or invalid path bytes).
pub fn path_exists(path: &str) -> bool {
    match std::ffi::CString::new(path) {
        Ok(c) => unsafe { libc::access(c.as_ptr(), libc::F_OK) == 0 },
        Err(_) => false,
    }
}

/// Probe whether a path exists without following symbolic links.
///
/// Returns `true` if the path exists, including a dangling symlink.
pub fn path_lstat_exists(path: &str) -> bool {
    match std::ffi::CString::new(path) {
        Ok(c) => unsafe {
            let mut stat = std::mem::zeroed();
            libc::lstat(c.as_ptr(), &mut stat) == 0
        },
        Err(_) => false,
    }
}

/// Read a file into a string.
///
/// This stays as a small convenience helper for low-level modules that treat
/// blocking filesystem or procfs reads as an acceptable boundary cost.
pub fn read_to_string(path: &str) -> Result<String, CoreError> {
    std::fs::read_to_string(path)
        .map_err(|err| CoreError::sys(err.raw_os_error().unwrap_or(libc::EIO), "read_to_string"))
}

/// Advise the kernel to begin reading file data into the page cache.
///
/// This is an advisory hint only. It can help warm likely-needed file ranges,
/// but the kernel may ignore the request, perform only part of it, or return
/// before the data is fully resident in memory.
///
/// The `offset` and `len` identify the byte range to prefetch for `fd`.
/// Success means the kernel accepted the request, not that subsequent reads
/// are guaranteed to be cache hits.
pub fn readahead(fd: impl AsRawFd, offset: u64, len: usize) -> Result<(), CoreError> {
    readahead_raw(fd.as_raw_fd(), offset, len)
}

/// Map a file range, advise the kernel that it will be needed, then unmap it.
///
/// `offset` must be page-aligned. This low-level primitive rejects unaligned
/// offsets with `EINVAL` instead of silently widening the requested range.
pub fn mmap_madvise(
    fd: impl AsRawFd,
    offset: u64,
    len: usize,
    touch: bool,
) -> Result<(), CoreError> {
    mmap_madvise_raw(fd.as_raw_fd(), offset, len, touch)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn mmap_madvise_raw(
    fd: libc::c_int,
    offset: u64,
    len: usize,
    touch: bool,
) -> Result<(), CoreError> {
    if len == 0 {
        return Ok(());
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(CoreError::sys(libc::EINVAL, "sysconf(_SC_PAGESIZE)"));
    }
    let page_size = page_size as u64;
    if offset % page_size != 0 || offset > libc::off_t::MAX as u64 {
        return Err(CoreError::sys(libc::EINVAL, "mmap"));
    }

    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            offset as libc::off_t,
        )
    };
    if ptr == libc::MAP_FAILED {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CoreError::sys(code, "mmap"));
    }

    let result = if unsafe { libc::madvise(ptr, len, libc::MADV_WILLNEED) } == -1 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Err(CoreError::sys(code, "madvise"))
    } else {
        if touch {
            let mut pos = 0usize;
            let page_size = page_size as usize;
            while pos < len {
                unsafe {
                    std::ptr::read_volatile((ptr as *const u8).add(pos));
                }
                pos = pos.saturating_add(page_size);
            }
        }
        Ok(())
    };

    if unsafe { libc::munmap(ptr, len) } == -1 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(CoreError::sys(code, "munmap"));
    }
    result
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn mmap_madvise_raw(
    _fd: libc::c_int,
    _offset: u64,
    _len: usize,
    _touch: bool,
) -> Result<(), CoreError> {
    Err(CoreError::sys(libc::ENOSYS, "mmap"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn readahead_raw(fd: libc::c_int, offset: u64, len: usize) -> Result<(), CoreError> {
    if offset > libc::off64_t::MAX as u64 {
        return Err(CoreError::sys(libc::EINVAL, "readahead"));
    }

    let count = len as libc::size_t;
    let offset = offset as libc::off64_t;

    loop {
        let ret = unsafe { libc::syscall(readahead_syscall_number(), fd, offset, count) };
        if ret == -1 {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if code == libc::EINTR {
                continue;
            }
            return Err(CoreError::sys(code, "readahead"));
        }
        return Ok(());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn readahead_raw(_fd: libc::c_int, _offset: u64, _len: usize) -> Result<(), CoreError> {
    Err(CoreError::sys(libc::ENOSYS, "readahead"))
}

#[cfg(target_os = "linux")]
#[inline(always)]
const fn readahead_syscall_number() -> libc::c_long {
    libc::SYS_readahead
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
#[inline(always)]
const fn readahead_syscall_number() -> libc::c_long {
    213
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(always)]
const fn readahead_syscall_number() -> libc::c_long {
    225
}

#[cfg(all(target_os = "android", target_arch = "x86_64"))]
#[inline(always)]
const fn readahead_syscall_number() -> libc::c_long {
    187
}

#[cfg(all(target_os = "android", target_arch = "x86"))]
#[inline(always)]
const fn readahead_syscall_number() -> libc::c_long {
    225
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn test_readahead_syscall_number_linux_matches_libc() {
        assert_eq!(super::readahead_syscall_number(), libc::SYS_readahead);
    }

    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    #[test]
    fn test_readahead_syscall_number_android_aarch64() {
        assert_eq!(super::readahead_syscall_number(), 213);
    }

    #[cfg(all(target_os = "android", target_arch = "arm"))]
    #[test]
    fn test_readahead_syscall_number_android_arm() {
        assert_eq!(super::readahead_syscall_number(), 225);
    }

    #[cfg(all(target_os = "android", target_arch = "x86_64"))]
    #[test]
    fn test_readahead_syscall_number_android_x86_64() {
        assert_eq!(super::readahead_syscall_number(), 187);
    }

    #[cfg(all(target_os = "android", target_arch = "x86"))]
    #[test]
    fn test_readahead_syscall_number_android_x86() {
        assert_eq!(super::readahead_syscall_number(), 225);
    }
}
