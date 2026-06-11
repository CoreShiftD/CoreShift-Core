// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Raw inotify helpers.
//!
//! This module provides low-level interaction with the Linux `inotify` subsystem.
//! It handles the initialization of watches, reading of raw events, and
//! decoding of the packed event stream.
//!
//! Higher-level modules should use these primitives to monitor configuration
//! files, log directories, or process markers.
//! The API stays close to kernel behavior and does only minimal decoding.

use crate::CoreError;
use crate::error::syscall_ret;
use crate::reactor::Fd;

/// A decoded inotify event header.
///
/// This structure represents an `inotify_event` including its optional name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InotifyEvent {
    /// Watch descriptor that generated this event.
    pub wd: i32,
    /// Event mask (e.g., [`MODIFY_MASK`]).
    pub mask: u32,
    /// Optional raw name bytes associated with the event.
    ///
    /// Inotify names are arbitrary bytes except for the NUL terminator. Callers
    /// decide whether and how to interpret them as text.
    pub name: Option<Vec<u8>>,
}

/// File was modified (`IN_MODIFY`).
pub const MODIFY_MASK: u32 = libc::IN_MODIFY;
/// Mask for monitoring package file state changes (`IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF`).
pub const PACKAGE_FILE_MASK: u32 = libc::IN_MODIFY | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
/// Mask for monitoring parent directories that may create, replace, or remove a watched file.
/// Maps to `IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE | IN_MODIFY | IN_DELETE_SELF | IN_MOVE_SELF`.
pub const PARENT_WATCH_MASK: u32 = libc::IN_CREATE
    | libc::IN_MOVED_TO
    | libc::IN_CLOSE_WRITE
    | libc::IN_MODIFY
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;
/// Inotify event queue overflowed (`IN_Q_OVERFLOW`).
pub const QUEUE_OVERFLOW_MASK: u32 = libc::IN_Q_OVERFLOW;
/// Watch was removed (`IN_IGNORED`).
pub const IGNORED_MASK: u32 = libc::IN_IGNORED;
/// Filesystem containing watched object was unmounted (`IN_UNMOUNT`).
pub const UNMOUNT_MASK: u32 = libc::IN_UNMOUNT;
/// Watched file/directory was deleted (`IN_DELETE_SELF`).
pub const DELETE_SELF_MASK: u32 = libc::IN_DELETE_SELF;
/// Watched file/directory was moved (`IN_MOVE_SELF`).
pub const MOVE_SELF_MASK: u32 = libc::IN_MOVE_SELF;

/// Create a non-blocking close-on-exec inotify file descriptor.
///
/// The descriptor is created with `IN_CLOEXEC` and `IN_NONBLOCK` set.
///
/// ### Fork Safety
/// The descriptor is `O_CLOEXEC` and will be closed in the child after `exec`.
///
/// ### Errors
/// - `EMFILE`: Process limit on open file descriptors hit.
/// - `ENFILE`: System-wide limit on open files hit.
/// - `ENOMEM`: Insufficient kernel memory.
pub fn init() -> Result<Fd, CoreError> {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    syscall_ret(fd, "inotify_init1")?;
    Fd::new(fd, "inotify_init1")
}

/// Add a watch to an existing inotify instance.
///
/// # Arguments
/// * `fd` - The inotify file descriptor.
/// * `path` - Path to the file or directory to watch.
/// * `mask` - Events to monitor (e.g., [`MODIFY_MASK`]).
///
/// ### Errors
/// - `EACCES`: Read access to the path is denied.
/// - `EBADF`: The provided file descriptor is invalid.
/// - `EINVAL`: The mask contains invalid bits or the path is invalid.
/// - `ENOENT`: A component of the path does not exist.
/// - `ENOSPC`: The user limit on the total number of inotify watches was reached.
/// - `ENOMEM`: Insufficient kernel memory.
pub fn add_watch(fd: &Fd, path: &str, mask: u32) -> Result<i32, CoreError> {
    let path = std::ffi::CString::new(path)
        .map_err(|_| CoreError::sys(libc::EINVAL, "inotify path contains nul"))?;
    let wd = unsafe { libc::inotify_add_watch(fd.raw(), path.as_ptr(), mask) };
    if wd < 0 {
        return Err(CoreError::sys(
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
            "inotify_add_watch",
        ));
    }
    Ok(wd)
}

/// Remove an existing watch descriptor from an inotify instance.
///
/// ### Errors
/// - `EBADF`: The provided file descriptor is invalid.
/// - `EINVAL`: The watch descriptor `wd` is invalid for this inotify instance.
pub fn remove_watch(fd: &Fd, wd: i32) -> Result<(), CoreError> {
    #[cfg(target_os = "android")]
    let raw_wd = u32::try_from(wd).map_err(|_| CoreError::sys(libc::EINVAL, "inotify_rm_watch"))?;

    #[cfg(not(target_os = "android"))]
    let raw_wd = wd;

    let ret = unsafe { libc::inotify_rm_watch(fd.raw(), raw_wd) };
    syscall_ret(ret, "inotify_rm_watch")
}

/// Read all available inotify events from the descriptor.
///
/// This function drains the inotify file descriptor until no more events
/// are available (`EAGAIN`). It is safe to use with edge-triggered reactors.
///
/// ### Edge Cases
/// - **Zero-length read**: If the descriptor is non-blocking and no data is
///   ready, this returns `Ok(Vec::new())` (via `EAGAIN` mapping).
/// - **Partial read**: This function ensures that only complete event
///   structures are decoded from the buffer.
///
/// ### Errors
/// - `EBADF`: The provided file descriptor is invalid.
/// - `EFAULT`: The internal buffer points outside the process's address space.
/// - `EINVAL`: Internal buffer is too small for even one event (should not happen).
/// - `EIO`: Low-level I/O error.
pub fn read_events(fd: &Fd) -> Result<Vec<InotifyEvent>, CoreError> {
    let mut all_events = Vec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match fd.read_slice(&mut buf) {
            Ok(Some(0)) => break,
            Ok(Some(n)) => {
                all_events.extend(decode_events(&buf[..n])?);
            }
            Ok(None) => break, // EAGAIN
            Err(e) => return Err(e),
        }
    }

    Ok(all_events)
}

/// Decode packed inotify events from a raw byte buffer.
///
/// This handles multi-event buffers and handles unaligned reads safely.
/// Malformed or truncated events result in an error.
pub fn decode_events(buf: &[u8]) -> Result<Vec<InotifyEvent>, CoreError> {
    let mut events = Vec::new();
    let mut offset = 0;
    let base = std::mem::size_of::<libc::inotify_event>();

    while offset + base <= buf.len() {
        // SAFETY: We have at least 'base' bytes. We use read_unaligned to
        // handle potential alignment issues in the raw buffer.
        let event: libc::inotify_event = unsafe {
            std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::inotify_event)
        };

        let Some(size) = base.checked_add(event.len as usize) else {
            return Err(CoreError::sys(libc::EINVAL, "decode_inotify_event"));
        };
        if offset + size > buf.len() {
            return Err(CoreError::sys(libc::EINVAL, "decode_inotify_event"));
        }

        let name = if event.len > 0 {
            let name_buf = &buf[offset + base..offset + base + event.len as usize];
            // Name is null-terminated, but may have multiple trailing nulls for padding.
            name_buf.split(|&b| b == 0).next().map(|s| s.to_vec())
        } else {
            None
        };

        events.push(InotifyEvent {
            wd: event.wd,
            mask: event.mask,
            name,
        });
        offset += size;
    }

    if offset != buf.len() {
        return Err(CoreError::sys(libc::EINVAL, "decode_inotify_event"));
    }

    Ok(events)
}
