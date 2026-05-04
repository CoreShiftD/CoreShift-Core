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

/// File was modified.
pub const MODIFY_MASK: u32 = libc::IN_MODIFY;
/// Mask for monitoring package file state changes.
pub const PACKAGE_FILE_MASK: u32 = libc::IN_MODIFY | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF;
/// Mask for monitoring parent directories that may create, replace, or remove a watched file.
pub const PARENT_WATCH_MASK: u32 = libc::IN_CREATE
    | libc::IN_MOVED_TO
    | libc::IN_CLOSE_WRITE
    | libc::IN_MODIFY
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF;
/// Inotify event queue overflowed.
pub const QUEUE_OVERFLOW_MASK: u32 = libc::IN_Q_OVERFLOW;
/// Watch was removed (explicitly or because file was deleted).
pub const IGNORED_MASK: u32 = libc::IN_IGNORED;
/// Filesystem containing watched object was unmounted.
pub const UNMOUNT_MASK: u32 = libc::IN_UNMOUNT;
/// Watched file/directory was deleted.
pub const DELETE_SELF_MASK: u32 = libc::IN_DELETE_SELF;
/// Watched file/directory was moved.
pub const MOVE_SELF_MASK: u32 = libc::IN_MOVE_SELF;

/// Create a non-blocking close-on-exec inotify file descriptor.
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
/// # Errors
/// Returns [`CoreError`] if `inotify_add_watch` fails or if the path contains a NUL byte.
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
/// # Errors
/// Returns [`CoreError`] if a `read` syscall fails (excluding `EAGAIN`/`EWOULDBLOCK`).
pub fn read_events(fd: &Fd) -> Result<Vec<InotifyEvent>, CoreError> {
    let mut all_events = Vec::new();
    let mut buf = vec![0u8; 4096];

    loop {
        match fd.read_slice(&mut buf) {
            Ok(Some(0)) => break,
            Ok(Some(n)) => {
                all_events.extend(decode_events_checked(&buf[..n])?);
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
/// Truncated events at the end of the buffer are ignored.
pub fn decode_events(buf: &[u8]) -> Vec<InotifyEvent> {
    decode_events_lenient(buf)
}

/// Decode packed inotify events and reject malformed trailing data.
pub fn decode_events_checked(buf: &[u8]) -> Result<Vec<InotifyEvent>, CoreError> {
    decode_events_inner(buf, true)
}

fn decode_events_lenient(buf: &[u8]) -> Vec<InotifyEvent> {
    decode_events_inner(buf, false).unwrap_or_default()
}

fn decode_events_inner(buf: &[u8], checked: bool) -> Result<Vec<InotifyEvent>, CoreError> {
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
            if checked {
                return Err(CoreError::sys(libc::EINVAL, "decode_inotify_event"));
            } else {
                break;
            }
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

    if checked && offset != buf.len() {
        return Err(CoreError::sys(libc::EINVAL, "decode_inotify_event"));
    }

    Ok(events)
}
