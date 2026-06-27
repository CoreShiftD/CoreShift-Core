// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Netlink socket helpers.
//!
//! Provides a non-blocking `NETLINK_KOBJECT_UEVENT` socket for receiving
//! kernel uevents (power supply changes, hotplug events, etc.).

use crate::CoreError;
use crate::reactor::Fd;

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    pub fn uevent_open() -> Result<Fd, CoreError> {
        unsafe {
            let fd = libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_KOBJECT_UEVENT,
            );
            if fd < 0 {
                return Err(CoreError::sys(errno(), "netlink socket"));
            }
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_pid    = 0;
            addr.nl_groups = 1; // UGRP_KERNEL — all uevents
            let r = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if r < 0 {
                libc::close(fd);
                return Err(CoreError::sys(errno(), "netlink bind"));
            }
            Fd::from_owned_raw_fd(fd, "netlink_uevent")
        }
    }

    pub fn uevent_recv_raw(fd: &Fd, buf: &mut [u8]) -> Option<usize> {
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n > 0 { Some(n as usize) } else { None }
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use super::*;

    pub fn uevent_open() -> Result<Fd, CoreError> {
        Err(CoreError::sys(libc::ENOSYS, "netlink uevent: android only"))
    }

    pub fn uevent_recv_raw(_fd: &Fd, _buf: &mut [u8]) -> Option<usize> {
        None
    }
}

/// Open a non-blocking `NETLINK_KOBJECT_UEVENT` socket bound to all kernel groups.
///
/// ### Errors
/// - `EMFILE` / `ENFILE`: File descriptor limit hit.
/// - `ENOMEM`: Insufficient kernel memory.
/// - `EPERM`: Insufficient privilege to bind to the multicast group.
pub fn uevent_open() -> Result<Fd, CoreError> {
    imp::uevent_open()
}

/// Drain all pending uevent messages; return the last `power_supply` event seen.
///
/// Returns `(capacity, status)` where `capacity` is `None` if `POWER_SUPPLY_CAPACITY`
/// was absent from the uevent (caller should fall back to sysfs).
/// Returns `None` if the queue contained no `power_supply` events at all.
/// Must be called in a loop after `EPOLLET` fires to drain the edge-triggered fd.
pub fn uevent_drain_battery(fd: &Fd) -> Option<(Option<u8>, String)> {
    let mut result: Option<(Option<u8>, String)> = None;
    let mut buf = [0u8; 4096];
    loop {
        match imp::uevent_recv_raw(fd, &mut buf) {
            None => break,
            Some(n) => {
                if let Some(batt) = parse_battery(&buf[..n]) {
                    result = Some(batt);
                }
            }
        }
    }
    result
}

/// Receive one raw uevent message. Returns the number of bytes written into `buf`,
/// or `None` if no message is pending (`EAGAIN`).
pub fn uevent_recv(fd: &Fd, buf: &mut [u8]) -> Option<usize> {
    imp::uevent_recv_raw(fd, buf)
}

fn parse_battery(msg: &[u8]) -> Option<(Option<u8>, String)> {
    let parts: Vec<&str> = msg
        .split(|&b| b == 0)
        .filter_map(|s| std::str::from_utf8(s).ok())
        .filter(|s| !s.is_empty())
        .collect();

    if !parts.iter().any(|s| *s == "SUBSYSTEM=power_supply") {
        return None;
    }

    let cap = parts.iter()
        .find_map(|s| s.strip_prefix("POWER_SUPPLY_CAPACITY="))
        .and_then(|v| v.parse::<u8>().ok());

    let status = parts.iter()
        .find_map(|s| s.strip_prefix("POWER_SUPPLY_STATUS="))
        .unwrap_or("Unknown")
        .to_string();

    Some((cap, status))
}
