// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Procfs and process-introspection helpers.
//!
//! These functions provide a small, Linux-oriented view into `/proc` for
//! callers that need process names, command lines, UIDs, or clock-tick
//! information without bringing in a broader process-inspection crate.

use crate::CoreError;
use std::path::Path;

/// A snapshot of process status information from procfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcStatus {
    /// Command name of the process.
    pub name: String,
    /// Real UID of the process.
    pub uid: u32,
}

/// Read process status from `/proc/<pid>/status`.
///
pub fn read_proc_status(pid: i32) -> Result<ProcStatus, CoreError> {
    read_proc_status_at("/proc", pid)
}

/// Read process status from an explicit procfs root.
pub fn read_proc_status_at(proc_root: impl AsRef<Path>, pid: i32) -> Result<ProcStatus, CoreError> {
    let path = proc_root.as_ref().join(pid.to_string()).join("status");
    let content = std::fs::read_to_string(path).map_err(|err| io_error(err, "read_proc_status"))?;
    parse_proc_status(&content)
}

/// Read process command line from `/proc/<pid>/cmdline`.
///
/// NUL separators are converted into spaces so the returned string is easier
/// to log or inspect.
pub fn read_proc_cmdline(pid: i32) -> Result<String, CoreError> {
    read_proc_cmdline_at("/proc", pid)
}

/// Read process command line from an explicit procfs root.
///
/// This is useful for tests, alternate proc mounts, or callers that need the
/// same parsing behavior without being hard-wired to `/proc`.
pub fn read_proc_cmdline_at(proc_root: impl AsRef<Path>, pid: i32) -> Result<String, CoreError> {
    let path = proc_root.as_ref().join(pid.to_string()).join("cmdline");
    let bytes = std::fs::read(path).map_err(|err| io_error(err, "read_proc_cmdline"))?;
    Ok(parse_proc_cmdline_bytes(&bytes))
}

pub(crate) fn parse_proc_cmdline_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .replace('\0', " ")
}

/// Parse the contents of a `/proc/<pid>/status` file.
pub fn parse_proc_status(content: &str) -> Result<ProcStatus, CoreError> {
    let mut name = None;
    let mut uid = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u32>().ok());
        }

        if name.is_some() && uid.is_some() {
            break;
        }
    }

    match (name, uid) {
        (Some(name), Some(uid)) => Ok(ProcStatus { name, uid }),
        _ => Err(CoreError::sys(libc::EINVAL, "parse_proc_status")),
    }
}

fn io_error(err: std::io::Error, op: &'static str) -> CoreError {
    CoreError::sys(err.raw_os_error().unwrap_or(libc::EIO), op)
}

/// Return the number of clock ticks per second for the current system.
#[inline(always)]
pub fn clock_ticks_per_second() -> Result<u64, CoreError> {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        Err(CoreError::sys(code, "sysconf(_SC_CLK_TCK)"))
    } else {
        Ok(ticks as u64)
    }
}
