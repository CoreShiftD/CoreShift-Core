// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Shared low-level error types.
//!
//! [`CoreError`] is the crate-wide error for Linux and Android primitive
//! operations. It intentionally stays small: low-level modules surface the
//! syscall that failed and the raw OS error code, while callers decide how
//! much policy or recovery to layer on top.

use std::fmt;

/// Error type for low-level system operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A syscall or libc-style operation failed with the specified OS error.
    Syscall {
        /// The raw OS error code.
        code: i32,
        /// The name of the failed operation.
        op: &'static str,
    },
    /// An NDK binder operation failed with the specified status code.
    Binder {
        /// The NDK binder status code (`binder_status_t`).
        code: i32,
        /// The name of the failed operation.
        op: &'static str,
    },
}

impl CoreError {
    /// Construct a new syscall error.
    pub fn sys(code: i32, op: &'static str) -> Self {
        Self::Syscall { code, op }
    }

    /// Construct a new binder error.
    pub fn binder(code: i32, op: &'static str) -> Self {
        Self::Binder { code, op }
    }

    /// Return the raw OS error code if applicable.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Syscall { code, .. } => Some(*code),
            Self::Binder { .. } => None,
        }
    }

    /// Convert this low-level error into a standard I/O error.
    pub fn to_io_error(&self) -> std::io::Error {
        std::io::Error::from_raw_os_error(self.raw_os_error().unwrap_or(libc::EIO))
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall { code, op } => write!(f, "{op} failed (code={code})"),
            Self::Binder { code, op } => write!(f, "binder {op} failed (status={code})"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Common errno constants, re-exported so callers need not depend on `libc`.
pub mod errno {
    pub const EADDRINUSE: i32 = libc::EADDRINUSE;
    pub const EPIPE: i32      = libc::EPIPE;
    pub const EAGAIN: i32     = libc::EAGAIN;
    pub const EINTR: i32      = libc::EINTR;
    pub const ENOENT: i32     = libc::ENOENT;
    pub const EACCES: i32     = libc::EACCES;
}

#[inline(always)]
pub(crate) fn syscall_ret(ret: i32, op: &'static str) -> Result<(), CoreError> {
    if ret == -1 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Err(CoreError::sys(code, op))
    } else {
        Ok(())
    }
}

#[inline(always)]
pub(crate) fn posix_ret(ret: i32, op: &'static str) -> Result<(), CoreError> {
    if ret != 0 {
        Err(CoreError::sys(ret, op))
    } else {
        Ok(())
    }
}
