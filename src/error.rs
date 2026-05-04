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
        op: String,
    },
}

impl CoreError {
    /// Construct a new syscall error.
    pub fn sys(code: i32, op: &str) -> Self {
        Self::Syscall {
            code,
            op: op.to_string(),
        }
    }

    /// Return the raw OS error code if applicable.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Syscall { code, .. } => Some(*code),
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
        }
    }
}

impl std::error::Error for CoreError {}

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
