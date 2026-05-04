// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Asynchronous I/O writing.
//!
//! This module provides the [`WriterState`] structure which handles
//! non-blocking writes of stdin buffers to monitored processes.

use crate::CoreError;
use crate::reactor::Fd;

const WRITE_CHUNK: usize = 65536;

/// Manages the transmission of a fixed buffer to a pipe.
pub(crate) struct WriterState {
    pub(crate) buf: Option<Box<[u8]>>,
    off: usize,
}

impl WriterState {
    /// Create a new writer state for the specified buffer.
    pub(crate) fn new(buf: Option<Box<[u8]>>) -> Self {
        Self { buf, off: 0 }
    }

    /// Write as much data as possible to the specified descriptor.
    ///
    /// # Returns
    /// * `Ok(true)` if the entire buffer has been written or the pipe is closed.
    /// * `Ok(false)` if the operation would block (`EAGAIN`).
    #[inline(always)]
    pub(crate) fn write_to_fd(&mut self, fd: &Fd) -> Result<bool, CoreError> {
        if let Some(buf) = &self.buf {
            while self.off < buf.len() {
                let remaining = buf.len() - self.off;
                let chunk = remaining.min(WRITE_CHUNK);

                match fd.write_slice(&buf[self.off..self.off + chunk]) {
                    Ok(Some(n)) if n > 0 => {
                        self.off += n;
                    }
                    Ok(Some(_)) => {
                        self.buf = None;
                        return Ok(true); // Done
                    }
                    Ok(None) => {
                        return Ok(false); // Would block
                    }
                    Err(e) => {
                        let CoreError::Syscall { code, .. } = &e;
                        if *code == libc::EPIPE {
                            self.buf = None;
                            return Ok(true); // Broken pipe (treat as end of write stream)
                        } else {
                            self.buf = None;
                            return Err(e); // Propagate actual error
                        }
                    }
                }
            }
            // Done writing
            self.buf = None;
            return Ok(true);
        }
        Ok(true)
    }
}
