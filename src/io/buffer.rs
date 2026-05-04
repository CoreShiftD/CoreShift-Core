// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Asynchronous I/O buffering.
//!
//! This module provides the [`BufferState`] structure which accumulates
//! stdout and stderr data from monitored processes.

use crate::CoreError;
use crate::reactor::Fd;

const READ_CHUNK: usize = 65536;

/// Accumulates output from process streams.
///
/// `BufferState` manages the collection of bytes from stdout and stderr pipes.
/// It enforces a combined memory limit to prevent runaway memory usage by
/// misbehaving processes.
#[derive(Default)]
#[repr(align(64))]
pub(crate) struct BufferState {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    limit: usize,
    output_limit_exceeded: bool,
    stdout_early_exited: bool,
}

/// Result of one non-blocking drain attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadState {
    /// The descriptor would block before EOF.
    Open,
    /// Kernel EOF was reached.
    Eof,
    /// The caller-provided early-exit predicate requested stdout shutdown.
    EarlyExit,
}

impl BufferState {
    /// Create a new buffer state with the specified memory limit.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            stdout: Vec::with_capacity(1024),
            stderr: Vec::with_capacity(1024),
            limit,
            output_limit_exceeded: false,
            stdout_early_exited: false,
        }
    }

    /// Drain available data from a file descriptor into internal storage.
    ///
    /// # Returns
    /// * `Ok(ReadState::Eof)` if EOF was reached.
    /// * `Ok(ReadState::EarlyExit)` if stdout matched the early-exit callback.
    /// * `Ok(ReadState::Open)` if the operation would block (`EAGAIN`).
    #[inline(always)]
    pub(crate) fn read_from_fd(
        &mut self,
        fd: &Fd,
        is_stdout: bool,
        early_exit: &mut Option<impl FnMut(&[u8]) -> bool>,
    ) -> Result<ReadState, CoreError> {
        loop {
            let current_total = self.stdout.len().saturating_add(self.stderr.len());
            let remaining_limit = self.limit.saturating_sub(current_total);

            if remaining_limit == 0 {
                let mut drop_buf = [0u8; 8192];
                match fd.read_slice(&mut drop_buf) {
                    Ok(Some(n)) if n > 0 => {
                        self.output_limit_exceeded = true;
                        continue;
                    }
                    Ok(Some(_)) => return Ok(ReadState::Eof),
                    Ok(None) => return Ok(ReadState::Open),
                    Err(e) => return Err(e),
                }
            }

            let dest = if is_stdout {
                &mut self.stdout
            } else {
                &mut self.stderr
            };
            let len = dest.len();

            // Ensure space and read directly into the Vec.
            // We resize with 0s to remain safe (no UB with uninitialized memory).
            let to_read = remaining_limit.min(READ_CHUNK);
            dest.resize(len + to_read, 0);

            match fd.read_slice(&mut dest[len..len + to_read]) {
                Ok(Some(n)) if n > 0 => {
                    dest.truncate(len + n);

                    if is_stdout
                        && let Some(f) = early_exit
                        && f(&dest[len..len + n])
                    {
                        self.stdout_early_exited = true;
                        return Ok(ReadState::EarlyExit);
                    }
                }
                Ok(Some(_)) => {
                    dest.truncate(len);
                    return Ok(ReadState::Eof);
                }
                Ok(None) => {
                    dest.truncate(len);
                    return Ok(ReadState::Open);
                }
                Err(e) => {
                    dest.truncate(len);
                    return Err(e);
                }
            }
        }
    }

    /// Return whether the combined stdout+stderr output limit was exceeded.
    #[inline(always)]
    pub(crate) fn output_limit_exceeded(&self) -> bool {
        self.output_limit_exceeded
    }

    /// Return whether stdout was closed by the early-exit predicate.
    #[inline(always)]
    pub(crate) fn stdout_early_exited(&self) -> bool {
        self.stdout_early_exited
    }

    /// Consume the state and return the accumulated buffers.
    pub(crate) fn into_parts(mut self) -> (Vec<u8>, Vec<u8>, bool, bool) {
        (
            std::mem::take(&mut self.stdout),
            std::mem::take(&mut self.stderr),
            self.output_limit_exceeded,
            self.stdout_early_exited,
        )
    }
}
