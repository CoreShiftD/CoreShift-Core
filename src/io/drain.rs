// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! High-level process I/O management.
//!
//! This module provides the [`DrainState`] structure, which coordinates the
//! simultaneous reading from process output pipes and writing to process
//! input pipes.
//!
//! This is an advanced helper for callers that already own child-process file
//! descriptors and want non-blocking drain semantics without reimplementing
//! the bookkeeping.

use crate::CoreError;
use crate::io::buffer::{BufferState, ReadState};
use crate::io::writer::WriterState;
use crate::reactor::{Fd, Token};

/// Associates a file descriptor with an optional reactor token.
pub(crate) struct FdSlot {
    /// Token assigned by the reactor for this descriptor.
    pub token: Option<Token>,
    /// The managed file descriptor.
    pub fd: Fd,
}

/// Orchestrates non-blocking process I/O.
///
/// `DrainState` tracks the state of stdin, stdout, and stderr pipes for a
/// single process. It handles the multiplexing of data between these pipes
/// and internal buffers.
///
/// # Example
/// ```no_run
/// # use coreshift_core::io::DrainState;
/// # use coreshift_core::reactor::Reactor;
/// # fn example(mut drain: DrainState<fn(&[u8]) -> bool>, mut reactor: Reactor) -> Result<(), Box<dyn std::error::Error>> {
/// while !drain.is_done() {
///     let mut events = Vec::new();
///     reactor.wait(&mut events, 64, -1)?;
///     for ev in events {
///         // Map event tokens to drain calls...
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[repr(align(64))]
pub struct DrainState<F>
where
    F: FnMut(&[u8]) -> bool,
{
    pub(crate) stdout_slot: Option<FdSlot>,
    pub(crate) stderr_slot: Option<FdSlot>,
    pub(crate) stdin_slot: Option<FdSlot>,

    pub(crate) buffer: BufferState,
    pub(crate) writer: WriterState,

    pub(crate) early_exit: Option<F>,
}

impl<F> DrainState<F>
where
    F: FnMut(&[u8]) -> bool,
{
    /// Initialize a new drain state for the provided descriptors.
    ///
    /// This consumes the descriptors and sets them to non-blocking mode.
    pub fn new(
        stdin_fd: Option<Fd>,
        stdin_buf: Option<Box<[u8]>>,
        stdout_fd: Option<Fd>,
        stderr_fd: Option<Fd>,
        limit: usize,
        early_exit: Option<F>,
    ) -> Result<Self, CoreError> {
        let stdin_slot = if stdin_buf.is_some() {
            if let Some(fd) = stdin_fd {
                fd.set_nonblock()?;
                Some(FdSlot { token: None, fd })
            } else {
                None
            }
        } else {
            None
        };

        let stdout_slot = if let Some(fd) = stdout_fd {
            fd.set_nonblock()?;
            Some(FdSlot { token: None, fd })
        } else {
            None
        };

        let stderr_slot = if let Some(fd) = stderr_fd {
            fd.set_nonblock()?;
            Some(FdSlot { token: None, fd })
        } else {
            None
        };

        Ok(Self {
            stdin_slot,
            stdout_slot,
            stderr_slot,
            buffer: BufferState::new(limit),
            writer: WriterState::new(stdin_buf),
            early_exit,
        })
    }

    /// Returns `true` if all pipes have been closed or fully drained.
    #[inline(always)]
    pub fn is_done(&self) -> bool {
        self.stdin_slot.is_none() && self.stdout_slot.is_none() && self.stderr_slot.is_none()
    }

    /// Perform a non-blocking write to stdin if pending.
    #[inline(always)]
    pub fn write_stdin(&mut self) -> Result<bool, CoreError> {
        let fd = if let Some(s) = &self.stdin_slot {
            &s.fd
        } else {
            return Ok(true);
        };

        let done = self.writer.write_to_fd(fd)?;
        if done {
            self.stdin_slot.take();
            return Ok(true);
        }
        Ok(false)
    }

    /// Perform a non-blocking read from stdout or stderr.
    #[inline(always)]
    pub fn read_fd(&mut self, is_stdout: bool) -> Result<bool, CoreError> {
        let read_state = {
            let slot = if is_stdout {
                &self.stdout_slot
            } else {
                &self.stderr_slot
            };
            let fd = if let Some(s) = slot {
                &s.fd
            } else {
                return Ok(true);
            };
            self.buffer
                .read_from_fd(fd, is_stdout, &mut self.early_exit)?
        };

        if read_state != ReadState::Open {
            if is_stdout {
                self.stdout_slot.take();
                return Ok(true);
            } else {
                self.stderr_slot.take();
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Extract all active slots for cleanup or reactor removal.
    pub(crate) fn take_all_slots(&mut self) -> Vec<FdSlot> {
        let mut slots = Vec::new();
        if let Some(slot) = self.stdin_slot.take() {
            slots.push(slot);
        }
        if let Some(slot) = self.stdout_slot.take() {
            slots.push(slot);
        }
        if let Some(slot) = self.stderr_slot.take() {
            slots.push(slot);
        }
        slots
    }

    pub(crate) fn register_with_reactor(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(mut slot) = self.stdin_slot.take() {
            slot.token = Some(reactor.add(&slot.fd, false, true)?);
            self.stdin_slot = Some(slot);
        }
        if let Some(mut slot) = self.stdout_slot.take() {
            slot.token = Some(reactor.add(&slot.fd, true, false)?);
            self.stdout_slot = Some(slot);
        }
        if let Some(mut slot) = self.stderr_slot.take() {
            slot.token = Some(reactor.add(&slot.fd, true, false)?);
            self.stderr_slot = Some(slot);
        }
        Ok(())
    }

    pub(crate) fn stdout_matches(&self, token: Token) -> bool {
        self.stdout_slot
            .as_ref()
            .is_some_and(|slot| slot.token == Some(token))
    }

    pub(crate) fn stderr_matches(&self, token: Token) -> bool {
        self.stderr_slot
            .as_ref()
            .is_some_and(|slot| slot.token == Some(token))
    }

    pub(crate) fn stdin_matches(&self, token: Token) -> bool {
        self.stdin_slot
            .as_ref()
            .is_some_and(|slot| slot.token == Some(token))
    }

    pub(crate) fn drop_stdout(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = self.stdout_slot.take() {
            reactor.del(&slot.fd)?;
        }
        Ok(())
    }

    pub(crate) fn drop_stderr(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = self.stderr_slot.take() {
            reactor.del(&slot.fd)?;
        }
        Ok(())
    }

    pub(crate) fn drop_stdin(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = self.stdin_slot.take() {
            reactor.del(&slot.fd)?;
        }
        self.writer.buf = None;
        Ok(())
    }

    pub(crate) fn handle_stdout_ready(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = &self.stdout_slot {
            let read_state = self
                .buffer
                .read_from_fd(&slot.fd, true, &mut self.early_exit)?;
            if read_state != ReadState::Open {
                self.drop_stdout(reactor)?;
            }
        }
        Ok(())
    }

    pub(crate) fn handle_stderr_ready(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = &self.stderr_slot {
            let read_state = self
                .buffer
                .read_from_fd(&slot.fd, false, &mut self.early_exit)?;
            if read_state != ReadState::Open {
                self.drop_stderr(reactor)?;
            }
        }
        Ok(())
    }

    pub(crate) fn handle_stdin_writable(
        &mut self,
        reactor: &mut crate::reactor::Reactor,
    ) -> Result<(), CoreError> {
        if let Some(slot) = &self.stdin_slot {
            let done = self.writer.write_to_fd(&slot.fd)?;
            if done {
                self.drop_stdin(reactor)?;
            }
        }
        Ok(())
    }

    /// Consume the state and return (stdout, stderr) buffers.
    pub fn into_parts(mut self) -> (Vec<u8>, Vec<u8>) {
        let (stdout, stderr, _, _) = std::mem::take(&mut self.buffer).into_parts();
        (stdout, stderr)
    }

    /// Return whether the combined stdout+stderr output limit was exceeded.
    #[inline(always)]
    pub fn output_limit_exceeded(&self) -> bool {
        self.buffer.output_limit_exceeded()
    }

    /// Return whether stdout was explicitly stopped by the early-exit predicate.
    #[inline(always)]
    pub fn stdout_early_exited(&self) -> bool {
        self.buffer.stdout_early_exited()
    }

    /// Consume the state and return buffers plus drain flags.
    pub(crate) fn into_parts_with_state(mut self) -> (Vec<u8>, Vec<u8>, bool, bool) {
        std::mem::take(&mut self.buffer).into_parts()
    }
}
