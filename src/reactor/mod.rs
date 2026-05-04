// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Asynchronous event reactor.
//!
//! This module provides a lightweight wrapper around Linux `epoll` for
//! multiplexing I/O events. It is optimized for edge-triggered monitoring.
//! It is intentionally explicit about Linux readiness semantics rather than
//! hiding them behind a higher-level async runtime abstraction.

use crate::CoreError;
use crate::error::syscall_ret;
use std::io::Error as IoError;
use std::time::Duration;

#[inline(always)]
fn errno() -> i32 {
    IoError::last_os_error().raw_os_error().unwrap_or(0)
}

/// An owned file descriptor that closes on drop.
///
/// `Fd` is move-only. Constructing one from a raw descriptor transfers close
/// ownership to `Fd`; do not also close the raw descriptor elsewhere.
pub struct Fd(RawFd);

use std::os::unix::io::{AsRawFd, RawFd};

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Fd {
    /// Wrap a raw file descriptor.
    ///
    /// # Errors
    /// Returns a [`CoreError`] if the descriptor is negative.
    #[inline(always)]
    pub(crate) fn new(fd: RawFd, op: &'static str) -> Result<Self, CoreError> {
        if fd < 0 {
            Err(CoreError::sys(errno(), op))
        } else {
            Ok(Self(fd))
        }
    }

    /// Wrap an owned raw file descriptor.
    ///
    /// # Safety
    /// The caller must guarantee `fd` is valid, open, and uniquely owned by the
    /// returned `Fd`. Passing a borrowed fd, or closing `fd` after this call,
    /// can cause double-close or use-after-close bugs.
    #[inline(always)]
    pub unsafe fn from_owned_raw_fd(fd: RawFd, op: &'static str) -> Result<Self, CoreError> {
        Self::new(fd, op)
    }

    /// Create a non-blocking `eventfd`.
    pub fn eventfd(init: u32) -> Result<Self, CoreError> {
        let fd = unsafe { libc::eventfd(init, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        syscall_ret(fd, "eventfd")?;
        Self::new(fd, "eventfd")
    }

    /// Create a non-blocking `timerfd` using `CLOCK_MONOTONIC`.
    pub fn timerfd() -> Result<Self, CoreError> {
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
            )
        };
        syscall_ret(fd, "timerfd_create")?;
        Self::new(fd, "timerfd_create")
    }

    /// Access the underlying raw file descriptor.
    ///
    /// NOTE: This is an escape hatch for low-level interactions. Prefer using
    /// the safe methods on `Fd` or implementing `AsRawFd`.
    #[inline(always)]
    pub(crate) fn raw(&self) -> RawFd {
        self.0
    }

    /// Perform a `dup2` syscall.
    pub fn dup2(&self, target: RawFd) -> Result<(), CoreError> {
        loop {
            let r = unsafe { libc::dup2(self.0, target) };
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return syscall_ret(r, "dup2");
            }
            return Ok(());
        }
    }

    /// Set the `O_NONBLOCK` flag on the descriptor.
    pub fn set_nonblock(&self) -> Result<(), CoreError> {
        let flags = unsafe { libc::fcntl(self.0, libc::F_GETFL) };
        syscall_ret(flags, "fcntl(F_GETFL)")?;
        let r = unsafe { libc::fcntl(self.0, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        syscall_ret(r, "fcntl(F_SETFL)")
    }

    /// Set the `FD_CLOEXEC` flag on the descriptor.
    pub fn set_cloexec(&self) -> Result<(), CoreError> {
        let flags = unsafe { libc::fcntl(self.0, libc::F_GETFD) };
        syscall_ret(flags, "fcntl(F_GETFD)")?;
        let r = unsafe { libc::fcntl(self.0, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        syscall_ret(r, "fcntl(F_SETFD)")
    }

    /// Read bytes into a mutable slice.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub fn read_slice(&self, buf: &mut [u8]) -> Result<Option<usize>, CoreError> {
        self.read_raw(buf.as_mut_ptr(), buf.len())
    }

    /// Write bytes from a slice.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub fn write_slice(&self, buf: &[u8]) -> Result<Option<usize>, CoreError> {
        self.write_raw(buf.as_ptr(), buf.len())
    }

    /// Read a native-endian `u64`.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub fn read_u64(&self) -> Result<Option<u64>, CoreError> {
        let mut bytes = [0u8; std::mem::size_of::<u64>()];
        match self.read_slice(&mut bytes)? {
            Some(n) if n == bytes.len() => Ok(Some(u64::from_ne_bytes(bytes))),
            Some(_) => Err(CoreError::sys(libc::EIO, "read_u64")),
            None => Ok(None),
        }
    }

    /// Write a native-endian `u64`.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub fn write_u64(&self, value: u64) -> Result<Option<usize>, CoreError> {
        self.write_slice(&value.to_ne_bytes())
    }

    /// Arm or disarm a one-shot `timerfd`.
    ///
    /// Passing `None` disarms the timer. Zero durations are rounded up to one
    /// nanosecond so the timer still expires.
    pub fn set_timer_oneshot(&self, delay: Option<Duration>) -> Result<(), CoreError> {
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        if let Some(delay) = delay {
            let delay = delay.max(Duration::from_nanos(1));
            spec.it_value.tv_sec = delay.as_secs() as libc::time_t;
            spec.it_value.tv_nsec = delay.subsec_nanos() as libc::c_long;
        }

        let ret = unsafe { libc::timerfd_settime(self.raw(), 0, &spec, std::ptr::null_mut()) };
        syscall_ret(ret, "timerfd_settime")
    }

    /// Read bytes into a raw buffer.
    ///
    /// Internal callers must ensure `buf` points to a valid writable region of
    /// at least `count` bytes.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub(crate) fn read_raw(&self, buf: *mut u8, count: usize) -> Result<Option<usize>, CoreError> {
        loop {
            let n = unsafe { libc::read(self.0, buf as *mut libc::c_void, count) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    return Ok(None);
                }
                return Err(CoreError::sys(e, "read"));
            }
            return Ok(Some(n as usize));
        }
    }

    /// Write bytes from a raw buffer.
    ///
    /// Internal callers must ensure `buf` points to a valid readable region of
    /// at least `count` bytes.
    ///
    /// Returns `Ok(None)` if the operation would block (`EAGAIN`).
    pub(crate) fn write_raw(
        &self,
        buf: *const u8,
        count: usize,
    ) -> Result<Option<usize>, CoreError> {
        loop {
            let n = unsafe { libc::write(self.0, buf as *const libc::c_void, count) };
            if n < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    return Ok(None);
                }
                return Err(CoreError::sys(e, "write"));
            }
            return Ok(Some(n as usize));
        }
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// An opaque token representing a registered file descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token(u64);

#[allow(dead_code)]
impl Token {
    #[inline(always)]
    pub(crate) fn new(val: u64) -> Self {
        Self(val)
    }

    #[inline(always)]
    pub(crate) fn val(&self) -> u64 {
        self.0
    }
}

/// A readiness event generated by the reactor.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    /// Token associated with the ready descriptor.
    pub token: Token,
    /// Descriptor is ready for reading.
    pub readable: bool,
    /// Descriptor has priority data or an exceptional condition (EPOLLPRI).
    pub priority: bool,
    /// Descriptor is ready for writing.
    pub writable: bool,
    /// Indicates an error or hangup (EPOLLERR | EPOLLHUP).
    ///
    /// NOTE: For edge-triggered readiness, an error condition often means both
    /// readable and writable are set to ensure the handler drains the FD.
    pub error: bool,
}

/// A lightweight epoll reactor using edge-triggered monitoring (EPOLLET).
///
/// ### Edge-Triggered Contract
/// Because this reactor uses EPOLLET, all handlers MUST drain their respective
/// read or write sources until they receive an `EAGAIN` / `EWOULDBLOCK` error
/// (represented as `Ok(None)` in the `Fd` helpers).
///
/// Failure to drain a source will result in missing future readiness events
/// for that file descriptor until it is re-registered or another event occurs.
///
/// # Example
/// ```no_run
/// # use coreshift_core::reactor::{Reactor, Fd, Event};
/// # fn example(fd: Fd) -> Result<(), Box<dyn std::error::Error>> {
/// let mut reactor = Reactor::new()?;
/// let token = reactor.add(&fd, true, false)?;
///
/// let mut events = Vec::new();
/// loop {
///     reactor.wait(&mut events, 64, -1)?;
///     for ev in &events {
///         if ev.token == token {
///             // Drain fd...
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct Reactor {
    epfd: RawFd,
    next_token: u64,
    events_buf: Vec<libc::epoll_event>,
    signalfd: Option<Fd>,
    signalfd_previous_mask: Option<libc::sigset_t>,
    /// Token for the signalfd (if initialized).
    pub sigchld_token: Option<Token>,
    /// Token for the inotify fd (if initialized).
    pub inotify_token: Option<Token>,
}

impl Reactor {
    /// Create a new epoll reactor.
    ///
    /// # Errors
    /// Returns [`CoreError`] if `epoll_create1` fails.
    pub fn new() -> Result<Self, CoreError> {
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        syscall_ret(epfd, "epoll_create1")?;
        Ok(Self {
            epfd,
            next_token: 1,
            events_buf: Vec::with_capacity(64),
            signalfd: None,
            signalfd_previous_mask: None,
            sigchld_token: None,
            inotify_token: None,
        })
    }

    /// Initialize inotify and add it to the reactor.
    ///
    /// # Errors
    /// Returns [`CoreError`] if `inotify_init1` or `epoll_ctl` fails.
    pub fn setup_inotify(&mut self) -> Result<Fd, CoreError> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        syscall_ret(fd, "inotify_init1")?;

        let fd_obj = Fd::new(fd, "inotify")?;
        let token = self.add(&fd_obj, true, false)?;
        self.inotify_token = Some(token);

        Ok(fd_obj)
    }

    /// Initialize signalfd for SIGCHLD and add it to the reactor.
    ///
    /// # Errors
    /// Returns [`CoreError`] if `pthread_sigmask`, `signalfd`, or `epoll_ctl` fails.
    ///
    /// The previous current-thread signal mask is restored when the reactor is
    /// dropped.
    pub fn setup_signalfd(&mut self) -> Result<(), CoreError> {
        if self.signalfd.is_some() {
            return Err(CoreError::sys(
                libc::EINVAL,
                "setup_signalfd already initialized",
            ));
        }

        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut mask) };
        unsafe { libc::sigaddset(&mut mask, libc::SIGCHLD) };

        let mut previous_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous_mask) };
        if r != 0 {
            return Err(CoreError::sys(r, "pthread_sigmask(SIG_BLOCK)"));
        }

        let sfd = unsafe { libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        if let Err(err) = syscall_ret(sfd, "signalfd") {
            let _ = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
            };
            return Err(err);
        }

        let fd = Fd::new(sfd, "signalfd")?;
        let token = match self.add(&fd, true, false) {
            Ok(token) => token,
            Err(err) => {
                let _ = unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous_mask, std::ptr::null_mut())
                };
                return Err(err);
            }
        };

        self.signalfd = Some(fd);
        self.signalfd_previous_mask = Some(previous_mask);
        self.sigchld_token = Some(token);

        Ok(())
    }

    /// Drain the internal signalfd buffer.
    pub fn drain_signalfd(&self) -> Result<(), CoreError> {
        if let Some(fd) = &self.signalfd {
            let mut buf = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
            loop {
                match fd.read_slice(&mut buf) {
                    Ok(Some(n)) if n < buf.len() => break,
                    Ok(Some(_)) => continue,
                    Ok(None) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Register a file descriptor with the reactor.
    ///
    /// This assigns a new unique token for the descriptor and enables
    /// edge-triggered monitoring.
    #[inline(always)]
    pub fn add(&mut self, fd: &Fd, readable: bool, writable: bool) -> Result<Token, CoreError> {
        let token = Token(self.next_token);
        self.next_token += 1;
        self.add_with_token(fd.raw(), token, readable, writable, false)?;
        Ok(token)
    }

    /// Register a file descriptor for priority readiness (EPOLLPRI).
    #[inline(always)]
    pub fn add_priority(&mut self, fd: &Fd) -> Result<Token, CoreError> {
        let token = Token(self.next_token);
        self.next_token += 1;
        self.add_with_token(fd.raw(), token, false, false, true)?;
        Ok(token)
    }

    #[inline(always)]
    pub(crate) fn add_with_token(
        &mut self,
        raw_fd: RawFd,
        token: Token,
        readable: bool,
        writable: bool,
        priority: bool,
    ) -> Result<(), CoreError> {
        let mut events = libc::EPOLLET as u32;
        if readable {
            events |= libc::EPOLLIN as u32;
        }
        if writable {
            events |= libc::EPOLLOUT as u32;
        }
        if priority {
            events |= libc::EPOLLPRI as u32;
        }
        let mut ev = libc::epoll_event {
            events,
            u64: token.0,
        };
        let r = unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, raw_fd, &mut ev) };
        syscall_ret(r, "epoll_ctl_add")?;
        Ok(())
    }

    /// Remove a file descriptor from the reactor.
    #[inline(always)]
    pub fn del(&self, fd: &Fd) -> Result<(), CoreError> {
        self.del_raw(fd.raw())
    }

    /// Remove a raw descriptor from the reactor.
    ///
    /// NOTE: This is an escape hatch for low-level interactions. Prefer using
    /// [`del`](Self::del).
    #[inline(always)]
    pub(crate) fn del_raw(&self, raw: RawFd) -> Result<(), CoreError> {
        loop {
            let ret = unsafe {
                libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, raw, std::ptr::null_mut())
            };
            if ret == -1 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(CoreError::sys(e, "epoll_ctl_del"));
            }
            return Ok(());
        }
    }

    /// Wait for events.
    ///
    /// This function blocks until at least one event is ready or the timeout
    /// expires. Ready events are appended to the `buffer`.
    ///
    /// Returns the number of events received.
    #[inline(always)]
    pub fn wait(
        &mut self,
        buffer: &mut Vec<Event>,
        max_events: usize,
        timeout: i32,
    ) -> Result<usize, CoreError> {
        buffer.clear();

        if max_events == 0 {
            return Ok(0);
        }

        // Ensure buffer has enough capacity
        if buffer.capacity() < max_events {
            buffer.reserve(max_events.saturating_sub(buffer.len()));
        }

        if self.events_buf.capacity() < max_events {
            self.events_buf
                .reserve(max_events.saturating_sub(self.events_buf.len()));
        }

        let n = unsafe {
            libc::epoll_wait(
                self.epfd,
                self.events_buf.as_mut_ptr(),
                max_events as i32,
                timeout,
            )
        };

        if n > 0 {
            unsafe {
                self.events_buf.set_len(n as usize);
            }
            for i in 0..n as usize {
                let ev = self.events_buf[i];
                let is_read = (ev.events & libc::EPOLLIN as u32) != 0;
                let is_priority = (ev.events & libc::EPOLLPRI as u32) != 0;
                let is_write = (ev.events & libc::EPOLLOUT as u32) != 0;
                let is_err = (ev.events & (libc::EPOLLERR | libc::EPOLLHUP) as u32) != 0;

                buffer.push(Event {
                    token: Token(ev.u64),
                    readable: is_read || is_err,
                    priority: is_priority || is_err,
                    writable: is_write || is_err,
                    error: is_err,
                });
            }
            return Ok(n as usize);
        }

        if n < 0 {
            let e = errno();
            if e == libc::EINTR {
                return Ok(0);
            }
            return Err(CoreError::sys(e, "epoll_wait"));
        }
        Ok(0)
    }

    /// Return the raw epoll file descriptor.
    ///
    /// NOTE: This is an escape hatch for low-level interactions.
    #[allow(dead_code)]
    pub(crate) fn fd(&self) -> RawFd {
        self.epfd
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        if let Some(mask) = self.signalfd_previous_mask.take() {
            let _ =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) };
        }
        if self.epfd >= 0 {
            unsafe {
                libc::close(self.epfd);
            }
        }
    }
}
