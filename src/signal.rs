// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Signal and shutdown helpers.
//!
//! This module provides small process-global signal utilities intended for
//! low-level daemons and worker processes that want explicit signal handling
//! without a heavier runtime.

use crate::CoreError;
use crate::error::syscall_ret;
use crate::reactor::Fd;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub type SignalSet = libc::sigset_t;
pub type ThreadId = libc::pthread_t;

pub const SIGINT: i32  = libc::SIGINT;
pub const SIGTERM: i32 = libc::SIGTERM;
pub const SIGPIPE: i32 = libc::SIGPIPE;
pub const SIGKILL: i32 = libc::SIGKILL;
pub const SIGUSR1: i32 = libc::SIGUSR1;
pub const SIGUSR2: i32 = libc::SIGUSR2;
pub const SIGCHLD: i32 = libc::SIGCHLD;
pub const SIGHUP: i32  = libc::SIGHUP;

/// Type alias for the kernel signal info structure read from a `signalfd`.
pub type SignalfdSiginfo = libc::signalfd_siginfo;

/// Set a signal's disposition to SIG_IGN.
///
/// # Safety
/// Changes process-global signal disposition.
pub unsafe fn signal_ignore(sig: i32) {
    unsafe { libc::signal(sig, libc::SIG_IGN) };
}

static SHUTDOWN_FLAG_PTR: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());

extern "C" fn shutdown_signal_handler(_sig: libc::c_int) {
    let flag = SHUTDOWN_FLAG_PTR.load(Ordering::Relaxed);
    if !flag.is_null() {
        unsafe {
            (*flag).store(true, Ordering::Release);
        }
    }
}

/// Install SIGINT and SIGTERM handlers that flip a shared shutdown flag.
///
/// This is intended for simple daemon shutdown loops that want a reusable
/// signal hook without direct `sigaction(2)` setup. The handlers are
/// process-global and remain installed until replaced by another install.
/// Use [`install_shutdown_flag_guard`] when the previous process-global
/// handlers must be restored automatically.
///
/// ### Reactor Compatibility
/// This function uses standard Unix `signal()`/`sigaction()` handlers and is
/// **not** directly compatible with the `Reactor`. For event-loop based
/// applications, prefer using [`SignalRuntime::signalfd_new`].
///
/// ### Fork Safety
/// Signal handlers are inherited by the child. The shutdown flag pointer is
/// also inherited. If the child process receives SIGINT/SIGTERM, it will
/// attempt to flip the flag in its own address space at the same virtual
/// address.
///
/// ### Errors
/// - `EINVAL`: Invalid signal number.
pub fn install_shutdown_flag(flag: &'static AtomicBool) -> Result<(), CoreError> {
    install_shutdown_flag_inner(flag).map(|_| ())
}

/// Guard that restores previous SIGINT/SIGTERM handlers and shutdown flag on drop.
///
/// ### Fork Safety
/// The guard is owned by the process that created it. If the process forks,
/// the child will also have a copy of the guard, but dropping it in the child
/// will restore handlers in the child's context only.
pub struct ShutdownFlagGuard {
    old_sigint: libc::sigaction,
    old_sigterm: libc::sigaction,
    old_flag: *mut AtomicBool,
}

impl Drop for ShutdownFlagGuard {
    fn drop(&mut self) {
        SHUTDOWN_FLAG_PTR.store(self.old_flag, Ordering::Release);
        let _ = restore_signal_handler(SIGTERM, &self.old_sigterm);
        let _ = restore_signal_handler(SIGINT, &self.old_sigint);
    }
}

/// Install SIGINT and SIGTERM handlers and return a restore guard.
///
/// Dropping the guard restores the previous handlers and previous shutdown
/// flag pointer. This is the scoped form for tests and callers that do not
/// want the global convenience behavior of [`install_shutdown_flag`].
pub fn install_shutdown_flag_guard(
    flag: &'static AtomicBool,
) -> Result<ShutdownFlagGuard, CoreError> {
    let (old_sigint, old_sigterm, old_flag) = install_shutdown_flag_inner(flag)?;
    Ok(ShutdownFlagGuard {
        old_sigint,
        old_sigterm,
        old_flag,
    })
}

fn install_shutdown_flag_inner(
    flag: &'static AtomicBool,
) -> Result<(libc::sigaction, libc::sigaction, *mut AtomicBool), CoreError> {
    let old_flag = SHUTDOWN_FLAG_PTR.load(Ordering::Acquire);
    let old_sigint = install_signal_handler(SIGINT)?;
    match install_signal_handler(SIGTERM) {
        Ok(old_sigterm) => {
            SHUTDOWN_FLAG_PTR.store(
                flag as *const AtomicBool as *mut AtomicBool,
                Ordering::Release,
            );
            Ok((old_sigint, old_sigterm, old_flag))
        }
        Err(err) => {
            restore_signal_handler(SIGINT, &old_sigint)?;
            Err(err)
        }
    }
}

/// Return whether a shutdown flag was flipped by the installed handler.
#[inline]
pub fn shutdown_requested(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Acquire)
}

fn install_signal_handler(sig: libc::c_int) -> Result<libc::sigaction, CoreError> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = shutdown_signal_handler as *const () as usize;
    action.sa_flags = 0;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };

    let ret = unsafe { libc::sigaction(sig, &action, &mut old_action) };
    if ret == -1 {
        Err(last_sigaction_error(sig))
    } else {
        Ok(old_action)
    }
}

fn restore_signal_handler(sig: libc::c_int, old_action: &libc::sigaction) -> Result<(), CoreError> {
    let ret = unsafe { libc::sigaction(sig, old_action, std::ptr::null_mut()) };
    if ret == -1 {
        Err(last_sigaction_error(sig))
    } else {
        Ok(())
    }
}

fn last_sigaction_error(sig: libc::c_int) -> CoreError {
    let op = match sig {
        SIGINT => "sigaction(SIGINT)",
        SIGTERM => "sigaction(SIGTERM)",
        _ => "sigaction",
    };
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    CoreError::sys(code, op)
}

/// Utilities for process signal management.
pub struct SignalRuntime;

impl SignalRuntime {
    /// Create an empty signal set.
    pub fn empty_set() -> SignalSet {
        let mut set: SignalSet = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut set) };
        set
    }

    /// Create a signal set containing the specified signals.
    ///
    /// ### Errors
    /// - `EINVAL`: One of the signal numbers is invalid.
    pub fn set_with(signals: &[i32]) -> Result<SignalSet, CoreError> {
        let mut set: SignalSet = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut set) };
        for &sig in signals {
            let ret = unsafe { libc::sigaddset(&mut set, sig) };
            if ret == -1 {
                return Err(CoreError::sys(libc::EINVAL, "sigaddset"));
            }
        }
        Ok(set)
    }

    /// Block the specified signals for the current thread and return the previous mask.
    ///
    /// ### Errors
    /// - `EINVAL`: `how` or `signals` is invalid.
    pub fn block_current_thread(signals: &SignalSet) -> Result<SignalSet, CoreError> {
        let mut previous = Self::empty_set();
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, signals, &mut previous) };
        if result == 0 {
            Ok(previous)
        } else {
            Err(CoreError::sys(result, "pthread_sigmask(SIG_BLOCK)"))
        }
    }

    /// Restore the current thread signal mask.
    ///
    /// ### Errors
    /// - `EINVAL`: `mask` is invalid.
    pub fn restore_current_thread(mask: &SignalSet) -> Result<(), CoreError> {
        let result =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, mask, std::ptr::null_mut()) };
        if result == 0 {
            Ok(())
        } else {
            Err(CoreError::sys(result, "pthread_sigmask(SIG_SETMASK)"))
        }
    }

    /// Wait synchronously for one of the supplied signals.
    ///
    /// ### Errors
    /// - `EINVAL`: `signals` contains invalid signal numbers.
    pub fn wait(signals: &SignalSet) -> Result<i32, CoreError> {
        let mut received_signal = 0;
        let result = unsafe { libc::sigwait(signals, &mut received_signal) };
        if result == 0 {
            Ok(received_signal)
        } else {
            Err(CoreError::sys(result, "sigwait"))
        }
    }

    /// Deliver a signal to a specific thread.
    ///
    /// ### Errors
    /// - `EINVAL`: Invalid signal number.
    /// - `ESRCH`: The thread ID is invalid or the thread has terminated.
    pub fn interrupt_thread(thread: ThreadId, signal: i32) -> Result<(), CoreError> {
        let result = unsafe { libc::pthread_kill(thread, signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(CoreError::sys(result, "pthread_kill"))
        }
    }

    /// Block or unblock signals for the current thread and return the previous mask.
    pub fn set_current_thread_mask(
        how: i32,
        signals: &SignalSet,
    ) -> Result<SignalSet, CoreError> {
        let mut previous = Self::empty_set();
        let result = unsafe { libc::pthread_sigmask(how, signals, &mut previous) };
        if result == 0 {
            Ok(previous)
        } else {
            let op = match how {
                libc::SIG_BLOCK => "pthread_sigmask(SIG_BLOCK)",
                libc::SIG_UNBLOCK => "pthread_sigmask(SIG_UNBLOCK)",
                libc::SIG_SETMASK => "pthread_sigmask(SIG_SETMASK)",
                _ => "pthread_sigmask",
            };
            Err(CoreError::sys(result, op))
        }
    }

    /// Unblock all signals for the current thread.
    pub fn unblock_all() -> Result<(), CoreError> {
        let empty_mask = Self::empty_set();
        let r = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut()) };
        if r != 0 {
            Err(CoreError::sys(r, "pthread_sigmask(SIG_SETMASK)"))
        } else {
            Ok(())
        }
    }

    /// Create a new `signalfd` for the specified signal set.
    ///
    /// The descriptor is created with `SFD_CLOEXEC` and `SFD_NONBLOCK` set.
    /// Callers are responsible for blocking the signals in the set before
    /// reading from the `signalfd`.
    ///
    /// ### Fork Safety
    /// The descriptor is `O_CLOEXEC` and will be closed in the child after `exec`.
    ///
    /// ### Errors
    /// - `EINVAL`: `signals` is invalid.
    /// - `EMFILE`: Process limit on open file descriptors hit.
    /// - `ENFILE`: System-wide limit on open files hit.
    ///
    /// # Example
    /// ```no_run
    /// # use coreshift_core::signal::{SignalRuntime, SIGUSR1};
    /// let signals = SignalRuntime::set_with(&[SIGUSR1]).unwrap();
    /// SignalRuntime::block_current_thread(&signals).unwrap();
    /// let sfd = SignalRuntime::signalfd_new(&signals).unwrap();
    /// ```
    pub fn signalfd_new(signals: &SignalSet) -> Result<Fd, CoreError> {
        let fd = unsafe { libc::signalfd(-1, signals, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC) };
        syscall_ret(fd, "signalfd")?;
        Fd::new(fd, "signalfd")
    }

    /// Register a process-wide handler for a single signal.
    ///
    /// This is a low-level wrapper around `sigaction(2)`.
    ///
    /// ### Fork Safety
    /// Signal handlers are inherited across `fork`.
    ///
    /// ### Errors
    /// - `EINVAL`: Invalid signal number.
    ///
    /// # Example
    /// ```no_run
    /// # use coreshift_core::signal::{SignalRuntime, SIGUSR1};
    /// extern "C" fn handler(_: i32) {}
    /// SignalRuntime::register_handler(SIGUSR1, handler).unwrap();
    /// ```
    pub fn register_handler(
        sig: i32,
        handler: extern "C" fn(i32),
    ) -> Result<libc::sigaction, CoreError> {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handler as *const () as usize;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };

        let ret = unsafe { libc::sigaction(sig, &action, &mut old_action) };
        if ret == -1 {
            let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            Err(CoreError::sys(code, "sigaction"))
        } else {
            Ok(old_action)
        }
    }

    /// Reset a signal to its default kernel handler.
    ///
    /// ### Errors
    /// - `EINVAL`: Invalid signal number.
    pub fn reset_default(sig: i32) -> Result<(), CoreError> {
        let prev = unsafe { libc::signal(sig, libc::SIG_DFL) };
        if prev == libc::SIG_ERR {
            Err(CoreError::sys(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "signal(SIG_DFL)",
            ))
        } else {
            Ok(())
        }
    }
}
