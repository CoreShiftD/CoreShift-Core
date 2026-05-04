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
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub type SignalSet = libc::sigset_t;
pub type ThreadId = libc::pthread_t;

pub const SIGINT: i32 = libc::SIGINT;
pub const SIGTERM: i32 = libc::SIGTERM;
pub const SIGPIPE: i32 = libc::SIGPIPE;
pub const SIGKILL: i32 = libc::SIGKILL;

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
pub fn install_shutdown_flag(flag: &'static AtomicBool) -> Result<(), CoreError> {
    install_shutdown_flag_inner(flag).map(|_| ())
}

/// Guard that restores previous SIGINT/SIGTERM handlers and shutdown flag on drop.
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
    pub fn interrupt_thread(thread: ThreadId, signal: i32) -> Result<(), CoreError> {
        let result = unsafe { libc::pthread_kill(thread, signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(CoreError::sys(result, "pthread_kill"))
        }
    }

    /// Unblock all signals for the current thread.
    pub fn unblock_all() -> Result<(), CoreError> {
        let empty_mask = Self::empty_set();
        let r = unsafe { libc::sigprocmask(libc::SIG_SETMASK, &empty_mask, std::ptr::null_mut()) };
        syscall_ret(r, "sigprocmask")
    }

    /// Reset a signal to its default kernel handler.
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
