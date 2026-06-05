// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Backend-agnostic logging facade.

mod android;
mod null;
mod stderr;

/// Log severity levels.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Verbose = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
    Fatal = 7,
}

/// Legacy alias for [`LogLevel`].
pub type LogPriority = LogLevel;

/// Available logging backends.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogBackend {
    /// Android system log (liblog).
    Android = 0,
    /// Standard error.
    Stderr = 1,
    /// Discard all messages.
    Null = 2,
}

/// A handle for writing messages to a specific log backend.
///
/// Core follows a "no global mutable state" architecture. Callers that require
/// a non-default logging backend must create a [`Logger`] instance and use
/// it directly.
///
/// By default, macros like [`alog_info!`] use a platform-appropriate default
/// logger ([`LogBackend::Android`] on Android, [`LogBackend::Stderr`] otherwise).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logger {
    backend: LogBackend,
}

impl Default for Logger {
    fn default() -> Self {
        #[cfg(target_os = "android")]
        {
            Self::new(LogBackend::Android)
        }
        #[cfg(not(target_os = "android"))]
        {
            Self::new(LogBackend::Stderr)
        }
    }
}

impl Logger {
    /// Create a new logger with the specified backend.
    pub fn new(backend: LogBackend) -> Self {
        Self { backend }
    }

    /// Write a message to the logger's active backend.
    pub fn log(&self, level: LogLevel, tag: &str, msg: &str) {
        match self.backend {
            LogBackend::Android => android::log(level, tag, msg),
            LogBackend::Stderr => stderr::log(level, tag, msg),
            LogBackend::Null => null::log(level, tag, msg),
        }
    }
}

/// Write a message using the platform default logger.
///
/// This maintains compatibility with legacy callers and existing macros.
/// It uses direct compile-time dispatch to the appropriate platform backend.
pub fn log(level: LogLevel, tag: &str, msg: &str) {
    #[cfg(target_os = "android")]
    {
        android::log(level, tag, msg);
    }
    #[cfg(not(target_os = "android"))]
    {
        stderr::log(level, tag, msg);
    }
}

/// Legacy alias for [`log`].
pub fn log_write(level: LogLevel, tag: &str, msg: &str) {
    log(level, tag, msg);
}

#[macro_export]
macro_rules! alog_verbose {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Verbose, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Verbose, $tag, "")
    };
}

#[macro_export]
macro_rules! alog_debug {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Debug, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Debug, $tag, "")
    };
}

#[macro_export]
macro_rules! alog_info {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Info, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Info, $tag, "")
    };
}

#[macro_export]
macro_rules! alog_warn {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Warn, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Warn, $tag, "")
    };
}

#[macro_export]
macro_rules! alog_error {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Error, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Error, $tag, "")
    };
}

#[macro_export]
macro_rules! alog_fatal {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Fatal, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Fatal, $tag, "")
    };
}

#[macro_export]
macro_rules! log_verbose {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Verbose, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Verbose, $tag, "")
    };
}

#[macro_export]
macro_rules! log_debug {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Debug, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Debug, $tag, "")
    };
}

#[macro_export]
macro_rules! log_info {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Info, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Info, $tag, "")
    };
}

#[macro_export]
macro_rules! log_warn {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Warn, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Warn, $tag, "")
    };
}

#[macro_export]
macro_rules! log_error {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Error, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Error, $tag, "")
    };
}

#[macro_export]
macro_rules! log_fatal {
    ($tag:expr, $($arg:tt)*) => {
        $crate::log::log($crate::log::LogLevel::Fatal, $tag, &format!($($arg)*))
    };
    ($tag:expr) => {
        $crate::log::log($crate::log::LogLevel::Fatal, $tag, "")
    };
}
