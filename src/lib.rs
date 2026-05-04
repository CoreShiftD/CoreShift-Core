// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! CoreShift Core is the low-level Linux and Android foundation crate for the
//! CoreShift ecosystem.
//!
//! CoreShift Core keeps direct kernel, `libc`, and procfs interaction in one
//! place so higher layers can stay policy-oriented:
//! - **CoreShift Core**: low-level Linux and Android primitives
//! - **CoreShift Engine**: daemon and plugin runtime
//! - **CoreShift Policy**: policy logic and product behavior
//!
//! This crate is intentionally policy-neutral. It provides mechanisms such as
//! spawning, `epoll`, `inotify`, procfs inspection, and signal helpers. It
//! does not make daemon lifecycle or product decisions for callers.
//!
//! Public primitive modules:
//! - [`crate::fs`] for filesystem probes and readahead
//! - [`crate::proc`] for procfs helpers
//! - [`crate::signal`] for signal and shutdown helpers
//! - [`crate::uid`] for ownership lookups
//! - [`crate::spawn`] for explicit process spawning
//! - [`crate::reactor`] for fd readiness primitives
//! - [`crate::inotify`] for watch/decode helpers
//! - [`crate::unix_socket`] for Unix domain socket primitives
//! - [`crate::io`] for explicit drain helpers
//!
//! ```compile_fail
//! use coreshift_core::Daemon;
//! ```
//!
//! ```compile_fail
//! use coreshift_core::ForegroundResolver;
//! ```

pub mod error;
pub mod fs;
pub mod inotify;
pub mod io;
pub mod proc;
pub mod reactor;
pub mod signal;
pub mod spawn;
pub mod uid;
pub mod unix_socket;

pub use error::CoreError;

#[cfg(test)]
mod tests;
