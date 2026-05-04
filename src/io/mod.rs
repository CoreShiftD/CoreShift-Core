// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Buffered process I/O helpers.
//!
//! The public [`DrainState`] type is an advanced helper for managing
//! non-blocking stdin/stdout/stderr pipes around spawned processes.

pub(crate) mod buffer;
pub mod drain;
pub(crate) mod writer;
pub use drain::DrainState;
