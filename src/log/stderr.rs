// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

use super::LogLevel;
use libc::STDERR_FILENO;

pub fn log(level: LogLevel, tag: &str, msg: &str) {
    let level_str = match level {
        LogLevel::Verbose => "VERBOSE",
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
        LogLevel::Fatal => "FATAL",
    };

    let line = format!("[{}][{}] {}\n", level_str, tag, msg);
    let bytes = line.as_bytes();

    let mut written = 0;
    while written < bytes.len() {
        let r = unsafe {
            libc::write(
                STDERR_FILENO,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if r <= 0 {
            break;
        }
        written += r as usize;
    }
}
