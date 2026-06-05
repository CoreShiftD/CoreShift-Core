// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

use super::LogLevel;
#[cfg(target_os = "android")]
use std::ffi::CString;

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(prio: i32, tag: *const libc::c_char, text: *const libc::c_char) -> i32;
}

pub fn log(level: LogLevel, tag: &str, msg: &str) {
    #[cfg(target_os = "android")]
    {
        let prio = match level {
            LogLevel::Verbose => 2,
            LogLevel::Debug => 3,
            LogLevel::Info => 4,
            LogLevel::Warn => 5,
            LogLevel::Error => 6,
            LogLevel::Fatal => 7,
        };
        let tag_c = CString::new(tag).unwrap_or_else(|_| CString::new("CoreShift").unwrap());
        let text_c = CString::new(msg).unwrap_or_else(|_| CString::new("<invalid utf8>").unwrap());
        unsafe {
            __android_log_write(prio, tag_c.as_ptr(), text_c.as_ptr());
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = level;
        let _ = tag;
        let _ = msg;
    }
}
