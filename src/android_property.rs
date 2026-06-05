// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

use std::ffi::CString;
use std::io;
use std::time::Duration;

const ANDROID_PROP_VALUE_MAX: usize = 92;
const ANDROID_PROP_SERIAL_ERROR: u32 = u32::MAX;

#[repr(C)]
pub struct AndroidPropertyInfoOpaque {
    _private: [u8; 0],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidPropertyInfo {
    raw: *const AndroidPropertyInfoOpaque,
}

impl AndroidPropertyInfo {
    pub fn as_ptr(self) -> *const AndroidPropertyInfoOpaque {
        self.raw
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidPropertyValue {
    pub name: String,
    pub value: String,
    pub serial: u32,
}

pub trait AndroidPropertyStore {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&self, key: &str, value: &str) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemAndroidPropertyStore;

pub fn android_property_get(key: &str) -> Option<String> {
    SystemAndroidPropertyStore.get(key)
}

pub fn android_property_set(key: &str, value: &str) -> io::Result<()> {
    SystemAndroidPropertyStore.set(key, value)
}

pub fn android_property_find(key: &str) -> Option<AndroidPropertyInfo> {
    system_android_property_find(key)
}

pub fn android_property_read(property: AndroidPropertyInfo) -> io::Result<AndroidPropertyValue> {
    system_android_property_read(property)
}

pub fn android_property_serial(property: AndroidPropertyInfo) -> io::Result<u32> {
    system_android_property_serial(property)
}

pub fn android_property_wait(
    property: AndroidPropertyInfo,
    old_serial: u32,
    timeout: Option<Duration>,
) -> io::Result<Option<u32>> {
    system_android_property_wait(property, old_serial, timeout)
}

impl AndroidPropertyStore for SystemAndroidPropertyStore {
    fn get(&self, key: &str) -> Option<String> {
        system_android_property_get(key)
    }

    fn set(&self, key: &str, value: &str) -> io::Result<()> {
        validate_property_c_string(key)?;
        validate_property_c_string(value)?;
        system_android_property_set(key, value)
    }
}

fn validate_property_c_string(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"))
}

fn android_properties_unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "android system properties unavailable on this platform",
    )
}

#[cfg(target_os = "android")]
fn property_info_invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid android property info")
}

#[cfg(target_os = "android")]
fn serial_result(serial: u32) -> io::Result<u32> {
    if serial == ANDROID_PROP_SERIAL_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(serial)
    }
}

fn duration_to_timespec(duration: Duration) -> io::Result<libc::timespec> {
    let tv_sec = duration
        .as_secs()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "timeout too large"))?;
    let tv_nsec = duration.subsec_nanos() as _;
    Ok(libc::timespec { tv_sec, tv_nsec })
}

#[cfg(target_os = "android")]
fn system_android_property_get(key: &str) -> Option<String> {
    use std::ffi::CStr;

    let key = CString::new(key).ok()?;
    let mut value = [0 as libc::c_char; ANDROID_PROP_VALUE_MAX + 1];
    let len = unsafe { __system_property_get(key.as_ptr(), value.as_mut_ptr()) };
    if len <= 0 {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(value.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(target_os = "android")]
fn system_android_property_find(key: &str) -> Option<AndroidPropertyInfo> {
    let key = CString::new(key).ok()?;
    let raw = unsafe { __system_property_find(key.as_ptr()) };
    if raw.is_null() {
        None
    } else {
        Some(AndroidPropertyInfo { raw })
    }
}

#[cfg(target_os = "android")]
fn system_android_property_read(property: AndroidPropertyInfo) -> io::Result<AndroidPropertyValue> {
    if property.raw.is_null() {
        return Err(property_info_invalid());
    }
    let mut value = AndroidPropertyReadCookie::default();
    unsafe {
        __system_property_read_callback(
            property.raw,
            android_property_read_callback,
            (&mut value as *mut AndroidPropertyReadCookie).cast(),
        );
    }
    value
        .value
        .ok_or_else(|| io::Error::other("android property read callback did not run"))
}

#[cfg(target_os = "android")]
fn system_android_property_serial(property: AndroidPropertyInfo) -> io::Result<u32> {
    if property.raw.is_null() {
        return Err(property_info_invalid());
    }
    serial_result(unsafe { __system_property_serial(property.raw) })
}

#[cfg(target_os = "android")]
fn system_android_property_wait(
    property: AndroidPropertyInfo,
    old_serial: u32,
    timeout: Option<Duration>,
) -> io::Result<Option<u32>> {
    if property.raw.is_null() {
        return Err(property_info_invalid());
    }
    let timeout = timeout.map(duration_to_timespec).transpose()?;
    let timeout_ptr = timeout
        .as_ref()
        .map_or(std::ptr::null(), |value| value as *const libc::timespec);
    let mut new_serial = 0;
    let changed =
        unsafe { __system_property_wait(property.raw, old_serial, &mut new_serial, timeout_ptr) };
    if changed {
        Ok(Some(new_serial))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "android")]
fn system_android_property_set(key: &str, value: &str) -> io::Result<()> {
    let key = validate_property_c_string(key)?;
    let value = validate_property_c_string(value)?;
    let status = unsafe { __system_property_set(key.as_ptr(), value.as_ptr()) };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

#[cfg(not(target_os = "android"))]
fn system_android_property_get(_key: &str) -> Option<String> {
    let _ = ANDROID_PROP_VALUE_MAX;
    None
}

#[cfg(not(target_os = "android"))]
fn system_android_property_find(_key: &str) -> Option<AndroidPropertyInfo> {
    None
}

#[cfg(not(target_os = "android"))]
fn system_android_property_read(
    _property: AndroidPropertyInfo,
) -> io::Result<AndroidPropertyValue> {
    Err(android_properties_unsupported())
}

#[cfg(not(target_os = "android"))]
fn system_android_property_serial(_property: AndroidPropertyInfo) -> io::Result<u32> {
    let _ = ANDROID_PROP_SERIAL_ERROR;
    Err(android_properties_unsupported())
}

#[cfg(not(target_os = "android"))]
fn system_android_property_wait(
    _property: AndroidPropertyInfo,
    _old_serial: u32,
    timeout: Option<Duration>,
) -> io::Result<Option<u32>> {
    if let Some(timeout) = timeout {
        let _ = duration_to_timespec(timeout)?;
    }
    Err(android_properties_unsupported())
}

#[cfg(not(target_os = "android"))]
fn system_android_property_set(_key: &str, _value: &str) -> io::Result<()> {
    Err(android_properties_unsupported())
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
    fn __system_property_set(name: *const libc::c_char, value: *const libc::c_char) -> libc::c_int;
    fn __system_property_find(name: *const libc::c_char) -> *const AndroidPropertyInfoOpaque;
    fn __system_property_read_callback(
        pi: *const AndroidPropertyInfoOpaque,
        callback: unsafe extern "C" fn(
            *mut libc::c_void,
            *const libc::c_char,
            *const libc::c_char,
            u32,
        ),
        cookie: *mut libc::c_void,
    );
    fn __system_property_serial(pi: *const AndroidPropertyInfoOpaque) -> u32;
    fn __system_property_wait(
        pi: *const AndroidPropertyInfoOpaque,
        old_serial: u32,
        new_serial_ptr: *mut u32,
        relative_timeout: *const libc::timespec,
    ) -> bool;
}

#[cfg(target_os = "android")]
#[derive(Default)]
struct AndroidPropertyReadCookie {
    value: Option<AndroidPropertyValue>,
}

#[cfg(target_os = "android")]
unsafe extern "C" fn android_property_read_callback(
    cookie: *mut libc::c_void,
    name: *const libc::c_char,
    value: *const libc::c_char,
    serial: u32,
) {
    use std::ffi::CStr;

    let cookie = unsafe { &mut *(cookie.cast::<AndroidPropertyReadCookie>()) };
    let name = unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned();
    let value = unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();
    cookie.value = Some(AndroidPropertyValue {
        name,
        value,
        serial,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeStore {
        entries: RefCell<BTreeMap<String, String>>,
    }

    impl AndroidPropertyStore for FakeStore {
        fn get(&self, key: &str) -> Option<String> {
            self.entries.borrow().get(key).cloned()
        }

        fn set(&self, key: &str, value: &str) -> io::Result<()> {
            self.entries
                .borrow_mut()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }
    }

    #[test]
    fn fake_store_round_trips_properties() {
        let store = FakeStore::default();
        assert_eq!(store.get("debug.hwui.renderer"), None);
        store.set("debug.hwui.renderer", "skiagl").unwrap();
        assert_eq!(store.get("debug.hwui.renderer").as_deref(), Some("skiagl"));
    }

    #[test]
    fn system_store_rejects_embedded_nul() {
        let err = SystemAndroidPropertyStore
            .set("debug.hwui.renderer", "skia\0gl")
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn duration_to_timespec_rejects_large_timeout() {
        let err = duration_to_timespec(Duration::from_secs(u64::MAX)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[cfg(target_os = "android")]
    fn serial_error_maps_to_io_error() {
        assert!(serial_result(1).is_ok());
        assert!(serial_result(ANDROID_PROP_SERIAL_ERROR).is_err());
    }
}
