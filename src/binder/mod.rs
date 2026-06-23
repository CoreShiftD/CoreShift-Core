// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! NDK binder primitives for querying Android system services.
//!
//! Uses `dlopen` on `libbinder_ndk.so` to avoid hard-linking against a library
//! absent from older NDK toolchains or non-Android targets.
//!
//! All public types are gated on `#[cfg(target_os = "android")]`. On other
//! targets every entry point returns `CoreError::Binder`.
//!
//! ## Transaction code resolution
//!
//! `IActivityManager` transaction codes are AIDL-generated and shift with each
//! AOSP release. Resolution order (no subprocess required):
//!
//! 1. Parse `/data/local/tmp/tx_code.txt` if present (written by fgw).
//! 2. Look up a known code from the `ro.build.version.sdk` property table.
//! 3. Linear probe codes in a narrow SDK-version-dependent window.

use crate::CoreError;

// ─────────────────────────────────────────────────────────────────────────────
// Android-only implementation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
mod imp {
    use super::*;
    use crate::android_property::android_property_get;
    use std::os::raw::{c_char, c_void};

    // ── NDK binder status codes ───────────────────────────────────────────────

    const STATUS_OK: i32 = 0;
    const STATUS_UNKNOWN_TRANSACTION: i32 = -2;

    // writeNoException() writes 0; any non-zero is a Java exception code.
    const EX_NONE: i32 = 0;

    // ── Interface constants ───────────────────────────────────────────────────

    const ACTIVITY_MANAGER_DESCRIPTOR: &[u8] = b"android.app.IActivityManager\0";
    const ACTIVITY_SERVICE_NAME: &[u8] = b"activity\0";
    const LIBBINDER_NDK_PATH: &[u8] = b"/system/lib64/libbinder_ndk.so\0";

    // ── Tx code cache ─────────────────────────────────────────────────────────
    //
    // Format written by fgw (4 space-separated values):
    //   observer_code  focused_task_code  api_mode  fg_activities_code
    // api_mode: 1 = getFocusedRootTaskInfo (API 30+), 2 = getFocusedStackInfo (API 29)

    const TX_CACHE_PATH: &str = "/data/local/tmp/tx_code.txt";

    // ── SDK-version tx code table ─────────────────────────────────────────────

    #[derive(Clone, Copy)]
    struct TxEntry { api: u32, code: i32, legacy: bool }

    static TX_TABLE: &[TxEntry] = &[
        TxEntry { api: 29, code: 157, legacy: true  },
        TxEntry { api: 30, code: 168, legacy: false },
        TxEntry { api: 31, code: 176, legacy: false },
        TxEntry { api: 32, code: 178, legacy: false },
        TxEntry { api: 33, code: 181, legacy: false },
        TxEntry { api: 34, code: 183, legacy: false },
        TxEntry { api: 35, code: 187, legacy: false },
    ];

    const PROBE_WINDOW: i32 = 12;

    // ── Raw NDK type aliases ──────────────────────────────────────────────────

    type AIBinder = c_void;
    #[allow(non_camel_case_types)]
    type AIBinder_Class = c_void;
    type AParcel = c_void;
    type BinderStatus = i32;
    type StringAllocator =
        unsafe extern "C" fn(*mut c_void, i32, *mut *mut c_char) -> bool;

    // ── AIBinder_Class no-op callbacks (client-side only) ────────────────────

    unsafe extern "C" fn on_create(_: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
    unsafe extern "C" fn on_destroy(_: *mut c_void) {}
    unsafe extern "C" fn on_transact(
        _: *mut AIBinder, _: u32, _: *const AParcel, _: *mut AParcel,
    ) -> BinderStatus { STATUS_UNKNOWN_TRANSACTION }

    // ── String allocator callback ─────────────────────────────────────────────

    unsafe extern "C" fn string_alloc(
        cookie: *mut c_void,
        length: i32,
        buffer: *mut *mut c_char,
    ) -> bool {
        if length < 0 { return true; } // null string
        let s = unsafe { &mut *(cookie as *mut StringBuf) };
        s.0.reserve_exact(length as usize + 1);
        unsafe { s.0.as_mut_vec().resize(length as usize + 1, 0) };
        unsafe { *buffer = s.0.as_mut_ptr() as *mut c_char };
        true
    }

    struct StringBuf(String);

    impl StringBuf {
        fn new() -> Self { Self(String::new()) }

        fn finish(mut self) -> Option<String> {
            // Strip the trailing NUL written by the NDK allocator.
            if let Some(pos) = self.0.as_bytes().iter().position(|&b| b == 0) {
                unsafe { self.0.as_mut_vec().truncate(pos) };
            }
            if self.0.is_empty() { None } else { Some(self.0) }
        }
    }

    // ── NDK vtable ────────────────────────────────────────────────────────────

    struct Vtable {
        get_service:         unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
        #[allow(dead_code)]
        wait_for_service:    unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
        class_define:        unsafe extern "C" fn(
                                 *const c_char,
                                 unsafe extern "C" fn(*mut c_void) -> *mut c_void,
                                 unsafe extern "C" fn(*mut c_void),
                                 unsafe extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel) -> BinderStatus,
                             ) -> *mut AIBinder_Class,
        associate_class:     unsafe extern "C" fn(*mut AIBinder, *mut AIBinder_Class) -> bool,
        prepare_transaction: unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> BinderStatus,
        transact:            unsafe extern "C" fn(*mut AIBinder, u32, *mut *mut AParcel, *mut *mut AParcel, u32) -> BinderStatus,
        dec_strong:          unsafe extern "C" fn(*mut AIBinder),
        parcel_delete:       unsafe extern "C" fn(*mut AParcel),
        read_int32:          unsafe extern "C" fn(*const AParcel, *mut i32) -> BinderStatus,
        #[allow(dead_code)]
        read_bool:           unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus,
        read_string:         unsafe extern "C" fn(*const AParcel, *mut c_void, StringAllocator) -> BinderStatus,
    }

    // ── RAII wrappers ─────────────────────────────────────────────────────────

    struct DlHandle(*mut c_void);
    unsafe impl Send for DlHandle {}
    impl Drop for DlHandle {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { libc::dlclose(self.0) }; }
        }
    }

    struct OwnedParcel {
        ptr: *mut AParcel,
        delete: unsafe extern "C" fn(*mut AParcel),
    }
    impl Drop for OwnedParcel {
        fn drop(&mut self) {
            if !self.ptr.is_null() { unsafe { (self.delete)(self.ptr) }; }
        }
    }

    struct OwnedBinder {
        ptr: *mut AIBinder,
        dec_strong: unsafe extern "C" fn(*mut AIBinder),
    }
    unsafe impl Send for OwnedBinder {}
    impl Drop for OwnedBinder {
        fn drop(&mut self) {
            if !self.ptr.is_null() { unsafe { (self.dec_strong)(self.ptr) }; }
        }
    }

    // ── dlsym helper ─────────────────────────────────────────────────────────

    macro_rules! dlsym_fn {
        ($handle:expr, $name:literal, $ty:ty) => {{
            let sym = unsafe {
                libc::dlsym($handle, concat!($name, "\0").as_ptr() as *const c_char)
            };
            if sym.is_null() {
                return Err(CoreError::binder(-1, concat!("dlsym:", $name)));
            }
            unsafe { std::mem::transmute::<*mut c_void, $ty>(sym) }
        }};
    }

    fn load_vtable(handle: *mut c_void) -> Result<Vtable, CoreError> {
        Ok(Vtable {
            get_service: dlsym_fn!(handle, "AServiceManager_getService",
                unsafe extern "C" fn(*const c_char) -> *mut AIBinder),
            wait_for_service: dlsym_fn!(handle, "AServiceManager_waitForService",
                unsafe extern "C" fn(*const c_char) -> *mut AIBinder),
            class_define: dlsym_fn!(handle, "AIBinder_Class_define",
                unsafe extern "C" fn(
                    *const c_char,
                    unsafe extern "C" fn(*mut c_void) -> *mut c_void,
                    unsafe extern "C" fn(*mut c_void),
                    unsafe extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel) -> BinderStatus,
                ) -> *mut AIBinder_Class),
            associate_class: dlsym_fn!(handle, "AIBinder_associateClass",
                unsafe extern "C" fn(*mut AIBinder, *mut AIBinder_Class) -> bool),
            prepare_transaction: dlsym_fn!(handle, "AIBinder_prepareTransaction",
                unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> BinderStatus),
            transact: dlsym_fn!(handle, "AIBinder_transact",
                unsafe extern "C" fn(*mut AIBinder, u32, *mut *mut AParcel, *mut *mut AParcel, u32) -> BinderStatus),
            dec_strong: dlsym_fn!(handle, "AIBinder_decStrong",
                unsafe extern "C" fn(*mut AIBinder)),
            parcel_delete: dlsym_fn!(handle, "AParcel_delete",
                unsafe extern "C" fn(*mut AParcel)),
            read_int32: dlsym_fn!(handle, "AParcel_readInt32",
                unsafe extern "C" fn(*const AParcel, *mut i32) -> BinderStatus),
            read_bool: dlsym_fn!(handle, "AParcel_readBool",
                unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus),
            read_string: dlsym_fn!(handle, "AParcel_readString",
                unsafe extern "C" fn(*const AParcel, *mut c_void, StringAllocator) -> BinderStatus),
        })
    }

    // ── ParcelReader — safe parcel API ────────────────────────────────────────

    struct ParcelReader<'a> {
        vt: &'a Vtable,
        parcel: &'a OwnedParcel,
    }

    impl<'a> ParcelReader<'a> {
        fn read_i32(&self) -> Result<i32, CoreError> {
            let mut v = 0i32;
            let s = unsafe { (self.vt.read_int32)(self.parcel.ptr, &mut v) };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AParcel_readInt32")); }
            Ok(v)
        }

        fn read_string(&self) -> Result<Option<String>, CoreError> {
            let mut buf = StringBuf::new();
            let s = unsafe {
                (self.vt.read_string)(
                    self.parcel.ptr,
                    &mut buf as *mut StringBuf as *mut c_void,
                    string_alloc,
                )
            };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AParcel_readString")); }
            Ok(buf.finish())
        }

        fn skip_i32s(&self, n: usize) -> Result<(), CoreError> {
            for _ in 0..n { self.read_i32()?; }
            Ok(())
        }

        fn skip_int_array(&self) -> Result<(), CoreError> {
            let count = self.read_i32()?.max(0) as usize;
            self.skip_i32s(count)
        }

        // Read component name strings (count + strings), return first package.
        // Component format: "com.pkg/.Activity" — package is left of '/'.
        fn read_first_package_from_names(&self) -> Result<Option<String>, CoreError> {
            let count = self.read_i32()?.max(0) as usize;
            let mut first: Option<String> = None;
            for _ in 0..count {
                let s = self.read_string()?;
                if first.is_none() {
                    first = s.and_then(|c| c.split('/').next().map(str::to_owned));
                }
            }
            Ok(first)
        }
    }

    // ── Response parsers (safe — no unsafe blocks) ────────────────────────────
    //
    // Called after exception (int32=0) and present (int32!=0) are consumed
    // by get_focused_package. Mirrors watcher.c parseRootTaskInfoReply /
    // parseStackInfoReply exactly.

    // getFocusedRootTaskInfo (API 30+)
    fn parse_root_task_info_body(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        // scratch flag; if non-zero, 4 more ints follow (bounds-like fields)
        let scratch = r.read_i32()?;
        if scratch != 0 { r.skip_i32s(4)?; }
        r.skip_int_array()?;               // child task IDs
        r.read_first_package_from_names()  // child task names → first package
    }

    // getFocusedStackInfo (API 29)
    fn parse_stack_info_body(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        r.skip_i32s(5)?;                   // scratch fields
        r.skip_int_array()?;               // task IDs
        r.read_first_package_from_names()  // task names → first package
    }

    // ── Tx code resolution ────────────────────────────────────────────────────

    fn read_tx_cache() -> Option<(i32, bool)> {
        let text = std::fs::read_to_string(TX_CACHE_PATH).ok()?;
        // observer_code  focused_task_code  api_mode  fg_activities_code
        let mut parts = text.split_whitespace();
        let _observer: i32  = parts.next()?.parse().ok()?;
        let tx_code: i32    = parts.next()?.parse().ok()?;
        let api_mode: i32   = parts.next()?.parse().ok()?;
        if tx_code <= 0 { return None; }
        Some((tx_code, api_mode == 2)) // api_mode 2 = getFocusedStackInfo (legacy)
    }

    fn sdk_version() -> Option<u32> {
        android_property_get("ro.build.version.sdk")
            .and_then(|s| s.trim().parse().ok())
    }

    fn table_lookup(api: u32) -> Option<(i32, bool)> {
        TX_TABLE.iter()
            .filter(|e| e.api <= api)
            .last()
            .map(|e| (e.code, e.legacy))
    }

    fn probe_window(api: u32) -> impl Iterator<Item = (i32, bool)> {
        let centre = table_lookup(api).map(|(c, _)| c).unwrap_or(170);
        let legacy_threshold = 165i32;
        ((centre - PROBE_WINDOW)..(centre + PROBE_WINDOW))
            .map(move |c| (c, c < legacy_threshold))
    }

    // ── ActivityManagerBinder ─────────────────────────────────────────────────

    pub struct ActivityManagerBinder {
        _lib:     DlHandle,
        vt:       Vtable,
        _class:   *mut AIBinder_Class,
        service:  OwnedBinder,
        tx_code:  i32,
        legacy:   bool,
    }

    // SAFETY: AIBinder is internally reference-counted and thread-safe.
    unsafe impl Send for ActivityManagerBinder {}

    impl ActivityManagerBinder {
        pub fn open() -> Result<Self, CoreError> {
            let handle = unsafe {
                libc::dlopen(
                    LIBBINDER_NDK_PATH.as_ptr() as *const c_char,
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                )
            };
            if handle.is_null() {
                return Err(CoreError::binder(-1, "dlopen:libbinder_ndk.so"));
            }
            let lib = DlHandle(handle);
            let vt = load_vtable(handle)?;

            let class = unsafe {
                (vt.class_define)(
                    ACTIVITY_MANAGER_DESCRIPTOR.as_ptr() as *const c_char,
                    on_create, on_destroy, on_transact,
                )
            };
            if class.is_null() {
                return Err(CoreError::binder(-1, "AIBinder_Class_define"));
            }

            let raw_service = unsafe {
                (vt.get_service)(ACTIVITY_SERVICE_NAME.as_ptr() as *const c_char)
            };
            if raw_service.is_null() {
                return Err(CoreError::binder(-1, "AServiceManager_getService:activity"));
            }
            unsafe { (vt.associate_class)(raw_service, class) };

            let service = OwnedBinder { ptr: raw_service, dec_strong: vt.dec_strong };
            let (tx_code, legacy) = Self::resolve_tx(&vt, raw_service, class)?;

            Ok(Self { _lib: lib, vt, _class: class, service, tx_code, legacy })
        }

        fn resolve_tx(
            vt: &Vtable,
            service: *mut AIBinder,
            _class: *mut AIBinder_Class,
        ) -> Result<(i32, bool), CoreError> {
            if let Some(pair) = read_tx_cache() {
                return Ok(pair);
            }

            let api = sdk_version().unwrap_or(30);

            if let Some(pair) = table_lookup(api) {
                if Self::tx_code_valid(vt, service, pair.0) {
                    return Ok(pair);
                }
            }

            probe_window(api)
                .find(|&(code, _)| Self::tx_code_valid(vt, service, code))
                .ok_or_else(|| CoreError::binder(-1, "tx_code_resolution"))
        }

        fn tx_code_valid(vt: &Vtable, service: *mut AIBinder, code: i32) -> bool {
            let mut in_ptr: *mut AParcel = std::ptr::null_mut();
            if unsafe { (vt.prepare_transaction)(service, &mut in_ptr) } != STATUS_OK {
                return false;
            }
            let mut out_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (vt.transact)(service, code as u32, &mut in_ptr, &mut out_ptr, 0)
            };
            let out = OwnedParcel { ptr: out_ptr, delete: vt.parcel_delete };
            if s != STATUS_OK { return false; }
            let r = ParcelReader { vt, parcel: &out };
            r.read_i32().map(|ex| ex == EX_NONE).unwrap_or(false)
            // out dropped here → parcel_delete called automatically
        }

        fn do_transact(&self) -> Result<OwnedParcel, CoreError> {
            let mut in_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.prepare_transaction)(self.service.ptr, &mut in_ptr) };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AIBinder_prepareTransaction"));
            }
            let mut out_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (self.vt.transact)(
                    self.service.ptr, self.tx_code as u32,
                    &mut in_ptr, &mut out_ptr, 0,
                )
            };
            let out = OwnedParcel { ptr: out_ptr, delete: self.vt.parcel_delete };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AIBinder_transact"));
            }
            Ok(out)
        }

        pub fn get_focused_package(&self) -> Result<Option<String>, CoreError> {
            let out = self.do_transact()?;
            let r = ParcelReader { vt: &self.vt, parcel: &out };

            let ex = r.read_i32()?;
            if ex != EX_NONE {
                return Err(CoreError::binder(ex, "getFocusedTask:exception"));
            }
            let present = r.read_i32()?;
            if present == 0 {
                return Ok(None);
            }
            if self.legacy {
                parse_stack_info_body(&r)
            } else {
                parse_root_task_info_body(&r)
            }
            // out dropped here → parcel_delete called automatically
        }
    }
}

// ── Public re-exports ─────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
pub use imp::ActivityManagerBinder;

// ── Non-Android stub ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
pub struct ActivityManagerBinder;

#[cfg(not(target_os = "android"))]
impl ActivityManagerBinder {
    pub fn open() -> Result<Self, CoreError> {
        Err(CoreError::binder(-1, "binder:unsupported platform"))
    }

    pub fn get_focused_package(&self) -> Result<Option<String>, CoreError> {
        Err(CoreError::binder(-1, "binder:unsupported platform"))
    }
}
