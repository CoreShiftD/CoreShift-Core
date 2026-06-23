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
//! 1. Parse `/data/local/tmp/watcher_tx_code.txt` if present (written by fgw).
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


    // ── NDK binder status codes ───────────────────────────────────────────────

    const STATUS_OK: i32 = 0;
    // Returned by the kernel when the tx code is unknown to the stub.
    const STATUS_UNKNOWN_TRANSACTION: i32 = -2;

    // ── Parcel exception codes written by Java stubs ──────────────────────────

    // writeNoException() writes 0; any non-zero value is a Java exception code.
    const EX_NONE: i32 = 0;

    // ── Interface descriptor ──────────────────────────────────────────────────

    const ACTIVITY_MANAGER_DESCRIPTOR: &[u8] = b"android.app.IActivityManager\0";
    const ACTIVITY_SERVICE_NAME: &[u8] = b"activity\0";
    const LIBBINDER_NDK_PATH: &[u8] = b"/system/lib64/libbinder_ndk.so\0";

    // ── Tx code cache path ────────────────────────────────────────────────────

    const TX_CACHE_PATH: &str = "/data/local/tmp/watcher_tx_code.txt";

    // ── SDK-version tx code table ─────────────────────────────────────────────
    //
    // Codes shift each AOSP release. Derived from AOSP git history for stock
    // Android. Custom ROMs may differ; the probe fallback handles those.
    //
    // Android 10 (29): no getFocusedRootTaskInfo; use getFocusedStackInfo ≈ 157.
    // Android 11 (30): getFocusedRootTaskInfo first appears ≈ 168.
    // Android 12 (31): ≈ 176.  Android 12L (32): ≈ 178.
    // Android 13 (33): ≈ 181.  Android 14 (34): ≈ 183.
    // Android 15 (35): ≈ 187.

    #[derive(Clone, Copy)]
    struct TxEntry {
        api: u32,
        code: i32,
        legacy: bool,
    }

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
    use std::os::raw::{c_char, c_void};

    // ── Raw NDK binder type aliases ───────────────────────────────────────────

    type AIBinder = c_void;
    #[allow(non_camel_case_types)]
    type AIBinder_Class = c_void;
    type AParcel = c_void;

    type BinderStatus = i32;

    // AParcel_stringAllocator: called by AParcel_readString to allocate the
    // output buffer. We use a Box<String> as the cookie.
    type StringAllocator =
        unsafe extern "C" fn(string_data: *mut c_void, length: i32, buffer: *mut *mut c_char)
            -> bool;

    // AIBinder_Class callbacks (no-ops for client-side use).
    unsafe extern "C" fn on_create(_args: *mut c_void) -> *mut c_void {
        std::ptr::null_mut()
    }
    unsafe extern "C" fn on_destroy(_user_data: *mut c_void) {}
    unsafe extern "C" fn on_transact(
        _binder: *mut AIBinder,
        _code: u32,
        _in_parcel: *const AParcel,
        _out_parcel: *mut AParcel,
    ) -> BinderStatus {
        STATUS_UNKNOWN_TRANSACTION
    }

    // ── String allocator callback ─────────────────────────────────────────────

    unsafe extern "C" fn string_alloc(
        string_data: *mut c_void,
        length: i32,
        buffer: *mut *mut c_char,
    ) -> bool {
        if length < 0 {
            // null string
            return true;
        }
        let s = unsafe { &mut *(string_data as *mut StringBuf) };
        s.buf.resize((length as usize) + 1, 0u8);
        unsafe { *buffer = s.buf.as_mut_ptr() as *mut c_char };
        true
    }

    struct StringBuf {
        buf: Vec<u8>,
    }

    impl StringBuf {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }

        fn as_str(&self) -> Option<&str> {
            if self.buf.is_empty() {
                return None;
            }
            let len = self.buf.iter().position(|&b| b == 0).unwrap_or(self.buf.len());
            std::str::from_utf8(&self.buf[..len]).ok()
        }
    }

    // ── NDK vtable ────────────────────────────────────────────────────────────

    struct Vtable {
        // ServiceManager
        get_service: unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
        #[allow(dead_code)]
        wait_for_service: unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
        // AIBinder_Class
        class_define: unsafe extern "C" fn(
            descriptor: *const c_char,
            on_create: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
            on_destroy: unsafe extern "C" fn(*mut c_void),
            on_transact: unsafe extern "C" fn(
                *mut AIBinder,
                u32,
                *const AParcel,
                *mut AParcel,
            ) -> BinderStatus,
        ) -> *mut AIBinder_Class,
        associate_class:
            unsafe extern "C" fn(*mut AIBinder, *mut AIBinder_Class) -> bool,
        // AIBinder
        prepare_transaction:
            unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> BinderStatus,
        transact: unsafe extern "C" fn(
            *mut AIBinder,
            u32,
            *mut *mut AParcel,
            *mut *mut AParcel,
            u32,
        ) -> BinderStatus,
        dec_strong: unsafe extern "C" fn(*mut AIBinder),
        // AParcel
        parcel_delete: unsafe extern "C" fn(*mut AParcel),
        read_int32: unsafe extern "C" fn(*const AParcel, *mut i32) -> BinderStatus,
        #[allow(dead_code)]
        read_bool: unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus,
        read_string: unsafe extern "C" fn(
            *const AParcel,
            *mut c_void,
            StringAllocator,
        ) -> BinderStatus,
    }

    struct DlHandle(*mut c_void);
    unsafe impl Send for DlHandle {}
    impl Drop for DlHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { libc::dlclose(self.0) };
            }
        }
    }

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
            get_service: dlsym_fn!(
                handle,
                "AServiceManager_getService",
                unsafe extern "C" fn(*const c_char) -> *mut AIBinder
            ),
            wait_for_service: dlsym_fn!(
                handle,
                "AServiceManager_waitForService",
                unsafe extern "C" fn(*const c_char) -> *mut AIBinder
            ),
            class_define: dlsym_fn!(
                handle,
                "AIBinder_Class_define",
                unsafe extern "C" fn(
                    *const c_char,
                    unsafe extern "C" fn(*mut c_void) -> *mut c_void,
                    unsafe extern "C" fn(*mut c_void),
                    unsafe extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel)
                        -> BinderStatus,
                ) -> *mut AIBinder_Class
            ),
            associate_class: dlsym_fn!(
                handle,
                "AIBinder_associateClass",
                unsafe extern "C" fn(*mut AIBinder, *mut AIBinder_Class) -> bool
            ),
            prepare_transaction: dlsym_fn!(
                handle,
                "AIBinder_prepareTransaction",
                unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> BinderStatus
            ),
            transact: dlsym_fn!(
                handle,
                "AIBinder_transact",
                unsafe extern "C" fn(
                    *mut AIBinder,
                    u32,
                    *mut *mut AParcel,
                    *mut *mut AParcel,
                    u32,
                ) -> BinderStatus
            ),
            dec_strong: dlsym_fn!(
                handle,
                "AIBinder_decStrong",
                unsafe extern "C" fn(*mut AIBinder)
            ),
            parcel_delete: dlsym_fn!(
                handle,
                "AParcel_delete",
                unsafe extern "C" fn(*mut AParcel)
            ),
            read_int32: dlsym_fn!(
                handle,
                "AParcel_readInt32",
                unsafe extern "C" fn(*const AParcel, *mut i32) -> BinderStatus
            ),
            read_bool: dlsym_fn!(
                handle,
                "AParcel_readBool",
                unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus
            ),
            read_string: dlsym_fn!(
                handle,
                "AParcel_readString",
                unsafe extern "C" fn(*const AParcel, *mut c_void, StringAllocator) -> BinderStatus
            ),
        })
    }

    // ── Parcel helpers ────────────────────────────────────────────────────────

    struct ParcelReader<'a> {
        vt: &'a Vtable,
        parcel: *const AParcel,
    }

    impl<'a> ParcelReader<'a> {
        fn read_i32(&self) -> Result<i32, CoreError> {
            let mut v = 0i32;
            let s = unsafe { (self.vt.read_int32)(self.parcel, &mut v) };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AParcel_readInt32"));
            }
            Ok(v)
        }

        #[allow(dead_code)]
        fn read_bool(&self) -> Result<bool, CoreError> {
            let mut v = false;
            let s = unsafe { (self.vt.read_bool)(self.parcel, &mut v) };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AParcel_readBool"));
            }
            Ok(v)
        }

        fn read_string(&self) -> Result<Option<String>, CoreError> {
            let mut buf = StringBuf::new();
            let s = unsafe {
                (self.vt.read_string)(
                    self.parcel,
                    &mut buf as *mut StringBuf as *mut c_void,
                    string_alloc,
                )
            };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AParcel_readString"));
            }
            Ok(buf.as_str().map(str::to_owned))
        }

        // Skip a nullable Parcelable (int32 presence flag + 4 int32s if present).
        fn skip_nullable_rect(&self) -> Result<(), CoreError> {
            let present = self.read_i32()?;
            if present != 0 {
                for _ in 0..4 {
                    self.read_i32()?;
                }
            }
            Ok(())
        }

        // Skip an int32 array (count + count × int32).
        fn skip_int_array(&self) -> Result<(), CoreError> {
            let count = self.read_i32()?;
            for _ in 0..count.max(0) {
                self.read_i32()?;
            }
            Ok(())
        }

        // Skip a string array (count + count × string).
        fn skip_string_array(&self) -> Result<(), CoreError> {
            let count = self.read_i32()?;
            for _ in 0..count.max(0) {
                self.read_string()?;
            }
            Ok(())
        }

        // Skip a typed array of Rects (count + count × nullable_rect).
        fn skip_rect_array(&self) -> Result<(), CoreError> {
            let count = self.read_i32()?;
            for _ in 0..count.max(0) {
                // Each element written via writeTypedObject: presence flag + 4 ints.
                self.skip_nullable_rect()?;
            }
            Ok(())
        }

        // Read a nullable ComponentName → (package, class) or None.
        fn read_component_name(&self) -> Result<Option<(String, String)>, CoreError> {
            let present = self.read_i32()?;
            if present == 0 {
                return Ok(None);
            }
            let pkg = self.read_string()?.unwrap_or_default();
            let cls = self.read_string()?.unwrap_or_default();
            if pkg.is_empty() {
                return Ok(None);
            }
            Ok(Some((pkg, cls)))
        }
    }

    // ── Response parsing ──────────────────────────────────────────────────────

    // Android 11+ response: getFocusedRootTaskInfo
    //   exception (int32=0)
    //   non-null flag for RootTaskInfo (int32: 0=null, 1=present)
    //   topActivity nullable ComponentName (int32 flag + string + string)
    fn parse_root_task_info(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        let ex = r.read_i32()?;
        if ex != EX_NONE {
            return Err(CoreError::binder(ex, "getFocusedRootTaskInfo:exception"));
        }
        let has_info = r.read_i32()?;
        if has_info == 0 {
            return Ok(None);
        }
        Ok(r.read_component_name()?.map(|(pkg, _)| pkg))
    }

    // Android 10 response: getFocusedStackInfo
    //   exception (int32=0)
    //   stackId (int32)
    //   bounds nullable Rect (int32 flag + 4 int32s)
    //   taskIds int32[]
    //   taskNames String[]
    //   taskBounds Rect[] (count + count × nullable_rect)
    //   taskUserIds int32[]
    //   topActivity nullable ComponentName
    fn parse_stack_info(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        let ex = r.read_i32()?;
        if ex != EX_NONE {
            return Err(CoreError::binder(ex, "getFocusedStackInfo:exception"));
        }
        r.read_i32()?;              // stackId
        r.skip_nullable_rect()?;    // bounds
        r.skip_int_array()?;        // taskIds
        r.skip_string_array()?;     // taskNames
        r.skip_rect_array()?;       // taskBounds
        r.skip_int_array()?;        // taskUserIds
        Ok(r.read_component_name()?.map(|(pkg, _)| pkg))
    }

    // ── Tx code resolution ────────────────────────────────────────────────────

    fn read_tx_cache() -> Option<(i32, bool)> {
        let text = std::fs::read_to_string(TX_CACHE_PATH).ok()?;
        let mut parts = text.split_whitespace();
        let root: i32 = parts.next()?.parse().ok()?;
        let stack: i32 = parts.next()?.parse().ok()?;
        // First value is getFocusedRootTaskInfo code; if zero/invalid fall back.
        if root > 0 {
            Some((root, false))
        } else if stack > 0 {
            Some((stack, true))
        } else {
            None
        }
    }

    fn sdk_version() -> Option<u32> {
        android_property_get("ro.build.version.sdk")
            .and_then(|s| s.trim().parse().ok())
    }

    fn table_lookup(api: u32) -> Option<(i32, bool)> {
        // Walk the table and return the entry whose api matches; if exact match
        // not found use the nearest lower entry.
        let mut best: Option<&TxEntry> = None;
        for entry in TX_TABLE {
            if entry.api <= api {
                best = Some(entry);
            }
        }
        best.map(|e| (e.code, e.legacy))
    }

    fn probe_window(api: u32) -> std::ops::Range<i32> {
        // Centre the probe window on the table entry for this API level.
        let centre = table_lookup(api).map(|(c, _)| c).unwrap_or(170);
        (centre - PROBE_WINDOW)..(centre + PROBE_WINDOW)
    }

    // ── ActivityManagerBinder ─────────────────────────────────────────────────

    pub struct ActivityManagerBinder {
        _lib: DlHandle,
        vt: Vtable,
        _class: *mut AIBinder_Class,
        service: *mut AIBinder,
        tx_code: i32,
        legacy: bool,
    }

    // SAFETY: AIBinder is internally reference-counted and thread-safe.
    unsafe impl Send for ActivityManagerBinder {}

    impl ActivityManagerBinder {
        pub fn open() -> Result<Self, CoreError> {
            // dlopen libbinder_ndk.so
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

            // Define the class (client-side, no real transaction handler).
            let class = unsafe {
                (vt.class_define)(
                    ACTIVITY_MANAGER_DESCRIPTOR.as_ptr() as *const c_char,
                    on_create,
                    on_destroy,
                    on_transact,
                )
            };
            if class.is_null() {
                return Err(CoreError::binder(-1, "AIBinder_Class_define"));
            }

            // Get ActivityManager binder handle.
            let service = unsafe {
                (vt.get_service)(ACTIVITY_SERVICE_NAME.as_ptr() as *const c_char)
            };
            if service.is_null() {
                return Err(CoreError::binder(-1, "AServiceManager_getService:activity"));
            }

            // Associate class so prepareTransaction writes the interface descriptor.
            unsafe { (vt.associate_class)(service, class) };

            // Resolve the transaction code.
            let (tx_code, legacy) = Self::resolve_tx(&vt, service, class)?;

            Ok(Self { _lib: lib, vt, _class: class, service, tx_code, legacy })
        }

        fn resolve_tx(
            vt: &Vtable,
            service: *mut AIBinder,
            _class: *mut AIBinder_Class,
        ) -> Result<(i32, bool), CoreError> {
            // 1. Cache file written by fgw.
            if let Some(pair) = read_tx_cache() {
                return Ok(pair);
            }

            // 2. SDK-version table.
            let api = sdk_version().unwrap_or(30);
            if let Some(pair) = table_lookup(api) {
                // Validate the table entry before trusting it.
                if Self::tx_code_valid(vt, service, pair.0, pair.1) {
                    return Ok(pair);
                }
            }

            // 3. Linear probe.
            let window = probe_window(api);
            for code in window {
                let is_legacy = code < 165; // rough heuristic
                if Self::tx_code_valid(vt, service, code, is_legacy) {
                    return Ok((code, is_legacy));
                }
            }

            Err(CoreError::binder(-1, "tx_code_resolution"))
        }

        fn tx_code_valid(
            vt: &Vtable,
            service: *mut AIBinder,
            code: i32,
            _legacy: bool,
        ) -> bool {
            let mut in_parcel: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (vt.prepare_transaction)(service, &mut in_parcel) };
            if s != STATUS_OK {
                return false;
            }

            let mut out_parcel: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (vt.transact)(service, code as u32, &mut in_parcel, &mut out_parcel, 0)
            };
            if s != STATUS_OK {
                if !out_parcel.is_null() {
                    unsafe { (vt.parcel_delete)(out_parcel) };
                }
                return false;
            }

            let r = ParcelReader { vt, parcel: out_parcel };
            let ex = r.read_i32().unwrap_or(-1);
            unsafe { (vt.parcel_delete)(out_parcel) };

            // A valid transaction returns exception code 0.
            // UNKNOWN_TRANSACTION and other errors produce non-zero exception codes
            // or a non-OK binder status that was caught above.
            ex == EX_NONE
        }

        fn do_transact(&self) -> Result<*mut AParcel, CoreError> {
            let mut in_parcel: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.prepare_transaction)(self.service, &mut in_parcel) };
            if s != STATUS_OK {
                return Err(CoreError::binder(s, "AIBinder_prepareTransaction"));
            }

            let mut out_parcel: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (self.vt.transact)(
                    self.service,
                    self.tx_code as u32,
                    &mut in_parcel,
                    &mut out_parcel,
                    0,
                )
            };
            if s != STATUS_OK {
                if !out_parcel.is_null() {
                    unsafe { (self.vt.parcel_delete)(out_parcel) };
                }
                return Err(CoreError::binder(s, "AIBinder_transact"));
            }

            Ok(out_parcel)
        }

        pub fn get_focused_package(&self) -> Result<Option<String>, CoreError> {
            let out = self.do_transact()?;
            let r = ParcelReader { vt: &self.vt, parcel: out };
            let result = if self.legacy {
                parse_stack_info(&r)
            } else {
                parse_root_task_info(&r)
            };
            unsafe { (self.vt.parcel_delete)(out) };
            result
        }
    }

    impl Drop for ActivityManagerBinder {
        fn drop(&mut self) {
            unsafe { (self.vt.dec_strong)(self.service) };
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
