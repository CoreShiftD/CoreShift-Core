// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! NDK binder primitives for querying Android system services.
//!
//! Uses `dlopen` on `libbinder_ndk.so` to avoid hard-linking against a library
//! absent from older NDK toolchains or non-Android targets.
//!
//! ## Transaction code resolution
//!
//! Transaction codes are resolved fresh from `framework.jar` DEX on each
//! startup; no persistent cache.
//!
//! ## Observer mode
//!
//! `ActivityManagerBinder::open_with_observer` registers this process as an
//! `IProcessObserver` with ActivityManager. Callbacks fire when foreground
//! activities change and signal an `eventfd` that callers can poll via epoll.
//! After the eventfd fires, call `get_focused_package` to read the new value.

// ─────────────────────────────────────────────────────────────────────────────
// Android-only implementation
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
mod imp {
    use crate::CoreError;
    use crate::dex;
    use std::os::raw::{c_char, c_void};
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    // ── NDK binder status codes ───────────────────────────────────────────────

    const STATUS_OK: i32 = 0;
    const STATUS_UNKNOWN_TRANSACTION: i32 = -2;
    const EX_NONE: i32 = 0;

    // ── Interface constants ───────────────────────────────────────────────────

    const AM_DESCRIPTOR:    &[u8] = b"android.app.IActivityManager\0";
    const OBS_DESCRIPTOR:   &[u8] = b"android.app.IProcessObserver\0";
    const ACTIVITY_SERVICE: &[u8] = b"activity\0";
    #[cfg(target_pointer_width = "64")]
    const LIBBINDER_PATH: &[u8] = b"/system/lib64/libbinder_ndk.so\0";
    #[cfg(target_pointer_width = "32")]
    const LIBBINDER_PATH: &[u8] = b"/system/lib/libbinder_ndk.so\0";

    // ── Tx code cache ─────────────────────────────────────────────────────────
    // Format (watcher.c compatible): observer_code query_code api_mode fg_code
    // api_mode: 1 = getFocusedRootTaskInfo, 2 = getFocusedStackInfo (API 29)

    // ── Statics for observer callback (binder thread pool context) ────────────
    // These are set once during observer setup before joinThreadPool, and then
    // only read from the callback. Safe to access from multiple binder threads.

    static OBS_FG_CODE: AtomicU32 = AtomicU32::new(0);
    static OBS_EVENTFD:  AtomicI32 = AtomicI32::new(-1);

    // ── Raw NDK type aliases ──────────────────────────────────────────────────

    type AIBinder = c_void;
    #[allow(non_camel_case_types)]
    type AIBinder_Class = c_void;
    type AParcel = c_void;
    type BinderStatus = i32;
    type StringAllocator = unsafe extern "C" fn(*mut c_void, i32, *mut *mut c_char) -> bool;

    // ── AIBinder_Class callbacks ──────────────────────────────────────────────

    // AM client — no-op server side (we're a client only)
    unsafe extern "C" fn am_on_create(_: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
    unsafe extern "C" fn am_on_destroy(_: *mut c_void) {}
    unsafe extern "C" fn am_on_transact(
        _: *mut AIBinder, _: u32, _: *const AParcel, _: *mut AParcel,
    ) -> BinderStatus { STATUS_UNKNOWN_TRANSACTION }

    // IProcessObserver server callbacks
    unsafe extern "C" fn obs_on_create(_: *mut c_void) -> *mut c_void { std::ptr::null_mut() }
    unsafe extern "C" fn obs_on_destroy(_: *mut c_void) {}
    unsafe extern "C" fn obs_on_transact(
        _: *mut AIBinder, code: u32, _: *const AParcel, _: *mut AParcel,
    ) -> BinderStatus {
        if code == OBS_FG_CODE.load(Ordering::Relaxed) {
            let efd = OBS_EVENTFD.load(Ordering::Relaxed);
            if efd >= 0 {
                let val: u64 = 1;
                unsafe { libc::write(efd, &val as *const u64 as *const c_void, 8) };
            }
        }
        STATUS_OK
    }

    // ── String allocator ─────────────────────────────────────────────────────

    unsafe extern "C" fn string_alloc(
        cookie: *mut c_void, length: i32, buffer: *mut *mut c_char,
    ) -> bool {
        if length < 0 { return true; }
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
            if let Some(pos) = self.0.as_bytes().iter().position(|&b| b == 0) {
                unsafe { self.0.as_mut_vec().truncate(pos) };
            }
            if self.0.is_empty() { None } else { Some(self.0) }
        }
    }

    // ── Vtable ────────────────────────────────────────────────────────────────

    struct Vtable {
        get_service:         unsafe extern "C" fn(*const c_char) -> *mut AIBinder,
        class_define:        unsafe extern "C" fn(
                                 *const c_char,
                                 unsafe extern "C" fn(*mut c_void) -> *mut c_void,
                                 unsafe extern "C" fn(*mut c_void),
                                 unsafe extern "C" fn(*mut AIBinder, u32, *const AParcel, *mut AParcel) -> BinderStatus,
                             ) -> *mut AIBinder_Class,
        associate_class:     unsafe extern "C" fn(*mut AIBinder, *mut AIBinder_Class) -> bool,
        new_binder:          unsafe extern "C" fn(*const AIBinder_Class, *mut c_void) -> *mut AIBinder,
        prepare_transaction: unsafe extern "C" fn(*mut AIBinder, *mut *mut AParcel) -> BinderStatus,
        transact:            unsafe extern "C" fn(*mut AIBinder, u32, *mut *mut AParcel, *mut *mut AParcel, u32) -> BinderStatus,
        dec_strong:          unsafe extern "C" fn(*mut AIBinder),
        parcel_delete:       unsafe extern "C" fn(*mut AParcel),
        read_int32:          unsafe extern "C" fn(*const AParcel, *mut i32) -> BinderStatus,
        read_string:         unsafe extern "C" fn(*const AParcel, *mut c_void, StringAllocator) -> BinderStatus,
        write_strong_binder: unsafe extern "C" fn(*mut AParcel, *mut AIBinder) -> BinderStatus,
        set_thread_pool_max: unsafe extern "C" fn(u32),
        join_thread_pool:    unsafe extern "C" fn(),
        write_int32:         unsafe extern "C" fn(*mut AParcel, i32) -> BinderStatus,
        // Optional: only present on API 29+, but all modern Android has this
        read_bool:           Option<unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus>,
    }

    // ── RAII wrappers ─────────────────────────────────────────────────────────

    struct DlHandle(*mut c_void);
    unsafe impl Send for DlHandle {}
    impl Drop for DlHandle {
        fn drop(&mut self) {
            // Intentionally no dlclose: the binder thread pool spawned in
            // open_with_observer() keeps executing library code until process
            // exit. Unloading the library while that thread runs causes
            // use-after-free. libbinder_ndk.so is never unloaded during the
            // daemon lifetime; the OS reclaims it on exit.
        }
    }

    struct OwnedParcel { ptr: *mut AParcel, delete: unsafe extern "C" fn(*mut AParcel) }
    impl Drop for OwnedParcel {
        fn drop(&mut self) { if !self.ptr.is_null() { unsafe { (self.delete)(self.ptr) }; } }
    }

    struct OwnedBinder { ptr: *mut AIBinder, dec_strong: unsafe extern "C" fn(*mut AIBinder) }
    unsafe impl Send for OwnedBinder {}
    impl Drop for OwnedBinder {
        fn drop(&mut self) { if !self.ptr.is_null() { unsafe { (self.dec_strong)(self.ptr) }; } }
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

    macro_rules! dlsym_opt {
        ($handle:expr, $name:literal, $ty:ty) => {{
            let sym = unsafe {
                libc::dlsym($handle, concat!($name, "\0").as_ptr() as *const c_char)
            };
            if sym.is_null() { None }
            else { Some(unsafe { std::mem::transmute::<*mut c_void, $ty>(sym) }) }
        }};
    }

    fn load_vtable(handle: *mut c_void) -> Result<Vtable, CoreError> {
        Ok(Vtable {
            get_service: dlsym_fn!(handle, "AServiceManager_getService",
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
            new_binder: dlsym_fn!(handle, "AIBinder_new",
                unsafe extern "C" fn(*const AIBinder_Class, *mut c_void) -> *mut AIBinder),
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
            read_string: dlsym_fn!(handle, "AParcel_readString",
                unsafe extern "C" fn(*const AParcel, *mut c_void, StringAllocator) -> BinderStatus),
            write_strong_binder: dlsym_fn!(handle, "AParcel_writeStrongBinder",
                unsafe extern "C" fn(*mut AParcel, *mut AIBinder) -> BinderStatus),
            set_thread_pool_max: dlsym_fn!(handle, "ABinderProcess_setThreadPoolMaxThreadCount",
                unsafe extern "C" fn(u32)),
            join_thread_pool: dlsym_fn!(handle, "ABinderProcess_joinThreadPool",
                unsafe extern "C" fn()),
            write_int32: dlsym_fn!(handle, "AParcel_writeInt32",
                unsafe extern "C" fn(*mut AParcel, i32) -> BinderStatus),
            read_bool: dlsym_opt!(handle, "AParcel_readBool",
                unsafe extern "C" fn(*const AParcel, *mut bool) -> BinderStatus),
        })
    }

    // ── ParcelReader ──────────────────────────────────────────────────────────

    struct ParcelReader<'a> { vt: &'a Vtable, parcel: &'a OwnedParcel }

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
                (self.vt.read_string)(self.parcel.ptr, &mut buf as *mut StringBuf as *mut c_void, string_alloc)
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

    // ── Response parsers ──────────────────────────────────────────────────────

    fn parse_root_task_info_body(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        let scratch = r.read_i32()?;
        if scratch != 0 { r.skip_i32s(4)?; }
        r.skip_int_array()?;
        r.read_first_package_from_names()
    }

    fn parse_stack_info_body(r: &ParcelReader<'_>) -> Result<Option<String>, CoreError> {
        r.skip_i32s(5)?;
        r.skip_int_array()?;
        r.read_first_package_from_names()
    }

    // ── Tx code resolution ────────────────────────────────────────────────────

    pub struct TxCodes {
        pub observer_code: u32,
        pub query_code:    u32,
        pub api_mode:      u8,  // 1 = RootTaskInfo, 2 = StackInfo
        pub fg_code:       u32,
    }

    pub fn resolve_tx_codes() -> Result<TxCodes, CoreError> {
        let (obs, query, api, fg) = dex::resolve_tx_codes_from_dex()
            .ok_or_else(|| CoreError::binder(-1, "tx_code_resolution:dex_parse_failed"))?;
        Ok(TxCodes { observer_code: obs, query_code: query, api_mode: api, fg_code: fg })
    }

    // ── ActivityManagerBinder ─────────────────────────────────────────────────

    pub struct ActivityManagerBinder {
        _lib:    DlHandle,
        vt:      Vtable,
        _class:  *mut AIBinder_Class,
        service: OwnedBinder,
        tx_code: u32,
        legacy:  bool,
    }
    unsafe impl Send for ActivityManagerBinder {}

    impl ActivityManagerBinder {
        fn open_inner(handle: *mut c_void) -> Result<(DlHandle, Vtable, *mut AIBinder_Class, OwnedBinder), CoreError> {
            let lib = DlHandle(handle);
            let vt = load_vtable(handle)?;

            let am_class = unsafe {
                (vt.class_define)(
                    AM_DESCRIPTOR.as_ptr() as *const c_char,
                    am_on_create, am_on_destroy, am_on_transact,
                )
            };
            if am_class.is_null() { return Err(CoreError::binder(-1, "AIBinder_Class_define:AM")); }

            let raw = unsafe { (vt.get_service)(ACTIVITY_SERVICE.as_ptr() as *const c_char) };
            if raw.is_null() { return Err(CoreError::binder(-1, "AServiceManager_getService:activity")); }
            unsafe { (vt.associate_class)(raw, am_class) };

            let service = OwnedBinder { ptr: raw, dec_strong: vt.dec_strong };
            Ok((lib, vt, am_class, service))
        }

        fn dlopen_libbinder() -> Result<*mut c_void, CoreError> {
            use std::os::raw::c_char;
            let handle = unsafe {
                libc::dlopen(LIBBINDER_PATH.as_ptr() as *const c_char, libc::RTLD_NOW | libc::RTLD_LOCAL)
            };
            if handle.is_null() { return Err(CoreError::binder(-1, "dlopen:libbinder_ndk.so")); }
            Ok(handle)
        }

        /// Open ActivityManager binder (polling mode — no observer).
        /// Resolves the query tx code from cache or DEX.
        pub fn open() -> Result<Self, CoreError> {
            let handle = Self::dlopen_libbinder()?;
            let (lib, vt, class, service) = Self::open_inner(handle)?;
            let codes = resolve_tx_codes()?;
            let legacy = codes.api_mode == 2;
            Ok(Self { _lib: lib, vt, _class: class, service, tx_code: codes.query_code, legacy })
        }

        /// Open ActivityManager binder and register as IProcessObserver.
        ///
        /// Returns `(Self, eventfd_raw_fd)`. The eventfd becomes readable
        /// whenever `onForegroundActivitiesChanged` fires. Caller must add it
        /// to epoll. After the event fires, call `get_focused_package`.
        pub fn open_with_observer() -> Result<(Self, i32), CoreError> {
            let handle = Self::dlopen_libbinder()?;
            let (lib, vt, am_class, service) = Self::open_inner(handle)?;
            let codes = resolve_tx_codes()?;
            let legacy = codes.api_mode == 2;

            // Create eventfd for callback → epoll bridge
            let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            if efd < 0 { return Err(CoreError::sys(unsafe { *libc::__errno() }, "eventfd")); }

            // Store fg_code and eventfd in statics for the callback
            OBS_FG_CODE.store(codes.fg_code, Ordering::Relaxed);
            OBS_EVENTFD.store(efd, Ordering::Relaxed);

            // Define IProcessObserver class (we're the server)
            let obs_class = unsafe {
                (vt.class_define)(
                    OBS_DESCRIPTOR.as_ptr() as *const c_char,
                    obs_on_create, obs_on_destroy, obs_on_transact,
                )
            };
            if obs_class.is_null() {
                unsafe { libc::close(efd) };
                return Err(CoreError::binder(-1, "AIBinder_Class_define:Observer"));
            }

            // Instantiate our observer binder object
            let obs_binder = unsafe { (vt.new_binder)(obs_class, std::ptr::null_mut()) };
            if obs_binder.is_null() {
                unsafe { libc::close(efd) };
                return Err(CoreError::binder(-1, "AIBinder_new:Observer"));
            }
            unsafe { (vt.associate_class)(obs_binder, obs_class) };

            // Call registerProcessObserver(observer)
            let mut in_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (vt.prepare_transaction)(service.ptr, &mut in_ptr) };
            if s != STATUS_OK {
                unsafe { libc::close(efd) };
                return Err(CoreError::binder(s, "prepareTransaction:registerObserver"));
            }
            unsafe { (vt.write_strong_binder)(in_ptr, obs_binder) };
            let mut out_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (vt.transact)(service.ptr, codes.observer_code, &mut in_ptr, &mut out_ptr, 0)
            };
            if !out_ptr.is_null() { unsafe { (vt.parcel_delete)(out_ptr) }; }
            if s != STATUS_OK {
                unsafe { libc::close(efd) };
                return Err(CoreError::binder(s, "transact:registerProcessObserver"));
            }

            // Start binder thread pool — blocks forever in background thread
            unsafe { (vt.set_thread_pool_max)(0) };
            let join_fn = vt.join_thread_pool;
            std::thread::spawn(move || unsafe { join_fn() });

            let binder = Self { _lib: lib, vt, _class: am_class, service, tx_code: codes.query_code, legacy };
            Ok((binder, efd))
        }

        fn do_transact(&self) -> Result<OwnedParcel, CoreError> {
            let mut in_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.prepare_transaction)(self.service.ptr, &mut in_ptr) };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_prepareTransaction")); }
            let mut out_ptr: *mut AParcel = std::ptr::null_mut();
            let s = unsafe {
                (self.vt.transact)(self.service.ptr, self.tx_code, &mut in_ptr, &mut out_ptr, 0)
            };
            let out = OwnedParcel { ptr: out_ptr, delete: self.vt.parcel_delete };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_transact")); }
            Ok(out)
        }

        pub fn get_focused_package(&self) -> Result<Option<String>, CoreError> {
            let out = self.do_transact()?;
            let r = ParcelReader { vt: &self.vt, parcel: &out };
            let ex = r.read_i32()?;
            if ex != EX_NONE { return Err(CoreError::binder(ex, "getFocusedTask:exception")); }
            let present = r.read_i32()?;
            if present == 0 { return Ok(None); }
            if self.legacy { parse_stack_info_body(&r) } else { parse_root_task_info_body(&r) }
        }
    }

    // ── RawBinderService ──────────────────────────────────────────────────────

    /// Generic binder client for any named Android service.
    ///
    /// Handles its own `dlopen` on `libbinder_ndk.so`. Callers provide raw
    /// transaction codes (resolved via [`crate::dex::find_transaction_code`])
    /// and use [`RawBinderService::transact_bool`] /
    /// [`RawBinderService::transact_i32`] for typed round-trips.
    pub struct RawBinderService {
        _lib:    DlHandle,
        vt:      Vtable,
        service: OwnedBinder,
    }
    unsafe impl Send for RawBinderService {}

    impl RawBinderService {
        /// Open a connection to the named service (e.g. `"power"`, `"batterystats"`).
        pub fn open(service_name: &str) -> Result<Self, CoreError> {
            use std::ffi::CString;
            let handle = unsafe {
                libc::dlopen(LIBBINDER_PATH.as_ptr() as *const c_char, libc::RTLD_NOW | libc::RTLD_LOCAL)
            };
            if handle.is_null() {
                return Err(CoreError::binder(-1, "dlopen:libbinder_ndk.so"));
            }
            let lib = DlHandle(handle);
            let vt = load_vtable(handle)?;
            let cs = CString::new(service_name)
                .map_err(|_| CoreError::binder(-1, "service_name:nul_byte"))?;
            let raw = unsafe { (vt.get_service)(cs.as_ptr()) };
            if raw.is_null() {
                return Err(CoreError::binder(-1, "AServiceManager_getService:null"));
            }
            let service = OwnedBinder { ptr: raw, dec_strong: vt.dec_strong };
            Ok(Self { _lib: lib, vt, service })
        }

        /// Send a no-argument transaction; read exception header then bool reply.
        pub fn transact_bool(&self, code: u32) -> Result<bool, CoreError> {
            let out = self.raw_noarg(code)?;
            let r = ParcelReader { vt: &self.vt, parcel: &out };
            let ex = r.read_i32()?;
            if ex != EX_NONE { return Err(CoreError::binder(ex, "transact_bool:exception")); }
            if let Some(rb) = self.vt.read_bool {
                let mut v = false;
                let s = unsafe { rb(out.ptr as *const AParcel, &mut v) };
                if s != STATUS_OK { return Err(CoreError::binder(s, "AParcel_readBool")); }
                Ok(v)
            } else {
                Ok(r.read_i32()? != 0)
            }
        }

        /// Send a transaction with one i32 argument; discard reply.
        pub fn transact_i32(&self, code: u32, arg: i32) -> Result<(), CoreError> {
            let mut inp: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.prepare_transaction)(self.service.ptr, &mut inp) };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_prepareTransaction")); }
            let s = unsafe { (self.vt.write_int32)(inp, arg) };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AParcel_writeInt32")); }
            let mut out: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.transact)(self.service.ptr, code, &mut inp, &mut out, 0) };
            if !out.is_null() { unsafe { (self.vt.parcel_delete)(out) }; }
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_transact")); }
            Ok(())
        }

        fn raw_noarg(&self, code: u32) -> Result<OwnedParcel, CoreError> {
            let mut inp: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.prepare_transaction)(self.service.ptr, &mut inp) };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_prepareTransaction")); }
            let mut out: *mut AParcel = std::ptr::null_mut();
            let s = unsafe { (self.vt.transact)(self.service.ptr, code, &mut inp, &mut out, 0) };
            let out = OwnedParcel { ptr: out, delete: self.vt.parcel_delete };
            if s != STATUS_OK { return Err(CoreError::binder(s, "AIBinder_transact")); }
            Ok(out)
        }
    }
}

// ── Public re-exports ─────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
pub use imp::{ActivityManagerBinder, RawBinderService, TxCodes, resolve_tx_codes};

// ── Non-Android stubs ─────────────────────────────────────────────────────────

#[cfg(not(target_os = "android"))]
pub struct ActivityManagerBinder;

#[cfg(not(target_os = "android"))]
impl ActivityManagerBinder {
    pub fn open() -> Result<Self, crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
    pub fn open_with_observer() -> Result<(Self, i32), crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
    pub fn get_focused_package(&self) -> Result<Option<String>, crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
}

#[cfg(not(target_os = "android"))]
pub struct RawBinderService;

#[cfg(not(target_os = "android"))]
impl RawBinderService {
    pub fn open(_service_name: &str) -> Result<Self, crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
    pub fn transact_bool(&self, _code: u32) -> Result<bool, crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
    pub fn transact_i32(&self, _code: u32, _arg: i32) -> Result<(), crate::CoreError> {
        Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
    }
}

#[cfg(not(target_os = "android"))]
pub struct TxCodes { pub observer_code: u32, pub query_code: u32, pub api_mode: u8, pub fg_code: u32 }

#[cfg(not(target_os = "android"))]
pub fn resolve_tx_codes() -> Result<TxCodes, crate::CoreError> {
    Err(crate::CoreError::binder(-1, "binder:unsupported platform"))
}
