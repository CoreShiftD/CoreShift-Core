// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Low-level Unix domain socket primitives.
//!
//! This module exposes Linux/Android `AF_UNIX` stream socket mechanics only:
//! bind, listen, accept, connect, chmod for filesystem sockets, peer
//! credentials, and byte I/O through [`Fd`]. Callers own all protocol, message
//! framing, authentication policy, daemon behavior, and socket naming.
//!
//! Abstract socket names are Linux/Android-only. They are encoded with a
//! leading NUL byte in `sun_path`; interior NUL bytes in the caller-provided
//! abstract name are preserved because the kernel uses the explicit sockaddr
//! length, not C string termination.

use crate::CoreError;
use crate::error::syscall_ret;
use crate::reactor::Fd;
use std::io::Error as IoError;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[inline(always)]
fn errno() -> i32 {
    IoError::last_os_error().raw_os_error().unwrap_or(0)
}

/// Owned non-blocking Unix listener descriptor.
pub struct UnixListenerFd {
    /// Underlying descriptor for reactor registration and raw byte helpers.
    pub fd: Fd,
}

/// Owned non-blocking Unix stream descriptor.
pub struct UnixStreamFd {
    /// Underlying descriptor for reactor registration and raw byte helpers.
    pub fd: Fd,
}

/// Result of starting a non-blocking Unix stream connection.
pub enum UnixConnectResult {
    /// The socket connected immediately.
    Connected(UnixStreamFd),
    /// The socket connection is in progress; register for writability and call
    /// [`UnixStreamFd::finish_connect`] or [`UnixStreamFd::check_connect_error`].
    InProgress(UnixStreamFd),
}

/// Unix socket address.
#[derive(Clone, Copy, Debug)]
pub enum UnixSocketAddr<'a> {
    /// Filesystem pathname socket.
    Path(&'a Path),
    /// Linux/Android abstract namespace socket name, without the leading NUL.
    Abstract(&'a [u8]),
}

/// Explicit stale pathname behavior for filesystem socket binds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StaleSocketPolicy {
    /// Preserve any existing path and let `bind` report the conflict.
    #[default]
    Preserve,
    /// Unlink only if the existing path is itself a socket.
    UnlinkSocketOnly,
    /// Unlink any existing filesystem path.
    ///
    /// This may delete non-socket files and should only be used when the caller
    /// owns the path namespace.
    UnlinkAnyPath,
}

/// Bind options for a Unix stream listener.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnixSocketBindOptions {
    /// Explicit stale pathname handling for filesystem socket binds.
    pub stale_socket_policy: StaleSocketPolicy,
    /// Optional filesystem socket path mode applied after a successful bind.
    pub mode: Option<u32>,
}

/// Peer process credentials when the platform exposes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Peer process id when available.
    pub pid: Option<i32>,
    /// Peer user id.
    pub uid: u32,
    /// Peer group id.
    pub gid: u32,
}

impl UnixListenerFd {
    /// Accept one non-blocking client.
    ///
    /// Returns `Ok(None)` if no client is ready.
    pub fn accept(&self) -> Result<Option<UnixStreamFd>, CoreError> {
        loop {
            let fd = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if fd >= 0 {
                return Ok(Some(UnixStreamFd {
                    fd: Fd::new(fd, "accept4")?,
                }));
            }

            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                return Ok(None);
            }
            return Err(CoreError::sys(e, "accept4"));
        }
    }
}

impl UnixStreamFd {
    /// Return peer credentials when the platform supports `SO_PEERCRED`.
    pub fn peer_cred(&self) -> Result<Option<PeerCred>, CoreError> {
        peer_cred_raw(&self.fd)
    }

    /// Return the pending `SO_ERROR` connect status.
    ///
    /// `Ok(None)` means no pending socket error was reported. `Ok(Some(code))`
    /// returns the raw connect error without making a policy decision.
    pub fn check_connect_error(&self) -> Result<Option<i32>, CoreError> {
        let mut code: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut code as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        syscall_ret(ret, "getsockopt(SO_ERROR)")?;
        if code == 0 { Ok(None) } else { Ok(Some(code)) }
    }

    /// Finish a non-blocking connect after the socket becomes writable.
    ///
    /// Returns the stream when `SO_ERROR` is clear; otherwise returns the raw
    /// socket error as [`CoreError`].
    pub fn finish_connect(self) -> Result<Self, CoreError> {
        match self.check_connect_error()? {
            None => Ok(self),
            Some(code) => Err(CoreError::sys(code, "connect(SO_ERROR)")),
        }
    }
}

/// Bind and listen on a non-blocking Unix stream socket.
pub fn bind_unix_listener(
    addr: UnixSocketAddr<'_>,
    opts: UnixSocketBindOptions,
) -> Result<UnixListenerFd, CoreError> {
    let encoded = UnixSockAddr::new(addr, "unix bind address")?;

    match addr {
        UnixSocketAddr::Path(path) => {
            apply_stale_socket_policy(path, opts.stale_socket_policy)?;
        }
        UnixSocketAddr::Abstract(_) => {
            if opts.stale_socket_policy != StaleSocketPolicy::Preserve || opts.mode.is_some() {
                return Err(CoreError::sys(libc::EINVAL, "abstract unix bind options"));
            }
        }
    }

    let fd = new_unix_stream_socket()?;
    let ret = unsafe { libc::bind(fd.as_raw_fd(), encoded.as_ptr(), encoded.len()) };
    syscall_ret(ret, "bind")?;

    if let (UnixSocketAddr::Path(path), Some(mode)) = (addr, opts.mode) {
        if let Err(err) = chmod_unix_socket(UnixSocketAddr::Path(path), mode) {
            cleanup_created_path(addr);
            return Err(err);
        }
    }

    let ret = unsafe { libc::listen(fd.as_raw_fd(), libc::SOMAXCONN) };
    if let Err(err) = syscall_ret(ret, "listen") {
        cleanup_created_path(addr);
        return Err(err);
    }

    Ok(UnixListenerFd { fd })
}

/// Connect a non-blocking Unix stream socket.
pub fn connect_unix_stream(addr: UnixSocketAddr<'_>) -> Result<UnixConnectResult, CoreError> {
    let encoded = UnixSockAddr::new(addr, "unix connect address")?;
    let fd = new_unix_stream_socket()?;

    loop {
        let ret = unsafe { libc::connect(fd.as_raw_fd(), encoded.as_ptr(), encoded.len()) };
        if ret == 0 {
            return Ok(UnixConnectResult::Connected(UnixStreamFd { fd }));
        }

        let e = errno();
        if e == libc::EINTR {
            continue;
        }
        if e == libc::EINPROGRESS || e == libc::EALREADY {
            return Ok(UnixConnectResult::InProgress(UnixStreamFd { fd }));
        }
        if e == libc::EISCONN {
            return Ok(UnixConnectResult::Connected(UnixStreamFd { fd }));
        }
        return Err(CoreError::sys(e, "connect"));
    }
}

/// Change mode bits on a Unix socket filesystem path.
pub fn chmod_unix_socket(addr: UnixSocketAddr<'_>, mode: u32) -> Result<(), CoreError> {
    match addr {
        UnixSocketAddr::Path(path) => {
            let metadata = std::fs::symlink_metadata(path).map_err(|err| {
                CoreError::sys(
                    err.raw_os_error().unwrap_or(libc::EIO),
                    "lstat unix socket path",
                )
            })?;
            if !metadata.file_type().is_socket() {
                return Err(CoreError::sys(libc::EINVAL, "chmod unix socket path"));
            }
            let c_path = path_cstring(path, "chmod unix socket path")?;
            let ret = unsafe { libc::chmod(c_path.as_ptr(), mode as libc::mode_t) };
            syscall_ret(ret, "chmod")
        }
        UnixSocketAddr::Abstract(_) => Err(CoreError::sys(libc::EINVAL, "chmod abstract socket")),
    }
}

/// Change mode bits on a Unix socket filesystem path.
pub fn chmod_socket_path(path: impl AsRef<Path>, mode: u32) -> Result<(), CoreError> {
    chmod_unix_socket(UnixSocketAddr::Path(path.as_ref()), mode)
}

fn new_unix_stream_socket() -> Result<Fd, CoreError> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    syscall_ret(fd, "socket(AF_UNIX)")?;
    Fd::new(fd, "socket(AF_UNIX)")
}

fn apply_stale_socket_policy(path: &Path, policy: StaleSocketPolicy) -> Result<(), CoreError> {
    match policy {
        StaleSocketPolicy::Preserve => Ok(()),
        StaleSocketPolicy::UnlinkSocketOnly => {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
                Err(err) => {
                    return Err(CoreError::sys(
                        err.raw_os_error().unwrap_or(libc::EIO),
                        "lstat unix socket path",
                    ));
                }
            };
            if !metadata.file_type().is_socket() {
                return Err(CoreError::sys(libc::EEXIST, "stale unix socket path"));
            }
            unlink_path(path, "unlink stale unix socket")
        }
        StaleSocketPolicy::UnlinkAnyPath => unlink_path(path, "unlink unix socket path"),
    }
}

fn unlink_path(path: &Path, op: &'static str) -> Result<(), CoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(err) => Err(CoreError::sys(err.raw_os_error().unwrap_or(libc::EIO), op)),
    }
}

fn cleanup_created_path(addr: UnixSocketAddr<'_>) {
    if let UnixSocketAddr::Path(path) = addr {
        let _ = std::fs::remove_file(path);
    }
}

struct UnixSockAddr {
    inner: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl UnixSockAddr {
    fn new(addr: UnixSocketAddr<'_>, op: &'static str) -> Result<Self, CoreError> {
        let mut inner: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        inner.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let sun_path_offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);

        let len = match addr {
            UnixSocketAddr::Path(path) => {
                let bytes = path.as_os_str().as_bytes();
                if bytes.is_empty() {
                    return Err(CoreError::sys(libc::EINVAL, op));
                }
                if bytes.contains(&0) {
                    return Err(CoreError::sys(libc::EINVAL, op));
                }
                if bytes.len() >= inner.sun_path.len() {
                    return Err(CoreError::sys(libc::ENAMETOOLONG, op));
                }

                for (slot, byte) in inner.sun_path.iter_mut().zip(bytes.iter().copied()) {
                    *slot = byte as libc::c_char;
                }
                sun_path_offset + bytes.len() + 1
            }
            UnixSocketAddr::Abstract(name) => {
                validate_abstract_supported()?;
                if name.is_empty() {
                    return Err(CoreError::sys(libc::EINVAL, op));
                }
                if name.len() + 1 > inner.sun_path.len() {
                    return Err(CoreError::sys(libc::ENAMETOOLONG, op));
                }

                inner.sun_path[0] = 0;
                for (slot, byte) in inner.sun_path[1..].iter_mut().zip(name.iter().copied()) {
                    *slot = byte as libc::c_char;
                }
                sun_path_offset + 1 + name.len()
            }
        };
        let len = libc::socklen_t::try_from(len).map_err(|_| CoreError::sys(libc::EINVAL, op))?;

        Ok(Self { inner, len })
    }

    fn len(&self) -> libc::socklen_t {
        self.len
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        (&self.inner as *const libc::sockaddr_un).cast()
    }
}

fn validate_abstract_supported() -> Result<(), CoreError> {
    if cfg!(any(target_os = "linux", target_os = "android")) {
        Ok(())
    } else {
        Err(CoreError::sys(libc::ENOSYS, "abstract unix socket"))
    }
}

fn path_cstring(path: &Path, op: &'static str) -> Result<std::ffi::CString, CoreError> {
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| CoreError::sys(libc::EINVAL, op))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_cred_raw(fd: &Fd) -> Result<Option<PeerCred>, CoreError> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    syscall_ret(ret, "getsockopt(SO_PEERCRED)")?;

    Ok(Some(PeerCred {
        pid: Some(cred.pid),
        uid: cred.uid,
        gid: cred.gid,
    }))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn peer_cred_raw(_fd: &Fd) -> Result<Option<PeerCred>, CoreError> {
    Ok(None)
}
