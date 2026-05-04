// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

use crate::fs::{path_exists, path_lstat_exists, readahead};
use crate::inotify::{InotifyEvent, decode_events, decode_events_checked};
use crate::io::DrainState;
use crate::proc::{
    clock_ticks_per_second, parse_proc_cmdline_bytes, parse_proc_status, read_proc_cmdline_at,
};
use crate::reactor::{Fd, Reactor};
use crate::signal::{install_shutdown_flag, install_shutdown_flag_guard, shutdown_requested};
use crate::spawn::{Process, ProcessGroup, SpawnBackend, SpawnFdPolicy, SpawnOptions, spawn_start};
use crate::uid::{path_lstat, path_stat, path_uid, proc_stat_at, proc_uid, proc_uid_at};
use crate::unix_socket::{
    StaleSocketPolicy, UnixConnectResult, UnixSocketAddr, UnixSocketBindOptions,
    bind_unix_listener, chmod_unix_socket, connect_unix_stream,
};
use std::fs::{File, remove_file};
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

fn with_temp_readahead_file<T>(f: impl FnOnce(File, &std::path::Path) -> T) -> T {
    let path = std::env::temp_dir().join(format!(
        "coreshift_test_readahead_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    file.write_all(b"readahead test data").unwrap();
    file.sync_all().unwrap();

    let result = f(file, &path);
    let _ = remove_file(&path);
    result
}

fn temp_socket_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "coreshift_test_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn bind_test_unix_listener(path: &Path, unlink_stale: bool) -> crate::unix_socket::UnixListenerFd {
    bind_unix_listener(
        UnixSocketAddr::Path(path),
        UnixSocketBindOptions {
            stale_socket_policy: if unlink_stale {
                StaleSocketPolicy::UnlinkSocketOnly
            } else {
                StaleSocketPolicy::Preserve
            },
            mode: None,
        },
    )
    .unwrap()
}

fn connect_test_unix_stream(addr: UnixSocketAddr<'_>) -> crate::unix_socket::UnixStreamFd {
    match connect_unix_stream(addr).unwrap() {
        UnixConnectResult::Connected(stream) => stream,
        UnixConnectResult::InProgress(stream) => stream.finish_connect().unwrap(),
    }
}

fn assert_readahead_result(result: Result<(), crate::CoreError>) {
    match result {
        Ok(()) => {}
        Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {
            eprintln!("skipping readahead test: unsupported on this target");
        }
        Err(err) => panic!("readahead failed unexpectedly: {err}"),
    }
}

struct RawFdRef(RawFd);

static TEST_SHUTDOWN_FLAG_A: AtomicBool = AtomicBool::new(false);
static TEST_SHUTDOWN_FLAG_B: AtomicBool = AtomicBool::new(false);

impl AsRawFd for RawFdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[test]
fn test_decode_inotify_events() {
    // Mock multiple inotify_event records.
    let mut buf = Vec::new();

    // Event 1: wd=1, mask=0x2, len=0
    buf.extend_from_slice(&1i32.to_ne_bytes());
    buf.extend_from_slice(&2u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cookie
    buf.extend_from_slice(&0u32.to_ne_bytes()); // len

    // Event 2: wd=2, mask=0x4, len=8 (with name padding)
    buf.extend_from_slice(&2i32.to_ne_bytes());
    buf.extend_from_slice(&4u32.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // cookie
    buf.extend_from_slice(&8u32.to_ne_bytes()); // len
    buf.extend_from_slice(b"file.txt"); // 8 bytes

    // Event 3: truncated (only 8 bytes of header)
    buf.extend_from_slice(&3i32.to_ne_bytes());
    buf.extend_from_slice(&8u32.to_ne_bytes());

    let events = decode_events(&buf);
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        InotifyEvent {
            wd: 1,
            mask: 2,
            name: None,
        }
    );
    assert_eq!(
        events[1],
        InotifyEvent {
            wd: 2,
            mask: 4,
            name: Some(b"file.txt".to_vec()),
        }
    );

    let err = decode_events_checked(&buf).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_parse_proc_status() {
    let content = "Name:\tcore_daemon\nState:\tR (running)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
    let status = parse_proc_status(content).unwrap();
    assert_eq!(status.name, "core_daemon");
    assert_eq!(status.uid, 1000);
}

#[test]
fn test_parse_proc_status_missing_uid_is_invalid() {
    let content = "Name:\tcore_daemon\nState:\tR (running)\n";
    let err = parse_proc_status(content).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_parse_proc_cmdline_bytes_replaces_nul_separators() {
    let content = b"/system/bin/sh\0-c\0echo hello\0";
    assert_eq!(
        parse_proc_cmdline_bytes(content),
        "/system/bin/sh -c echo hello"
    );
}

#[test]
fn test_read_proc_cmdline_at_uses_explicit_root() {
    let proc_root = std::env::temp_dir().join(format!(
        "coreshift_test_proc_root_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pid_dir = proc_root.join("12345");
    std::fs::create_dir_all(&pid_dir).unwrap();
    std::fs::write(pid_dir.join("cmdline"), b"com.example.app\0:service\0").unwrap();

    let cmdline = read_proc_cmdline_at(&proc_root, 12345).unwrap();
    assert_eq!(cmdline, "com.example.app :service");

    let _ = std::fs::remove_dir_all(&proc_root);
}

#[test]
fn test_exec_context_validation() {
    // Empty argv
    let res = SpawnOptions::builder(vec![]).build();
    assert!(res.is_err());

    // Interior NUL in argv
    let res = SpawnOptions::builder(vec!["valid".to_string(), "inv\0alid".to_string()]).build();
    assert!(res.is_err());

    // Valid
    let res = SpawnOptions::builder(vec!["/bin/ls".to_string(), "-l".to_string()])
        .backend(SpawnBackend::Fork)
        .cwd("/tmp".to_string())
        .build();
    assert!(res.is_ok());
}

#[test]
fn test_spawn_backend_required() {
    let err = match SpawnOptions::builder(vec!["/bin/true".to_string()]).build() {
        Ok(_) => panic!("expected missing backend to fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_posix_spawn_rejects_unsupported_cwd() {
    let opts = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::PosixSpawn)
        .cwd("/tmp".to_string())
        .build()
        .unwrap();

    let err = match spawn_start(opts) {
        Ok(_) => panic!("expected unsupported posix_spawn cwd to fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_posix_spawn_rejects_unsupported_setsid() {
    let opts = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::PosixSpawn)
        .pgroup(ProcessGroup::new(None, true))
        .build()
        .unwrap();

    let err = match spawn_start(opts) {
        Ok(_) => panic!("expected unsupported posix_spawn setsid to fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_posix_spawn_rejects_close_from3_fd_policy() {
    let opts = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::PosixSpawn)
        .fd_policy(SpawnFdPolicy::CloseFrom3)
        .build()
        .unwrap();

    let err = match spawn_start(opts) {
        Ok(_) => panic!("expected unsupported fd policy to fail"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_fork_reports_child_chdir_error() {
    let err = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::Fork)
        .cwd("/definitely/missing/coreshift-core-test".to_string())
        .build()
        .unwrap()
        .run()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    assert!(err.to_string().contains("fork child chdir"));
}

#[test]
fn test_spawn_fd_policy_rejects_dirty_allowlist() {
    let file = File::open("/dev/null").unwrap();
    let fd = file.as_raw_fd();
    let err = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::Fork)
        .fd_policy(SpawnFdPolicy::Allowlist(vec![fd, fd]))
        .build()
        .unwrap()
        .run()
        .unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_fork_close_from3_closes_inherited_fd() {
    let file = File::open("/dev/null").unwrap();
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_eq!(ret, 0);

    let script = format!("if [ -e /proc/$$/fd/{fd} ]; then echo open; else echo closed; fi");
    let output = SpawnOptions::builder(vec!["/bin/sh".to_string(), "-c".to_string(), script])
        .backend(SpawnBackend::Fork)
        .fd_policy(SpawnFdPolicy::CloseFrom3)
        .capture_stdout()
        .build()
        .unwrap()
        .run()
        .unwrap();

    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "closed");
}

#[test]
fn test_fork_allowlist_preserves_allowed_fd() {
    let file = File::open("/dev/null").unwrap();
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_eq!(ret, 0);

    let script = format!("if [ -e /proc/$$/fd/{fd} ]; then echo open; else echo closed; fi");
    let output = SpawnOptions::builder(vec!["/bin/sh".to_string(), "-c".to_string(), script])
        .backend(SpawnBackend::Fork)
        .fd_policy(SpawnFdPolicy::Allowlist(vec![fd]))
        .capture_stdout()
        .build()
        .unwrap()
        .run()
        .unwrap();

    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "open");
}

#[test]
fn test_process_echild() {
    // Use an invalid PID that likely doesn't exist and isn't our child.
    let p = Process::new(999999);
    let res = p.wait_step();
    // Should be an error (ECHILD), not Ok(Some(Exited(0))).
    assert!(res.is_err());
}

#[test]
fn test_spawn_start_wait_false_validation() {
    let base_builder = SpawnOptions::builder(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "true".to_string(),
    ])
    .backend(SpawnBackend::PosixSpawn)
    .wait(false)
    .max_output(1024)
    .kill_grace_ms(1000);

    // Valid: wait=false, no I/O capture
    assert!(spawn_start(base_builder.clone().build().unwrap()).is_ok());

    // Invalid: wait=false, capture_stdout=true
    assert!(spawn_start(base_builder.clone().capture_stdout().build().unwrap()).is_err());

    // Invalid: wait=false, stdin=Some(...)
    assert!(spawn_start(base_builder.stdin(vec![1, 2, 3]).build().unwrap()).is_err());
}

#[test]
fn test_reactor_wait_zero_events() {
    let mut reactor = Reactor::new().unwrap();
    let mut events = Vec::new();
    let res = reactor.wait(&mut events, 0, 0);
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), 0);
}

#[test]
fn test_reactor_add_priority_registers_fd() {
    let mut reactor = Reactor::new().unwrap();
    let fd = Fd::eventfd(0).unwrap();
    let token = reactor.add_priority(&fd).unwrap();
    let mut events = Vec::new();

    assert_eq!(reactor.wait(&mut events, 4, 0).unwrap(), 0);
    assert!(events.is_empty());
    assert!(format!("{token:?}").starts_with("Token("));
}

#[test]
fn test_fd_slice_io_helpers() {
    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let r = Fd::new(fds[0], "pipe").unwrap();
    let w = Fd::new(fds[1], "pipe").unwrap();

    let input = b"hello";
    let written = w.write_slice(input).unwrap().unwrap();
    assert_eq!(written, input.len());

    let mut buf = [0u8; 8];
    let read = r.read_slice(&mut buf).unwrap().unwrap();
    assert_eq!(read, input.len());
    assert_eq!(&buf[..read], input);
}

#[test]
fn test_unix_socket_bind_connect_roundtrip() {
    let path = temp_socket_path("unix_roundtrip");
    let listener = bind_test_unix_listener(&path, false);
    let client = connect_test_unix_stream(UnixSocketAddr::Path(&path));

    let server = loop {
        if let Some(server) = listener.accept().unwrap() {
            break server;
        }
        std::thread::yield_now();
    };

    let written = client.fd.write_slice(b"ping").unwrap().unwrap();
    assert_eq!(written, 4);

    let mut buf = [0u8; 8];
    let read = loop {
        if let Some(read) = server.fd.read_slice(&mut buf).unwrap() {
            break read;
        }
        std::thread::yield_now();
    };
    assert_eq!(&buf[..read], b"ping");

    chmod_unix_socket(UnixSocketAddr::Path(&path), 0o600).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_abstract_bind_connect_roundtrip() {
    let name = format!(
        "coreshift_abstract_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let listener = bind_unix_listener(
        UnixSocketAddr::Abstract(name.as_bytes()),
        UnixSocketBindOptions::default(),
    )
    .unwrap();
    let client = connect_test_unix_stream(UnixSocketAddr::Abstract(name.as_bytes()));

    let server = loop {
        if let Some(server) = listener.accept().unwrap() {
            break server;
        }
        std::thread::yield_now();
    };

    let written = client.fd.write_slice(b"pong").unwrap().unwrap();
    assert_eq!(written, 4);

    let mut buf = [0u8; 8];
    let read = loop {
        if let Some(read) = server.fd.read_slice(&mut buf).unwrap() {
            break read;
        }
        std::thread::yield_now();
    };
    assert_eq!(&buf[..read], b"pong");
}

#[test]
fn test_unix_socket_connect_result_finish_is_safe() {
    let path = temp_socket_path("unix_connect_result");
    let _listener = bind_test_unix_listener(&path, false);

    let client = match connect_unix_stream(UnixSocketAddr::Path(&path)).unwrap() {
        UnixConnectResult::Connected(stream) => {
            assert_eq!(stream.check_connect_error().unwrap(), None);
            stream
        }
        UnixConnectResult::InProgress(stream) => stream.finish_connect().unwrap(),
    };

    drop(client);
    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_unlinks_stale_path_when_requested() {
    let path = temp_socket_path("unix_unlink_stale");
    {
        let _listener = bind_test_unix_listener(&path, false);
    }

    let _listener = bind_test_unix_listener(&path, true);
    assert!(std::fs::metadata(&path).unwrap().file_type().is_socket());

    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_does_not_unlink_stale_path_by_default() {
    let path = temp_socket_path("unix_no_unlink");
    File::create(&path).unwrap();

    let result = bind_unix_listener(
        UnixSocketAddr::Path(&path),
        UnixSocketBindOptions {
            stale_socket_policy: StaleSocketPolicy::Preserve,
            mode: None,
        },
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EADDRINUSE));

    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_unlink_socket_only_preserves_regular_file() {
    let path = temp_socket_path("unix_regular_preserved");
    File::create(&path).unwrap();

    let result = bind_unix_listener(
        UnixSocketAddr::Path(&path),
        UnixSocketBindOptions {
            stale_socket_policy: StaleSocketPolicy::UnlinkSocketOnly,
            mode: None,
        },
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
    assert!(std::fs::metadata(&path).unwrap().is_file());

    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_nul_path_rejected() {
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/core\0socket".to_vec()));
    let result = bind_unix_listener(
        UnixSocketAddr::Path(&path),
        UnixSocketBindOptions {
            stale_socket_policy: StaleSocketPolicy::Preserve,
            mode: None,
        },
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));

    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/core\0socket".to_vec()));
    let result = connect_unix_stream(UnixSocketAddr::Path(&path));
    let err = match result {
        Ok(_) => panic!("connect unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_unix_socket_overlong_path_and_abstract_rejected() {
    let path = PathBuf::from("/tmp".to_string() + &"/x".repeat(120));
    let result = bind_unix_listener(
        UnixSocketAddr::Path(&path),
        UnixSocketBindOptions::default(),
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::ENAMETOOLONG));

    let name = vec![b'x'; 108];
    let result = bind_unix_listener(
        UnixSocketAddr::Abstract(&name),
        UnixSocketBindOptions::default(),
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::ENAMETOOLONG));
}

#[test]
fn test_unix_socket_accept_returns_none_on_eagain() {
    let path = temp_socket_path("unix_accept_eagain");
    let listener = bind_test_unix_listener(&path, false);

    assert!(listener.accept().unwrap().is_none());

    let _ = remove_file(&path);
}

#[test]
fn test_unix_socket_chmod_path_only() {
    let regular = temp_socket_path("unix_chmod_regular");
    File::create(&regular).unwrap();
    let err = chmod_unix_socket(UnixSocketAddr::Path(&regular), 0o600).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    let _ = remove_file(&regular);

    let name = b"coreshift_abstract_chmod_rejected";
    let err = chmod_unix_socket(UnixSocketAddr::Abstract(name), 0o600).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));

    let result = bind_unix_listener(
        UnixSocketAddr::Abstract(name),
        UnixSocketBindOptions {
            stale_socket_policy: StaleSocketPolicy::Preserve,
            mode: Some(0o600),
        },
    );
    let err = match result {
        Ok(_) => panic!("bind unexpectedly succeeded"),
        Err(err) => err,
    };
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_unix_socket_peer_credentials_when_supported() {
    let path = temp_socket_path("unix_peer_cred");
    let listener = bind_test_unix_listener(&path, false);
    let client = connect_test_unix_stream(UnixSocketAddr::Path(&path));

    let server = loop {
        if let Some(server) = listener.accept().unwrap() {
            break server;
        }
        std::thread::yield_now();
    };

    if let Some(cred) = server.peer_cred().unwrap() {
        assert_eq!(cred.pid, Some(std::process::id() as i32));
        assert_eq!(cred.uid, unsafe { libc::geteuid() });
        assert_eq!(cred.gid, unsafe { libc::getegid() });
    }

    drop(client);
    let _ = remove_file(&path);
}

fn early_exit_on_stop(chunk: &[u8]) -> bool {
    chunk.windows(4).any(|window| window == b"stop")
}

#[test]
fn test_drain_early_exit_is_explicit_state_not_eof() {
    let mut fds = [0; 2];
    unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
    let r = Fd::new(fds[0], "pipe").unwrap();
    let w = Fd::new(fds[1], "pipe").unwrap();
    w.write_slice(b"stop").unwrap();

    let mut drain =
        DrainState::new(None, None, Some(r), None, 128, Some(early_exit_on_stop)).unwrap();
    assert!(drain.read_fd(true).unwrap());
    assert!(drain.stdout_early_exited());

    assert!(!drain.output_limit_exceeded());
}

#[test]
fn test_spawn_output_limit_is_combined_and_errors() {
    let err = SpawnOptions::builder(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "printf 12345; printf 67890 >&2".to_string(),
    ])
    .backend(SpawnBackend::PosixSpawn)
    .capture_stdout()
    .capture_stderr()
    .max_output(8)
    .build()
    .unwrap()
    .run()
    .unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EOVERFLOW));
}

#[test]
fn test_spawn_output_exact_limit_eof_is_not_overflow() {
    let out = SpawnOptions::builder(vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "printf 12345".to_string(),
    ])
    .backend(SpawnBackend::PosixSpawn)
    .capture_stdout()
    .max_output(5)
    .build()
    .unwrap()
    .run()
    .unwrap();

    assert_eq!(out.stdout, b"12345");
}

#[test]
fn test_spawn_zero_output_limit_without_output_is_not_overflow() {
    let out = SpawnOptions::builder(vec!["/bin/true".to_string()])
        .backend(SpawnBackend::PosixSpawn)
        .capture_stdout()
        .capture_stderr()
        .max_output(0)
        .build()
        .unwrap()
        .run()
        .unwrap();

    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
}

#[test]
fn test_writer_state_epipe() {
    use crate::io::writer::WriterState;

    let mut fds = [0; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let r = Fd::new(fds[0], "pipe").unwrap();
    let w = Fd::new(fds[1], "pipe").unwrap();

    let mut writer = WriterState::new(Some(vec![0u8; 1024 * 1024].into_boxed_slice()));

    // Close read end to trigger EPIPE on next write
    drop(r);

    // Some kernels might not trigger EPIPE on the first write if the pipe buffer has space,
    // but with enough data it will fail.
    let mut last_res = Ok(false);
    for _ in 0..100 {
        last_res = writer.write_to_fd(&w);
        if last_res.is_err() || (last_res.is_ok() && writer.buf.is_none()) {
            break;
        }
    }

    // EPIPE should be handled as "done" (Ok(true))
    assert!(last_res.is_ok());
    assert!(last_res.unwrap());
    assert!(writer.buf.is_none());
}

#[test]
fn test_path_existence() {
    let temp_file = std::env::temp_dir().join("coreshift_test_path");
    let path_str = temp_file.to_str().unwrap();

    std::fs::write(&temp_file, "test").unwrap();
    assert!(path_exists(path_str));
    assert!(path_lstat_exists(path_str));

    std::fs::remove_file(&temp_file).unwrap();
    assert!(!path_exists(path_str));
    assert!(!path_lstat_exists(path_str));
}

#[test]
fn test_path_uid_temp_file() {
    let path = std::env::temp_dir().join(format!(
        "coreshift_test_uid_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"uid").unwrap();

    let uid = path_uid(&path).unwrap();
    assert_eq!(uid, unsafe { libc::geteuid() });

    remove_file(&path).unwrap();
}

#[test]
fn test_path_stat_reports_identity_fields() {
    let path = std::env::temp_dir().join(format!(
        "coreshift_test_path_stat_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"identity").unwrap();

    let stat = path_stat(&path).unwrap();
    assert_eq!(stat.uid, unsafe { libc::geteuid() });
    assert!(stat.inode > 0);

    remove_file(&path).unwrap();
}

#[test]
fn test_path_stat_follows_symlink_and_lstat_reports_link() {
    let dir = std::env::temp_dir().join(format!(
        "coreshift_test_symlink_stat_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let target = dir.join("target");
    let link = dir.join("link");
    std::fs::write(&target, b"identity").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let target_stat = path_stat(&target).unwrap();
    let followed = path_stat(&link).unwrap();
    let link_stat = path_lstat(&link).unwrap();

    assert_eq!(followed.inode, target_stat.inode);
    assert_ne!(link_stat.inode, target_stat.inode);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_clock_ticks_per_second_checked_result() {
    let ticks = clock_ticks_per_second().unwrap();
    assert!(ticks > 0);
}

#[test]
fn test_proc_uid_current_process() {
    let uid = proc_uid(std::process::id() as i32).unwrap();
    assert_eq!(uid, unsafe { libc::geteuid() });
}

#[test]
fn test_proc_uid_at_uses_explicit_root() {
    let proc_root = std::env::temp_dir().join(format!(
        "coreshift_test_proc_uid_root_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pid_dir = proc_root.join("54321");
    std::fs::create_dir_all(&pid_dir).unwrap();

    let uid = proc_uid_at(&proc_root, 54321).unwrap();
    assert_eq!(uid, unsafe { libc::geteuid() });

    let _ = std::fs::remove_dir_all(&proc_root);
}

#[test]
fn test_proc_stat_at_uses_explicit_root() {
    let proc_root = std::env::temp_dir().join(format!(
        "coreshift_test_proc_stat_root_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let pid_dir = proc_root.join("54321");
    std::fs::create_dir_all(&pid_dir).unwrap();

    let stat = proc_stat_at(&proc_root, 54321).unwrap();
    assert_eq!(stat.uid, unsafe { libc::geteuid() });
    assert!(stat.inode > 0);

    let _ = std::fs::remove_dir_all(&proc_root);
}

#[test]
fn test_proc_uid_invalid_pid_returns_error() {
    let err = proc_uid(999_999).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn test_path_uid_missing_path_returns_error() {
    let path = std::env::temp_dir().join(format!(
        "coreshift_missing_uid_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let err = path_uid(&path).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
}

#[test]
fn test_install_shutdown_flag_compiles_and_sets_helper_state() {
    TEST_SHUTDOWN_FLAG_A.store(false, Ordering::Release);
    install_shutdown_flag(&TEST_SHUTDOWN_FLAG_A).unwrap();
    assert!(!shutdown_requested(&TEST_SHUTDOWN_FLAG_A));

    TEST_SHUTDOWN_FLAG_A.store(true, Ordering::Release);
    assert!(shutdown_requested(&TEST_SHUTDOWN_FLAG_A));
    TEST_SHUTDOWN_FLAG_A.store(false, Ordering::Release);
}

#[test]
fn test_install_shutdown_flag_repeated_install_does_not_panic() {
    TEST_SHUTDOWN_FLAG_A.store(false, Ordering::Release);
    TEST_SHUTDOWN_FLAG_B.store(false, Ordering::Release);

    install_shutdown_flag(&TEST_SHUTDOWN_FLAG_A).unwrap();
    install_shutdown_flag(&TEST_SHUTDOWN_FLAG_B).unwrap();

    assert!(!shutdown_requested(&TEST_SHUTDOWN_FLAG_A));
    assert!(!shutdown_requested(&TEST_SHUTDOWN_FLAG_B));
}

#[test]
fn test_shutdown_flag_guard_restores_previous_handler() {
    let mut ignore_action: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut old_action: libc::sigaction = unsafe { std::mem::zeroed() };
    ignore_action.sa_sigaction = libc::SIG_IGN;
    unsafe { libc::sigemptyset(&mut ignore_action.sa_mask) };

    let ret = unsafe { libc::sigaction(libc::SIGTERM, &ignore_action, &mut old_action) };
    assert_eq!(ret, 0);

    {
        let _guard = install_shutdown_flag_guard(&TEST_SHUTDOWN_FLAG_A).unwrap();
    }

    let mut current_action: libc::sigaction = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut current_action) };
    assert_eq!(ret, 0);
    assert_eq!(current_action.sa_sigaction, libc::SIG_IGN);

    let ret = unsafe { libc::sigaction(libc::SIGTERM, &old_action, std::ptr::null_mut()) };
    assert_eq!(ret, 0);
}

#[test]
fn test_reactor_setup_signalfd_restores_previous_mask_on_drop() {
    let mut before: libc::sigset_t = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut before) };
    assert_eq!(ret, 0);
    let was_blocked = unsafe { libc::sigismember(&before, libc::SIGCHLD) };

    {
        let mut reactor = Reactor::new().unwrap();
        reactor.setup_signalfd().unwrap();
        let mut during: libc::sigset_t = unsafe { std::mem::zeroed() };
        let ret =
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut during) };
        assert_eq!(ret, 0);
        assert_eq!(unsafe { libc::sigismember(&during, libc::SIGCHLD) }, 1);
    }

    let mut after: libc::sigset_t = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut after) };
    assert_eq!(ret, 0);
    assert_eq!(
        unsafe { libc::sigismember(&after, libc::SIGCHLD) },
        was_blocked
    );
}

#[test]
fn test_reactor_setup_signalfd_rejects_repeated_setup() {
    let mut reactor = Reactor::new().unwrap();
    reactor.setup_signalfd().unwrap();

    let err = reactor.setup_signalfd().unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
}

#[test]
fn test_readahead_small_temp_file() {
    with_temp_readahead_file(|file, _| {
        assert_readahead_result(readahead(file, 0, 16));
    });
}

#[test]
fn test_readahead_zero_length() {
    with_temp_readahead_file(|file, _| {
        assert_readahead_result(readahead(file, 0, 0));
    });
}

#[test]
fn test_readahead_offset_beyond_eof() {
    with_temp_readahead_file(|file, _| {
        assert_readahead_result(readahead(file, 1 << 20, 16));
    });
}

#[test]
fn test_readahead_invalid_fd() {
    let result = readahead(RawFdRef(-1), 0, 16);
    match result {
        Err(err) if err.raw_os_error() == Some(libc::EBADF) => {}
        Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {
            eprintln!("skipping readahead test: unsupported on this target");
        }
        Err(err) => panic!("expected EBADF from invalid fd, got: {err}"),
        Ok(()) => panic!("expected invalid fd to fail"),
    }
}
