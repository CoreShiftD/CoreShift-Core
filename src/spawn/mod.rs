// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/

//! Process spawning and lifecycle management.
//!
//! This module exposes explicit Linux/Android process primitives. Callers must
//! provide the exact argument vector and choose the spawn backend. Core does not
//! infer shell/root behavior, select backends from platform properties, or
//! silently switch between backends.

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::ptr;

use crate::CoreError;
use crate::error::{posix_ret, syscall_ret};
use crate::reactor::Fd;
use crate::signal::SignalRuntime;
use libc::{
    O_CLOEXEC, O_NONBLOCK, WEXITSTATUS, WIFEXITED, WIFSIGNALED, WTERMSIG, c_char, pid_t, pipe2,
    waitpid,
};

unsafe extern "C" {
    pub(crate) static mut environ: *mut *mut libc::c_char;
}

pub(crate) const POSIX_SPAWN_SETPGROUP: i32 = 2;
pub(crate) const POSIX_SPAWN_SETSIGDEF: i32 = 4;
pub(crate) const POSIX_SPAWN_SETSIGMASK: i32 = 8;

unsafe extern "C" {
    pub(crate) fn posix_spawn(
        pid: *mut libc::pid_t,
        path: *const libc::c_char,
        file_actions: *const libc::posix_spawn_file_actions_t,
        attrp: *const libc::posix_spawnattr_t,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> libc::c_int;

    pub(crate) fn posix_spawn_file_actions_addclose(
        file_actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;

    pub(crate) fn posix_spawn_file_actions_adddup2(
        file_actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
        newfd: libc::c_int,
    ) -> libc::c_int;

    pub(crate) fn posix_spawn_file_actions_destroy(
        file_actions: *mut libc::posix_spawn_file_actions_t,
    ) -> libc::c_int;

    pub(crate) fn posix_spawn_file_actions_init(
        file_actions: *mut libc::posix_spawn_file_actions_t,
    ) -> libc::c_int;

    pub(crate) fn posix_spawnattr_destroy(attr: *mut libc::posix_spawnattr_t) -> libc::c_int;

    pub(crate) fn posix_spawnattr_init(attr: *mut libc::posix_spawnattr_t) -> libc::c_int;

    pub(crate) fn posix_spawnattr_setflags(
        attr: *mut libc::posix_spawnattr_t,
        flags: libc::c_short,
    ) -> libc::c_int;

    pub(crate) fn posix_spawnattr_setpgroup(
        attr: *mut libc::posix_spawnattr_t,
        pgroup: libc::pid_t,
    ) -> libc::c_int;

    pub(crate) fn posix_spawnattr_setsigdefault(
        attr: *mut libc::posix_spawnattr_t,
        sigdefault: *const libc::sigset_t,
    ) -> libc::c_int;

    pub(crate) fn posix_spawnattr_setsigmask(
        attr: *mut libc::posix_spawnattr_t,
        sigmask: *const libc::sigset_t,
    ) -> libc::c_int;
}

/// Policy for handling process cancellation or timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CancelPolicy {
    /// Do nothing on cancellation; let the process run to completion.
    #[default]
    None,
    /// Send SIGTERM, then SIGKILL after a grace period.
    Graceful,
    /// Send SIGKILL immediately.
    Kill,
}

/// Process group and session configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessGroup {
    /// Join an existing process group leader.
    pub leader: Option<pid_t>,
    /// Create a new session (`setsid`).
    pub isolated: bool,
}

impl ProcessGroup {
    /// Create a new process group configuration.
    pub fn new(leader: Option<pid_t>, isolated: bool) -> Self {
        Self { leader, isolated }
    }
}

#[inline(always)]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Creates a pipe with O_CLOEXEC | O_NONBLOCK flags.
/// Invariants: FDs returned are strictly non-negative and will close automatically on drop.
#[inline(always)]
fn make_pipe() -> Result<(Fd, Fd), CoreError> {
    let mut fds = [0; 2];
    let r = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC | O_NONBLOCK) };
    syscall_ret(r, "pipe2")?;
    Ok((Fd::new(fds[0], "pipe2")?, Fd::new(fds[1], "pipe2")?))
}

fn make_cloexec_pipe() -> Result<(RawFd, RawFd), CoreError> {
    let mut fds = [0; 2];
    let r = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
    syscall_ret(r, "pipe2")?;
    Ok((fds[0], fds[1]))
}

#[repr(u8)]
#[derive(Clone, Copy)]
enum ChildSetupOp {
    DupStdin = 1,
    DupStdout = 2,
    DupStderr = 3,
    Setsid = 4,
    Chdir = 5,
    Setpgid = 6,
    SignalMask = 7,
    Execve = 8,
}

impl ChildSetupOp {
    fn as_str(self) -> &'static str {
        match self {
            Self::DupStdin => "fork child dup2 stdin",
            Self::DupStdout => "fork child dup2 stdout",
            Self::DupStderr => "fork child dup2 stderr",
            Self::Setsid => "fork child setsid",
            Self::Chdir => "fork child chdir",
            Self::Setpgid => "fork child setpgid",
            Self::SignalMask => "fork child signal setup",
            Self::Execve => "fork child execve",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::DupStdin,
            2 => Self::DupStdout,
            3 => Self::DupStderr,
            4 => Self::Setsid,
            5 => Self::Chdir,
            6 => Self::Setpgid,
            7 => Self::SignalMask,
            _ => Self::Execve,
        }
    }
}

unsafe fn report_child_setup_error(fd: RawFd, op: ChildSetupOp, code: i32) -> ! {
    let mut msg = [0u8; 5];
    msg[..4].copy_from_slice(&code.to_ne_bytes());
    msg[4] = op as u8;
    let mut written = 0;
    while written < msg.len() {
        let n = unsafe {
            libc::write(
                fd,
                msg[written..].as_ptr().cast::<libc::c_void>(),
                msg.len() - written,
            )
        };
        if n <= 0 {
            break;
        }
        written += n as usize;
    }
    unsafe {
        libc::_exit(127);
    }
}

fn read_child_setup_error(fd: RawFd) -> Result<Option<CoreError>, CoreError> {
    let mut msg = [0u8; 5];
    let mut read_len = 0;
    loop {
        let n = unsafe {
            libc::read(
                fd,
                msg[read_len..].as_mut_ptr().cast::<libc::c_void>(),
                msg.len() - read_len,
            )
        };
        if n == 0 {
            return Ok(None);
        }
        if n < 0 {
            let code = errno();
            if code == libc::EINTR {
                continue;
            }
            return Err(CoreError::sys(code, "read fork child setup error"));
        }
        read_len += n as usize;
        if read_len == msg.len() {
            let code = i32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]);
            return Ok(Some(CoreError::sys(
                code,
                ChildSetupOp::from_u8(msg[4]).as_str(),
            )));
        }
    }
}

struct Pipes {
    stdin_r: Option<Fd>,
    stdin_w: Option<Fd>,
    stdout_r: Option<Fd>,
    stdout_w: Option<Fd>,
    stderr_r: Option<Fd>,
    stderr_w: Option<Fd>,
}

impl Pipes {
    fn new(in_buf: Option<&[u8]>, out: bool, err: bool) -> Result<Self, CoreError> {
        let (stdin_r, stdin_w) = if in_buf.is_some() {
            let (r, w) = make_pipe()?;
            (Some(r), Some(w))
        } else {
            (None, None)
        };

        let (stdout_r, stdout_w) = if out {
            let (r, w) = make_pipe()?;
            (Some(r), Some(w))
        } else {
            (None, None)
        };

        let (stderr_r, stderr_w) = if err {
            let (r, w) = make_pipe()?;
            (Some(r), Some(w))
        } else {
            (None, None)
        };

        Ok(Self {
            stdin_r,
            stdin_w,
            stdout_r,
            stdout_w,
            stderr_r,
            stderr_w,
        })
    }

    #[inline(always)]
    fn close_all(&mut self) {
        self.stdin_r.take();
        self.stdin_w.take();
        self.stdout_r.take();
        self.stdout_w.take();
        self.stderr_r.take();
        self.stderr_w.take();
    }
}

/// Represents the termination status of a process.
#[derive(Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// Process exited normally with the specified code.
    Exited(i32),
    /// Process was terminated by a signal.
    Signaled(i32),
}

/// Explicit process spawning backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnBackend {
    /// Force the use of `posix_spawn`.
    PosixSpawn,
    /// Force the use of `fork`/`exec`.
    ///
    /// The fork backend supports explicit [`SpawnFdPolicy`] handling before
    /// `execve`.
    Fork,
}

/// Explicit file-descriptor inheritance policy for spawned children.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SpawnFdPolicy {
    /// Inherit descriptors according to their existing `FD_CLOEXEC` flags.
    #[default]
    CloexecOnly,
    /// For the fork backend, close every descriptor >= 3 before `execve`,
    /// except Core-required pipe descriptors.
    CloseFrom3,
    /// For the fork backend, close every descriptor >= 3 before `execve`,
    /// except Core-required pipe descriptors and the listed descriptors.
    ///
    /// Core does not close allowlisted descriptors, but their existing
    /// `FD_CLOEXEC` state still applies. Callers that want an allowlisted
    /// descriptor to survive `execve` must clear `FD_CLOEXEC` before spawning.
    Allowlist(Vec<RawFd>),
}

/// Owned argument vector storage for spawn internals.
#[derive(Clone)]
enum ExecArgv {
    /// Dynamically allocated C-compatible strings.
    Dynamic(Vec<CString>),
}

/// Validated execution context for process spawning.
#[derive(Clone)]
struct ExecContext {
    argv: ExecArgv,
    envp: Option<Vec<CString>>,
    cwd: Option<CString>,
}

impl ExecContext {
    /// Build a validated execution context for process spawn.
    fn new(
        argv: Vec<String>,
        env: Option<Vec<String>>,
        cwd: Option<String>,
    ) -> Result<Self, CoreError> {
        if argv.is_empty() {
            return Err(CoreError::sys(libc::EINVAL, "exec argv empty"));
        }

        let c_argv: Vec<CString> = argv
            .into_iter()
            .map(|s| {
                CString::new(s).map_err(|_| CoreError::sys(libc::EINVAL, "exec argv contains nul"))
            })
            .collect::<Result<_, _>>()?;

        let c_envp = match env {
            Some(vars) => Some(
                vars.into_iter()
                    .map(|s| {
                        CString::new(s)
                            .map_err(|_| CoreError::sys(libc::EINVAL, "exec env contains nul"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };

        let c_cwd = match cwd {
            Some(c) => Some(
                CString::new(c)
                    .map_err(|_| CoreError::sys(libc::EINVAL, "exec cwd contains nul"))?,
            ),
            None => None,
        };

        Ok(Self {
            argv: ExecArgv::Dynamic(c_argv),
            envp: c_envp,
            cwd: c_cwd,
        })
    }

    /// Return a vector of pointers to the argument strings.
    fn get_argv_ptrs(&self) -> Vec<*mut libc::c_char> {
        let mut ptrs = Vec::new();
        match &self.argv {
            ExecArgv::Dynamic(v) => {
                for s in v {
                    ptrs.push(s.as_ptr() as *mut libc::c_char);
                }
            }
        }
        ptrs.push(ptr::null_mut());
        ptrs
    }

    /// Return a vector of pointers to the environment strings.
    fn get_envp_ptrs(&self) -> Option<Vec<*mut libc::c_char>> {
        self.envp.as_ref().map(|envp| {
            let mut ptrs = Vec::new();
            for s in envp {
                ptrs.push(s.as_ptr() as *mut libc::c_char);
            }
            ptrs.push(ptr::null_mut());
            ptrs
        })
    }
}

#[inline(always)]
fn decode_status(status: i32) -> ExitStatus {
    if WIFEXITED(status) {
        ExitStatus::Exited(WEXITSTATUS(status))
    } else if WIFSIGNALED(status) {
        ExitStatus::Signaled(WTERMSIG(status))
    } else {
        ExitStatus::Exited(-1)
    }
}

/// A handle to a spawned process.
pub struct Process {
    pid: pid_t,
}

impl Process {
    /// Create a handle for an existing PID.
    pub fn new(pid: pid_t) -> Self {
        Self { pid }
    }

    /// Return the process ID.
    pub fn pid(&self) -> pid_t {
        self.pid
    }

    /// Perform a non-blocking wait for process termination.
    pub fn wait_step(&self) -> Result<Option<ExitStatus>, CoreError> {
        loop {
            let mut status = 0;
            let r = unsafe { waitpid(self.pid, &mut status, libc::WNOHANG) };
            if r == 0 {
                return Ok(None);
            }
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(CoreError::sys(e, "waitpid_step"));
            }
            return Ok(Some(decode_status(status)));
        }
    }

    /// Block until the process terminates.
    pub fn wait_blocking(&self) -> Result<ExitStatus, CoreError> {
        loop {
            let mut status = 0;
            let r = unsafe { waitpid(self.pid, &mut status, 0) };
            if r < 0 {
                let e = errno();
                if e == libc::EINTR {
                    continue;
                }
                return Err(CoreError::sys(e, "waitpid_blocking"));
            }
            return Ok(decode_status(status));
        }
    }

    /// Send a signal to the process.
    pub fn kill(&self, sig: i32) -> Result<(), CoreError> {
        let r = unsafe { libc::kill(self.pid, sig) };
        if r < 0 {
            let e = errno();
            if e == libc::ESRCH {
                return Ok(());
            }
            syscall_ret(-1, "kill")?;
        }
        Ok(())
    }

    /// Send a signal to the process group.
    pub fn kill_pgroup(&self, sig: i32) -> Result<(), CoreError> {
        let r = unsafe { libc::kill(-self.pid, sig) };
        if r < 0 {
            let e = errno();
            if e == libc::ESRCH {
                return Ok(());
            }
            syscall_ret(-1, "kill_pgroup")?;
        }
        Ok(())
    }
}

/// Configuration options for spawning a new process.
#[derive(Clone)]
pub struct SpawnOptions {
    ctx: ExecContext,
    stdin: Option<Box<[u8]>>,
    capture_stdout: bool,
    capture_stderr: bool,
    wait: bool,
    pgroup: ProcessGroup,
    max_output: usize,
    timeout_ms: Option<u32>,
    kill_grace_ms: u32,
    cancel: CancelPolicy,
    backend: SpawnBackend,
    fd_policy: SpawnFdPolicy,
    early_exit: Option<fn(&[u8]) -> bool>,
}

impl SpawnOptions {
    /// Create a new builder for process spawning.
    pub fn builder(argv: Vec<String>) -> SpawnOptionsBuilder {
        SpawnOptionsBuilder::new(argv)
    }

    /// Execute the process according to the options and block until completion.
    pub fn run(self) -> Result<Output, CoreError> {
        spawn(self)
    }
}

/// Builder for [`SpawnOptions`].
#[derive(Clone)]
pub struct SpawnOptionsBuilder {
    argv: Vec<String>,
    env: Option<Vec<String>>,
    cwd: Option<String>,
    stdin: Option<Box<[u8]>>,
    capture_stdout: bool,
    capture_stderr: bool,
    wait: bool,
    pgroup: ProcessGroup,
    max_output: usize,
    timeout_ms: Option<u32>,
    kill_grace_ms: u32,
    cancel: CancelPolicy,
    backend: Option<SpawnBackend>,
    fd_policy: SpawnFdPolicy,
    early_exit: Option<fn(&[u8]) -> bool>,
}

impl SpawnOptionsBuilder {
    /// Create a new builder with the specified argument vector.
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            env: None,
            cwd: None,
            stdin: None,
            capture_stdout: false,
            capture_stderr: false,
            wait: true,
            pgroup: ProcessGroup::default(),
            max_output: 1024 * 1024,
            timeout_ms: None,
            kill_grace_ms: 2000,
            cancel: CancelPolicy::Kill,
            backend: None,
            fd_policy: SpawnFdPolicy::default(),
            early_exit: None,
        }
    }

    /// Set environment variables.
    pub fn env(mut self, env: Vec<String>) -> Self {
        self.env = Some(env);
        self
    }

    /// Set the working directory.
    pub fn cwd(mut self, cwd: String) -> Self {
        self.cwd = Some(cwd);
        self
    }

    /// Provide data to be written to the child's stdin.
    pub fn stdin(mut self, data: impl Into<Box<[u8]>>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Enable stdout capture.
    pub fn capture_stdout(mut self) -> Self {
        self.capture_stdout = true;
        self
    }

    /// Enable stderr capture.
    pub fn capture_stderr(mut self) -> Self {
        self.capture_stderr = true;
        self
    }

    /// Set whether to wait for the process to terminate (default: true).
    pub fn wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }

    /// Set process group and isolation policy.
    pub fn pgroup(mut self, pgroup: ProcessGroup) -> Self {
        self.pgroup = pgroup;
        self
    }

    /// Set the combined stdout+stderr output buffer size (default: 1MB).
    ///
    /// If captured output exceeds this limit, spawn drains the child pipes to
    /// completion and returns `EOVERFLOW`.
    pub fn max_output(mut self, max: usize) -> Self {
        self.max_output = max;
        self
    }

    /// Set the execution timeout in milliseconds.
    pub fn timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = Some(ms);
        self
    }

    /// Set the grace period before SIGKILL (default: 2s).
    pub fn kill_grace_ms(mut self, ms: u32) -> Self {
        self.kill_grace_ms = ms;
        self
    }

    /// Set the cancellation policy (default: Kill).
    pub fn cancel(mut self, policy: CancelPolicy) -> Self {
        self.cancel = policy;
        self
    }

    /// Set the required spawning backend.
    pub fn backend(mut self, backend: SpawnBackend) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Set the child file-descriptor inheritance policy.
    pub fn fd_policy(mut self, policy: SpawnFdPolicy) -> Self {
        self.fd_policy = policy;
        self
    }

    /// Set an early exit callback.
    pub fn early_exit(mut self, callback: fn(&[u8]) -> bool) -> Self {
        self.early_exit = Some(callback);
        self
    }

    /// Build the spawn options.
    pub fn build(self) -> Result<SpawnOptions, CoreError> {
        let backend = self
            .backend
            .ok_or_else(|| CoreError::sys(libc::EINVAL, "spawn backend required"))?;
        let ctx = ExecContext::new(self.argv, self.env, self.cwd)?;
        Ok(SpawnOptions {
            ctx,
            stdin: self.stdin,
            capture_stdout: self.capture_stdout,
            capture_stderr: self.capture_stderr,
            wait: self.wait,
            pgroup: self.pgroup,
            max_output: self.max_output,
            timeout_ms: self.timeout_ms,
            kill_grace_ms: self.kill_grace_ms,
            cancel: self.cancel,
            backend,
            fd_policy: self.fd_policy,
            early_exit: self.early_exit,
        })
    }
}

/// The result of a process execution.
#[derive(Debug)]
pub struct Output {
    /// The PID of the finished process.
    pub pid: pid_t,
    /// Final exit status (None if `wait=false`).
    pub status: Option<ExitStatus>,
    /// Captured stdout buffer.
    pub stdout: Vec<u8>,
    /// Captured stderr buffer.
    pub stderr: Vec<u8>,
    /// Whether the process timed out.
    pub timed_out: bool,
    /// Whether stdout drain stopped because the early-exit callback matched.
    pub stdout_early_exited: bool,
}

fn validate_backend(opts: &SpawnOptions) -> Result<(), CoreError> {
    validate_fd_policy(&opts.fd_policy)?;
    match opts.backend {
        SpawnBackend::PosixSpawn => {
            if opts.ctx.cwd.is_some() {
                return Err(CoreError::sys(libc::EINVAL, "posix_spawn cwd unsupported"));
            }
            if opts.pgroup.isolated {
                return Err(CoreError::sys(
                    libc::EINVAL,
                    "posix_spawn setsid unsupported",
                ));
            }
            if opts.fd_policy != SpawnFdPolicy::CloexecOnly {
                return Err(CoreError::sys(
                    libc::EINVAL,
                    "posix_spawn fd policy unsupported",
                ));
            }
            Ok(())
        }
        SpawnBackend::Fork => Ok(()),
    }
}

fn validate_fd_policy(policy: &SpawnFdPolicy) -> Result<(), CoreError> {
    if let SpawnFdPolicy::Allowlist(fds) = policy {
        let mut seen = Vec::with_capacity(fds.len());
        for &fd in fds {
            if fd < 0 {
                return Err(CoreError::sys(libc::EINVAL, "spawn fd allowlist invalid"));
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(CoreError::sys(errno(), "spawn fd allowlist fcntl(F_GETFD)"));
            }
            if seen.contains(&fd) {
                return Err(CoreError::sys(libc::EINVAL, "spawn fd allowlist duplicate"));
            }
            seen.push(fd);
        }
    }
    Ok(())
}

use crate::io::DrainState;

/// Specialized drain state for process spawning.
pub type SpawnDrain = DrainState<fn(&[u8]) -> bool>;

/// A process that is currently running and being monitored.
pub struct RunningProcess {
    /// Handle to the process.
    pub process: Process,
    drain: SpawnDrain,
}

impl RunningProcess {
    /// Register active stdio pipe descriptors with a reactor.
    ///
    /// Call this once after [`spawn_start`] when the process was started with
    /// captured output or stdin data. The assigned tokens are kept internally
    /// and later matched by [`Self::handle_reactor_event`].
    pub fn register_with_reactor(&mut self, reactor: &mut Reactor) -> Result<(), CoreError> {
        self.drain.register_with_reactor(reactor)
    }

    /// Apply one reactor readiness event to this process' stdio drain state.
    ///
    /// Events for unrelated tokens are ignored. Callers remain responsible for
    /// waiting on [`Self::process`] and driving the reactor until [`Self::io_done`]
    /// returns true.
    pub fn handle_reactor_event(
        &mut self,
        reactor: &mut Reactor,
        event: &crate::reactor::Event,
    ) -> Result<(), CoreError> {
        if self.drain.stdout_matches(event.token) {
            if event.readable {
                self.drain.handle_stdout_ready(reactor)?;
            } else if event.error {
                self.drain.drop_stdout(reactor)?;
            }
        } else if self.drain.stderr_matches(event.token) {
            if event.readable {
                self.drain.handle_stderr_ready(reactor)?;
            } else if event.error {
                self.drain.drop_stderr(reactor)?;
            }
        } else if self.drain.stdin_matches(event.token) {
            if event.writable {
                self.drain.handle_stdin_writable(reactor)?;
            } else if event.error {
                self.drain.drop_stdin(reactor)?;
            }
        }
        Ok(())
    }

    /// Return whether all managed stdio pipes have been drained or closed.
    pub fn io_done(&self) -> bool {
        self.drain.is_done()
    }

    /// Consume the running process handle and return captured stdout/stderr buffers.
    pub fn into_output_parts(self) -> (Vec<u8>, Vec<u8>) {
        self.drain.into_parts()
    }
}

use crate::reactor::Reactor;

/// Start spawning a process and return a monitor handle.
///
/// This initializes the pipes and starts the process, but does not block. Use
/// [`RunningProcess::register_with_reactor`],
/// [`RunningProcess::handle_reactor_event`], [`RunningProcess::io_done`], and
/// [`RunningProcess::into_output_parts`] to drive captured stdio without
/// exposing internal drain state.
///
/// # Errors
/// Returns [`CoreError`] if pipe creation, process spawning, or backend selection fails.
pub fn spawn_start(opts: SpawnOptions) -> Result<RunningProcess, CoreError> {
    if !opts.wait && (opts.stdin.is_some() || opts.capture_stdout || opts.capture_stderr) {
        return Err(CoreError::sys(
            libc::EINVAL,
            "background I/O capture not supported (wait must be true)",
        ));
    }

    validate_backend(&opts)?;

    let (pid, drain) = match opts.backend {
        SpawnBackend::PosixSpawn => spawn_posix_internal(opts)?,
        SpawnBackend::Fork => spawn_fork_internal(opts)?,
    };

    Ok(RunningProcess {
        process: Process::new(pid),
        drain,
    })
}

/// Spawn a process and block until completion or timeout.
///
/// This is the primary high-level interface for process execution. It handles
/// the full lifecycle, including I/O multiplexing and signal management.
///
/// # Errors
/// Returns [`CoreError`] if any underlying syscall (spawn, pipe, epoll) fails.
pub fn spawn(opts: SpawnOptions) -> Result<Output, CoreError> {
    let wait = opts.wait;
    let timeout_ms = opts.timeout_ms;
    let kill_grace_ms = opts.kill_grace_ms;
    let cancel = opts.cancel;
    let pgroup = opts.pgroup;

    let mut reactor = Reactor::new()?;
    let running = spawn_start(opts)?;

    let pid = running.process.pid();
    let mut drain = running.drain;

    drain.register_with_reactor(&mut reactor)?;

    if !wait {
        let (stdout, stderr) = drain.into_parts();
        return Ok(Output {
            pid,
            status: None,
            stdout,
            stderr,
            timed_out: false,
            stdout_early_exited: false,
        });
    }

    wait_loop(
        pid,
        drain,
        reactor,
        timeout_ms,
        kill_grace_ms,
        cancel,
        pgroup,
    )
}

fn spawn_posix_internal(opts: SpawnOptions) -> Result<(pid_t, SpawnDrain), CoreError> {
    let mut pipes = Pipes::new(
        opts.stdin.as_deref(),
        opts.capture_stdout,
        opts.capture_stderr,
    )?;

    let exe_ptr = match &opts.ctx.argv {
        ExecArgv::Dynamic(v) => v[0].as_ptr(),
    };

    let argv = opts.ctx.get_argv_ptrs();
    let envp = opts.ctx.get_envp_ptrs();

    let actions = MaybeUninit::zeroed();
    let mut actions = unsafe { actions.assume_init() };
    if let Err(e) = posix_ret(
        unsafe { posix_spawn_file_actions_init(&mut actions) },
        "file_actions_init",
    ) {
        pipes.close_all();
        return Err(e);
    }

    struct Actions(*mut libc::posix_spawn_file_actions_t);
    impl Drop for Actions {
        fn drop(&mut self) {
            unsafe {
                posix_spawn_file_actions_destroy(self.0);
            }
        }
    }
    let _guard = Actions(&mut actions);

    if let (Some(r), Some(w)) = (&pipes.stdin_r, &pipes.stdin_w) {
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_adddup2(&mut actions, r.raw(), 0) },
            "dup2 stdin",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, r.raw()) },
            "close stdin pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, w.raw()) },
            "close stdin write pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
    }

    if let (Some(r), Some(w)) = (&pipes.stdout_r, &pipes.stdout_w) {
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_adddup2(&mut actions, w.raw(), 1) },
            "dup2 stdout",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, w.raw()) },
            "close stdout pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, r.raw()) },
            "close stdout read pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
    }

    if let (Some(r), Some(w)) = (&pipes.stderr_r, &pipes.stderr_w) {
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_adddup2(&mut actions, w.raw(), 2) },
            "dup2 stderr",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, w.raw()) },
            "close stderr pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
        if let Err(e) = posix_ret(
            unsafe { posix_spawn_file_actions_addclose(&mut actions, r.raw()) },
            "close stderr read pipe",
        ) {
            pipes.close_all();
            return Err(e);
        }
    }

    let attr = MaybeUninit::zeroed();
    let mut attr = unsafe { attr.assume_init() };
    if let Err(e) = posix_ret(unsafe { posix_spawnattr_init(&mut attr) }, "attr_init") {
        pipes.close_all();
        return Err(e);
    }

    struct Attr(*mut libc::posix_spawnattr_t);
    impl Drop for Attr {
        fn drop(&mut self) {
            unsafe {
                posix_spawnattr_destroy(self.0);
            }
        }
    }
    let _attr = Attr(&mut attr);

    let mut flags = 0;

    if let Some(pg) = opts.pgroup.leader {
        flags |= POSIX_SPAWN_SETPGROUP;
        if let Err(e) = posix_ret(
            unsafe { posix_spawnattr_setpgroup(&mut attr, pg) },
            "setpgroup",
        ) {
            pipes.close_all();
            return Err(e);
        }
    }

    flags |= POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;

    if let Err(e) = posix_ret(
        unsafe { posix_spawnattr_setflags(&mut attr, flags as _) },
        "setflags",
    ) {
        pipes.close_all();
        return Err(e);
    }

    let empty_mask = SignalRuntime::empty_set();
    let def = SignalRuntime::set_with(&[libc::SIGPIPE])?;

    if let Err(e) = posix_ret(
        unsafe { posix_spawnattr_setsigmask(&mut attr, &empty_mask) },
        "setsigmask",
    ) {
        pipes.close_all();
        return Err(e);
    }
    if let Err(e) = posix_ret(
        unsafe { posix_spawnattr_setsigdefault(&mut attr, &def) },
        "setsigdefault",
    ) {
        pipes.close_all();
        return Err(e);
    }

    let mut pid: pid_t = 0;

    let envp_ptr = envp.as_ref().map_or_else(
        || unsafe { environ as *const *mut c_char },
        |e: &Vec<*mut c_char>| e.as_ptr(),
    );

    if let Err(e) = posix_ret(
        unsafe { posix_spawn(&mut pid, exe_ptr, &actions, &attr, argv.as_ptr(), envp_ptr) },
        "posix_spawn",
    ) {
        pipes.close_all();
        return Err(e);
    }

    drop(pipes.stdin_r.take());
    drop(pipes.stdout_w.take());
    drop(pipes.stderr_w.take());

    let drain = crate::io::DrainState::new(
        pipes.stdin_w.take().filter(|_| opts.stdin.is_some()),
        opts.stdin,
        pipes.stdout_r.take(),
        pipes.stderr_r.take(),
        opts.max_output,
        opts.early_exit,
    )?;

    Ok((pid, drain))
}

fn collect_required_pipe_fds(pipes: &Pipes) -> Vec<RawFd> {
    let mut fds = Vec::new();
    if let Some(fd) = &pipes.stdin_r {
        fds.push(fd.raw());
    }
    if let Some(fd) = &pipes.stdin_w {
        fds.push(fd.raw());
    }
    if let Some(fd) = &pipes.stdout_r {
        fds.push(fd.raw());
    }
    if let Some(fd) = &pipes.stdout_w {
        fds.push(fd.raw());
    }
    if let Some(fd) = &pipes.stderr_r {
        fds.push(fd.raw());
    }
    if let Some(fd) = &pipes.stderr_w {
        fds.push(fd.raw());
    }
    fds
}

fn collect_open_fds_for_child_policy(policy: &SpawnFdPolicy) -> Result<Vec<RawFd>, CoreError> {
    match policy {
        SpawnFdPolicy::CloexecOnly => Ok(Vec::new()),
        SpawnFdPolicy::CloseFrom3 | SpawnFdPolicy::Allowlist(_) => {
            let dir_fd = unsafe {
                libc::open(
                    c"/proc/self/fd".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if dir_fd < 0 {
                return Err(CoreError::sys(errno(), "open /proc/self/fd"));
            }

            let dir = unsafe { libc::fdopendir(dir_fd) };
            if dir.is_null() {
                let code = errno();
                unsafe {
                    libc::close(dir_fd);
                }
                return Err(CoreError::sys(code, "fdopendir /proc/self/fd"));
            }

            let mut open_fds = Vec::new();
            loop {
                let entry = unsafe { libc::readdir(dir) };
                if entry.is_null() {
                    break;
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                if let Ok(s) = name.to_str()
                    && let Ok(fd) = s.parse::<RawFd>()
                    && fd != dir_fd
                {
                    open_fds.push(fd);
                }
            }
            unsafe {
                libc::closedir(dir);
            }
            Ok(open_fds)
        }
    }
}

fn close_child_fds_for_policy(policy: &SpawnFdPolicy, required_fds: &[RawFd], open_fds: &[RawFd]) {
    match policy {
        SpawnFdPolicy::CloexecOnly => {}
        SpawnFdPolicy::CloseFrom3 | SpawnFdPolicy::Allowlist(_) => {
            for &fd in open_fds {
                if fd > 2
                    && !required_fds.contains(&fd)
                    && !matches!(policy, SpawnFdPolicy::Allowlist(allowlist) if allowlist.contains(&fd))
                {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }
    }
}

fn spawn_fork_internal(opts: SpawnOptions) -> Result<(pid_t, SpawnDrain), CoreError> {
    let mut pipes = Pipes::new(
        opts.stdin.as_deref(),
        opts.capture_stdout,
        opts.capture_stderr,
    )?;

    let exe_ptr = match &opts.ctx.argv {
        ExecArgv::Dynamic(v) => v[0].as_ptr(),
    };

    let argv = opts.ctx.get_argv_ptrs();
    let envp = opts.ctx.get_envp_ptrs();
    let cwd_cstr = &opts.ctx.cwd;
    let (child_error_r, child_error_w) = make_cloexec_pipe()?;
    let mut required_fds = collect_required_pipe_fds(&pipes);
    required_fds.push(child_error_w);
    let open_fds = collect_open_fds_for_child_policy(&opts.fd_policy)?;

    let pid = unsafe { libc::fork() };

    if pid < 0 {
        unsafe {
            libc::close(child_error_r);
            libc::close(child_error_w);
        }
        pipes.close_all();
        syscall_ret(-1, "fork")?;
    }

    if pid == 0 {
        // Child
        unsafe {
            libc::close(child_error_r);
        }

        // dup stdin
        if let (Some(r), Some(_)) = (&pipes.stdin_r, &pipes.stdin_w) {
            unsafe {
                if libc::dup2(r.raw(), 0) < 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::DupStdin, errno());
                }
            }
        }

        // dup stdout
        if let (Some(_), Some(w)) = (&pipes.stdout_r, &pipes.stdout_w) {
            unsafe {
                if libc::dup2(w.raw(), 1) < 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::DupStdout, errno());
                }
            }
        }

        // dup stderr
        if let (Some(_), Some(w)) = (&pipes.stderr_r, &pipes.stderr_w) {
            unsafe {
                if libc::dup2(w.raw(), 2) < 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::DupStderr, errno());
                }
            }
        }

        // SAFETY: Close all pipe FDs in child before exec, except the ones duped to 0,1,2.
        pipes.close_all();

        close_child_fds_for_policy(&opts.fd_policy, &required_fds, &open_fds);

        // setsid
        if opts.pgroup.isolated {
            // SAFETY: safe to call setsid in child.
            unsafe {
                if libc::setsid() < 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::Setsid, errno());
                }
            }
        }

        // chdir
        if let Some(cwd) = cwd_cstr {
            // SAFETY: cwd is a valid null-terminated CString.
            unsafe {
                if libc::chdir(cwd.as_ptr()) != 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::Chdir, errno());
                }
            }
        }

        // setpgid
        if let Some(pg) = opts.pgroup.leader {
            // SAFETY: valid pgroup.
            unsafe {
                if libc::setpgid(0, pg) < 0 {
                    report_child_setup_error(child_error_w, ChildSetupOp::Setpgid, errno());
                }
            }
        }

        let envp_ptr = envp.as_ref().map_or_else(
            || unsafe { environ as *const *mut c_char },
            |e: &Vec<*mut c_char>| e.as_ptr(),
        );

        // unblock signals and reset SIGPIPE
        // SAFETY: valid signal mask array manipulation
        if let Err(err) = SignalRuntime::unblock_all() {
            unsafe {
                report_child_setup_error(
                    child_error_w,
                    ChildSetupOp::SignalMask,
                    err.raw_os_error().unwrap_or(libc::EIO),
                );
            }
        }
        if let Err(err) = SignalRuntime::reset_default(libc::SIGPIPE) {
            unsafe {
                report_child_setup_error(
                    child_error_w,
                    ChildSetupOp::SignalMask,
                    err.raw_os_error().unwrap_or(libc::EIO),
                );
            }
        }

        // exec
        // SAFETY: exe_ptr is null-terminated. argv and envp_ptr are valid null-terminated arrays.
        unsafe {
            libc::execve(
                exe_ptr,
                argv.as_ptr() as *const *const _,
                envp_ptr as *const *const _,
            );
            report_child_setup_error(child_error_w, ChildSetupOp::Execve, errno());
        }
    }

    // Parent
    unsafe {
        libc::close(child_error_w);
    }
    match read_child_setup_error(child_error_r) {
        Ok(Some(err)) => {
            unsafe {
                libc::close(child_error_r);
                let mut status = 0;
                let _ = libc::waitpid(pid, &mut status, 0);
            }
            pipes.close_all();
            return Err(err);
        }
        Ok(None) => {}
        Err(err) => {
            unsafe {
                libc::close(child_error_r);
            }
            pipes.close_all();
            return Err(err);
        }
    }
    unsafe {
        libc::close(child_error_r);
    }
    drop(pipes.stdin_r.take());
    drop(pipes.stdout_w.take());
    drop(pipes.stderr_w.take());

    let drain = crate::io::DrainState::new(
        pipes.stdin_w.take().filter(|_| opts.stdin.is_some()),
        opts.stdin,
        pipes.stdout_r.take(),
        pipes.stderr_r.take(),
        opts.max_output,
        opts.early_exit,
    )?;

    Ok((pid, drain))
}

enum KillState {
    None,
    TermSent,
    KillSent,
}

fn wait_loop(
    pid: pid_t,
    mut drain: crate::io::DrainState<fn(&[u8]) -> bool>,
    mut reactor: Reactor,
    timeout_ms: Option<u32>,
    kill_grace_ms: u32,
    cancel: CancelPolicy,
    pgroup: ProcessGroup,
) -> Result<Output, CoreError> {
    let process = Process::new(pid);
    let mut status_raw = process.wait_step()?;
    let mut state = KillState::None;
    let mut timed_out = false;

    let start_time = std::time::Instant::now();
    let deadline = timeout_ms.map(|t| std::time::Duration::from_millis(t as u64));

    loop {
        let mut poll_timeout = -1;

        if let Some(dl) = deadline {
            let elapsed = start_time.elapsed();
            if elapsed >= dl {
                timed_out = true;
                let elapsed_over = (elapsed - dl).as_millis();

                let target_is_group = pgroup.isolated || pgroup.leader.is_some();

                match state {
                    KillState::None => {
                        if cancel == CancelPolicy::Graceful {
                            let r = if target_is_group {
                                process.kill_pgroup(libc::SIGTERM)
                            } else {
                                process.kill(libc::SIGTERM)
                            };
                            if r.is_err() {
                                state = KillState::KillSent; // Process already gone
                            } else {
                                state = KillState::TermSent;
                            }
                        } else if cancel == CancelPolicy::Kill {
                            let _ = if target_is_group {
                                process.kill_pgroup(libc::SIGKILL)
                            } else {
                                process.kill(libc::SIGKILL)
                            };
                            state = KillState::KillSent;
                        } else {
                            // CancelPolicy::None just times out without killing
                        }
                    }
                    KillState::TermSent if elapsed_over > kill_grace_ms as u128 => {
                        let _ = if target_is_group {
                            process.kill_pgroup(libc::SIGKILL)
                        } else {
                            process.kill(libc::SIGKILL)
                        };
                        state = KillState::KillSent;
                    }
                    _ => {}
                }
                poll_timeout = 100; // Poll frequently while waiting for kill to take effect
            } else {
                let remaining = dl - elapsed;
                poll_timeout = remaining.as_millis().min(i32::MAX as u128) as i32;
            }
        }

        if status_raw.is_none()
            && let Some(s) = process.wait_step()?
        {
            status_raw = Some(s);
        }

        if drain.is_done() {
            let s = match status_raw {
                Some(s) => s,
                None => process.wait_blocking()?,
            };

            for slot in drain.take_all_slots() {
                reactor.del(&slot.fd)?;
            }
            let (stdout, stderr, output_limit_exceeded, stdout_early_exited) =
                drain.into_parts_with_state();
            if output_limit_exceeded {
                return Err(CoreError::sys(libc::EOVERFLOW, "spawn output limit"));
            }
            return Ok(Output {
                pid,
                status: Some(s),
                stdout,
                stderr,
                timed_out,
                stdout_early_exited,
            });
        }

        let timeout = if status_raw.is_some() {
            if poll_timeout == -1 || poll_timeout > 1 {
                1
            } else {
                poll_timeout
            }
        } else {
            poll_timeout
        };

        let mut events = Vec::new();
        let nevents = reactor.wait(&mut events, 64, timeout)?;

        for ev in events.iter().take(nevents) {
            if drain.stdout_matches(ev.token) {
                if ev.readable {
                    drain.handle_stdout_ready(&mut reactor)?;
                } else if ev.error {
                    drain.drop_stdout(&mut reactor)?;
                }
            } else if drain.stderr_matches(ev.token) {
                if ev.readable {
                    drain.handle_stderr_ready(&mut reactor)?;
                } else if ev.error {
                    drain.drop_stderr(&mut reactor)?;
                }
            } else if drain.stdin_matches(ev.token) {
                if ev.writable {
                    drain.handle_stdin_writable(&mut reactor)?;
                } else if ev.error {
                    drain.drop_stdin(&mut reactor)?;
                }
            }
        }
    }
}
