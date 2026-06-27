# CoreShift Core

CoreShift Core is the low-level Linux/Android primitives crate at the bottom of
the CoreShift stack.

```text
Policy / product behavior
        ↓
Engine coordination
        ↓
Core syscall and filesystem primitives  ← this crate
```

Core exposes explicit wrappers for process spawning, file descriptor handling,
procfs parsing, signals, reactor primitives, inotify, Unix sockets, and
filesystem preload helpers. It does not choose Android policy, foreground app
behavior, package discovery, daemon protocols, or preload rules.

## Modules

| Module | Description |
|--------|-------------|
| `android_property` | Direct `__system_property_get` access |
| `binder` | NDK binder client + `IProcessObserver` server via `dlopen`; resolves `IActivityManager` transaction codes from DEX at runtime |
| `dex` | Minimal ZIP + DEX parser; reads `TRANSACTION_*` static int fields from `framework.jar` without subprocesses |
| `error` | `CoreError` and errno constants |
| `fs` | Filesystem probes and readahead |
| `inotify` | Watch setup and event decode |
| `io` | Explicit drain helpers |
| `proc` | procfs helpers (`/proc/<pid>/cmdline`, `oom_score_adj`, etc.) |
| `process` | `fork`, `setsid`, `setpgid`, `redirect_fd_to`, `setresuid/gid` |
| `reactor` | `epoll`-based fd readiness (`Reactor`, `Token`, `Fd`) |
| `signal` | Signal masking, `signalfd`, `signal_ignore` |
| `spawn` | Explicit process spawning and wait |
| `uid` | UID → package ownership (`/proc/<pid>/status`) |
| `unix_socket` | Abstract Unix domain socket bind/connect/accept |

## Binder observer

Registers as `IProcessObserver` with ActivityManager; returns an `eventfd`
that fires on `onForegroundActivitiesChanged`. Transaction codes are resolved by parsing `TRANSACTION_*` fields directly from `framework.jar` DEX at startup — no subprocess required.

See [docs/BINDER_OBSERVER.md](docs/BINDER_OBSERVER.md) for full details.

## Release Dependency

```toml
[dependencies]
coreshift-core = "1.2.9"
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Binder Observer](docs/BINDER_OBSERVER.md)
- [I/O Subsystem](docs/IO_SUBSYSTEM.md)
- [Signal Handling](docs/SIGNAL_HANDLING.md)
- [Preload primitives](docs/PRELOAD_PRIMITIVES.md)
- [Testing](docs/TESTING.md)

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
