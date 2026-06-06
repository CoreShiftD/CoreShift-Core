# CoreShift-Core Architecture

CoreShift-Core is the primitive layer for the CoreShift stack. It wraps
Linux/Android facilities with small Rust APIs and leaves product decisions to
higher layers.

## Role

Core owns:

- Process spawning primitives and explicit file descriptor policy.
- Process lifecycle helpers.
- Stream draining and bounded output capture.
- Procfs and UID/GID/path identity helpers.
- Signals and reactor primitives.
- Inotify watch/decode helpers.
- Unix domain socket primitives.
- Filesystem preload primitives such as readahead and mmap/madvise.

Core returns structured errors from the underlying platform. It does not turn a
failed primitive into a policy decision, retry plan, fallback command, or Android
product behavior.

## Boundaries

Core does not own:

- Android package discovery.
- Foreground package or process decisions.
- Daemon command-line behavior.
- Socket message protocols.
- App allowlists, blocklists, or preload policy.
- Android default paths.

Those choices live in Engine, Policy, or product packaging layers.

## Core Guarantees

Future contributors must ensure Core maintains these invariants:

- **No Policy Decisions**: Core provides primitives, not behaviors. It does not choose package allowlists, retry strategies, or product-specific defaults.
- **No Android-specific Behavior**: Core uses Android syscalls and properties when running on Android, but it does not implement higher-level Android product logic (like foreground app detection).
- **No Hidden Threads**: Core performs work on the caller's thread. It does not spawn background maintenance threads or global worker pools.
- **No Global Mutable State**: Core is stateless. Configuration must be passed to primitives via options or arguments.
- **No Capability Enforcement**: Core performs syscalls; it does not implement its own permission or capability model.
- **No Scheduler Ownership**: Core provides reactor primitives (`epoll`) but does not include a task scheduler or executor.

## Use From Higher Layers

Higher layers should pass exact descriptors, paths, argv, offsets, byte counts,
and socket names into Core. Core should not infer a package, widen a preload
range for policy reasons, or decide whether a preload is desirable.

When a platform primitive is unsupported, Core returns an error such as `ENOSYS`
so the caller can decide whether to skip, fall back, or fail.

## Subsystems

### Process Spawning (`spawn`)

Core provides explicit control over process creation via `posix_spawn` or `fork/exec`.

- **Explicit Backends**: Callers must choose a `SpawnBackend`. Core does not silently switch backends based on capability; it returns an error if a backend cannot fulfill the requested `SpawnOptions`.
- **FD Policy**: Child file descriptor inheritance is controlled through `SpawnFdPolicy`. Core defaults to `CloexecOnly` to prevent accidental descriptor leakage.
- **Bounded Output**: Output capture is combined (stdout + stderr) and strictly bounded to prevent memory exhaustion by runaway processes.

### Reactor and I/O (`reactor`, `io`)

Core implements a lightweight, edge-triggered `epoll` reactor.

- **Non-blocking by Default**: Reactor primitives are designed for non-blocking operations.
- **Explicit Readiness**: Callers must drain descriptors until `EAGAIN` to satisfy the edge-triggered contract.
- **Stateless Orchestration**: `DrainState` manages the bookkeeping of multiple process pipes without owning the reactor or the thread.

### Signal Handling (`signal`)

Core provides a centralized shutdown coordination mechanism.

- **Shared State**: `install_shutdown_flag` uses a process-global atomic pointer to signal shutdown to the caller's main loop.
- **No Signal Policy**: Core installs handlers for `SIGINT` and `SIGTERM` but does not decide how the application should exit.

### Logging (`log`)

Logging is a backend-agnostic facade designed for zero global mutable state.

- **Immutability**: The default logging path uses compile-time dispatch to the platform's primary backend (Android `liblog` or `stderr`).
- **Explicit Instances**: Dynamic backend selection (e.g., for silencing specific components or redirection) requires an explicit `Logger` instance.

## Maintenance Notes

Keep new APIs primitive-shaped. If an API needs Android package metadata,
foreground state, daemon configuration, or product defaults, it belongs above
Core.
