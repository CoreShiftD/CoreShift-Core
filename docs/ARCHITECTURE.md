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

## Maintenance Notes

Keep new APIs primitive-shaped. If an API needs Android package metadata,
foreground state, daemon configuration, or product defaults, it belongs above
Core.
