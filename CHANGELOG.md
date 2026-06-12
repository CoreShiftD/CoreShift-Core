# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-05-12

### Fixed

- **Reactor**: Fixed a bug where `EPOLLERR` events were not folded into `readable`/`writable` flags, potentially causing hangs in callers that do not explicitly check `error`.
- **Spawn**: Fixed a potential hang in the process wait loop by explicitly handling `EPOLLHUP` (hangup) events.
- **Documentation**: Cleaned up redundant lines in `proc` module documentation.

## [1.1.0] - 2026-05-12

### Added

- **Reactor**: Exposed `add_with_flags` for custom epoll registration.
- **Unix Sockets**: Added `accept_timeout` for millisecond-based timeouts.
- **Unix Sockets**: Added `peer_cred` support for retrieving peer process identity.
- **Signals**: Added `register_handler` for arbitrary process-wide signal handlers.
- **Signals**: Added `signalfd_new` for reactor-compatible signal reception.

## [1.0.0] - 2026-05-12

### Added

- **Logging**: Refactored to a backend-agnostic facade with `Logger` instances.
- **Reactor**: Added `hangup` field to `Event`.
- **Documentation**: Comprehensive behavioral contract and architectural invariant documentation.

### Changed

- **Spawn**: `SpawnBackend` is now mandatory at builder construction.
- **Layering**: Renamed `blocklist_fingerprint` to `path_fingerprint`.

### Stability Contract

The 1.x series guarantees stability for the following behavioral contracts. Changes to these are considered **breaking changes**:

- **Reactor Events**: The mapping of epoll flags to `Event` fields (`EPOLLERR` -> `error`, `EPOLLHUP` -> `hangup`).
- **Reactor Timeouts**: The `-1`/`0`/`positive` millisecond contract in `Reactor::wait`.
- **Descriptor Defaults**: The use of `O_CLOEXEC` / `SOCK_CLOEXEC` for all Core-created descriptors.
- **Signal Compatibility**: The requirement to use `signalfd` (via `signalfd_new`) for reactor-compatible signal handling.
- **Policy Neutrality**: The architectural commitment to provide primitives without policy.

## [0.3.0] - 2026-05-11

### Added

- Added Unix socket peer credential support through `SO_PEERCRED`.

## [0.2.0] - 2026-05-10

### Added

- Added low-level mmap/madvise preload primitive with page-aligned offset validation.

## [0.1.0] - 2026-05-04

### Added

- Initial official CoreShift Core release.
- Primitive Linux/Android APIs for process spawning, process lifecycle, process
  I/O draining, procfs parsing, filesystem helpers, UID/GID/path identity,
  readahead, signals, inotify, epoll/reactor use, eventfd, timerfd, signalfd,
  and Unix domain sockets.
- Explicit spawn backends: `Fork` and `PosixSpawn`.
- Explicit file descriptor inheritance policy through `SpawnFdPolicy`.
- Low-level abstract and pathname Unix stream socket primitives.

### Notes

- Core is policy-free and runs the exact argv it is given.
- Core does not choose shell, root, package, foreground, daemon, fallback, or
  product behavior.
- Unsupported backend/option combinations return errors instead of selecting a
  different backend.
