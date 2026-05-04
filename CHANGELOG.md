# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
