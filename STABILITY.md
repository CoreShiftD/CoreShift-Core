# Stability Policy

CoreShift Core follows [Semantic Versioning 2.0.0](https://semver.org/).

## v0.1.0

`0.1.0` is the first official CoreShift Core release.

- Core is policy-free and exposes explicit Linux/Android primitives only.
- Spawn backend selection is caller-owned and required.
- Spawn file descriptor inheritance is caller-owned through explicit
  `SpawnFdPolicy`.
- Captured process output uses a combined stdout+stderr limit.
- Core does not provide automatic fallback or degraded behavior.

## Minimum Supported Rust Version

- Current MSRV is **Rust 1.85.0** due to the 2024 edition.

## Platform Support

### Linux

- Supported target for primitives backed by available kernel/libc features.

### Android

- Supported target for Android/Linux primitives.
- Core does not inspect Android SDK level, libc version, or system properties to
  choose behavior. Unsupported primitive/backend combinations return errors.

## Breaking Changes

Breaking changes after `0.1.0` will be documented in `CHANGELOG.md`.
