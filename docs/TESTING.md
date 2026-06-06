# Testing CoreShift-Core

Run the standard validation set from the repository root:

```bash
cargo fmt --check
cargo test -j 1
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
```

## Preload Tests

Filesystem preload tests cover supported and unsupported platforms:

- `readahead` syscall number and basic execution.
- `mmap_madvise` offset zero.
- `mmap_madvise` rejection of an unaligned offset.
- `ENOSYS` handling where the primitive is not available.

## Test Types

CoreShift-Core uses three complementary testing strategies:

1.  **Unit Tests (`src/tests.rs`)**: Internal tests for individual components. These can access `pub(crate)` items and are the primary way to verify edge cases in parsing, error mapping, and small primitives.
2.  **Integration Tests (`tests/*.rs`)**: Tests that use only the public API. These verify that Core components work together correctly and that the public surface is sufficient for external callers.
3.  **Doc-tests**: Snippets in documentation comments that ensure examples remain valid and compile.

## Platform Primitives

Many Core features rely on Linux-specific syscalls (e.g., `epoll`, `inotify`, `readahead`).

- **Linux/Android**: Tests should ideally run on a Linux machine to exercise the real syscall paths.
- **CI**: GitHub Actions runs the test suite on Linux to ensure correctness.
- **Other Platforms**: Core is designed to compile on non-Linux platforms, but many primitives will return `ENOSYS`. Tests should verify that fallback behavior (returning the correct error code) works correctly.

## Maintenance Checks

Before changing Core APIs, verify that the API remains primitive-level. A change
that needs Android packages, foreground state, or daemon configuration should be
implemented in a higher layer.
