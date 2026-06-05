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

## Maintenance Checks

Before changing Core APIs, verify that the API remains primitive-level. A change
that needs Android packages, foreground state, or daemon configuration should be
implemented in a higher layer.
