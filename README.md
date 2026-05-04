# CoreShift Core

CoreShift Core is the primitive crate at the bottom of the CoreShift stack.

```text
Policy / daemon / product behavior
        ↓
Engine coordination
        ↓
Core Linux/Android primitives
```

Core exposes Linux/Android building blocks only: process spawning, process
lifecycle control, stdout/stderr/stdin draining, procfs parsing, UID/GID/path
identity, filesystem helpers, readahead, signals, epoll/reactor primitives,
eventfd/timerfd/signalfd helpers, inotify watch/decode helpers, and Unix domain
socket primitives.

Core does not choose behavior for callers. It does not choose shell, root, `su`,
package handling, daemon behavior, foreground behavior, fallback behavior, or
feature policy. Callers pass exact argv, options, paths, signals, and file
descriptors.

## Spawn

Process spawning is explicit:

- `SpawnBackend::Fork` uses `fork`/`execve` or returns an error.
- `SpawnBackend::PosixSpawn` uses `posix_spawn` or returns an error.
- There is no automatic backend selection.
- Unsupported backend/option combinations return clear errors.
- File descriptor handling is explicit through `SpawnFdPolicy`.
- `max_output` is a combined stdout+stderr capture limit.

Core runs the exact argv it receives. Shell or privilege behavior is represented
only by caller-provided argv such as `["/bin/sh", "-c", "..."]` or
`["su", "-c", "..."]`.

## Unix Sockets

`unix_socket` exposes low-level Linux/Android `AF_UNIX` stream helpers:
nonblocking bind/listen, accept, connect, filesystem-socket chmod, byte I/O,
nonblocking connect completion, stale pathname policy, and peer credentials when
the platform exposes them.

`UnixSocketAddr` supports filesystem pathname sockets and Linux/Android abstract
namespace sockets. Existing filesystem paths are preserved by default; callers
must explicitly choose an unlink policy when they want one. Abstract sockets
have no unlink or chmod behavior.

Core does not define message framing, daemon protocols, authentication policy,
fallback behavior, or product socket paths. Those decisions belong above Core.

## Dependency

Release consumers should pin the release tag:

```toml
[dependencies]
coreshift-core = { git = "https://github.com/CoreShiftD/CoreShift-Core", tag = "v0.1.0" }
```

## Example

```rust
use coreshift_core::spawn::{SpawnBackend, SpawnOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = SpawnOptions::builder(vec!["/bin/echo".into(), "hello".into()])
        .backend(SpawnBackend::PosixSpawn)
        .capture_stdout()
        .timeout_ms(1_000)
        .build()?
        .run()?;

    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hello");
    Ok(())
}
```

## Validation

```bash
cargo fmt --check
cargo test -j 1
cargo clippy -j 1 --all-targets --all-features -- -D warnings
cargo doc --no-deps
```

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
