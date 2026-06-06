# Reactor and I/O Subsystem

CoreShift-Core implements a high-performance, non-blocking I/O system based on the Linux `epoll` facility.

## Design Philosophy

The I/O subsystem is designed to be **explicit** and **stateless**. It does not include a background thread pool or a complex async runtime. Instead, it provides the building blocks for callers to drive their own event loops.

## Components

### `Reactor`

The `Reactor` is a thin wrapper around a Linux `epoll` file descriptor.

- **Edge-Triggered**: Core uses `EPOLLET` (edge-triggered) readiness. This means that when a readiness event occurs, the caller **must** continue reading or writing to the descriptor until it receives an `EAGAIN` or `EWOULDBLOCK` error.
- **Tokens**: Every registered descriptor is associated with a `Token` (an opaque `u64`). This allows the caller to quickly identify which component is ready for I/O.

### `Fd`

`Fd` is an owned file descriptor wrapper. It ensures that descriptors are closed correctly on drop and provides safe, non-blocking helper methods for `read` and `write`.

### `DrainState`

`DrainState` is a high-level orchestrator for process I/O. It manages the bookkeeping for a process's `stdin`, `stdout`, and `stderr` pipes.

- **Multiplexing**: It coordinates reading from multiple output streams into internal buffers while respecting a global memory limit.
- **Early Exit**: Supports a predicate that can stop consumption early (e.g., if a specific log line is detected).
- **Stateless**: `DrainState` does not own the `Reactor`. It provides tokens and handlers that the caller must integrate into their own event loop.

## Typical usage with Process Spawning

When using `spawn_start`, you receive a `RunningProcess` handle which contains a `DrainState`.

```rust
use coreshift_core::spawn::{self, SpawnBackend, SpawnOptions};
use coreshift_core::reactor::Reactor;

fn example() -> Result<(), coreshift_core::CoreError> {
    let mut reactor = Reactor::new()?;
    let mut running = spawn::spawn_start(
        SpawnOptions::builder(vec!["/bin/ls".to_string()], SpawnBackend::PosixSpawn)
            .capture_stdout()
            .build()?
    )?;

    // Register process pipes with the reactor
    running.register_with_reactor(&mut reactor)?;

    let mut events = Vec::new();
    while !running.io_done() {
        reactor.wait(&mut events, 64, -1)?;
        for ev in &events {
            // Let the process handle its own readiness events
            running.handle_reactor_event(&mut reactor, ev)?;
        }
    }

    let (stdout, stderr) = running.into_output_parts();
    Ok(())
}
```

## Guarantees

- **No Hidden Threads**: All I/O occurs on the thread that calls `Reactor::wait` and the subsequent handler methods.
- **Memory Safety**: `DrainState` enforces strict bounds on captured output to prevent process-driven memory exhaustion.
