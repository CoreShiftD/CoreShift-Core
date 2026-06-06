# Signal Handling and Shutdown Coordination

CoreShift-Core provides a centralized mechanism for managing process shutdown via standard Unix signals (`SIGINT`, `SIGTERM`).

## Design Goal

Core does not impose a shutdown policy. Instead, it provides a thread-safe way for a signal handler to notify the application's main loop that a shutdown has been requested.

## Key Primitives

### `install_shutdown_flag`

`install_shutdown_flag(flag: &'static AtomicBool)` installs global signal handlers for `SIGINT` and `SIGTERM`. When either signal is received, the handler sets the provided `AtomicBool` to `true`.

This is intended for the application's primary entry point.

### `install_shutdown_flag_guard`

`install_shutdown_flag_guard(flag: &'static AtomicBool)` is the scoped version of the above. It returns a guard that, when dropped, restores the previous signal handlers and the previous shutdown flag pointer.

This is primarily used in tests or transient worker threads to ensure isolation.

### `shutdown_requested`

`shutdown_requested(flag: &AtomicBool)` is a convenience helper to check the current state of the shutdown flag using the correct atomic ordering (`Ordering::Acquire`).

## Typical Usage Pattern

```rust
use coreshift_core::signal;
use std::sync::atomic::AtomicBool;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<(), coreshift_core::CoreError> {
    // Install the global handler
    signal::install_shutdown_flag(&SHUTDOWN)?;

    while !signal::shutdown_requested(&SHUTDOWN) {
        // Perform work...
        // If a signal arrives, the loop will exit gracefully.
    }

    Ok(())
}
```

## Safety Invariants

- **Signal Safety**: The internal signal handler is async-signal-safe. It only performs a `store` operation on an atomic pointer.
- **Global State**: Core uses a single `static AtomicPtr<AtomicBool>` to track the active flag. Only one flag can be active at a time per process.
