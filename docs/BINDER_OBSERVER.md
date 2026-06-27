# Binder Observer

`ActivityManagerBinder::open_with_observer()` registers the calling
process as an `IProcessObserver` with Android's ActivityManager. On success it
returns a raw `eventfd` that becomes readable whenever
`onForegroundActivitiesChanged` fires.

## Usage

Add the returned fd to an epoll reactor. On event:

1. Drain the eventfd (read 8 bytes).
2. Call `get_focused_package()` — this calls `getFocusedRootTaskInfo` inside
   the observer callback context, where it returns live (non-stale) data.

No persistent transaction-code cache is used; codes are resolved from `framework.jar` DEX at startup.

## Transaction code resolution

Codes are resolved once at startup by parsing `TRANSACTION_*` static `int` fields from `IActivityManager` and `IProcessObserver` directly from the ZIP STORED DEX entries in `framework.jar`, with no subprocess or `app_process` required.

## Lifetime

The binder thread pool (`ABinderProcess_joinThreadPool`) runs on a background
thread for the process lifetime. The loaded `libbinder_ndk.so` is intentionally
never unloaded — `dlclose` while the thread pool executes from the library
causes use-after-free. This is safe for daemon processes.

## Accessibility

`open_with_observer` requires:

- `/dev/binder` accessible to the calling process
- SELinux policy permits `registerProcessObserver` on `IActivityManager`
- `activity` service reachable via service manager

On rooted devices this typically succeeds. `try_open()` returns `None` on any
failure so callers can fall back gracefully.

## Acknowledgement

The binder observer technique — registering as `IProcessObserver` to gate
`getFocusedRootTaskInfo` — is based on the approach by
**[sehan64](https://github.com/sehan64)**.
