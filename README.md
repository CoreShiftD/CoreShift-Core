# CoreShift Core

CoreShift Core is the low-level Linux/Android primitives crate at the bottom of
the CoreShift stack.

```text
Policy / product behavior
        ↓
Engine coordination
        ↓
Core syscall and filesystem primitives
```

Core exposes explicit wrappers for process spawning, file descriptor handling,
procfs parsing, signals, reactor primitives, inotify, Unix sockets, and
filesystem preload helpers. It does not choose Android policy, foreground app
behavior, package discovery, daemon protocols, or preload rules.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Preload primitives](docs/PRELOAD_PRIMITIVES.md)
- [Testing](docs/TESTING.md)

## Release Dependency

```toml
[dependencies]
coreshift-core = "1.0.0"
```

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
