# Filesystem Preload Primitives

CoreShift-Core provides the low-level file operations used by higher layers to
warm file data. Core does not discover files or decide which files deserve
preload.

## `readahead`

`readahead(fd, offset, len)` asks the kernel to begin reading a byte range for an
open file descriptor.

Callers choose:

- The file descriptor.
- The byte offset.
- The byte length.

Unsupported platforms return `ENOSYS`. Offsets that cannot fit the platform
syscall type return `EINVAL`.

## `fadvise`

CoreShift-Core 1.x does not expose a separate public `posix_fadvise` wrapper.
Higher layers should use the currently exported `readahead` and `mmap_madvise`
helpers until a dedicated fadvise primitive is added.

## `mmap_madvise`

`mmap_madvise(fd, offset, len, touch)` maps a read-only byte range and applies
`MADV_WILLNEED`.

When `touch` is false, Core maps the range, calls `madvise`, and unmaps it. When
`touch` is true, Core also reads one byte from each page after `madvise` so the
caller can request page touching.

Unsupported platforms return `ENOSYS`.

## Offset Alignment

`mmap` requires page-aligned offsets. Core validates this before calling into the
kernel:

- Page-aligned offsets are allowed.
- Unaligned offsets return `EINVAL`.
- Offsets larger than the platform `off_t` range return `EINVAL`.

Core does not silently widen, shift, or round the request. Policy layers should
align ranges before calling Core when they want a wider mapping.

## Safety and Errors

The mapping is read-only and private to the process. Core unmaps the range before
returning. Errors are reported as `CoreError` values with the platform operation
name, such as `readahead`, `mmap`, or `madvise`.

Higher layers should treat preload as best-effort unless their product policy
requires a hard failure.
