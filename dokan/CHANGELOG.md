# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-07

See the [migration guide](https://github.com/dokan-dev/dokan-rust/blob/dokan@v0.4.0/MIGRATION.md)
for the complete upgrade guide.

### Added

- Crate-owned `NtStatus`, typed access/attribute/create/share/security/volume
  flags, and common NT status constants.
- Optional `windows-interop` conversions for the projected `windows` crate.
- Safe, bounded security-descriptor views and an owned volume security
  descriptor.
- Property-fuzz and libFuzzer harnesses for public boundary conversions and
  Dokany name-expression matching.

### Changed

- Upgrade to **Dokan 2.3.0** through `dokan-sys`.
- Adopt Rust 2024 and set Rust 1.85 as the minimum supported version.
- Make filesystem handlers and per-open contexts owned, thread-safe, and
  independent of callback lifetimes.
- Make `FileSystemMounter` own all native callback state and automatically
  reference-count Dokany runtime initialization.
- Make `FileSystemHandle` cloneable rather than `Copy`; notification functions
  now borrow it and safely reject calls after native handle closure.
- Replace public `winapi` and generated-binding types with stable,
  crate-owned API types.
- **Library breaking change:** rename `DOKAN_FILE_INFO.DeleteOnClose` to
  `DOKAN_FILE_INFO.DeletePending`. It retains the same removal semantics, but
  is set when the last handle for the object is closed
  ([dokan-dev/dokany#883](https://github.com/dokan-dev/dokany/issues/883)).

### Fixed

- Prevent unwinding across native callbacks and return an internal-error status
  after a handler panic.
- Preserve high/low words and extreme values in file sizes, identifiers,
  `FILETIME` values, status codes, and timeout conversions.
- Guarantee native alignment for security and notification buffers in the
  example and integration harness.
- Parse directory-change records using their explicit UTF-16 length before
  issuing the next asynchronous read.
- Route Dokany debug output to the requested standard stream.

## [0.3.1] - 2022-10-04

### Added

- `FileSystemHandle` to send a `DOKAN_HANDLE` across threads.
- `map_win32_error_to_ntstatus`
- `win32_ensure`
- In `memfs` example: add status messages and show how another thread can unmount the file system.

### Changed

- Upgrade to **Dokan 2.0.6** through `dokan-sys`.
- Split the code into multiple files.
- Replace `Drive` builder by `FileSystemMounter` and `MountOptions`.
- Operations errors are simply `NTSTATUS`.  
  To return errors from `GetLastError`, use `win32_ensure` or `map_win32_error_to_ntstatus`.
- Access mount point list through an iterator.

### Fixed

- Access to dangling pointer caused panic when the file system handle was used.  
  It's the reason for `FileSystemMounter`, which keeps needed variables onto the stack.

[unreleased]: https://github.com/dokan-dev/dokan-rust/compare/dokan@v0.4.0...HEAD
[0.4.0]: https://github.com/dokan-dev/dokan-rust/compare/dokan@v0.3.1...dokan@v0.4.0
[0.3.1]: https://github.com/dokan-dev/dokan-rust/releases/tag/dokan@v0.3.1
