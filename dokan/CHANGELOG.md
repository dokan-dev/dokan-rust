# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Upgrade to **Dokan 2.2.0** through `dokan-sys`.
- Bump dependencies.

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

[unreleased]: https://github.com/dokan-dev/dokan-rust/compare/dokan@v0.3.1...HEAD
[0.3.1]: https://github.com/dokan-dev/dokan-rust/releases/tag/dokan@v0.3.1
