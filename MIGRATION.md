# Migrating to 0.4

Version 0.4 adopts Rust 2024 and intentionally breaks the 0.3 wrapper API to
remove unsound lifetime and ownership assumptions.

## Handler and handle state

- Implement `FileSystemHandler` without lifetime parameters.
- The handler must be `Send + Sync + 'static`.
- `FileSystemHandler::Context` must be `Send + Sync + 'static`, because Dokany
  may operate on and close a handle from different worker threads.
- `OperationInfo` is callback-scoped. Its constructor, raw handler lookup, and
  per-open context lookup are no longer public.

## Mounting

`FileSystemMounter::new` now owns the handler, mount point, UNC name, and
options:

```rust
let filesystem = FileSystemMounter::new(handler, mount_point, options).mount()?;
```

`mount` consumes the mounter. The returned `FileSystem` owns all callback
storage and automatically holds a process-wide Dokany runtime reference.

## Notification handles

`FileSystemHandle` is cloneable but no longer `Copy`. It shares the full native
session lifetime and serializes notification calls against native handle
closure. Notification functions borrow `&FileSystemHandle`; calls made after
unmount return `false`.

## Raw bindings

The raw declarations are checked-in bindgen output generated from the vendored
Dokany headers. Regenerate them with:

```text
cargo run -p generate-dokan-bindings
```

The generator requires LLVM/libclang and a Windows SDK; normal crate consumers
do not.

## Rust-native Windows boundary

- The high-level `dokan` API no longer exposes `winapi` or generated
  `dokan-sys` structures.
- `create_file` now receives a `CreateFileRequest` containing typed
  `AccessRights`, `FileAttributes`, `ShareAccess`, `CreateDisposition`, and
  `CreateOptions`.
- Security callbacks receive `SecurityInformation` and safe byte slices rather
  than unbounded security-descriptor pointers.
- `FileInfo` and `FindData` use `FileAttributes`; `VolumeInfo` uses
  `VolumeFeatures`.
- Common operation failures are available from `dokan::status`.
- `NtStatus` is now a transparent crate-owned type. Its raw conversions work
  with `windows-sys` and `winapi`; enable `windows-interop` for direct
  conversions to and from `windows::Win32::Foundation::NTSTATUS`.
- `MountOptions::volume_security_descriptor` owns a `Vec<u8>` and validates the
  Dokany size limit when the mounter is constructed.
- Generated ABI types come directly from the vendored Windows/Dokany headers;
  `dokan-sys` therefore has no runtime Rust dependencies. `winapi` remains only
  a development dependency for the legacy Win32-heavy test harness and memfs
  example internals.
