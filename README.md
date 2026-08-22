# Dokan Rust Wrapper

[![Build status](https://ci.appveyor.com/api/projects/status/github/dokan-dev/dokan-rust?svg=true)](https://ci.appveyor.com/project/Liryna/dokan-rust)

This project allows you to easily use [Dokan](https://github.com/dokan-dev/dokany) in Rust. It consists of two crates:

- [![crates.io](https://img.shields.io/crates/v/dokan-sys)](https://crates.io/crates/dokan-sys) `dokan-sys` provides raw bindings generated from Dokany's C headers.

- [![crates.io](https://img.shields.io/crates/v/dokan)](https://crates.io/crates/dokan) `dokan` is built on top of `dokan-sys` and provides high-level, Rust-friendly wrappers for Dokan.

Generally, it is recommended to use the `dokan` crate, which has the unsafe raw bindings wrapped and is easier to use. However, if you want to access the low-level interface provided by Dokan, `dokan-sys` can save you from writing the function and structure definitions yourself.

Implementing a filesystem through `dokan` does not require a direct dependency
on a Windows binding crate. Its public API provides typed access rights,
attributes, create options, sharing modes, security information, volume
features, owned handles, safe security buffers, and common NT status values.
The ABI structs are generated directly from the vendored C headers, so
`dokan-sys` has no runtime Rust dependencies.

`NtStatus` has binding-neutral `from_raw`/`into_raw` methods, which work
directly with the integer aliases used by `windows-sys` and legacy `winapi`.
Applications using Microsoft's projected `windows` crate can enable
`dokan`'s `windows-interop` feature for direct `From` conversions.

All dependency versions are declared once under the workspace's
`[workspace.dependencies]`. Cargo automatically unifies these with compatible
versions selected by an application. The default consumer graph is only
`dokan`, `dokan-sys`, `bitflags`, and `widestring`; the larger projected
`windows` graph and the bindgen maintainer tool are opt-in.

# Build

The Rust crates use the Rust 2024 edition and require Rust 1.85 or newer.

`dokan-sys`, which is also a dependency of `dokan`, requires the import library of the native Dokan library in order to link against it.

If the `DokanLibrary2_LibraryPath_{ARCH}` environment variable exists (`{ARCH}` can be `x86` or `x64` depending on the architecture of your target platform), `dokan-sys` will look for the import library in the directory specified by the aforementioned environment variable. These environment variables are automatically set by Dokan's installer since v1.0.0.

Otherwise, `dokan-sys` will build the import library from bundled Dokan source code. The DLL file will be built as well and you can use the `DOKAN_DLL_OUTPUT_PATH` environment variable to have the build script copy it to the specified directory.

Maintainers can regenerate the checked-in raw bindings with
`cargo run -p generate-dokan-bindings`. This requires LLVM/libclang and the
Windows SDK; normal builds do not.

Note that the versions of the `dokan-sys` crate, the linked import library and the Dokan library loaded at runtime should be identical, or you may run into troubles. So please take care when using the `DokanLibrary2_LibraryPath_*` environment variables and [deploying your application](https://github.com/dokan-dev/dokany/wiki/How-to-package-your-application-with-Dokan#dokan-application-considerations).

# Quality gates

The workspace enforces shared dependency declarations, warning-free Rust,
missing public documentation, unsafe-operation checks, and Clippy's pedantic
group. CI covers x86/x64 MSVC and GNU builds against both installed and bundled
Dokany libraries, plus the Rust 1.85 MSRV.

Run the portable unit, driver-integration, and property-fuzz suites with:

```text
cargo test --workspace --all-features --locked -- --test-threads=1
```

See [RELEASING.md](RELEASING.md) for all release gates and
[fuzz/README.md](fuzz/README.md) for sustained fuzz campaigns.

# Usage

- `dokan-sys` can be used in exactly the same way as the native Dokan library. Read [Dokan's documentation](https://dokan-dev.github.io/dokany-doc/html/) for more information.
- `dokan` has [detailed documentation](https://dokan-dev.github.io/dokan-rust-doc/html/dokan/) and a [memfs example](https://github.com/dokan-dev/dokan-rust/tree/master/dokan/examples/memfs) available. The [driver integration tests](https://github.com/dokan-dev/dokan-rust/blob/master/dokan/tests/driver-integration.rs) provide additional complete examples.
