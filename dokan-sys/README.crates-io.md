# dokan-sys

`dokan-sys` provides raw Rust FFI declarations for
[Dokany](https://github.com/dokan-dev/dokany). The checked-in bindings are
generated from the vendored Dokany 2.3 and Windows headers.

Most applications should use the higher-level
[`dokan`](https://crates.io/crates/dokan) crate instead.

```toml
[dependencies]
dokan-sys = "0.4"
```

Rust 1.85 or newer and a Windows C toolchain are required. If
`DokanLibrary2_LibraryPath_x64` or `DokanLibrary2_LibraryPath_x86` identifies
an installed import library, the build script links it. Otherwise the
published crate contains the minimal Dokany user-mode sources needed to build
the import library and DLL.

The crate version, import library, runtime DLL, and installed driver must use
compatible Dokany APIs.

- [Raw API documentation](https://dokan-dev.github.io/dokan-rust-doc/html/dokan_sys/)
- [Dokany documentation](https://dokan-dev.github.io/dokany-doc/html/)
- [Repository](https://github.com/dokan-dev/dokan-rust)
