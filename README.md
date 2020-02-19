# Dokan Rust Wrapper

[![Build status](https://ci.appveyor.com/api/projects/status/github/dokan-dev/dokan-rust?svg=true)](https://ci.appveyor.com/project/Liryna/dokan-rust)

This project allows you to easily use [Dokan](https://github.com/dokan-dev/dokany) in Rust. It consists of two crates:

- [![crates.io](https://img.shields.io/crates/v/dokan-sys)](https://crates.io/crates/dokan-sys) `dokan-sys` provides raw bindings to the functions and structures provided by Dokan.

- [![crates.io](https://img.shields.io/crates/v/dokan)](https://crates.io/crates/dokan) `dokan` is built on top of dokan-sys and provides high-level, Rust-friendly wrappers for Dokan.

Generally, it is recommended to use the `dokan` crate, which has the unsafe raw bindings wrapped and is easier to use. However, if you want to access the low-level interface provided by Dokan, `dokan-sys` can save you from writing the function and structure definitions yourself.

# Build

`dokan-sys`, which is also a dependency of `dokan`, requires the import library of the native Dokan library in order to link against it.

If the `DokanLibrary1_LibraryPath_{ARCH}` environment variable exists (`{ARCH}` can be `x86` or `x64` depending on the architecture of your target platform), `dokan-sys` will look for the import library in the directory specified by the aforementioned environment variable. These environment variables are automatically set by Dokan's installer since v1.0.0.

Otherwise, `dokan-sys` will build the import library from bundled Dokan source code.

Note that the versions of the `dokan-sys` crate, the linked import library and the Dokan library loaded at runtime should be identical, or you may run into troubles. So please take care when using the `DokanLibrary1_LibraryPath_*` environment variables and [deploying your application](https://github.com/dokan-dev/dokany/wiki/How-to-package-your-application-with-Dokan#dokan-application-considerations).

# Usage

- `dokan-sys` can be used in exactly the same way as the native Dokan library. Read [Dokan's documentation](https://dokan-dev.github.io/dokany-doc/html/) for more information.
- `dokan` has [detailed documentation](https://dokan-dev.github.io/dokan-rust-doc/html/dokan/) available. You can also find some examples in [the unit tests](https://github.com/dokan-dev/dokan-rust/blob/master/dokan/src/tests.rs) and existing projects like [yasfw](https://github.com/DDoSolitary/yasfw).
