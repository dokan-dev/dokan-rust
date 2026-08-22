# dokan

`dokan` is a safe, Rust-friendly wrapper for
[Dokany](https://github.com/dokan-dev/dokany), a Windows user-mode filesystem
library.

The API provides owned filesystem/session state, typed access and create
flags, safe security-descriptor views, crate-owned NT status values, and panic
containment at every native callback boundary. Most filesystem implementations
only need this crate; they do not need to depend directly on a Windows binding
crate.

```toml
[dependencies]
dokan = "0.4"
```

Rust 1.85 or newer and a Windows C toolchain are required. The Dokany library
and installed driver must be compatible with the Dokany version recorded in
the crate's build metadata. If an installed Dokany import library is not
available, `dokan-sys` builds the bundled user-mode library from source.

- [API documentation](https://dokan-dev.github.io/dokan-rust-doc/html/dokan/)
- [MemFS example](https://github.com/dokan-dev/dokan-rust/tree/master/dokan/examples/memfs)
- [0.4 migration guide](https://github.com/dokan-dev/dokan-rust/blob/master/MIGRATION.md)
- [Repository](https://github.com/dokan-dev/dokan-rust)
