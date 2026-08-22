# Release checklist

The publishable crates are `dokan-sys` and `dokan`. They must be released
together at the same core SemVer version, with `dokan-sys` published first.
Build metadata records the bundled Dokany API version but is not a substitute
for a core-version bump.

## Prerequisites

- A clean checkout with the Dokany submodule initialized.
- Windows with the Dokany 2.3 driver installed for driver integration tests.
- Stable Rust and the declared MSRV, Rust 1.85.0.
- A working x64 MSVC C toolchain. AppVeyor additionally covers x86 and GNU,
  both with installed and source-built Dokany import libraries.
- `cargo-deny` 0.20.2 and `cargo-llvm-cov` 0.8.7, with the
  `llvm-tools-preview` Rust component installed.

Verify that the workspace version, the `dokan`/`dokan-sys` dependency
requirements, both changelogs, and the vendored Dokany version describe the
same release.

## Required local gates

Run from the repository root in PowerShell:

```powershell
.\scripts\check-workspace-policy.ps1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked
cargo deny --locked check
cargo +1.85.0 check --workspace --all-targets --all-features --locked
cargo test --workspace --all-features --locked -- --test-threads=1
cargo test --workspace --all-features --locked -- --ignored --test-threads=1
cargo llvm-cov --workspace --all-features --locked --summary-only --fail-under-lines 75 -- --test-threads=1

$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --all-features --locked --no-deps
Remove-Item Env:RUSTDOCFLAGS

cargo package -p dokan-sys -p dokan --locked
```

The ignored driver timeout test is intentional, but it is still a release
gate. Do not run the driver integration binary concurrently with itself.

## Fuzz gates

Normal CI performs one second of randomized property fuzzing per target. For a
release candidate, run at least ten minutes per target:

```powershell
$env:BOLERO_RANDOM_TEST_TIME_MS = "600000"
cargo test -p dokan-fuzz --release --test properties --locked -- --test-threads=1
Remove-Item Env:BOLERO_RANDOM_TEST_TIME_MS
```

The same exercisers have `cargo-fuzz` entry points. On a Windows environment
with compatible nightly libFuzzer and AddressSanitizer runtimes, disable the
workspace release LTO and run each target:

```powershell
$env:CARGO_PROFILE_RELEASE_LTO = "false"
cargo +nightly fuzz run api_inputs
cargo +nightly fuzz run name_expression
Remove-Item Env:CARGO_PROFILE_RELEASE_LTO
```

Native `cargo-fuzz` support on Windows depends on the installed LLVM sanitizer
runtime. The Bolero campaign above is the portable Windows release gate and
must not be skipped when that runtime is unavailable.

## Publish

Wait for the full AppVeyor matrix to pass, including the quality and MSRV jobs.
Inspect the package file lists and sizes in the packaging output, then publish
in dependency order:

```powershell
cargo publish -p dokan-sys --locked
# Wait until the new dokan-sys version is visible in the crates.io index.
cargo publish -p dokan --locked
```

Create signed `dokan-sys@vX.Y.Z` and `dokan@vX.Y.Z` tags from the exact
published commit. Confirm that each crates.io page, repository tag, generated
documentation site, and changelog link points to that commit.
