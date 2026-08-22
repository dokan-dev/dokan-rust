# Dokan fuzzing

This package keeps fuzz logic in shared exercisers so the same invariants can
run through two engines:

- Bolero property tests run on stable Rust and are part of the Windows CI gate.
- `cargo-fuzz` targets provide coverage-guided libFuzzer entry points when a
  compatible Windows LLVM sanitizer runtime is available.

The targets cover:

- Arbitrary native flag values, `CreateDisposition` validation, kernel-to-user
  flag mapping, and bit-exact NT-status round trips.
- Arbitrary non-NUL UTF-16 expressions and names passed to Dokany's native
  expression matcher.

Run the portable smoke suite with:

```text
cargo test -p dokan-fuzz --test properties --locked
```

Increase `BOLERO_RANDOM_TEST_TIME_MS` for a sustained randomized campaign. A
failure reports `BOLERO_RANDOM_SEED`; set that variable to reproduce the exact
generated case.

For native libFuzzer runs, install `cargo-fuzz` and use nightly Rust:

```text
cargo +nightly fuzz run api_inputs
cargo +nightly fuzz run name_expression
```

The workspace release profile uses LTO, which is incompatible with the Windows
sanitizer objects used by these targets. Set
`CARGO_PROFILE_RELEASE_LTO=false` for `cargo fuzz` commands. Crashes and corpus
directories are intentionally ignored; promote minimized regressions into
deterministic unit or integration tests before merging a fix.
