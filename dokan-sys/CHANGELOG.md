# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-08-07

### Added

- Checked-in bindgen output generated directly from the vendored Dokany and
  Windows headers.
- Crate-local Win32 ABI declarations needed by the high-level wrapper.

### Changed

- Upgrade to **Dokan 2.3.0**.
- Adopt Rust 2024 and set Rust 1.85 as the minimum supported version.
- Remove all runtime Rust dependencies; only `cc` remains as a build
  dependency.
- Limit the published crate to the Rust sources, required Dokany user-mode
  sources, headers, and license files.

### Fixed

- Generate documented version constants with checked build-script execution.
- Preserve the exact Dokany source version in package metadata and reject
  mismatched crate/source builds.

## [0.3.1] - 2022-10-04

### Added

- Various `FILE_*` constants.
- `VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE`

### Changed

- Upgrade to **Dokan 2.0.6**.

[unreleased]: https://github.com/dokan-dev/dokan-rust/compare/dokan-sys@v0.4.0...HEAD
[0.4.0]: https://github.com/dokan-dev/dokan-rust/compare/dokan-sys@v0.3.1...dokan-sys@v0.4.0
[0.3.1]: https://github.com/dokan-dev/dokan-rust/releases/tag/dokan-sys@v0.3.1
