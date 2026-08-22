#![cfg(windows)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! Raw FFI bindings for [Dokany].
//!
//! The declarations in this crate are generated from the vendored Dokany
//! headers. Regenerate `bindings.rs` with the repository's
//! `tools/generate-bindings` utility when updating Dokany.
//!
//! Most applications should use the safe [`dokan`] crate instead.
//!
//! [Dokany]: https://github.com/dokan-dev/dokany
//! [`dokan`]: https://crates.io/crates/dokan

// bindgen mirrors C identifiers verbatim and many declarations have no upstream
// documentation comments. Keep the exception scoped to generated code.
#[allow(
	missing_docs,
	non_camel_case_types,
	non_snake_case,
	non_upper_case_globals,
	rustdoc::bare_urls,
	unsafe_op_in_unsafe_fn,
	clippy::pedantic,
	reason = "generated directly from Dokany C headers"
)]
mod bindings;

/// Raw Win32 types and constants needed by the generated Dokany API.
#[allow(
	missing_docs,
	non_camel_case_types,
	clippy::unreadable_literal,
	reason = "names and values mirror constants from the Windows SDK"
)]
pub mod win32;

pub use bindings::*;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

// bindgen intentionally does not emit these macro constants. Keeping the
// public constants here gives them precise Rust types and avoids signedness
// changes when C headers or bindgen versions change.
/// Enables Dokany debug output.
pub const DOKAN_OPTION_DEBUG: ULONG = 1 << 0;
/// Sends Dokany debug output to standard error.
pub const DOKAN_OPTION_STDERR: ULONG = 1 << 1;
/// Enables alternate data streams.
pub const DOKAN_OPTION_ALT_STREAM: ULONG = 1 << 2;
/// Mounts the filesystem as write-protected.
pub const DOKAN_OPTION_WRITE_PROTECT: ULONG = 1 << 3;
/// Mounts the filesystem as a network drive.
pub const DOKAN_OPTION_NETWORK: ULONG = 1 << 4;
/// Mounts the filesystem as removable media.
pub const DOKAN_OPTION_REMOVABLE: ULONG = 1 << 5;
/// Lets the Windows mount manager assign the drive letter.
pub const DOKAN_OPTION_MOUNT_MANAGER: ULONG = 1 << 6;
/// Restricts the mount to the current Windows session.
pub const DOKAN_OPTION_CURRENT_SESSION: ULONG = 1 << 7;
/// Handles file locking in user mode.
pub const DOKAN_OPTION_FILELOCK_USER_MODE: ULONG = 1 << 8;
/// Enables case-sensitive path matching.
pub const DOKAN_OPTION_CASE_SENSITIVE: ULONG = 1 << 9;
/// Allows unmounting a network drive through the Dokany API.
pub const DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE: ULONG = 1 << 10;
/// Dispatches kernel-driver log messages to user mode.
pub const DOKAN_OPTION_DISPATCH_DRIVER_LOGS: ULONG = 1 << 11;
/// Enables batching for Dokany IPC operations.
pub const DOKAN_OPTION_ALLOW_IPC_BATCHING: ULONG = 1 << 12;

/// Maximum security-descriptor size accepted for volume information.
pub const VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE: usize = 16 * 1024;

/// Dokany operation completed successfully.
pub const DOKAN_SUCCESS: i32 = 0;
/// Generic Dokany error.
pub const DOKAN_ERROR: i32 = -1;
/// The requested drive letter is invalid or unavailable.
pub const DOKAN_DRIVE_LETTER_ERROR: i32 = -2;
/// The Dokany driver could not be installed.
pub const DOKAN_DRIVER_INSTALL_ERROR: i32 = -3;
/// Dokany could not start the filesystem.
pub const DOKAN_START_ERROR: i32 = -4;
/// Dokany could not mount the filesystem.
pub const DOKAN_MOUNT_ERROR: i32 = -5;
/// The requested mount point is invalid.
pub const DOKAN_MOUNT_POINT_ERROR: i32 = -6;
/// The Dokany library and driver versions are incompatible.
pub const DOKAN_VERSION_ERROR: i32 = -7;
