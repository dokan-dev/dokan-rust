#![cfg(windows)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! [Dokan] is a user mode file system for Windows. It allows anyone to safely and easily develop
//! new file systems on Windows.
//!
//! This crate is a Rust-friendly wrapper for Dokan, allowing you to create file systems using Rust.
//! It builds upon the low-level [`dokan-sys`] crate.
//!
//! In general, to create a file system with this library, you need to implement the
//! [`FileSystemHandler`] trait, create a [`FileSystemMounter`], and [mount](FileSystemMounter::mount) it
//! to create a [`FileSystem`]. When dropped, the latter will block the current thread until it gets unmounted.
//! You have to call [`init`] once before, and [`shutdown`] when you're done.
//!
//! The same explanations with a few lines of code: see [the MemFS example](https://github.com/dokan-dev/dokan-rust/blob/master/dokan/examples/memfs/main.rs#L1330)!
//!
//! The high-level API provides typed access rights, attributes, create options,
//! sharing modes, volume features, security information, and common
//! [`status`] values. Applications do not need a Windows binding crate merely
//! to implement [`FileSystemHandler`].
//!
//! [Dokan]: https://dokan-dev.github.io/
//! [`dokan-sys`]: https://crates.io/crates/dokan-sys

mod data;
mod file_system;
mod file_system_handler;
mod notify;
mod operations;
mod operations_helpers;
pub mod status;
mod to_file_time;
mod types;

use dokan_sys::{
	DokanDebugMode, DokanDriverVersion, DokanInit, DokanIsNameInExpression,
	DokanMapKernelToUserCreateFileFlags, DokanNtStatusFromWin32, DokanRemoveMountPoint,
	DokanSetDebugMode, DokanShutdown, DokanUseStdErr, DokanVersion,
};
use std::sync::{Mutex, OnceLock};
use widestring::U16CStr;
const FALSE: i32 = 0;
const TRUE: i32 = 1;

pub use crate::{data::*, file_system::*, file_system_handler::*, notify::*, types::*};

/// Re-exported from `dokan-sys` for convenience.
pub use dokan_sys::{
	DOKAN_DRIVER_NAME as DRIVER_NAME, DOKAN_MAJOR_API_VERSION as MAJOR_API_VERSION,
	DOKAN_NP_NAME as NP_NAME, DOKAN_VERSION as WRAPPER_VERSION,
};

/// Initializes all required Dokan internal resources.
///
/// This needs to be called only once before trying to use other functions for the first time.
/// Otherwise they will fail and raise an exception.
fn runtime_users() -> &'static Mutex<usize> {
	static USERS: OnceLock<Mutex<usize>> = OnceLock::new();
	USERS.get_or_init(|| Mutex::new(0))
}

pub(crate) struct RuntimeGuard;

impl RuntimeGuard {
	pub(crate) fn acquire() -> Self {
		let mut users = runtime_users()
			.lock()
			.expect("Dokany runtime lock poisoned");
		if *users == 0 {
			unsafe { DokanInit() }
		}
		*users += 1;
		Self
	}
}

impl Drop for RuntimeGuard {
	fn drop(&mut self) {
		release_runtime();
	}
}

fn release_runtime() {
	let mut users = runtime_users()
		.lock()
		.expect("Dokany runtime lock poisoned");
	assert!(*users != 0, "shutdown called without a matching init");
	*users -= 1;
	if *users == 0 {
		unsafe { DokanShutdown() }
	}
}

/// Acquires one process-wide reference to the Dokany runtime.
///
/// New code normally does not need this function: mounted filesystems acquire
/// and release the runtime automatically.
pub fn init() {
	std::mem::forget(RuntimeGuard::acquire());
}

/// Releases all allocated resources by [`init`] when they are no longer needed.
///
/// This should be called when the application no longer expects to create a new `FileSystem` and after all devices are unmount.
pub fn shutdown() {
	release_runtime();
}

/// Gets version of the loaded Dokan library.
///
/// The returned value is the version number without dots. For example, it returns `131` if Dokan
/// v1.3.1 is loaded.
#[must_use]
pub fn get_lib_version() -> u32 {
	unsafe { DokanVersion() }
}

/// Gets version of the Dokan driver installed on the current system.
///
/// The returned value is the version number without dots.
#[must_use]
pub fn get_driver_version() -> u32 {
	unsafe { DokanDriverVersion() }
}

#[test]
fn test_versions() {
	assert_eq!(MAJOR_API_VERSION, (get_lib_version() / 100).to_string());
	assert!(get_driver_version() < 1000);
	assert_eq!(DRIVER_NAME, format!("dokan{MAJOR_API_VERSION}.sys"));
	assert_eq!(NP_NAME, format!("Dokan{MAJOR_API_VERSION}"));
}

/// Checks whether the `name` matches the specified `expression`.
///
/// This is a helper function that can be used to implement
/// [`FileSystemHandler::find_files_with_pattern`]. It behaves like the [`FsRtlIsNameInExpression`]
/// routine provided for file system drivers by Windows.
///
/// [`FsRtlIsNameInExpression`]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression
pub fn is_name_in_expression(
	expression: impl AsRef<U16CStr>,
	name: impl AsRef<U16CStr>,
	ignore_case: bool,
) -> bool {
	unsafe {
		DokanIsNameInExpression(
			expression.as_ref().as_ptr(),
			name.as_ref().as_ptr(),
			ignore_case.into(),
		) == TRUE
	}
}

#[test]
fn test_is_name_in_expression() {
	use widestring::U16CString;

	let convert_str = |value: &str| U16CString::from_str(value).unwrap();

	assert!(is_name_in_expression(
		convert_str("foo"),
		convert_str("foo"),
		true
	));

	assert!(is_name_in_expression(
		convert_str("*"),
		convert_str("foo"),
		true
	));

	assert!(is_name_in_expression(
		convert_str("?"),
		convert_str("x"),
		true
	));

	assert!(!is_name_in_expression(
		convert_str("?"),
		convert_str("foo"),
		true
	));

	assert!(is_name_in_expression(
		convert_str("F*"),
		convert_str("foo"),
		true
	));

	assert!(!is_name_in_expression(
		convert_str("F*"),
		convert_str("foo"),
		false
	));
}

/// Converts a Win32 error, such as one returned by
/// [`GetLastError`](https://learn.microsoft.com/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror),
/// to [`NtStatus`].
#[must_use]
pub fn map_win32_error_to_ntstatus(error: u32) -> NtStatus {
	NtStatus::from_raw(unsafe { DokanNtStatusFromWin32(error) })
}

#[test]
fn can_map_win32_error_to_ntstatus() {
	use winapi::shared::{ntstatus::STATUS_INTERNAL_ERROR, winerror::ERROR_INTERNAL_ERROR};

	assert_eq!(
		map_win32_error_to_ntstatus(ERROR_INTERNAL_ERROR).into_raw(),
		STATUS_INTERNAL_ERROR
	);
}

/// Converts the current thread's Win32 last-error value when `condition` is false.
///
/// It builds upon [`map_win32_error_to_ntstatus`].
///
/// **Warning**: success of some functions can only be known by checking `GetLastError`.
/// In such cases, **do not use this function!**
/// For instance, `ReadFile` and `WriteFile` in asynchronous mode are successful if they
/// return `FALSE` and `GetLastError` returns `ERROR_IO_PENDING`.
///
/// # Errors
///
/// Returns the current thread's last-error value converted to [`NtStatus`] when
/// `condition` is `false`.
pub fn win32_ensure(condition: bool) -> Result<(), NtStatus> {
	if condition {
		Ok(())
	} else {
		let error = std::io::Error::last_os_error()
			.raw_os_error()
			.map_or(0, |value| u32::from_ne_bytes(value.to_ne_bytes()));
		Err(map_win32_error_to_ntstatus(error))
	}
}

/// Flags returned by [`map_kernel_to_user_create_file_flags`].
///
/// These flags are the same as those accepted by [`CreateFile`].
///
/// [`CreateFile`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserCreateFileFlags {
	/// The requested access to the file.
	pub desired_access: AccessRights,
	/// The file attributes and flags.
	pub flags_and_attributes: u32,
	/// The action to take on the file that exists or does not exist.
	pub creation_disposition: u32,
}

/// Converts the arguments passed to [`FileSystemHandler::create_file`] to flags accepted by the
/// Win32 [`CreateFile`] function.
///
/// Dokan forwards the parameters directly from [`IRP_MJ_CREATE`]. This functions converts them to
/// corresponding flags in Win32, making it easier to process them.
///
/// [`CreateFile`]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
/// [`IRP_MJ_CREATE`]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create
#[must_use]
pub fn map_kernel_to_user_create_file_flags(
	desired_access: AccessRights,
	file_attributes: FileAttributes,
	create_options: CreateOptions,
	create_disposition: CreateDisposition,
) -> UserCreateFileFlags {
	let mut mapped_access = 0;
	let mut flags_and_attributes = 0;
	let mut creation_disposition = 0;
	unsafe {
		DokanMapKernelToUserCreateFileFlags(
			desired_access.bits(),
			file_attributes.bits(),
			create_options.bits(),
			create_disposition as u32,
			&raw mut mapped_access,
			&raw mut flags_and_attributes,
			&raw mut creation_disposition,
		);
	}
	UserCreateFileFlags {
		desired_access: AccessRights::from_bits_retain(mapped_access),
		flags_and_attributes,
		creation_disposition,
	}
}

#[test]
fn test_map_kernel_to_user_create_file_flags() {
	use winapi::um::{
		fileapi::OPEN_EXISTING,
		winbase::FILE_FLAG_WRITE_THROUGH,
		winnt::{
			FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ,
			GENERIC_WRITE,
		},
	};

	let result = map_kernel_to_user_create_file_flags(
		AccessRights::from_bits_retain(FILE_ALL_ACCESS),
		FileAttributes::NORMAL,
		CreateOptions::WRITE_THROUGH,
		CreateDisposition::Open,
	);
	assert_eq!(
		result.desired_access.bits(),
		GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL
	);
	assert_eq!(
		result.flags_and_attributes,
		FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_NORMAL
	);
	assert_eq!(result.creation_disposition, OPEN_EXISTING);
}

/// Unmounts a Dokan volume from the specified mount point.
///
/// Returns whether it succeeded.
#[must_use]
pub fn unmount(mount_point: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanRemoveMountPoint(mount_point.as_ref().as_ptr()) == TRUE }
}

/// Output stream to write debug messages to.
///
/// Used by [`set_debug_stream`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DebugStream {
	/// The standard output stream.
	Stdout,
	/// The standard error stream.
	Stderr,
}

/// Sets the output stream to write debug messages to.
pub fn set_debug_stream(stream: DebugStream) {
	unsafe {
		DokanUseStdErr(if let DebugStream::Stderr = stream {
			TRUE
		} else {
			FALSE
		});
	}
}

/// Enables or disables debug mode of the user mode library.
pub fn set_lib_debug_mode(enabled: bool) {
	unsafe {
		DokanDebugMode(if enabled { TRUE } else { FALSE });
	}
}

/// Enables or disables debug mode of the kernel driver;
///
/// Returns `true` on success.
#[must_use]
pub fn set_driver_debug_mode(enabled: bool) -> bool {
	unsafe { DokanSetDebugMode(u32::from(enabled)) == TRUE }
}

#[test]
fn test_debug_mode() {
	set_debug_stream(DebugStream::Stdout);
	set_debug_stream(DebugStream::Stderr);
	set_lib_debug_mode(true);
	set_lib_debug_mode(false);
	assert!(set_driver_debug_mode(true));
	assert!(set_driver_debug_mode(false));
}
