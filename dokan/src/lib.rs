#![cfg(windows)]

//! [Dokan][Dokan] is a user mode file system for Windows. It allows anyone to
//! safely and easily develop new file systems on Windows.
//!
//! This crate is a Rust-friendly wrapper for Dokan, allowing you to create file systems using Rust.
//!
//! In general, to create a file system with this library, you need to implement the
//! [`FileSystemHandler`][FileSystemHandler] trait, and pass it to [`Drive::mount`][mount].
//!
//! Please note that some of the constants from Win32 API that might be used when interacting with
//! this crate are not provided directly here. However, you can easily find them in the
//! [winapi][winapi] crate.
//!
//! [Dokan]: https://dokan-dev.github.io/
//! [FileSystemHandler]: trait.FileSystemHandler.html
//! [mount]: struct.Drive.html#method.mount
//! [winapi]: https://crates.io/crates/winapi

#[macro_use]
extern crate bitflags;
extern crate dokan_sys;
extern crate widestring;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
extern crate parking_lot;
#[cfg(test)]
extern crate regex;

#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{ptr, mem, panic, slice};

use dokan_sys::{*, win32::*};
use widestring::{U16CStr, U16CString};
use winapi::ctypes::c_int;
use winapi::shared::minwindef::{BOOL, DWORD, FILETIME, LPCVOID, LPVOID, LPDWORD, MAX_PATH, PULONG, TRUE, ULONG};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, LONGLONG, LPCWSTR, LPWSTR, PULONGLONG};
use winapi::shared::ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_INTERNAL_ERROR, STATUS_NOT_IMPLEMENTED, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS};
use winapi::um::fileapi::{BY_HANDLE_FILE_INFORMATION, LPBY_HANDLE_FILE_INFORMATION};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::WIN32_FIND_DATAW;
use winapi::um::winnt::{ACCESS_MASK, PSECURITY_DESCRIPTOR, PSECURITY_INFORMATION};

pub use dokan_sys::{DOKAN_IO_SECURITY_CONTEXT, PDOKAN_IO_SECURITY_CONTEXT};

/// Name of Dokan's kernel driver file.
pub use dokan_sys::DOKAN_DRIVER_NAME as DRIVER_NAME;
/// The major version number of Dokan that this wrapper is targeting.
pub use dokan_sys::DOKAN_MAJOR_API_VERSION as MAJOR_API_VERSION;
/// Name of Dokan's network provider.
pub use dokan_sys::DOKAN_NP_NAME as NP_NAME;
/// The version of Dokan that this wrapper is targeting.
pub use dokan_sys::DOKAN_VERSION as WRAPPER_VERSION;

/// Gets version of the loaded Dokan library.
///
/// The returned value is the version number without dots. For example, it returns `131` if Dokan
/// v1.3.1 is loaded.
pub fn lib_version() -> u32 { unsafe { DokanVersion() } }

/// Gets version of the Dokan driver installed on the current system.
///
/// The returned value is the version number without dots.
pub fn driver_version() -> u32 { unsafe { DokanDriverVersion() } }

/// Checks whether the `name` matches the specified `expression`.
///
/// This is a helper function that can be used to implement
/// [`FileSystemHandler::find_files_with_pattern`][find_files_with_pattern]. It behaves like the
/// [`FsRtlIsNameInExpression`][FsRtlIsNameInExpression] routine provided for file system drivers by
/// Windows.
///
/// [find_files_with_pattern]: trait.FileSystemHandler.html#method.find_files_with_pattern
/// [FsRtlIsNameInExpression]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisnameinexpression
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

/// The flags returned by
/// [`map_kernel_to_user_create_file_flags`][map_kernel_to_user_create_file_flags].
///
/// These flags are the same as those accepted by [CreateFile][CreateFile].
///
/// [map_kernel_to_user_create_file_flags]: fn.map_kernel_to_user_create_file_flags.html
/// [CreateFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserCreateFileFlags {
	/// The requested access to the file.
	pub desired_access: ACCESS_MASK,
	/// The file attributes and flags.
	pub flags_and_attributes: u32,
	/// The action to take on the file that exists or does not exist.
	pub creation_disposition: u32,
}

/// Converts the arguments passed to [`FileSystemHandler::create_file`][create_file] to flags
/// accepted by the Win32 [CreateFile][CreateFile] function.
///
/// Dokan forwards the parameters directly from  [IRP_MJ_CREATE][IRP_MJ_CREATE]. This functions
/// converts them to corresponding flags in Win32, making it easier to process them.
///
/// [create_file]: trait.FileSystemHandler.html#method.create_file
/// [CreateFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
/// [IRP_MJ_CREATE]: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create
pub fn map_kernel_to_user_create_file_flags(
	desired_access: ACCESS_MASK,
	file_attributes: u32,
	create_options: u32,
	create_disposition: u32,
) -> UserCreateFileFlags {
	let mut result = UserCreateFileFlags {
		desired_access: 0,
		flags_and_attributes: 0,
		creation_disposition: 0,
	};
	unsafe {
		DokanMapKernelToUserCreateFileFlags(
			desired_access,
			file_attributes,
			create_options,
			create_disposition,
			&mut result.desired_access,
			&mut result.flags_and_attributes,
			&mut result.creation_disposition,
		);
	}
	result
}

/// Unmount a Dokan volume from the specified mount point.
///
/// Returns `true` on success.
#[must_use]
pub fn unmount(mount_point: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanRemoveMountPoint(mount_point.as_ref().as_ptr()) == TRUE }
}

/// Mount point information.
#[derive(Debug, Clone)]
pub struct MountPointInfo {
	/// File system type of the mounted volume.
	///
	/// Value can be `FILE_DEVICE_DISK_FILE_SYSTEM` or `FILE_DEVICE_NETWORK_FILE_SYSTEM`, which are
	/// defined in `ntifs.h`.
	pub device_type: u32,

	/// Mount point path.
	pub mount_point: Option<U16CString>,

	/// UNC name of the network volume.
	pub unc_name: Option<U16CString>,

	/// Device name of the mounted volume.
	pub device_name: U16CString,

	/// The session in which the volume is mounted.
	///
	/// It will be `-1` if the volume is mounted globally.
	pub session_id: u32,
}

struct MountPointListWrapper {
	list_ptr: PDOKAN_CONTROL,
}

impl Drop for MountPointListWrapper {
	fn drop(&mut self) {
		if !self.list_ptr.is_null() {
			unsafe { DokanReleaseMountPointList(self.list_ptr); }
		}
	}
}

/// Gets a list of active Dokan mount points.
///
/// Returns `None` in case of error.
pub fn get_mount_point_list(unc_only: bool) -> Option<Vec<MountPointInfo>> {
	unsafe {
		let mut count: ULONG = 0;
		let ffi_list = MountPointListWrapper {
			list_ptr: DokanGetMountPointList(unc_only.into(), &mut count)
		};
		if ffi_list.list_ptr.is_null() { None } else {
			let count = count as usize;
			let mut list = Vec::with_capacity(count);
			for control in slice::from_raw_parts(ffi_list.list_ptr, count) {
				let mount_point = if control.MountPoint[0] == 0 { None } else {
					Some(U16CStr::from_slice_with_nul(&control.MountPoint).unwrap().to_owned())
				};
				let unc_name = if control.UNCName[0] == 0 { None } else {
					Some(U16CStr::from_slice_with_nul(&control.UNCName).unwrap().to_owned())
				};
				list.push(MountPointInfo {
					device_type: control.Type,
					mount_point,
					unc_name,
					device_name: U16CStr::from_slice_with_nul(&control.DeviceName).unwrap().to_owned(),
					session_id: control.SessionId,
				})
			}
			Some(list)
		}
	}
}

/// Notifies Dokan that a file or directory has been created.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_create(path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyCreate(path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

/// Notifies Dokan that a file or directory has been deleted.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_delete(path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyDelete(path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

/// Notifies Dokan that attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_update(path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyUpdate(path.as_ref().as_ptr()) == TRUE }
}


/// Notifies Dokan that extended attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_xattr_update(path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyXAttrUpdate(path.as_ref().as_ptr()) == TRUE }
}

/// Notifies Dokan that a file or directory has been renamed.
///
/// `is_same_dir` indicates if the new file or directory is in the same directory as the old one.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_rename(old_path: impl AsRef<U16CStr>, new_path: impl AsRef<U16CStr>, is_dir: bool, is_same_dir: bool) -> bool {
	unsafe {
		DokanNotifyRename(
			old_path.as_ref().as_ptr(), new_path.as_ref().as_ptr(),
			is_dir.into(), is_same_dir.into(),
		) == TRUE
	}
}

bitflags! {
	/// Flags that control behavior of the mounted volume.
	pub struct MountFlags : u32 {
		/// Enable debug message output.
		const DEBUG = DOKAN_OPTION_DEBUG;

		/// Write debug messages to stderr.
		const STDERR = DOKAN_OPTION_STDERR;

		/// Enable support for alternative streams.
		///
		/// The driver will fail any attempts to access a path with a colon (`:`).
		const ALT_STREAM = DOKAN_OPTION_ALT_STREAM;

		/// Make the mounted volume write-protected (i.e. read-only).
		const WRITE_PROTECT = DOKAN_OPTION_WRITE_PROTECT;

		/// Mount as a network drive.
		///
		/// Dokan network provider must be installed for this to work.
		const NETWORK = DOKAN_OPTION_NETWORK;

		/// Mount as a removable device.
		const REMOVABLE = DOKAN_OPTION_REMOVABLE;

		/// Use Mount Manager to mount the volume.
		const MOUNT_MANAGER = DOKAN_OPTION_MOUNT_MANAGER;

		/// Mount the volume on current session only.
		const CURRENT_SESSION = DOKAN_OPTION_CURRENT_SESSION;

		/// Use [`FileSystemHandler::lock_file`][lock_file] and
		/// [`FileSystemHandler::unlock_file`][unlock_file] to handle file locking.
		///
		/// Dokan will take care of file locking if this flags is not present.
		///
		/// [lock_file]: trait.FileSystemHandler.html#method.lock_file
		/// [unlock_file]: trait.FileSystemHandler.html#method.unlock_file
		const FILELOCK_USER_MODE = DOKAN_OPTION_FILELOCK_USER_MODE;

		/// Enable notification API support.
		///
		/// Notification functions like [`notify_create`][notify_create] require this flag to be
		/// present, otherwise they will always fail and return `false`.
		///
		/// [notify_create]: fn.notify_create.html
		const ENABLE_NOTIFICATION_API = DOKAN_OPTION_ENABLE_NOTIFICATION_API;

		/// Disable support for opportunistic locks (i.e. oplocks).
		///
		/// Regular range locks are always supported regardless of this flag.
		const DISABLE_OPLOCKS = DOKAN_OPTION_DISABLE_OPLOCKS;

		/// Satisfy single-entry, name-only directory searches directly without dispatching to
		/// [`FileSystemHandler`][FileSystemHandler] callbacks.
		///
		/// Such kind of searches are frequently requested by [`CreateFile`][CreateFile] on Windows
		/// 7. If the target file is already opened, the driver can just simply the name without
		/// external information.
		///
		/// [FileSystemHandler]: trait.FileSystemHandler.html
		/// [CreateFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
		const OPTIMIZE_SINGLE_NAME_SEARCH = DOKAN_OPTION_OPTIMIZE_SINGLE_NAME_SEARCH;
	}
}

/// A simple wrapper struct that holds a Win32 handle.
///
/// It calls [`CloseHandle`][CloseHandle] automatically when dropped.
///
/// [CloseHandle]: https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
#[derive(Debug, Eq, PartialEq)]
pub struct Handle {
	value: HANDLE,
}

impl Handle {
	/// Gets the handle value.
	pub fn value(&self) -> HANDLE { self.value }
}

impl Drop for Handle {
	fn drop(&mut self) {
		if self.value != INVALID_HANDLE_VALUE {
			unsafe { CloseHandle(self.value); }
		}
	}
}

/// Information about the current operation.
#[derive(Debug)]
pub struct OperationInfo<'a, T: FileSystemHandler> {
	file_info: PDOKAN_FILE_INFO,
	phantom: PhantomData<&'a T>,
}

impl<'a, T: FileSystemHandler> OperationInfo<'a, T> {
	fn new(file_info: PDOKAN_FILE_INFO) -> OperationInfo<'a, T> {
		OperationInfo {
			file_info,
			phantom: PhantomData,
		}
	}

	fn file_info(&self) -> &DOKAN_FILE_INFO {
		unsafe { &*self.file_info }
	}

	fn mount_options(&self) -> &DOKAN_OPTIONS {
		unsafe { &*self.file_info().DokanOptions }
	}

	fn handler(&self) -> &'a T {
		unsafe { &*(self.mount_options().GlobalContext as *const T) }
	}

	fn context(&self) -> &T::Context {
		unsafe { &*(self.file_info().Context as *const T::Context) }
	}

	fn drop_context(&mut self) {
		unsafe {
			let info = &mut *self.file_info;
			let ptr = info.Context as *mut T::Context;
			if !ptr.is_null() {
				mem::drop(Box::from_raw(ptr));
				info.Context = 0;
			}
		}
	}

	/// Gets process ID of the calling process.
	pub fn pid(&self) -> u32 { self.file_info().ProcessId }

	/// Gets whether the target file is a directory.
	pub fn is_dir(&self) -> bool { self.file_info().IsDirectory != 0 }

	/// Gets whether the file should be deleted when it is closed.
	pub fn delete_on_close(&self) -> bool { self.file_info().DeleteOnClose != 0 }

	/// Gets whether it is a paging I/O operation.
	pub fn paging_io(&self) -> bool { self.file_info().PagingIo != 0 }

	/// Gets whether it is a synchronous I/O operation.
	pub fn synchronous_io(&self) -> bool { self.file_info().SynchronousIo != 0 }

	/// Gets whether it is a non-cached I/O operation.
	pub fn no_cache(&self) -> bool { self.file_info().Nocache != 0 }

	/// Gets whether the current write operation should write to end of file instead of the
	/// position specified by the offset argument.
	pub fn write_to_eof(&self) -> bool { self.file_info().WriteToEndOfFile != 0 }

	/// Gets the number of threads used to handle file system operations.
	pub fn thread_count(&self) -> u16 { self.mount_options().ThreadCount }

	/// Gets flags that controls behavior of the mounted volume.
	pub fn mount_flags(&self) -> MountFlags { MountFlags::from_bits_truncate(self.mount_options().Options) }

	/// Gets mount point path.
	pub fn mount_point(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().MountPoint;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	/// Gets UNC name of the network drive.
	pub fn unc_name(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().UNCName;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	/// Gets the time that Dokan will wait for an operation to complete.
	///
	/// See [`Drive::timeout`][timeout] for more information.
	///
	/// [timeout]: struct.Drive.html#method.timeout
	pub fn timeout(&self) -> Duration { Duration::from_millis(self.mount_options().Timeout.into()) }

	/// Gets allocation unit size of the volume.
	pub fn allocation_unit_size(&self) -> u32 { self.mount_options().AllocationUnitSize }

	/// Gets sector size of the volume.
	pub fn sector_size(&self) -> u32 { self.mount_options().SectorSize }

	/// Temporarily extend the timeout of the current operation.
	///
	/// Returns `true` on success.
	#[must_use]
	pub fn reset_timeout(&self, timeout: Duration) -> bool {
		unsafe { DokanResetTimeout(timeout.as_millis() as u32, self.file_info) == TRUE }
	}

	/// Gets the access token associated with the calling process.
	///
	/// Returns `None` on error.
	pub fn requester_token(&self) -> Option<Handle> {
		let value = unsafe { DokanOpenRequestorToken(self.file_info) };
		if value == INVALID_HANDLE_VALUE {
			None
		} else {
			Some(Handle { value })
		}
	}
}

/// The error type for callbacks of [`FileSystemHandler`][FileSystemHandler].
///
/// This enum represents either an NTSTATUS code or a Win32 error code. Dokan only accepts NTSTATUS
/// codes, so if a Win32 error code is present, it will be automatically converted to the
/// corresponding NTSTATUS value.
///
/// Note that although `STATUS_SUCCESS` and `ERROR_SUCCESS` are used to indicate successes in the
/// Windows world, they are not expected to appear in this enum and will be converted to
/// `STATUS_INTERNAL_ERROR` if detected. This error type is always used along with `Result`s in this
/// crate and `Ok` should be returned to indicate successes instead.
///
/// [FileSystemHandler]: trait.FileSystemHandler.html
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum OperationError {
	NtStatus(NTSTATUS),
	Win32(DWORD),
}

impl Error for OperationError {}

impl Display for OperationError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "Dokan operation failed: ")?;
		match self {
			OperationError::NtStatus(e) => write!(f, "NTSTATUS 0x{:08x}", e),
			OperationError::Win32(e) => write!(f, "Win32 error {} (converted to NTSTATUS 0x{:08x})", e, self.ntstatus()),
		}
	}
}

impl OperationError {
	pub fn ntstatus(&self) -> NTSTATUS {
		let status = match self {
			OperationError::NtStatus(e) => *e,
			OperationError::Win32(e) => unsafe { DokanNtStatusFromWin32(*e) },
		};
		match status {
			STATUS_SUCCESS => STATUS_INTERNAL_ERROR,
			_ => status,
		}
	}
}

trait OperationResultExt {
	fn ntstatus(&self) -> NTSTATUS;
}

impl<T> OperationResultExt for Result<T, OperationError> {
	fn ntstatus(&self) -> NTSTATUS {
		match self {
			Ok(_) => STATUS_SUCCESS,
			Err(e) => e.ntstatus(),
		}
	}
}

const FILETIME_OFFSET: Duration = Duration::from_secs(11644473600);

trait FileTimeExt {
	fn from_filetime(time: FILETIME) -> SystemTime;
	fn to_filetime(&self) -> FILETIME;
}

impl FileTimeExt for SystemTime {
	fn from_filetime(time: FILETIME) -> SystemTime {
		let nanos = (time.dwLowDateTime as u64 + ((time.dwHighDateTime as u64) << 32)) * 100;
		UNIX_EPOCH - FILETIME_OFFSET + Duration::from_nanos(nanos)
	}
	fn to_filetime(&self) -> FILETIME {
		let intervals = self.duration_since(UNIX_EPOCH - FILETIME_OFFSET)
			.unwrap_or(Duration::from_secs(0)).as_nanos() / 100;
		FILETIME {
			dwLowDateTime: intervals as u32,
			dwHighDateTime: (intervals >> 32) as u32,
		}
	}
}

/// The file information returned by
/// [`FileSystemHandler::get_file_information`][get_file_information].
///
/// [get_file_information]: trait.FileSystemHandler.html#method.get_file_information
#[derive(Debug, Clone)]
pub struct FileInfo {
	/// Attribute flags of the files.
	///
	/// It can be combination of one or more [file attribute constants][constants] defined by
	/// Windows.
	///
	/// [constants]: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
	pub attributes: u32,

	/// The time when the file was created.
	pub creation_time: SystemTime,

	/// The time when the file was last accessed.
	pub last_access_time: SystemTime,

	/// The time when the file was last written to.
	pub last_write_time: SystemTime,

	/// Size of the file.
	pub file_size: u64,

	/// Number of hardlinks to the file.
	pub number_of_links: u32,

	/// The index that uniquely identifies the file in a volume.
	pub file_index: u64,
}

impl FileInfo {
	fn to_raw_struct(&self) -> BY_HANDLE_FILE_INFORMATION {
		BY_HANDLE_FILE_INFORMATION {
			dwFileAttributes: self.attributes,
			ftCreationTime: self.creation_time.to_filetime(),
			ftLastAccessTime: self.last_access_time.to_filetime(),
			ftLastWriteTime: self.last_write_time.to_filetime(),
			dwVolumeSerialNumber: 0,
			nFileSizeHigh: (self.file_size >> 32) as u32,
			nFileSizeLow: self.file_size as u32,
			nNumberOfLinks: self.number_of_links,
			nFileIndexHigh: (self.file_index >> 32) as u32,
			nFileIndexLow: self.file_index as u32,
		}
	}
}

trait ToRawStruct<T> {
	fn to_raw_struct(&self) -> Option<T>;
}

/// File information provided by [`FileSystemHandler::find_files`][find_files] or
/// [`FileSystemHandler::find_files_with_pattern`][find_files_with_pattern].
///
/// [find_files]: trait.FileSystemHandler.html#method.find_files
/// [find_files_with_pattern]: trait.FileSystemHandler.html#method.find_files_with_pattern
#[derive(Debug, Clone)]
pub struct FindData {
	/// Attribute flags of the files.
	///
	/// It can be combination of one or more [file attribute constants][constants] defined by
	/// Windows.
	///
	/// [constants]: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
	pub attributes: u32,

	/// The time when the file was created.
	pub creation_time: SystemTime,

	/// The time when the file was last accessed.
	pub last_access_time: SystemTime,

	/// The time when the file was last written to.
	pub last_write_time: SystemTime,

	/// Size of the file.
	pub file_size: u64,

	/// Name of the file.
	pub file_name: U16CString,
}

impl ToRawStruct<WIN32_FIND_DATAW> for FindData {
	fn to_raw_struct(&self) -> Option<WIN32_FIND_DATAW> {
		let mut data = WIN32_FIND_DATAW {
			dwFileAttributes: self.attributes,
			ftCreationTime: self.creation_time.to_filetime(),
			ftLastAccessTime: self.last_access_time.to_filetime(),
			ftLastWriteTime: self.last_write_time.to_filetime(),
			nFileSizeHigh: (self.file_size >> 32) as u32,
			nFileSizeLow: self.file_size as u32,
			dwReserved0: 0,
			dwReserved1: 0,
			cFileName: [0; MAX_PATH],
			cAlternateFileName: [0; 14],
		};
		let name_slice = self.file_name.as_slice_with_nul();
		if name_slice.len() <= data.cFileName.len() {
			data.cFileName[..name_slice.len()].copy_from_slice(name_slice);
			Some(data)
		} else {
			None
		}
	}
}

/// Alternative stream information provided by [`FileSystemHandler::find_streams`][find_streams].
///
/// [find_streams]: trait.FileSystemHandler.html#method.find_streams
#[derive(Debug, Clone)]
pub struct FindStreamData {
	/// Size of the stream.
	pub size: i64,

	/// Name of stream.
	///
	/// The format of this name should be `:streamname:$streamtype`. See [NTFS Streams][streams] for
	/// more information.
	///
	/// [streams]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3
	pub name: U16CString,
}

impl ToRawStruct<WIN32_FIND_STREAM_DATA> for FindStreamData {
	fn to_raw_struct(&self) -> Option<WIN32_FIND_STREAM_DATA> {
		let mut data = WIN32_FIND_STREAM_DATA {
			StreamSize: unsafe { mem::transmute(self.size) },
			cStreamName: [0; MAX_PATH + 36],
		};
		let name_slice = self.name.as_slice_with_nul();
		if name_slice.len() <= data.cStreamName.len() {
			data.cStreamName[..name_slice.len()].copy_from_slice(name_slice);
			Some(data)
		} else {
			None
		}
	}
}

/// The error type for the fill-data callbacks.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FillDataError {
	/// File name exceeds the limit of `MAX_PATH`.
	NameTooLong,

	/// Buffer is full.
	BufferFull,
}

impl Error for FillDataError {}

impl Display for FillDataError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			FillDataError::NameTooLong => "File name exceeds the limit of MAX_PATH.",
			FillDataError::BufferFull => "Buffer is full.",
		};
		write!(f, "{}", msg)
	}
}

impl From<FillDataError> for OperationError {
	fn from(_: FillDataError) -> OperationError {
		OperationError::NtStatus(STATUS_INTERNAL_ERROR)
	}
}

/// Disk space information returned by
/// [`FileSystemHandler::get_disk_free_space`][get_disk_free_space].
///
/// [get_disk_free_space]: trait.FileSystemHandler.html#method.get_disk_free_space
#[derive(Debug, Clone)]
pub struct DiskSpaceInfo {
	/// Total number of bytes that are available to the calling user.
	pub byte_count: u64,

	/// Total number of free bytes on the disk.
	pub free_byte_count: u64,

	/// Total number of free bytes that are available to the calling user.
	pub available_byte_count: u64,
}

/// Volume information returned by
/// [`FileSystemHandler::get_volume_information`][get_volume_information].
///
/// [get_volume_information]: trait.FileSystemHandler.html#method.get_volume_information
#[derive(Debug, Clone)]
pub struct VolumeInfo {
	/// Name of the volume.
	pub name: U16CString,

	/// Serial number of the volume.
	pub serial_number: u32,

	/// The maximum length of a path component that is supported.
	pub max_component_length: u32,

	/// The flags associated with the file system.
	///
	/// It can be combination of one or more [flags defined by Windows][flags].
	///
	/// `FILE_READ_ONLY_VOLUME` is automatically added if
	/// [`MountFlags::WRITE_PROTECT`][WRITE_PROTECT] was specified when mounting the volume.
	///
	/// [flags]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw#parameters
	/// [WRITE_PROTECT]: struct.MountFlags.html#associatedconstant.WRITE_PROTECT
	pub fs_flags: u32,

	/// Name of the file system.
	///
	/// Windows checks feature availability based on file system name, so it is recommended to set
	/// it to well-known names like NTFS or FAT.
	///
	/// [flags]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa
	pub fs_name: U16CString,
}

/// Information about the opened file returned by [`FileSystemHandler::create_file`][create_file].
///
/// [create_file]: trait.FileSystemHandler.html#method.create_file
pub struct CreateFileInfo<T: Sync> {
	/// The context to be associated with the new file object.
	pub context: T,

	/// Indicates whether the file is a directory.
	pub is_dir: bool,

	/// Indicates whether a new file
	pub new_file_created: bool,
}

/// Types that implements this trait can handle file system operations for a mounted volume.
///
/// Dokan invokes the callback functions in this trait to handle file system operations. These
/// functions has similar semantics to that of corresponding Windows API functions.
///
/// Implementation of most callback functions can be omitted by returning `STATUS_NOT_IMPLEMENTED`
/// if the corresponding feature is not supported. To make things flexible, all of the functions are
/// provided with a default implementation which is a no-op and returns `STATUS_NOT_IMPLEMENTED`
/// (except [`cleanup`][cleanup] and [`close_file`][close_file] which don't have return values).
/// However, omitting the implementation of some important callbacks such as
/// [`create_file`][create_file] will make the file system unusable.
///
/// [cleanup]: trait.FileSystemHandler.html#method.cleanup
/// [close_file]: trait.FileSystemHandler.html#method.close_file
/// [create_file]: trait.FileSystemHandler.html#method.create_file
pub trait FileSystemHandler: Sync + Sized {
	/// Type of the context associated with an open file object.
	type Context: Sync;

	/// Called when a file object is created.
	///
	/// The flags passed to this function has similar meaning to that of
	/// [ZwCreateFile][ZwCreateFile]. You can convert them to flags accepted by
	/// [CreateFile][CreateFile] using the
	/// [`map_kernel_to_user_create_file_flags`][map_kernel_to_user_create_file_flags] helper
	/// function.
	///
	/// [ZwCreateFile]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile
	/// [CreateFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
	/// [map_kernel_to_user_create_file_flags]: fn.map_kernel_to_user_create_file_flags.html
	fn create_file(
		&self,
		_file_name: &U16CStr,
		_security_context: PDOKAN_IO_SECURITY_CONTEXT,
		_desired_access: ACCESS_MASK,
		_file_attributes: u32,
		_share_access: u32,
		_create_disposition: u32,
		_create_options: u32,
		_info: &mut OperationInfo<Self>,
	) -> Result<CreateFileInfo<Self::Context>, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Called when the last handle for the file object has been closed.
	///
	/// If [`info.delete_on_close`][delete_on_close] returns `true`, the file should be deleted in
	/// this function.
	///
	/// Note that the file object hasn't been released and there might be more I/O operations before
	/// [`close_file`][close_file] gets called. (This typically happens when the file is
	/// memory-mapped.)
	///
	/// Normally [`close_file`][close_file] will be called shortly after this function. However, the
	/// file object may also be reused, and in that case [`create_file`][create_file] will be called
	/// instead.
	///
	/// [delete_on_close]: struct.OperationInfo.html#method.delete_on_close
	/// [close_file]: trait.FileSystemHandler.html#method.close_file
	/// [create_file]: trait.FileSystemHandler.html#method.create_file
	fn cleanup(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) {}

	/// Called when the last handle for the handle object has been closed and released.
	///
	/// This is the last function called during the lifetime of the file object. You can safely
	/// release any resources allocated for it (such as file handles, buffers, etc.). The associated
	/// [context][context] object will also be dropped once this function returns. In case the file
	/// object is reused and thus this function isn't called, the [context][context] will be dropped
	/// before [create_file][create_file] gets called.
	///
	/// [context]: trait.FileSystemHandler.html#associatedtype.Context
	/// [create_file]: trait.FileSystemHandler.html#method.create_file
	fn close_file(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) {}

	/// Reads data from the file.
	///
	/// The number of bytes that actually gets read should be returned.
	///
	/// See [ReadFile][ReadFile] for more information.
	///
	/// [ReadFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
	fn read_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_buffer: &mut [u8],
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<u32, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Writes data to the file.
	///
	/// The number of bytes that actually gets written should be returned.
	///
	/// If [`info.write_to_eof`][write_to_eof] returns `true`, data should be written to the end of
	/// file and the `offset` parameter should be ignored.
	///
	/// See [WriteFile][WriteFile] for more information.
	///
	/// [write_to_eof]: struct.OperationInfo.html#method.write_to_eof
	/// [WriteFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
	fn write_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_buffer: &[u8],
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<u32, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Flushes the buffer of the file and causes all buffered data to be written to the file.
	///
	/// See [FlushFileBuffers][FlushFileBuffers] for more information.
	///
	/// [FlushFileBuffers]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
	fn flush_file_buffers(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Gets information about the file.
	///
	/// See [GetFileInformationByHandle][GetFileInformationByHandle]
	///
	/// [GetFileInformationByHandle]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
	fn get_file_information(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<FileInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Lists all child items in the directory.
	///
	/// `fill_find_data` should be called for every child item in the directory.
	///
	/// It will only be called if [`find_files_with_pattern`][find_files_with_pattern] returns
	/// `STATUS_NOT_IMPLEMENTED`.
	///
	/// See [FindFirstFile][FindFirstFile] for more information.
	///
	/// [find_files_with_pattern]: trait.FileSystemHandler.html#method.find_files_with_pattern
	/// [FindFirstFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
	fn find_files(
		&self,
		_file_name: &U16CStr,
		_fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Lists all child items that matches the specified `pattern` in the directory.
	///
	/// `fill_find_data` should be called for every matching child item in the directory.
	///
	/// [`is_name_in_expression`][is_name_in_expression] can be used to determine if a file name
	/// matches the pattern.
	///
	/// If this function returns `STATUS_NOT_IMPLEMENTED`, [`find_files`][find_files] will be called
	/// instead and pattern matching will be handled directly by Dokan.
	///
	/// See [FindFirstFile][FindFirstFile] for more information.
	///
	/// [is_name_in_expression]: fn.is_name_in_expression.html
	/// [find_files]: trait.FileSystemHandler.html#method.find_files
	/// [FindFirstFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
	fn find_files_with_pattern(
		&self,
		_file_name: &U16CStr,
		_pattern: &U16CStr,
		_fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Sets attributes of the file.
	///
	/// `file_attributes` can be combination of one or more [file attribute constants][constants]
	/// defined by Windows.
	///
	/// See [SetFileAttributes][SetFileAttributes] for more information.
	///
	/// [constants]: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
	/// [SetFileAttributes]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileattributesw
	fn set_file_attributes(
		&self,
		_file_name: &U16CStr,
		_file_attributes: u32,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Sets the time when the file was created, last accessed and last written.
	///
	/// See [SetFileTime][SetFileTime] for more information.
	///
	/// [SetFileTime]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
	fn set_file_time(
		&self,
		_file_name: &U16CStr,
		_creation_time: SystemTime,
		_last_access_time: SystemTime,
		_last_write_time: SystemTime,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Checks if the file can be deleted.
	///
	/// The file should not be deleted in this function. Instead, it should only check if the file
	/// can be deleted and return `Ok` if that is possible.
	///
	/// It will also be called with [`info.delete_on_close`][delete_on_close] returning true to
	/// notify that the file is no longer requested to be deleted.
	///
	/// [delete_on_close]: struct.OperationInfo.html#method.delete_on_close
	fn delete_file(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Checks if the directory can be deleted.
	///
	/// Similar to [`delete_file`][delete_file], it should only check if the directory can be
	/// deleted and delay the actual deletion to the [`cleanup`][cleanup] function.
	///
	/// It will also be called with [`info.delete_on_close`][delete_on_close] returning true to
	/// notify that the directory is no longer requested to be deleted.
	///
	/// [delete_file]: trait.FileSystemHandler.html#method.delete_file
	/// [cleanup]: trait.FileSystemHandler.html#method.cleanup
	/// [delete_on_close]: struct.OperationInfo.html#method.delete_on_close
	fn delete_directory(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Moves the file.
	///
	/// If the `new_file_name` already exists, the function should only replace the existing file
	/// when `replace_if_existing` is `true`, otherwise it should return appropriate error.
	///
	/// Note that renaming is a special kind of moving and is also handled by this function.
	///
	/// See [MoveFileEx][MoveFileEx] for more information.
	///
	/// [MoveFileEx]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
	fn move_file(
		&self,
		_file_name: &U16CStr,
		_new_file_name: &U16CStr,
		_replace_if_existing: bool,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Sets end-of-file position of the file.
	///
	/// The `offset` value is zero-based, so it actually refers to the offset to the byte
	/// immediately following the last valid byte in the file.
	///
	/// See [FILE_END_OF_FILE_INFORMATION][FILE_END_OF_FILE_INFORMATION] for more information.
	///
	/// [FILE_END_OF_FILE_INFORMATION]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_end_of_file_information
	fn set_end_of_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Sets allocation size of the file.
	///
	/// The allocation size is the number of bytes allocated in the underlying physical device for
	/// the file.
	///
	/// See [FILE_ALLOCATION_INFORMATION][FILE_ALLOCATION_INFORMATION] for more information.
	///
	/// [FILE_ALLOCATION_INFORMATION]: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_allocation_information
	fn set_allocation_size(
		&self,
		_file_name: &U16CStr,
		_alloc_size: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Locks the file for exclusive access.
	///
	/// It will only be called if [`MountFlags::FILELOCK_USER_MODE`][FILELOCK_USER_MODE] was
	/// specified when mounting the volume, otherwise Dokan will take care of file locking.
	///
	/// See [LockFile][LockFile] for more information.
	///
	/// [FILELOCK_USER_MODE]: struct.MountFlags.html#associatedconstant.FILELOCK_USER_MODE
	/// [LockFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfile
	fn lock_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_length: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Unlocks the previously locked file.
	///
	/// It will only be called if [`MountFlags::FILELOCK_USER_MODE`][FILELOCK_USER_MODE] was
	/// specified when mounting the volume, otherwise Dokan will take care of file locking.
	///
	/// See [UnlockFile][UnlockFile] for more information.
	///
	/// [FILELOCK_USER_MODE]: struct.MountFlags.html#associatedconstant.FILELOCK_USER_MODE
	/// [UnlockFile]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-unlockfile
	fn unlock_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_length: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Gets free space information about the disk.
	///
	/// See [GetDiskFreeSpaceEx][GetDiskFreeSpaceEx] for more information.
	///
	/// [GetDiskFreeSpaceEx]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespaceexw
	fn get_disk_free_space(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<DiskSpaceInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Gets information about the volume and file system.
	///
	/// See [GetVolumeInformation][GetVolumeInformation] for more information.
	///
	/// [GetVolumeInformation]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
	fn get_volume_information(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<VolumeInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Called when Dokan has successfully mounted the volume.
	fn mounted(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Called when Dokan is unmounting the volume.
	fn unmounted(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Gets security information of a file.
	///
	/// Size of the security descriptor in bytes should be returned on success. If the buffer is not
	/// large enough, the number should still be returned, and `STATUS_BUFFER_OVERFLOW` will be
	/// automatically passed to Dokan if it is larger than `buffer_length`.
	///
	/// See [GetFileSecurity][GetFileSecurity] for more information.
	///
	/// [GetFileSecurity]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfilesecuritya
	fn get_file_security(
		&self,
		_file_name: &U16CStr,
		_security_information: u32,
		_security_descriptor: PSECURITY_DESCRIPTOR,
		_buffer_length: u32,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<u32, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Sets security information of a file.
	///
	/// See [SetFileSecurity][SetFileSecurity] for more information.
	///
	/// [SetFileSecurity]: https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilesecuritya
	fn set_file_security(
		&self,
		_file_name: &U16CStr,
		_security_information: u32,
		_security_descriptor: PSECURITY_DESCRIPTOR,
		_buffer_length: u32,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	/// Lists all alternative streams of the file.
	///
	/// `fill_find_stream_data` should be called for every stream of the file, including the default
	/// data stream `::$DATA`.
	///
	/// See [FindFirstStream][FindFirstStream] for more information.
	///
	/// [FindFirstStream]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw
	fn find_streams(
		&self,
		_file_name: &U16CStr,
		_fill_find_stream_data: impl FnMut(&FindStreamData) -> Result<(), FillDataError>,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}
}

fn fill_data_wrapper<T, U: ToRawStruct<T>>(
	fill_data: unsafe extern "stdcall" fn(*mut T, PDOKAN_FILE_INFO) -> c_int,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> impl FnMut(&U) -> Result<(), FillDataError> {
	move |data| {
		let mut ffi_data = data.to_raw_struct().ok_or(FillDataError::NameTooLong)?;
		if unsafe { fill_data(&mut ffi_data, dokan_file_info) == 0 } {
			Ok(())
		} else {
			Err(FillDataError::BufferFull)
		}
	}
}

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE_IF: u32 = 5;

extern "stdcall" fn create_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	security_context: PDOKAN_IO_SECURITY_CONTEXT,
	desired_access: ACCESS_MASK,
	file_attributes: ULONG,
	share_access: ULONG,
	create_disposition: ULONG,
	create_options: ULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut info = OperationInfo::<T> { file_info: dokan_file_info, phantom: PhantomData };
		info.drop_context();
		info.handler().create_file(
			file_name,
			security_context,
			desired_access,
			file_attributes,
			share_access,
			create_disposition,
			create_options,
			&mut info,
		).and_then(|create_info| {
			(&mut *dokan_file_info).Context = Box::into_raw(Box::new(create_info.context)) as u64;
			(&mut *dokan_file_info).IsDirectory = create_info.is_dir.into();
			if (create_disposition == FILE_OPEN_IF ||
				create_disposition == FILE_OVERWRITE_IF ||
				create_disposition == FILE_SUPERSEDE) &&
				!create_info.new_file_created {
				Err(OperationError::NtStatus(STATUS_OBJECT_NAME_COLLISION))
			} else {
				Ok(())
			}
		}).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

#[allow(unused_must_use)]
extern "stdcall" fn cleanup<T: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().cleanup(file_name, &info, info.context());
	});
}

#[allow(unused_must_use)]
extern "stdcall" fn close_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().close_file(file_name, &info, info.context());
		info.drop_context();
	});
}

extern "stdcall" fn read_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPVOID,
	buffer_length: DWORD,
	read_length: LPDWORD,
	offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		*read_length = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		let buffer = slice::from_raw_parts_mut(buffer as *mut u8, buffer_length as usize);
		let result = info.handler()
			.read_file(file_name, offset, buffer, &info, info.context());
		if let Ok(bytes_read) = result {
			*read_length = bytes_read;
		}
		result.ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn write_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPCVOID,
	number_of_bytes_to_write: DWORD,
	number_of_bytes_written: LPDWORD,
	offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		*number_of_bytes_written = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		let buffer = slice::from_raw_parts(buffer as *mut u8, number_of_bytes_to_write as usize);
		let result = info.handler()
			.write_file(file_name, offset, buffer, &info, info.context());
		if let Ok(bytes_written) = result {
			*number_of_bytes_written = bytes_written;
		}
		result.ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn flush_file_buffers<T: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().flush_file_buffers(file_name, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn get_file_information<T: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPBY_HANDLE_FILE_INFORMATION,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler()
			.get_file_information(file_name, &info, info.context())
			.and_then(|file_info| {
				*buffer = file_info.to_raw_struct();
				Ok(())
			}).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn find_files<T: FileSystemHandler>(
	file_name: LPCWSTR,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let fill_wrapper = fill_data_wrapper::<_, FindData>(fill_find_data, dokan_file_info);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().find_files(file_name, fill_wrapper, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn find_files_with_pattern<T: FileSystemHandler>(
	file_name: LPCWSTR,
	search_pattern: LPCWSTR,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let search_pattern = U16CStr::from_ptr_str(search_pattern);
		let fill_wrapper = fill_data_wrapper(fill_find_data, dokan_file_info);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().find_files_with_pattern(file_name, search_pattern, fill_wrapper, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn set_file_attributes<T: FileSystemHandler>(
	file_name: LPCWSTR,
	file_attributes: DWORD,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().set_file_attributes(file_name, file_attributes, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn set_file_time<T: FileSystemHandler>(
	file_name: LPCWSTR,
	creation_time: *const FILETIME,
	last_access_time: *const FILETIME,
	last_write_time: *const FILETIME,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		let creation_time = SystemTime::from_filetime(*creation_time);
		let last_access_time = SystemTime::from_filetime(*last_access_time);
		let last_write_time = SystemTime::from_filetime(*last_write_time);
		info.handler().set_file_time(file_name, creation_time, last_access_time, last_write_time, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn delete_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().delete_file(file_name, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn delete_directory<T: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().delete_directory(file_name, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn move_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	new_file_name: LPCWSTR,
	replace_if_existing: BOOL,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let new_file_name = U16CStr::from_ptr_str(new_file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().move_file(file_name, new_file_name, replace_if_existing == TRUE, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn set_end_of_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().set_end_of_file(file_name, byte_offset, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn set_allocation_size<T: FileSystemHandler>(
	file_name: LPCWSTR,
	alloc_size: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().set_allocation_size(file_name, alloc_size, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn lock_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	length: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().lock_file(file_name, byte_offset, length, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}


extern "stdcall" fn unlock_file<T: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	length: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().unlock_file(file_name, byte_offset, length, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn get_disk_free_space<T: FileSystemHandler>(
	free_bytes_available: PULONGLONG,
	total_number_of_bytes: PULONGLONG,
	total_number_of_free_bytes: PULONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| {
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().get_disk_free_space(&info).and_then(|space_info| unsafe {
			if !free_bytes_available.is_null() {
				*free_bytes_available = space_info.available_byte_count;
			}
			if !total_number_of_bytes.is_null() {
				*total_number_of_bytes = space_info.byte_count;
			}
			if !total_number_of_free_bytes.is_null() {
				*total_number_of_free_bytes = space_info.free_byte_count;
			}
			Ok(())
		}).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn get_volume_information<T: FileSystemHandler>(
	volume_name_buffer: LPWSTR,
	volume_name_size: DWORD,
	volume_serial_number: LPDWORD,
	maximum_component_length: LPDWORD,
	file_system_flags: LPDWORD,
	file_system_name_buffer: LPWSTR,
	file_system_name_size: DWORD,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| {
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().get_volume_information(&info).and_then(|volume_info| unsafe {
			volume_name_buffer.copy_from_nonoverlapping(
				volume_info.name.as_ptr(),
				(volume_info.name.len() + 1).min(volume_name_size as usize),
			);
			if !volume_serial_number.is_null() {
				*volume_serial_number = volume_info.serial_number;
			}
			if !maximum_component_length.is_null() {
				*maximum_component_length = volume_info.max_component_length;
			}
			if !file_system_flags.is_null() {
				*file_system_flags = volume_info.fs_flags;
			}
			file_system_name_buffer.copy_from_nonoverlapping(
				volume_info.fs_name.as_ptr(),
				(volume_info.fs_name.len() + 1).min(file_system_name_size as usize),
			);
			Ok(())
		}).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn mounted<T: FileSystemHandler>(dokan_file_info: PDOKAN_FILE_INFO) -> NTSTATUS {
	panic::catch_unwind(|| {
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().mounted(&info).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn unmounted<T: FileSystemHandler>(dokan_file_info: PDOKAN_FILE_INFO) -> NTSTATUS {
	panic::catch_unwind(|| {
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().unmounted(&info).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn get_file_security<T: FileSystemHandler>(
	file_name: LPCWSTR,
	security_information: PSECURITY_INFORMATION,
	security_descriptor: PSECURITY_DESCRIPTOR,
	buffer_length: ULONG,
	length_needed: PULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		let result = info.handler().get_file_security(
			file_name,
			*security_information,
			security_descriptor,
			buffer_length,
			&info,
			info.context(),
		);
		if let Ok(needed) = result {
			*length_needed = needed;
			if needed <= buffer_length {
				STATUS_SUCCESS
			} else {
				STATUS_BUFFER_OVERFLOW
			}
		} else {
			result.ntstatus()
		}
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn set_file_security<T: FileSystemHandler>(
	file_name: LPCWSTR,
	security_information: PSECURITY_INFORMATION,
	security_descriptor: PSECURITY_DESCRIPTOR,
	buffer_length: ULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().set_file_security(
			file_name,
			*security_information,
			security_descriptor,
			buffer_length,
			&info,
			info.context(),
		).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

extern "stdcall" fn find_streams<T: FileSystemHandler>(
	file_name: LPCWSTR,
	fill_find_stream_data: PFillFindStreamData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	panic::catch_unwind(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let fill_wrapper = fill_data_wrapper(fill_find_stream_data, dokan_file_info);
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().find_streams(file_name, fill_wrapper, &info, info.context()).ntstatus()
	}).unwrap_or(STATUS_INTERNAL_ERROR)
}

/// The error type for [`Drive::mount`][mount].
///
/// [mount]: struct.Drive.html#method.mount
#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MountError {
	/// A general error.
	Error = DOKAN_ERROR,

	/// Bad drive letter.
	DriveLetterError = DOKAN_DRIVE_LETTER_ERROR,

	/// Can't install the Dokan driver.
	DriverInstallError = DOKAN_DRIVER_INSTALL_ERROR,

	/// The driver responds that something is wrong.
	StartError = DOKAN_START_ERROR,

	/// Can't assign a drive letter or mount point.
	///
	/// This probably means that the mount point is already used by another volume.
	MountError = DOKAN_MOUNT_ERROR,

	/// The mount point is invalid.
	MountPointError = DOKAN_MOUNT_POINT_ERROR,

	/// The Dokan version that this wrapper is targeting is incompatible with the loaded Dokan
	/// library.
	VersionError = DOKAN_VERSION_ERROR,
}

impl Error for MountError {}

impl Display for MountError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			MountError::Error => "Dokan mount error.",
			MountError::DriveLetterError => "Bad drive letter.",
			MountError::DriverInstallError => "Can't install driver.",
			MountError::StartError => "The driver responds that something is wrong.",
			MountError::MountError => "Can't assign a drive letter or mount point. Probably already used by another volume.",
			MountError::MountPointError => "The mount point is invalid.",
			MountError::VersionError => "Requested an incompatible version.",
		};
		write!(f, "{}", msg)
	}
}

/// A builder that allows configuring and mounting a volume.
#[derive(Debug)]
pub struct Drive<'a> {
	options: DOKAN_OPTIONS,
	phantom: PhantomData<&'a U16CStr>,
}

impl<'a> Drive<'a> {
	/// Creates a new instance of this builder with default settings.
	pub fn new() -> Self {
		Drive {
			options: DOKAN_OPTIONS {
				Version: WRAPPER_VERSION as u16,
				ThreadCount: 0,
				Options: 0,
				GlobalContext: 0,
				MountPoint: ptr::null(),
				UNCName: ptr::null(),
				Timeout: 0,
				AllocationUnitSize: 0,
				SectorSize: 0,
			},
			phantom: PhantomData,
		}
	}

	/// Sets the number of threads used to handle file system operations.
	pub fn thread_count(&mut self, value: u16) -> &mut Self {
		self.options.ThreadCount = value;
		self
	}

	/// Sets flags that controls behavior of the volume.
	pub fn flags(&mut self, value: MountFlags) -> &mut Self {
		self.options.Options = value.bits();
		self
	}

	/// Sets mount point path.
	pub fn mount_point(&mut self, value: &'a impl AsRef<U16CStr>) -> &mut Self {
		self.options.MountPoint = value.as_ref().as_ptr();
		self
	}

	/// Sets UNC name of the network drive.
	pub fn unc_name(&mut self, value: &'a impl AsRef<U16CStr>) -> &mut Self {
		self.options.UNCName = value.as_ref().as_ptr();
		self
	}

	/// Sets the time that Dokan will wait for an operation to complete.
	///
	/// If an operation times out, the user mode implementation is considered to be unable to handle
	/// file system operations properly, and the driver will therefore unmount the volume in order
	/// to keep the system stable.
	///
	/// This timeout can be temporarily extended for an operation with
	/// [`OperationInfo::reset_timeout`][reset_timeout].
	///
	/// [reset_timeout]: struct.OperationInfo.html#method.reset_timeout
	pub fn timeout(&mut self, value: Duration) -> &mut Self {
		self.options.Timeout = value.as_millis() as u32;
		self
	}

	/// Sets allocation unit size of the volume.
	///
	/// This value will affect file sizes.
	pub fn allocation_unit_size(&mut self, value: u32) -> &mut Self {
		self.options.AllocationUnitSize = value;
		self
	}

	/// Sets sector size of the volume.
	///
	/// This value will affect file sizes.
	pub fn sector_size(&mut self, value: u32) -> &mut Self {
		self.options.SectorSize = value;
		self
	}

	/// Mounts the volume and blocks the current thread until the volume gets unmounted.
	pub fn mount<T: FileSystemHandler>(&mut self, handler: &T) -> Result<(), MountError> {
		let mut operations = DOKAN_OPERATIONS {
			ZwCreateFile: Some(create_file::<T>),
			Cleanup: Some(cleanup::<T>),
			CloseFile: Some(close_file::<T>),
			ReadFile: Some(read_file::<T>),
			WriteFile: Some(write_file::<T>),
			FlushFileBuffers: Some(flush_file_buffers::<T>),
			GetFileInformation: Some(get_file_information::<T>),
			FindFiles: Some(find_files::<T>),
			FindFilesWithPattern: Some(find_files_with_pattern::<T>),
			SetFileAttributes: Some(set_file_attributes::<T>),
			SetFileTime: Some(set_file_time::<T>),
			DeleteFile: Some(delete_file::<T>),
			DeleteDirectory: Some(delete_directory::<T>),
			MoveFile: Some(move_file::<T>),
			SetEndOfFile: Some(set_end_of_file::<T>),
			SetAllocationSize: Some(set_allocation_size::<T>),
			LockFile: Some(lock_file::<T>),
			UnlockFile: Some(unlock_file::<T>),
			GetDiskFreeSpace: Some(get_disk_free_space::<T>),
			GetVolumeInformation: Some(get_volume_information::<T>),
			Mounted: Some(mounted::<T>),
			Unmounted: Some(unmounted::<T>),
			GetFileSecurity: Some(get_file_security::<T>),
			SetFileSecurity: Some(set_file_security::<T>),
			FindStreams: Some(find_streams::<T>),
		};
		self.options.GlobalContext = handler as *const T as u64;
		let result = unsafe { DokanMain(&mut self.options, &mut operations) };
		self.options.GlobalContext = 0;
		match result {
			DOKAN_SUCCESS => Ok(()),
			_ => unsafe { Err(mem::transmute(result)) },
		}
	}
}
