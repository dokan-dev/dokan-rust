#![cfg(windows)]

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
use winapi::shared::ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_INTERNAL_ERROR, STATUS_NOT_IMPLEMENTED, STATUS_SUCCESS};
use winapi::um::fileapi::{BY_HANDLE_FILE_INFORMATION, LPBY_HANDLE_FILE_INFORMATION};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::minwinbase::WIN32_FIND_DATAW;
use winapi::um::winnt::{ACCESS_MASK, PSECURITY_DESCRIPTOR, PSECURITY_INFORMATION};

pub use dokan_sys::DOKAN_DRIVER_NAME as DRIVER_NAME;
pub use dokan_sys::DOKAN_MAJOR_API_VERSION as MAJOR_API_VERSION;
pub use dokan_sys::DOKAN_NP_NAME as NP_NAME;
pub use dokan_sys::DOKAN_VERSION as WRAPPER_VERSION;

pub fn lib_version() -> u32 { unsafe { DokanVersion() } }

pub fn driver_version() -> u32 { unsafe { DokanDriverVersion() } }

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UserCreateFileFlags {
	pub desired_access: ACCESS_MASK,
	pub flags_and_attributes: u32,
	pub creation_disposition: u32,
}

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

#[must_use]
pub fn unmount(mount_point: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanRemoveMountPoint(mount_point.as_ref().as_ptr()) == TRUE }
}

#[derive(Debug, Clone)]
pub struct MountPointInfo {
	pub device_type: u32,
	pub mount_point: U16CString,
	pub unc_name: U16CString,
	pub device_name: U16CString,
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
				list.push(MountPointInfo {
					device_type: control.Type,
					mount_point: U16CStr::from_slice_with_nul(&control.MountPoint).unwrap().to_owned(),
					unc_name: U16CStr::from_slice_with_nul(&control.UNCName).unwrap().to_owned(),
					device_name: U16CStr::from_slice_with_nul(&control.DeviceName).unwrap().to_owned(),
					session_id: control.SessionId,
				})
			}
			Some(list)
		}
	}
}

#[must_use]
pub fn notify_create(path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyCreate(path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

#[must_use]
pub fn notify_delete(path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyDelete(path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

#[must_use]
pub fn notify_update(path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyUpdate(path.as_ref().as_ptr()) == TRUE }
}

#[must_use]
pub fn notify_xattr_update(path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyXAttrUpdate(path.as_ref().as_ptr()) == TRUE }
}

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
	pub struct MountFlags : u32 {
		const DEBUG = DOKAN_OPTION_DEBUG;
		const STDERR = DOKAN_OPTION_STDERR;
		const ALT_STREAM = DOKAN_OPTION_ALT_STREAM;
		const WRITE_PROTECT = DOKAN_OPTION_WRITE_PROTECT;
		const NETWORK = DOKAN_OPTION_NETWORK;
		const REMOVABLE = DOKAN_OPTION_REMOVABLE;
		const MOUNT_MANAGER = DOKAN_OPTION_MOUNT_MANAGER;
		const CURRENT_SESSION = DOKAN_OPTION_CURRENT_SESSION;
		const FILELOCK_USER_MODE = DOKAN_OPTION_FILELOCK_USER_MODE;
		const ENABLE_NOTIFICATION_API = DOKAN_OPTION_ENABLE_NOTIFICATION_API;
		const DISABLE_OPLOCKS = DOKAN_OPTION_DISABLE_OPLOCKS;
		const OPTIMIZE_SINGLE_NAME_SEARCH = DOKAN_OPTION_OPTIMIZE_SINGLE_NAME_SEARCH;
	}
}

#[derive(Debug, Eq, PartialEq)]
pub struct Handle {
	value: HANDLE,
}

impl Handle {
	pub fn value(&self) -> HANDLE { self.value }
}

impl Drop for Handle {
	fn drop(&mut self) {
		if self.value != INVALID_HANDLE_VALUE {
			unsafe { CloseHandle(self.value); }
		}
	}
}

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

	pub fn pid(&self) -> u32 { self.file_info().ProcessId }

	pub fn is_dir(&self) -> bool { self.file_info().IsDirectory != 0 }

	pub fn set_is_dir(&mut self, value: bool) {
		unsafe { (&mut *self.file_info).IsDirectory = value.into() }
	}

	pub fn delete_on_close(&self) -> bool { self.file_info().DeleteOnClose != 0 }

	pub fn paging_io(&self) -> bool { self.file_info().PagingIo != 0 }

	pub fn synchronous_io(&self) -> bool { self.file_info().SynchronousIo != 0 }

	pub fn no_cache(&self) -> bool { self.file_info().Nocache != 0 }

	pub fn write_to_eof(&self) -> bool { self.file_info().WriteToEndOfFile != 0 }

	pub fn thread_count(&self) -> u16 { self.mount_options().ThreadCount }

	pub fn mount_flags(&self) -> MountFlags { MountFlags::from_bits_truncate(self.mount_options().Options) }

	pub fn mount_point(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().MountPoint;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	pub fn unc_name(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().UNCName;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	pub fn timeout(&self) -> Duration { Duration::from_millis(self.mount_options().Timeout.into()) }

	pub fn allocation_unit_size(&self) -> u32 { self.mount_options().AllocationUnitSize }

	pub fn sector_size(&self) -> u32 { self.mount_options().SectorSize }

	#[must_use]
	pub fn reset_timeout(&self, timeout: Duration) -> bool {
		unsafe { DokanResetTimeout(timeout.as_millis() as u32, self.file_info) == TRUE }
	}

	pub fn requester_token(&self) -> Option<Handle> {
		let value = unsafe { DokanOpenRequestorToken(self.file_info) };
		if value == INVALID_HANDLE_VALUE {
			None
		} else {
			Some(Handle { value })
		}
	}
}

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

#[derive(Debug, Clone)]
pub struct FileInfo {
	attributes: u32,
	creation_time: SystemTime,
	last_access_time: SystemTime,
	last_write_time: SystemTime,
	file_size: u64,
	number_of_links: u32,
	file_index: u64,
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

#[derive(Debug, Clone)]
pub struct FindData {
	attributes: u32,
	creation_time: SystemTime,
	last_access_time: SystemTime,
	last_write_time: SystemTime,
	file_size: u64,
	file_name: U16CString,
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

#[derive(Debug, Clone)]
pub struct FindStreamData {
	pub size: i64,
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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FillDataError {
	NameTooLong,
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

#[derive(Debug, Clone)]
pub struct DiskSpaceInfo {
	pub byte_count: u64,
	pub free_byte_count: u64,
	pub available_byte_count: u64,
}

#[derive(Debug, Clone)]
pub struct VolumeInfo {
	pub name: U16CString,
	pub serial_number: u32,
	pub max_component_length: u32,
	pub fs_flags: u32,
	pub fs_name: U16CString,
}

pub trait FileSystemHandler: Sync + Sized {
	type Context: Sync;

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
	) -> Result<Self::Context, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn cleanup(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) {}

	fn close_file(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) {}

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

	fn flush_file_buffers(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn get_file_information(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<FileInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn find_files(
		&self,
		_file_name: &U16CStr,
		_fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

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


	fn set_file_attributes(
		&self,
		_file_name: &U16CStr,
		_file_attributes: u32,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

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

	fn delete_file(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn delete_directory(
		&self,
		_file_name: &U16CStr,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

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

	fn set_end_of_file(
		&self,
		_file_name: &U16CStr,
		_offset: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn set_allocation_size(
		&self,
		_file_name: &U16CStr,
		_alloc_size: i64,
		_info: &OperationInfo<Self>,
		_context: &Self::Context,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

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

	fn get_disk_free_space(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<DiskSpaceInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn get_volume_information(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<VolumeInfo, OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn mounted(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

	fn unmounted(
		&self,
		_info: &OperationInfo<Self>,
	) -> Result<(), OperationError> {
		Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED))
	}

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
		info.handler().create_file(
			file_name,
			security_context,
			desired_access,
			file_attributes,
			share_access,
			create_disposition,
			create_options,
			&mut info,
		).and_then(|ctx| {
			(&mut *dokan_file_info).Context = Box::into_raw(Box::new(ctx)) as u64;
			Ok(())
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
		let info = OperationInfo::<T>::new(dokan_file_info);
		info.handler().close_file(file_name, &info, info.context());
		mem::drop(Box::from_raw((&*dokan_file_info).Context as *mut T::Context));
		(&mut *dokan_file_info).Context = 0;
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
			*free_bytes_available = space_info.available_byte_count;
			*total_number_of_bytes = space_info.byte_count;
			*total_number_of_free_bytes = space_info.free_byte_count;
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
			*volume_serial_number = volume_info.serial_number;
			*maximum_component_length = volume_info.max_component_length;
			*file_system_flags = volume_info.fs_flags;
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

#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MountError {
	Error = DOKAN_ERROR,
	DriveLetterError = DOKAN_DRIVE_LETTER_ERROR,
	DriverInstallError = DOKAN_DRIVER_INSTALL_ERROR,
	StartError = DOKAN_START_ERROR,
	MountError = DOKAN_MOUNT_ERROR,
	MountPointError = DOKAN_MOUNT_POINT_ERROR,
	VersionError = DOKAN_VERSION_ERROR,
}

impl Error for MountError {}

impl Display for MountError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			MountError::Error => "Dokan mount error.",
			MountError::DriveLetterError => "Bad drive letter.",
			MountError::DriverInstallError => "Can't install driver.",
			MountError::StartError => "Driver answer that something is wrong.",
			MountError::MountError => "Can't assign a drive letter or mount point. Probably already used by another volume.",
			MountError::MountPointError => "Mount point is invalid.",
			MountError::VersionError => "Requested an incompatible version.",
		};
		write!(f, "{}", msg)
	}
}

#[derive(Debug)]
pub struct Drive<'a> {
	options: DOKAN_OPTIONS,
	phantom: PhantomData<&'a U16CStr>,
}

impl<'a> Drive<'a> {
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

	pub fn thread_count(&mut self, value: u16) -> &mut Self {
		self.options.ThreadCount = value;
		self
	}

	pub fn flags(&mut self, value: MountFlags) -> &mut Self {
		self.options.Options = value.bits();
		self
	}

	pub fn mount_point(&mut self, value: &'a impl AsRef<U16CStr>) -> &mut Self {
		self.options.MountPoint = value.as_ref().as_ptr();
		self
	}

	pub fn unc_name(&mut self, value: &'a impl AsRef<U16CStr>) -> &mut Self {
		self.options.UNCName = value.as_ref().as_ptr();
		self
	}

	pub fn timeout(&mut self, value: Duration) -> &mut Self {
		self.options.Timeout = value.as_millis() as u32;
		self
	}

	pub fn allocation_unit_size(&mut self, value: u32) -> &mut Self {
		self.options.AllocationUnitSize = value;
		self
	}

	pub fn sector_size(&mut self, value: u32) -> &mut Self {
		self.options.SectorSize = value;
		self
	}

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
