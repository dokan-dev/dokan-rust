#![cfg(windows)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![doc(html_root_url = "https://dokan-dev.github.io/dokan-rust-doc/html")]

//! Raw FFI bindings for [Dokan].
//!
//! For more information, refer to corresponding items in [Dokan's documentation].
//!
//! [Dokan]: https://github.com/dokan-dev/dokany
//! [Dokan's documentation]: https://dokan-dev.github.io/dokany-doc/html/

extern crate libc;
extern crate winapi;

use libc::c_int;
use winapi::shared::basetsd::ULONG64;
use winapi::shared::minwindef::{BOOL, DWORD, FILETIME, LPCVOID, LPDWORD, LPVOID, MAX_PATH};
use winapi::shared::ntdef::{
	BOOLEAN, HANDLE, LONGLONG, LPCWSTR, LPWSTR, NTSTATUS, PULONG, PULONGLONG, PVOID64, UCHAR,
	ULONG, UNICODE_STRING, USHORT, WCHAR,
};
use winapi::um::fileapi::LPBY_HANDLE_FILE_INFORMATION;
use winapi::um::minwinbase::PWIN32_FIND_DATAW;
use winapi::um::winnt::{ACCESS_MASK, PSECURITY_DESCRIPTOR, PSECURITY_INFORMATION};

use win32::PWIN32_FIND_STREAM_DATA;

pub mod win32;

include!(concat!(env!("OUT_DIR"), "/version.rs"));

pub const DOKAN_OPTION_DEBUG: ULONG = 1;
pub const DOKAN_OPTION_STDERR: ULONG = 2;
pub const DOKAN_OPTION_ALT_STREAM: ULONG = 4;
pub const DOKAN_OPTION_WRITE_PROTECT: ULONG = 8;
pub const DOKAN_OPTION_NETWORK: ULONG = 16;
pub const DOKAN_OPTION_REMOVABLE: ULONG = 32;
pub const DOKAN_OPTION_MOUNT_MANAGER: ULONG = 64;
pub const DOKAN_OPTION_CURRENT_SESSION: ULONG = 128;
pub const DOKAN_OPTION_FILELOCK_USER_MODE: ULONG = 256;
pub const DOKAN_OPTION_ENABLE_NOTIFICATION_API: ULONG = 512;
pub const DOKAN_OPTION_ENABLE_FCB_GARBAGE_COLLECTION: ULONG = 2048;
pub const DOKAN_OPTION_CASE_SENSITIVE: ULONG = 4096;
pub const DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE: ULONG = 8192;
pub const DOKAN_OPTION_DISPATCH_DRIVER_LOGS: ULONG = 16384;

#[repr(C)]
#[derive(Debug)]
pub struct DOKAN_OPTIONS {
	pub Version: USHORT,
	pub ThreadCount: USHORT,
	pub Options: ULONG,
	pub GlobalContext: ULONG64,
	pub MountPoint: LPCWSTR,
	pub UNCName: LPCWSTR,
	pub Timeout: ULONG,
	pub AllocationUnitSize: ULONG,
	pub SectorSize: ULONG,
}

pub type PDOKAN_OPTIONS = *mut DOKAN_OPTIONS;

#[repr(C)]
#[derive(Debug)]
pub struct DOKAN_FILE_INFO {
	pub Context: ULONG64,
	pub DokanContext: ULONG64,
	pub DokanOptions: PDOKAN_OPTIONS,
	pub ProcessId: ULONG,
	pub IsDirectory: UCHAR,
	pub DeleteOnClose: UCHAR,
	pub PagingIo: UCHAR,
	pub SynchronousIo: UCHAR,
	pub Nocache: UCHAR,
	pub WriteToEndOfFile: UCHAR,
}

pub type PDOKAN_FILE_INFO = *mut DOKAN_FILE_INFO;

pub type PFillFindData = unsafe extern "stdcall" fn(PWIN32_FIND_DATAW, PDOKAN_FILE_INFO) -> c_int;
pub type PFillFindStreamData =
	unsafe extern "stdcall" fn(PWIN32_FIND_STREAM_DATA, PDOKAN_FILE_INFO) -> c_int;

#[repr(C)]
pub struct DOKAN_ACCESS_STATE {
	pub SecurityEvaluated: BOOLEAN,
	pub GenerateAudit: BOOLEAN,
	pub GenerateOnClose: BOOLEAN,
	pub AuditPrivileges: BOOLEAN,
	pub Flags: ULONG,
	pub RemainingDesiredAccess: ACCESS_MASK,
	pub PreviouslyGrantedAccess: ACCESS_MASK,
	pub OriginalDesiredAccess: ACCESS_MASK,
	pub SecurityDescriptor: PSECURITY_DESCRIPTOR,
	pub ObjectName: UNICODE_STRING,
	pub ObjectType: UNICODE_STRING,
}

pub type PDOKAN_ACCESS_STATE = *mut DOKAN_ACCESS_STATE;

#[repr(C)]
pub struct DOKAN_IO_SECURITY_CONTEXT {
	pub AccessState: DOKAN_ACCESS_STATE,
	pub DesiredAccess: ACCESS_MASK,
}

pub type PDOKAN_IO_SECURITY_CONTEXT = *mut DOKAN_IO_SECURITY_CONTEXT;

#[repr(C)]
#[derive(Clone)]
pub struct DOKAN_OPERATIONS {
	pub ZwCreateFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			SecurityContext: PDOKAN_IO_SECURITY_CONTEXT,
			DesiredAccess: ACCESS_MASK,
			FileAttributes: ULONG,
			ShareAccess: ULONG,
			CreateDisposition: ULONG,
			CreateOptions: ULONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub Cleanup: Option<extern "stdcall" fn(FileName: LPCWSTR, DokanFileInfo: PDOKAN_FILE_INFO)>,
	pub CloseFile: Option<extern "stdcall" fn(FileName: LPCWSTR, DokanFileInfo: PDOKAN_FILE_INFO)>,
	pub ReadFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			Buffer: LPVOID,
			BufferLength: DWORD,
			ReadLength: LPDWORD,
			Offset: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub WriteFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			Buffer: LPCVOID,
			NumberOfBytesToWrite: DWORD,
			NumberOfBytesWritten: LPDWORD,
			Offset: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FlushFileBuffers:
		Option<extern "stdcall" fn(FileName: LPCWSTR, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub GetFileInformation: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			Buffer: LPBY_HANDLE_FILE_INFORMATION,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindFiles: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			FillFindData: PFillFindData,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindFilesWithPattern: Option<
		extern "stdcall" fn(
			PathName: LPCWSTR,
			SearchPattern: LPCWSTR,
			FillFindData: PFillFindData,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileAttributes: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			FileAttributes: DWORD,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileTime: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			creation_time: *const FILETIME,
			last_access_time: *const FILETIME,
			last_write_time: *const FILETIME,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub DeleteFile:
		Option<extern "stdcall" fn(FileName: LPCWSTR, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub DeleteDirectory:
		Option<extern "stdcall" fn(FileName: LPCWSTR, DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub MoveFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			NewFileName: LPCWSTR,
			ReplaceIfExisting: BOOL,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetEndOfFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			ByteOffset: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetAllocationSize: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			AllocSize: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub LockFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			ByteOffset: LONGLONG,
			Length: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub UnlockFile: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			ByteOffset: LONGLONG,
			Length: LONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub GetDiskFreeSpace: Option<
		extern "stdcall" fn(
			FreeBytesAvailable: PULONGLONG,
			TotalNumberOfBytes: PULONGLONG,
			TotalNumberOfFreeBytes: PULONGLONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub GetVolumeInformation: Option<
		extern "stdcall" fn(
			VolumeNameBuffer: LPWSTR,
			VolumeNameSize: DWORD,
			VolumeSerialNumber: LPDWORD,
			MaximumComponentLength: LPDWORD,
			FileSystemFlags: LPDWORD,
			FileSystemNameBuffer: LPWSTR,
			FileSystemNameSize: DWORD,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub Mounted: Option<extern "stdcall" fn(DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub Unmounted: Option<extern "stdcall" fn(DokanFileInfo: PDOKAN_FILE_INFO) -> NTSTATUS>,
	pub GetFileSecurity: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			PSECURITY_INFORMATION: PSECURITY_INFORMATION,
			PSECURITY_DESCRIPTOR: PSECURITY_DESCRIPTOR,
			BufferLength: ULONG,
			LengthNeeded: PULONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub SetFileSecurity: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			SecurityInformation: PSECURITY_INFORMATION,
			SecurityDescriptor: PSECURITY_DESCRIPTOR,
			BufferLength: ULONG,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
	pub FindStreams: Option<
		extern "stdcall" fn(
			FileName: LPCWSTR,
			FillFindStreamData: PFillFindStreamData,
			DokanFileInfo: PDOKAN_FILE_INFO,
		) -> NTSTATUS,
	>,
}

pub type PDOKAN_OPERATIONS = *mut DOKAN_OPERATIONS;

pub const DOKAN_SUCCESS: c_int = 0;
pub const DOKAN_ERROR: c_int = -1;
pub const DOKAN_DRIVE_LETTER_ERROR: c_int = -2;
pub const DOKAN_DRIVER_INSTALL_ERROR: c_int = -3;
pub const DOKAN_START_ERROR: c_int = -4;
pub const DOKAN_MOUNT_ERROR: c_int = -5;
pub const DOKAN_MOUNT_POINT_ERROR: c_int = -6;
pub const DOKAN_VERSION_ERROR: c_int = -7;

#[repr(C)]
pub struct DOKAN_CONTROL {
	pub Type: ULONG,
	pub MountPoint: [WCHAR; MAX_PATH],
	pub UNCName: [WCHAR; 64],
	pub DeviceName: [WCHAR; 64],
	pub VolumeDeviceObject: PVOID64,
	pub SessionId: ULONG,
}

pub type PDOKAN_CONTROL = *mut DOKAN_CONTROL;

extern "stdcall" {
	pub fn DokanMain(DokanOptions: PDOKAN_OPTIONS, DokanOperations: PDOKAN_OPERATIONS) -> c_int;
	pub fn DokanUnmount(DriveLetter: WCHAR) -> BOOL;
	pub fn DokanRemoveMountPoint(MountPoint: LPCWSTR) -> BOOL;
	pub fn DokanIsNameInExpression(Expression: LPCWSTR, Name: LPCWSTR, IgnoreCase: BOOL) -> BOOL;
	pub fn DokanVersion() -> ULONG;
	pub fn DokanDriverVersion() -> ULONG;
	pub fn DokanResetTimeout(Timeout: ULONG, DokanFileInfo: PDOKAN_FILE_INFO) -> BOOL;
	pub fn DokanOpenRequestorToken(DokanFileInfo: PDOKAN_FILE_INFO) -> HANDLE;
	pub fn DokanGetMountPointList(uncOnly: BOOL, nbRead: PULONG) -> PDOKAN_CONTROL;
	pub fn DokanReleaseMountPointList(list: PDOKAN_CONTROL);
	pub fn DokanMapKernelToUserCreateFileFlags(
		DesiredAccess: ACCESS_MASK,
		FileAttributes: ULONG,
		CreateOptions: ULONG,
		CreateDisposition: ULONG,
		outDesiredAccess: *mut ACCESS_MASK,
		outFileAttributesAndFlags: *mut DWORD,
		outCreationDisposition: *mut DWORD,
	);
	pub fn DokanNotifyCreate(FilePath: LPCWSTR, IsDirectory: BOOL) -> BOOL;
	pub fn DokanNotifyDelete(FilePath: LPCWSTR, IsDirectory: BOOL) -> BOOL;
	pub fn DokanNotifyUpdate(FilePath: LPCWSTR) -> BOOL;
	pub fn DokanNotifyXAttrUpdate(FilePath: LPCWSTR) -> BOOL;
	pub fn DokanNotifyRename(
		OldPath: LPCWSTR,
		NewPath: LPCWSTR,
		IsDirectory: BOOL,
		IsInSameDirectory: BOOL,
	) -> BOOL;
	pub fn DokanNtStatusFromWin32(Error: DWORD) -> NTSTATUS;
	pub fn DokanUseStdErr(Status: BOOL);
	pub fn DokanDebugMode(Status: BOOL);
	pub fn DokanSetDebugMode(Status: BOOL) -> BOOL;
}
