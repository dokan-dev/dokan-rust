//! End-to-end tests that exercise callbacks through the installed Dokany driver.

use std::{
	cell::RefCell,
	fmt::Debug,
	mem,
	os::windows::prelude::{AsRawHandle, FromRawHandle, OwnedHandle},
	pin::Pin,
	process, ptr, slice,
	sync::mpsc::{self, Receiver, SyncSender},
	thread,
	time::{Duration, UNIX_EPOCH},
};

use dokan_sys::win32::{
	FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, FILE_WRITE_THROUGH,
	WIN32_FIND_STREAM_DATA,
};
use parking_lot::Mutex;
use widestring::{U16CStr, U16CString};
use winapi::{
	shared::{
		minwindef::{BOOL, FALSE, HLOCAL, LPCVOID, LPVOID, MAX_PATH, TRUE},
		ntdef::{HANDLE, NULL},
		sddl::ConvertSidToStringSidW,
		winerror::{
			ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER, ERROR_INTERNAL_ERROR, ERROR_IO_PENDING,
			ERROR_NO_MORE_FILES,
		},
	},
	um::{
		errhandlingapi::GetLastError,
		fileapi::*,
		handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
		ioapiset::GetOverlappedResult,
		minwinbase::OVERLAPPED,
		processthreadsapi::{GetCurrentProcess, OpenProcessToken, ProcessIdToSessionId},
		securitybaseapi::*,
		synchapi::CreateEventW,
		winbase::*,
		winnt::*,
	},
};

use dokan::status::{STATUS_ACCESS_DENIED, STATUS_NOT_IMPLEMENTED};
use dokan::{
	CreateFileInfo, DeviceType, DirectoryFiller, DiskSpaceInfo, FileInfo, FileSystemHandle,
	FileSystemHandler, FileSystemMountError, FileSystemMounter, FileTimeOperation, FindData,
	FindStreamData, MountFlags, MountOptions, OperationInfo, OperationResult, SecurityInformation,
	StreamFiller, VolumeInfo, init, list_mount_points, notify_create, notify_delete, notify_rename,
	notify_update, notify_xattr_update, shutdown, unmount,
};

#[derive(Debug, Clone, Eq, PartialEq)]
struct AlignedBuffer {
	words: Vec<usize>,
	len: usize,
}

impl AlignedBuffer {
	fn zeroed(len: usize) -> Self {
		Self {
			words: vec![0; len.div_ceil(mem::size_of::<usize>())],
			len,
		}
	}

	fn len(&self) -> usize {
		self.len
	}

	fn as_ptr<T>(&self) -> *const T {
		debug_assert!(mem::align_of::<T>() <= mem::align_of::<usize>());
		self.words.as_ptr().cast()
	}

	fn as_mut_ptr<T>(&mut self) -> *mut T {
		debug_assert!(mem::align_of::<T>() <= mem::align_of::<usize>());
		self.words.as_mut_ptr().cast()
	}

	fn as_bytes(&self) -> &[u8] {
		unsafe { slice::from_raw_parts(self.as_ptr(), self.len) }
	}
}

trait TestFileTimeExt {
	fn to_filetime(&self) -> winapi::shared::minwindef::FILETIME;
}

impl TestFileTimeExt for std::time::SystemTime {
	fn to_filetime(&self) -> winapi::shared::minwindef::FILETIME {
		const WINDOWS_EPOCH_OFFSET: Duration = Duration::from_secs(11_644_473_600);
		let intervals =
			self.duration_since(UNIX_EPOCH - WINDOWS_EPOCH_OFFSET)
				.unwrap_or_default()
				.as_nanos() / 100;
		let intervals = u64::try_from(intervals).unwrap_or(u64::MAX);
		let bytes = intervals.to_le_bytes();
		winapi::shared::minwindef::FILETIME {
			dwLowDateTime: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
			dwHighDateTime: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
		}
	}
}

type NtResult = OperationResult<()>;

fn convert_str(s: impl AsRef<str>) -> U16CString {
	unsafe { U16CString::from_str_unchecked(s) }
}

fn len_u32(len: usize) -> u32 {
	u32::try_from(len).expect("test buffer length must fit in a Windows DWORD")
}

macro_rules! assert_eq_win32 {
	($left:expr, $right:expr) => {
		match (&$left, &$right) {
			(left_val, right_val) => {
				if !(*left_val == *right_val) {
					let last_error = GetLastError();
					panic!(
						"assert_eq_win32 failed
      left: {:?}
     right: {:?}
last error: {:#x}",
						&*left_val, &*right_val, last_error
					);
				}
			}
		}
	};
}

macro_rules! assert_ne_win32 {
	($left:expr, $right:expr) => {
		match (&$left, &$right) {
			(left_val, right_val) => {
				if *left_val == *right_val {
					let last_error = GetLastError();
					panic!(
						"assert_ne_win32 failed
      left: {:?}
     right: {:?}
last error: {:#x}",
						&*left_val, &*right_val, last_error
					);
				}
			}
		}
	};
}

struct TestContext {
	tx: SyncSender<HandlerSignal>,
}

impl Drop for TestContext {
	fn drop(&mut self) {
		self.tx.send(HandlerSignal::ContextDropped).unwrap();
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(
	clippy::struct_excessive_bools,
	reason = "the test snapshots independent Dokany operation flags"
)]
struct OperationInfoDump {
	pid: u32,
	is_dir: bool,
	delete_pending: bool,
	paging_io: bool,
	synchronous_io: bool,
	no_cache: bool,
	write_to_eof: bool,
	single_thread: bool,
	mount_flags: MountFlags,
	mount_point: Option<U16CString>,
	unc_name: Option<U16CString>,
	timeout: Duration,
	allocation_unit_size: u32,
	sector_size: u32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum HandlerSignal {
	Mounted,
	Unmounted,
	CreateFile(u32, u32, u32, u32, u32),
	Cleanup,
	CloseFile,
	ContextDropped,
	ReadFile(u64, usize),
	WriteFile(i64, Vec<u8>),
	FlushFileBuffers,
	FindFilesWithPattern(U16CString),
	SetFileAttributes(u32),
	SetFileTime(FileTimeOperation, FileTimeOperation, FileTimeOperation),
	DeleteFile(bool),
	DeleteDirectory(bool),
	MoveFile(U16CString, bool),
	SetEndOfFile(i64),
	SetAllocationSize(i64),
	LockFile(i64, i64),
	UnlockFile(i64, i64),
	GetFileSecurity(u32, u32),
	SetFileSecurity(u32, u32, U16CString, i32),
	OpenRequesterToken(AlignedBuffer),
	OperationInfo(OperationInfoDump),
}

#[derive(Debug)]
struct TestHandler {
	tx: SyncSender<HandlerSignal>,
}

impl TestHandler {
	#[must_use]
	fn new(tx: SyncSender<HandlerSignal>) -> Self {
		Self { tx }
	}
}

fn check_pid(pid: u32) -> NtResult {
	if process::id() == pid {
		Ok(())
	} else {
		Err(STATUS_ACCESS_DENIED)
	}
}

fn get_descriptor_owner(desc: PSECURITY_DESCRIPTOR) -> (U16CString, BOOL) {
	unsafe {
		let mut psid = ptr::null_mut();
		let mut owner_defaulted = 0;
		GetSecurityDescriptorOwner(desc, &raw mut psid, &raw mut owner_defaulted);
		let mut ps = ptr::null_mut();
		assert_eq_win32!(ConvertSidToStringSidW(psid, &raw mut ps), TRUE);
		let sid = U16CStr::from_ptr_str(ps).to_owned();
		assert_eq_win32!(LocalFree(ps as HLOCAL), NULL);
		(sid, owner_defaulted)
	}
}

fn get_user_info(token: HANDLE) -> AlignedBuffer {
	unsafe {
		let mut user_info_len = 0;
		assert_eq_win32!(
			GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut user_info_len),
			FALSE
		);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		let mut user_info_buffer = AlignedBuffer::zeroed(
			usize::try_from(user_info_len).expect("a token-information length fits in usize"),
		);
		assert_eq_win32!(
			GetTokenInformation(
				token,
				TokenUser,
				user_info_buffer.as_mut_ptr(),
				user_info_len,
				&raw mut user_info_len,
			),
			TRUE
		);
		assert_eq!(
			usize::try_from(user_info_len).expect("a token-information length fits in usize"),
			user_info_buffer.len()
		);
		user_info_buffer
	}
}

fn get_current_user_info() -> AlignedBuffer {
	unsafe {
		let mut token = ptr::null_mut();
		assert_eq_win32!(
			OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token),
			TRUE
		);
		let info = get_user_info(token);
		assert_eq_win32!(CloseHandle(token), TRUE);
		info
	}
}

fn create_test_descriptor() -> AlignedBuffer {
	unsafe {
		let mut user_info_buffer = get_current_user_info();
		let user_info = &*user_info_buffer.as_mut_ptr::<TOKEN_USER>();
		let mut abs_desc = mem::zeroed::<SECURITY_DESCRIPTOR>();
		let abs_desc_ptr = &raw mut abs_desc as PSECURITY_DESCRIPTOR;
		assert_eq_win32!(
			InitializeSecurityDescriptor(abs_desc_ptr, SECURITY_DESCRIPTOR_REVISION),
			TRUE
		);
		assert_eq_win32!(
			SetSecurityDescriptorOwner(abs_desc_ptr, user_info.User.Sid, FALSE),
			TRUE
		);
		let mut rel_desc_len = 0;
		assert_eq_win32!(
			MakeSelfRelativeSD(abs_desc_ptr, ptr::null_mut(), &raw mut rel_desc_len),
			FALSE
		);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		let mut rel_desc_buffer = AlignedBuffer::zeroed(
			usize::try_from(rel_desc_len).expect("a security-descriptor length fits in usize"),
		);
		assert_eq_win32!(
			MakeSelfRelativeSD(
				abs_desc_ptr,
				rel_desc_buffer.as_mut_ptr(),
				&raw mut rel_desc_len,
			),
			TRUE
		);
		assert_eq!(
			usize::try_from(rel_desc_len).expect("a security-descriptor length fits in usize"),
			rel_desc_buffer.len()
		);
		rel_desc_buffer
	}
}

impl FileSystemHandler for TestHandler {
	type Context = Option<TestContext>;

	#[allow(
		clippy::too_many_lines,
		reason = "the integration handler routes all create-path scenarios in one callback"
	)]
	fn create_file(
		&self,
		request: &dokan::CreateFileRequest<'_, Self>,
	) -> OperationResult<CreateFileInfo<Self::Context>> {
		let file_name = request.path;
		let desired_access = request.desired_access.bits();
		let file_attributes = request.file_attributes.bits();
		let share_access = request.share_access.bits();
		let create_disposition = request.disposition as u32;
		let create_options = request.options.bits();
		let info = request.operation;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_file_io"
			| "\\test_get_file_information"
			| "\\test_set_file_attributes"
			| "\\test_set_file_time"
			| "\\test_delete_file"
			| "\\test_move_file"
			| "\\test_set_end_of_file"
			| "\\test_set_allocation_size"
			| "\\test_lock_unlock_file"
			| "\\test_get_file_security"
			| "\\test_get_file_security_overflow"
			| "\\test_set_file_security"
			| "\\test_find_streams" => Ok(CreateFileInfo {
				context: None,
				is_dir: false,
				new_file_created: false,
			}),
			"\\"
			| "\\test_delete_directory"
			| "\\test_find_files"
			| "\\test_find_files_with_pattern" => Ok(CreateFileInfo {
				context: None,
				is_dir: true,
				new_file_created: false,
			}),
			"\\test_open_requester_token" => {
				let token = info.requester_token().unwrap();
				self.tx
					.send(HandlerSignal::OpenRequesterToken(get_user_info(
						token.as_raw_handle(),
					)))
					.unwrap();
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_reset_timeout" => {
				thread::sleep(Duration::from_secs(14));
				assert!(info.reset_timeout(Duration::from_secs(10)));
				thread::sleep(Duration::from_secs(7));
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_operation_info" => {
				self.tx
					.send(HandlerSignal::OperationInfo(OperationInfoDump {
						pid: info.pid(),
						is_dir: info.is_dir(),
						delete_pending: info.delete_pending(),
						paging_io: info.paging_io(),
						synchronous_io: info.synchronous_io(),
						no_cache: info.no_cache(),
						write_to_eof: info.write_to_eof(),
						single_thread: info.single_thread(),
						mount_flags: info.mount_flags(),
						mount_point: info.mount_point().map(std::borrow::ToOwned::to_owned),
						unc_name: info.unc_name().map(std::borrow::ToOwned::to_owned),
						timeout: info.timeout(),
						allocation_unit_size: info.allocation_unit_size(),
						sector_size: info.sector_size(),
					}))
					.unwrap();
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_create_file" => {
				self.tx
					.send(HandlerSignal::CreateFile(
						desired_access,
						file_attributes,
						share_access,
						create_disposition,
						create_options,
					))
					.unwrap();
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_panic" => panic!(),
			"\\test_close_file" => Ok(CreateFileInfo {
				context: Some(TestContext {
					tx: self.tx.clone(),
				}),
				is_dir: false,
				new_file_created: false,
			}),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn cleanup(
		&self,
		file_name: &U16CStr,
		_info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) {
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_close_file" {
			self.tx.send(HandlerSignal::Cleanup).unwrap();
		}
	}

	fn close_file(
		&self,
		file_name: &U16CStr,
		_info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) {
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_close_file" {
			self.tx.send(HandlerSignal::CloseFile).unwrap();
		}
	}

	fn read_file(
		&self,
		file_name: &U16CStr,
		offset: u64,
		buffer: &mut [u8],
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<u32> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			let data = "test data".as_bytes();
			assert!(data.len() <= buffer.len());
			buffer[..data.len()].copy_from_slice(data);
			self.tx
				.send(HandlerSignal::ReadFile(offset, buffer.len()))
				.unwrap();
			Ok(len_u32(data.len()))
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn write_file(
		&self,
		file_name: &U16CStr,
		offset: i64,
		buffer: &[u8],
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<u32> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			self.tx
				.send(HandlerSignal::WriteFile(offset, Vec::from(buffer)))
				.unwrap();
			Ok(len_u32(buffer.len()))
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn flush_file_buffers(
		&self,
		file_name: &U16CStr,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			self.tx.send(HandlerSignal::FlushFileBuffers).unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn get_file_information(
		&self,
		_file_name: &U16CStr,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<FileInfo> {
		check_pid(info.pid())?;
		Ok(FileInfo {
			attributes: dokan::FileAttributes::from_bits_retain(if info.is_dir() {
				FILE_ATTRIBUTE_DIRECTORY
			} else {
				FILE_ATTRIBUTE_NORMAL
			}),
			creation_time: UNIX_EPOCH,
			last_access_time: UNIX_EPOCH + Duration::from_secs(1),
			last_write_time: UNIX_EPOCH + Duration::from_secs(2),
			file_size: (1 << 32) + 2,
			number_of_links: 2,
			file_index: (2 << 32) + 3,
		})
	}

	fn find_files(
		&self,
		file_name: &U16CStr,
		filler: &mut DirectoryFiller<'_>,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_find_files" => filler
				.push(&FindData {
					attributes: dokan::FileAttributes::NORMAL,
					creation_time: UNIX_EPOCH,
					last_access_time: UNIX_EPOCH + Duration::from_secs(1),
					last_write_time: UNIX_EPOCH + Duration::from_secs(2),
					file_size: (1 << 32) + 2,
					file_name: "test_inner_file".into(),
				})
				.map(|_| ())
				.map_err(Into::into),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn find_files_with_pattern(
		&self,
		file_name: &U16CStr,
		pattern: &U16CStr,
		filler: &mut DirectoryFiller<'_>,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_find_files" => Err(STATUS_NOT_IMPLEMENTED),
			"\\test_find_files_with_pattern" => filler
				.push(&FindData {
					attributes: dokan::FileAttributes::NORMAL,
					creation_time: UNIX_EPOCH,
					last_access_time: UNIX_EPOCH + Duration::from_secs(1),
					last_write_time: UNIX_EPOCH + Duration::from_secs(2),
					file_size: (1 << 32) + 2,
					file_name: "test_inner_file_with_pattern".into(),
				})
				.map(|_| {
					self.tx
						.send(HandlerSignal::FindFilesWithPattern(pattern.to_owned()))
						.unwrap();
				})
				.map_err(Into::into),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn set_file_attributes(
		&self,
		file_name: &U16CStr,
		file_attributes: dokan::FileAttributes,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_file_attributes" => {
				self.tx
					.send(HandlerSignal::SetFileAttributes(file_attributes.bits()))
					.unwrap();
				Ok(())
			}
			"\\test_set_file_time" => Ok(()),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn set_file_time(
		&self,
		file_name: &U16CStr,
		creation_time: FileTimeOperation,
		last_access_time: FileTimeOperation,
		last_write_time: FileTimeOperation,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_file_time" => {
				self.tx
					.send(HandlerSignal::SetFileTime(
						creation_time,
						last_access_time,
						last_write_time,
					))
					.unwrap();
				Ok(())
			}
			"\\test_set_file_attributes" => Ok(()),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn delete_file(
		&self,
		file_name: &U16CStr,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_delete_file" {
			self.tx
				.send(HandlerSignal::DeleteFile(info.delete_pending()))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn delete_directory(
		&self,
		file_name: &U16CStr,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_delete_directory" {
			self.tx
				.send(HandlerSignal::DeleteDirectory(info.delete_pending()))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn move_file(
		&self,
		file_name: &U16CStr,
		new_file_name: &U16CStr,
		replace_if_existing: bool,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_move_file" {
			self.tx
				.send(HandlerSignal::MoveFile(
					new_file_name.to_owned(),
					replace_if_existing,
				))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn set_end_of_file(
		&self,
		file_name: &U16CStr,
		offset: i64,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_end_of_file" => {
				self.tx.send(HandlerSignal::SetEndOfFile(offset)).unwrap();
				Ok(())
			}
			"\\test_set_allocation_size" => Ok(()),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn set_allocation_size(
		&self,
		file_name: &U16CStr,
		alloc_size: i64,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_set_allocation_size" {
			self.tx
				.send(HandlerSignal::SetAllocationSize(alloc_size))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn lock_file(
		&self,
		file_name: &U16CStr,
		offset: i64,
		length: i64,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_lock_unlock_file" {
			self.tx
				.send(HandlerSignal::LockFile(offset, length))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn unlock_file(
		&self,
		file_name: &U16CStr,
		offset: i64,
		length: i64,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_lock_unlock_file" {
			self.tx
				.send(HandlerSignal::UnlockFile(offset, length))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn get_disk_free_space(
		&self,
		_info: &OperationInfo<'_, Self>,
	) -> OperationResult<DiskSpaceInfo> {
		Ok(DiskSpaceInfo {
			byte_count: 2 * 1024 * 1024,
			free_byte_count: 1024 * 1024,
			available_byte_count: 512 * 1024,
		})
	}

	fn get_volume_information(
		&self,
		_info: &OperationInfo<'_, Self>,
	) -> OperationResult<VolumeInfo<'_>> {
		Ok(VolumeInfo {
			name: "Test Drive".into(),
			serial_number: 1,
			max_component_length: 255,
			features: dokan::VolumeFeatures::CASE_PRESERVED_NAMES
				| dokan::VolumeFeatures::CASE_SENSITIVE_SEARCH
				| dokan::VolumeFeatures::UNICODE_ON_DISK
				| dokan::VolumeFeatures::NAMED_STREAMS,
			fs_name: "TESTFS".into(),
		})
	}

	fn mounted(
		&self,
		_mount_point: &U16CStr,
		_info: &OperationInfo<'_, Self>,
	) -> OperationResult<()> {
		self.tx.send(HandlerSignal::Mounted).unwrap();
		Ok(())
	}

	fn unmounted(&self, _info: &OperationInfo<'_, Self>) -> OperationResult<()> {
		self.tx.send(HandlerSignal::Unmounted).unwrap();
		Ok(())
	}

	fn get_file_security(
		&self,
		file_name: &U16CStr,
		security_information: SecurityInformation,
		security_descriptor: &mut [u8],
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<usize> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_get_file_security" => {
				self.tx
					.send(HandlerSignal::GetFileSecurity(
						security_information.bits(),
						len_u32(security_descriptor.len()),
					))
					.unwrap();
				let desc = create_test_descriptor();
				let result = Ok(desc.len());
				if desc.len() <= security_descriptor.len() {
					security_descriptor[..desc.len()].copy_from_slice(desc.as_bytes());
				}
				result
			}
			"\\test_get_file_security_overflow" => Ok(security_descriptor.len() + 1),
			_ => Err(STATUS_ACCESS_DENIED),
		}
	}

	fn set_file_security(
		&self,
		file_name: &U16CStr,
		security_information: SecurityInformation,
		security_descriptor: &[u8],
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_set_file_security" {
			let (sid, owner_defaulted) =
				get_descriptor_owner(security_descriptor.as_ptr() as PSECURITY_DESCRIPTOR);
			self.tx
				.send(HandlerSignal::SetFileSecurity(
					len_u32(security_descriptor.len()),
					security_information.bits(),
					sid,
					owner_defaulted,
				))
				.unwrap();
			Ok(())
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}

	fn find_streams(
		&self,
		file_name: &U16CStr,
		filler: &mut StreamFiller<'_>,
		info: &OperationInfo<'_, Self>,
		_context: &Self::Context,
	) -> OperationResult<()> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_find_streams" {
			filler
				.push(&FindStreamData {
					size: 42,
					name: "::$DATA".into(),
				})
				.map(|_| ())
				.map_err(Into::into)
		} else {
			Err(STATUS_ACCESS_DENIED)
		}
	}
}

static TEST_DRIVE_LOCK: Mutex<()> = Mutex::new(());

struct TestDriveContext<'a> {
	rx_instance: &'a Receiver<FileSystemHandle>,
	rx_signal: &'a Receiver<HandlerSignal>,

	instance: RefCell<Option<FileSystemHandle>>,
}

impl TestDriveContext<'_> {
	fn signal(&self) -> HandlerSignal {
		self.rx_signal.recv().unwrap()
	}

	fn instance(&self) -> FileSystemHandle {
		self.instance
			.borrow_mut()
			.get_or_insert_with(|| self.rx_instance.recv().unwrap())
			.clone()
	}
}

// Errors might happen on CICD only. To facilitate debugging, output debug messages on console.
#[must_use]
fn test_flags() -> MountFlags {
	let mut flags =
		MountFlags::CURRENT_SESSION | MountFlags::FILELOCK_USER_MODE | MountFlags::ALT_STREAM;

	let enable_console_debug_log =
		std::env::var_os("DOKAN_CONSOLE_DEBUG_LOG").is_some_and(|x| &x != "0");
	if enable_console_debug_log {
		flags = flags | MountFlags::DEBUG | MountFlags::STDERR;
	}

	flags
}

fn with_test_drive<Scope: FnOnce(TestDriveContext)>(scope: Scope) {
	let _guard = TEST_DRIVE_LOCK.lock();

	init();

	// In case previous tests failed and didn't unmount the drive.
	let _ = unmount(convert_str("Z:\\"));

	let (tx_instance, rx_instance) = mpsc::sync_channel(1);

	let (tx_signal, rx_signal) = mpsc::sync_channel(1024);

	let drive_thread_handle = thread::spawn(move || {
		let mount_point = convert_str("Z:\\");
		let handler = TestHandler::new(tx_signal);
		let options = MountOptions {
			single_thread: true,
			flags: test_flags(),
			timeout: Duration::from_secs(15),
			allocation_unit_size: 1024,
			sector_size: 1024,
			..Default::default()
		};
		let file_system = FileSystemMounter::new(handler, &mount_point, options);
		let mount_handle = file_system.mount().unwrap();
		tx_instance.send(mount_handle.instance()).unwrap();
		drop(mount_handle);
		drop(mount_point);
	});

	assert_eq!(rx_signal.recv().unwrap(), HandlerSignal::Mounted);

	scope(TestDriveContext {
		rx_signal: &rx_signal,
		rx_instance: &rx_instance,
		instance: RefCell::new(None),
	});

	assert!(unmount(convert_str("Z:\\")));
	assert_eq!(rx_signal.recv().unwrap(), HandlerSignal::Unmounted);

	drive_thread_handle.join().unwrap();

	shutdown();
}

#[test]
fn supports_panic_in_handler() {
	with_test_drive(|_| unsafe {
		let path = convert_str("Z:\\test_panic");
		assert_eq_win32!(
			CreateFileW(
				path.as_ptr(),
				0,
				0,
				ptr::null_mut(),
				OPEN_EXISTING,
				0,
				ptr::null_mut()
			),
			INVALID_HANDLE_VALUE
		);
		assert_eq!(GetLastError(), ERROR_INTERNAL_ERROR);
	});
}

#[test]
fn can_retrieve_volume_information() {
	with_test_drive(|_| unsafe {
		let path = convert_str("Z:\\");
		let mut volume_name = [0; MAX_PATH + 1];
		let mut fs_name = [0; MAX_PATH + 1];
		let mut serial_number = 0;
		let mut max_component_length = 0;
		let mut fs_flags = 0;
		assert_ne_win32!(
			GetVolumeInformationW(
				path.as_ptr(),
				volume_name.as_mut_ptr(),
				len_u32(volume_name.len()),
				&raw mut serial_number,
				&raw mut max_component_length,
				&raw mut fs_flags,
				fs_name.as_mut_ptr(),
				len_u32(fs_name.len()),
			),
			0
		);
		assert_eq!(
			U16CStr::from_slice_truncate(&volume_name).unwrap(),
			convert_str("Test Drive")
		);
		assert_eq!(
			U16CStr::from_slice_truncate(&fs_name).unwrap(),
			convert_str("TESTFS")
		);
		assert_eq!(serial_number, 1);
		assert_eq!(max_component_length, 255);
		assert_eq!(
			fs_flags,
			FILE_CASE_PRESERVED_NAMES
				| FILE_CASE_SENSITIVE_SEARCH
				| FILE_UNICODE_ON_DISK
				| FILE_NAMED_STREAMS
		);
	});
}

#[test]
fn can_retrieve_disk_space() {
	with_test_drive(|_| unsafe {
		let path = convert_str("Z:\\");
		let mut free_bytes_available = 0u64;
		let mut total_number_of_bytes = 0u64;
		let mut total_number_of_free_bytes = 0u64;
		assert_eq_win32!(
			GetDiskFreeSpaceExW(
				path.as_ptr(),
				&raw mut free_bytes_available as PULARGE_INTEGER,
				&raw mut total_number_of_bytes as PULARGE_INTEGER,
				&raw mut total_number_of_free_bytes as PULARGE_INTEGER,
			),
			TRUE
		);
		assert_eq!(free_bytes_available, 512 * 1024);
		assert_eq!(total_number_of_bytes, 2 * 1024 * 1024);
		assert_eq!(total_number_of_free_bytes, 1024 * 1024);
	});
}

fn open_file(path: impl AsRef<str>) -> HANDLE {
	let path = convert_str(path);
	unsafe {
		let hf = CreateFileW(
			path.as_ptr(),
			GENERIC_ALL,
			FILE_SHARE_READ,
			ptr::null_mut(),
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
			ptr::null_mut(),
		);
		assert_ne_win32!(hf, INVALID_HANDLE_VALUE);
		hf
	}
}

#[test]
fn can_create_file() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_create_file");
		assert_eq_win32!(CloseHandle(hf), TRUE);
		assert_eq!(
			context.signal(),
			HandlerSignal::CreateFile(
				FILE_ALL_ACCESS,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
			)
		);
	});
}

#[test]
fn can_close_file() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_close_file");
		assert_eq_win32!(CloseHandle(hf), TRUE);
		assert_eq!(context.signal(), HandlerSignal::Cleanup);
		assert_eq!(context.signal(), HandlerSignal::CloseFile);
		assert_eq!(context.signal(), HandlerSignal::ContextDropped);
	});
}

#[test]
fn can_read_from_and_write_to_file() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_file_io");
		let mut buf = [0u8; 255];
		let mut len = 0;
		assert_eq_win32!(
			ReadFile(
				hf,
				buf.as_mut_ptr() as LPVOID,
				len_u32(buf.len()),
				&raw mut len,
				ptr::null_mut()
			),
			TRUE
		);
		assert_eq!(
			String::from_utf8(Vec::from(&buf[..len as usize])).unwrap(),
			"test data"
		);
		assert_eq!(context.signal(), HandlerSignal::ReadFile(0, buf.len()));
		let mut bytes_written = 0;
		assert_eq_win32!(
			WriteFile(
				hf,
				buf.as_ptr() as LPCVOID,
				len,
				&raw mut bytes_written,
				ptr::null_mut()
			),
			TRUE
		);
		assert_eq!(bytes_written, len);
		assert_eq!(
			context.signal(),
			HandlerSignal::WriteFile(i64::from(len), Vec::from(&buf[0..len as usize]))
		);
		assert_eq_win32!(FlushFileBuffers(hf), TRUE);
		assert_eq!(context.signal(), HandlerSignal::FlushFileBuffers);
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_get_file_information() {
	with_test_drive(|_context| unsafe {
		let hf = open_file("Z:\\test_get_file_information");
		let mut info = mem::zeroed();
		assert_eq_win32!(GetFileInformationByHandle(hf, &raw mut info), TRUE);
		assert_eq_win32!(CloseHandle(hf), TRUE);

		let ft_epoch = UNIX_EPOCH.to_filetime();
		assert_eq!(info.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
		assert_eq!(info.ftCreationTime.dwLowDateTime, ft_epoch.dwLowDateTime);
		assert_eq!(info.ftCreationTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(
			info.ftLastAccessTime.dwLowDateTime,
			ft_epoch.dwLowDateTime + 1000 * 1000 * 10
		);
		assert_eq!(
			info.ftLastAccessTime.dwHighDateTime,
			ft_epoch.dwHighDateTime
		);
		assert_eq!(
			info.ftLastWriteTime.dwLowDateTime,
			ft_epoch.dwLowDateTime + 2000 * 1000 * 10
		);
		assert_eq!(info.ftLastWriteTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(info.dwVolumeSerialNumber, 1);
		assert_eq!(info.nFileSizeLow, 2);
		assert_eq!(info.nFileSizeHigh, 1);
		assert_eq!(info.nNumberOfLinks, 2);
		assert_eq!(info.nFileIndexLow, 3);
		assert_eq!(info.nFileIndexHigh, 2);
	});
}

fn check_dir_content(pattern: &str, file_name: &str) {
	unsafe {
		let pattern = convert_str(pattern);
		let mut data = mem::zeroed();
		let hf = FindFirstFileW(pattern.as_ptr(), &raw mut data);
		let ft_epoch = UNIX_EPOCH.to_filetime();
		assert_ne_win32!(hf, INVALID_HANDLE_VALUE);
		assert_eq!(
			U16CStr::from_slice_truncate(&data.cFileName).unwrap(),
			convert_str(".")
		);
		assert_eq_win32!(FindNextFileW(hf, &raw mut data), TRUE);
		assert_eq!(
			U16CStr::from_slice_truncate(&data.cFileName).unwrap(),
			convert_str("..")
		);
		assert_eq_win32!(FindNextFileW(hf, &raw mut data), TRUE);
		assert_eq!(data.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
		assert_eq!(data.ftCreationTime.dwLowDateTime, ft_epoch.dwLowDateTime);
		assert_eq!(data.ftCreationTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(
			data.ftLastAccessTime.dwLowDateTime,
			ft_epoch.dwLowDateTime + 1000 * 1000 * 10
		);
		assert_eq!(
			data.ftLastAccessTime.dwHighDateTime,
			ft_epoch.dwHighDateTime
		);
		assert_eq!(
			data.ftLastWriteTime.dwLowDateTime,
			ft_epoch.dwLowDateTime + 2000 * 1000 * 10
		);
		assert_eq!(data.ftLastWriteTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(data.nFileSizeLow, 2);
		assert_eq!(data.nFileSizeHigh, 1);
		assert_eq!(
			U16CStr::from_slice_truncate(&data.cFileName).unwrap(),
			convert_str(file_name)
		);
		assert_eq!(data.dwReserved0, 0);
		assert_eq!(data.dwReserved1, 0);
		assert_eq!(
			U16CStr::from_slice_truncate(&data.cAlternateFileName).unwrap(),
			convert_str("")
		);
		assert_eq_win32!(FindNextFileW(hf, &raw mut data), FALSE);
		assert_eq!(GetLastError(), ERROR_NO_MORE_FILES);
		assert_eq_win32!(FindClose(hf), TRUE);
	}
}

#[test]
fn can_find_files() {
	with_test_drive(|context| {
		check_dir_content("Z:\\test_find_files\\*", "test_inner_file");
		check_dir_content(
			"Z:\\test_find_files_with_pattern\\*",
			"test_inner_file_with_pattern",
		);
		assert_eq!(
			context.signal(),
			HandlerSignal::FindFilesWithPattern(convert_str("*"))
		);
	});
}

#[test]
fn can_set_file_attributes() {
	with_test_drive(|context| unsafe {
		let path = convert_str("Z:\\test_set_file_attributes");
		assert_eq_win32!(
			SetFileAttributesW(path.as_ptr(), FILE_ATTRIBUTE_READONLY),
			TRUE
		);
		assert_eq!(
			context.signal(),
			HandlerSignal::SetFileAttributes(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY)
		);
	});
}

#[test]
fn can_set_file_time() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_set_file_time");
		let ctime = UNIX_EPOCH;
		let atime = UNIX_EPOCH + Duration::from_secs(1);
		let mtime = UNIX_EPOCH + Duration::from_secs(2);
		assert_eq_win32!(
			SetFileTime(
				hf,
				&ctime.to_filetime(),
				&atime.to_filetime(),
				&mtime.to_filetime()
			),
			TRUE
		);
		assert_eq!(
			context.signal(),
			HandlerSignal::SetFileTime(
				FileTimeOperation::SetTime(ctime),
				FileTimeOperation::SetTime(atime),
				FileTimeOperation::SetTime(mtime),
			)
		);
		let time_dont_change = mem::transmute::<i64, winapi::shared::minwindef::FILETIME>(0);
		let time_disable_update = mem::transmute::<i64, winapi::shared::minwindef::FILETIME>(-1);
		let time_resume_update = mem::transmute::<i64, winapi::shared::minwindef::FILETIME>(-2);
		assert_eq_win32!(
			SetFileTime(
				hf,
				&raw const time_dont_change,
				&raw const time_disable_update,
				&raw const time_resume_update
			),
			TRUE
		);
		assert_eq!(
			context.signal(),
			HandlerSignal::SetFileTime(
				FileTimeOperation::DontChange,
				FileTimeOperation::DisableUpdate,
				FileTimeOperation::ResumeUpdate,
			)
		);
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_delete_file() {
	with_test_drive(|context| unsafe {
		let path = convert_str("Z:\\test_delete_file");
		assert_eq_win32!(DeleteFileW(path.as_ptr()), TRUE);
		assert_eq!(context.signal(), HandlerSignal::DeleteFile(true));
	});
}

#[test]
fn can_delete_directory() {
	with_test_drive(|context| unsafe {
		let path = convert_str("Z:\\test_delete_directory");
		assert_eq_win32!(RemoveDirectoryW(path.as_ptr()), TRUE);
		assert_eq!(context.signal(), HandlerSignal::DeleteDirectory(true));
	});
}

#[test]
fn can_move_file() {
	with_test_drive(|context| unsafe {
		let path = convert_str("Z:\\test_move_file");
		let new_path = convert_str("Z:\\test_move_file_new");
		assert_eq_win32!(
			MoveFileExW(path.as_ptr(), new_path.as_ptr(), MOVEFILE_REPLACE_EXISTING),
			TRUE
		);
		assert_eq!(
			context.signal(),
			HandlerSignal::MoveFile(convert_str("\\test_move_file_new"), true)
		);
	});
}

#[test]
fn can_set_end_of_file() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_set_end_of_file");
		assert_eq_win32!(SetFileValidData(hf, i64::MAX), TRUE);
		assert_eq!(context.signal(), HandlerSignal::SetEndOfFile(i64::MAX));
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_set_allocation_size() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_set_allocation_size");
		let dist_low = 42;
		let mut dist_high = 42;
		assert_eq_win32!(
			SetFilePointer(hf, dist_low, &raw mut dist_high, FILE_BEGIN),
			42
		);
		assert_eq!(dist_high, 42);
		assert_eq_win32!(SetEndOfFile(hf), TRUE);
		assert_eq!(
			context.signal(),
			HandlerSignal::SetAllocationSize(i64::from(dist_low) + (i64::from(dist_high) << 32))
		);
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_lock_unlock_file() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_lock_unlock_file");
		assert_eq_win32!(LockFile(hf, 0, 0, 1, 0), TRUE);
		assert_eq!(context.signal(), HandlerSignal::LockFile(0, 1));
		assert_eq_win32!(UnlockFile(hf, 0, 0, 1, 0), TRUE);
		assert_eq!(context.signal(), HandlerSignal::UnlockFile(0, 1));
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_get_file_security() {
	with_test_drive(|context| unsafe {
		let expected_desc = create_test_descriptor();
		let path = convert_str("Z:\\test_get_file_security");
		let mut desc_len = 0;
		assert_eq_win32!(
			GetFileSecurityW(
				path.as_ptr(),
				OWNER_SECURITY_INFORMATION,
				ptr::null_mut(),
				0,
				&raw mut desc_len
			),
			FALSE
		);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		assert_eq!(
			context.signal(),
			HandlerSignal::GetFileSecurity(OWNER_SECURITY_INFORMATION, 0)
		);
		let mut desc = vec![0u8; desc_len as usize];
		assert_eq_win32!(
			GetFileSecurityW(
				path.as_ptr(),
				OWNER_SECURITY_INFORMATION,
				desc.as_mut_ptr() as PSECURITY_DESCRIPTOR,
				len_u32(desc.len()),
				&raw mut desc_len,
			),
			TRUE
		);
		assert_eq!(desc.len(), desc_len as usize);
		assert_eq!(
			context.signal(),
			HandlerSignal::GetFileSecurity(OWNER_SECURITY_INFORMATION, desc_len)
		);
		assert_eq!(desc, expected_desc.as_bytes());
	});
}

#[test]
fn can_get_file_security_overflow() {
	with_test_drive(|_context| unsafe {
		let path = convert_str("Z:\\test_get_file_security_overflow");
		let mut ret_len = 0;
		assert_eq_win32!(
			GetFileSecurityW(
				path.as_ptr(),
				OWNER_SECURITY_INFORMATION,
				ptr::null_mut(),
				0,
				&raw mut ret_len,
			),
			FALSE
		);
		assert_eq!(ret_len, 1);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
	});
}

#[test]
fn can_set_file_security() {
	with_test_drive(|context| unsafe {
		let path = convert_str("Z:\\test_set_file_security");
		let mut desc = create_test_descriptor();
		let desc_ptr = desc.as_mut_ptr();
		assert_eq_win32!(
			SetFileSecurityW(path.as_ptr(), OWNER_SECURITY_INFORMATION, desc_ptr),
			TRUE
		);
		let (sid, owner_defaulted) = get_descriptor_owner(desc_ptr);
		assert_eq!(
			context.signal(),
			HandlerSignal::SetFileSecurity(
				len_u32(desc.len()),
				OWNER_SECURITY_INFORMATION,
				sid,
				owner_defaulted
			)
		);
	});
}

#[test]
fn can_find_streams() {
	with_test_drive(|_context| unsafe {
		let path = convert_str("Z:\\test_find_streams");
		let mut data = mem::zeroed::<WIN32_FIND_STREAM_DATA>();
		let hf = FindFirstStreamW(
			path.as_ptr(),
			FindStreamInfoStandard,
			&raw mut data as LPVOID,
			0,
		);
		assert_ne_win32!(hf, INVALID_HANDLE_VALUE);
		assert_eq!(data.StreamSize.QuadPart, 42);
		assert_eq!(
			U16CStr::from_slice_truncate(&data.cStreamName).unwrap(),
			convert_str("::$DATA")
		);
		assert_eq_win32!(FindNextStreamW(hf, &raw mut data as LPVOID), FALSE);
		assert_eq!(GetLastError(), ERROR_HANDLE_EOF);
		assert_eq_win32!(FindClose(hf), TRUE);
	});
}

#[test]
#[ignore = "requires waiting for Dokany's timeout path"]
fn can_reset_timeout() {
	with_test_drive(|_context| unsafe {
		let path = convert_str("Z:\\test_reset_timeout");
		let hf = CreateFileW(
			path.as_ptr(),
			0,
			0,
			ptr::null_mut(),
			OPEN_EXISTING,
			0,
			ptr::null_mut(),
		);
		assert_ne_win32!(hf, INVALID_HANDLE_VALUE);
		assert_eq_win32!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn can_open_requester_token() {
	with_test_drive(|context| unsafe {
		let expected_info_buffer = get_current_user_info();
		let hf = open_file("Z:\\test_open_requester_token");
		assert_eq_win32!(CloseHandle(hf), TRUE);
		if let HandlerSignal::OpenRequesterToken(info_buffer) = context.signal() {
			let expected_info = &*expected_info_buffer.as_ptr::<TOKEN_USER>();
			let info = &*info_buffer.as_ptr::<TOKEN_USER>();
			assert_eq_win32!(EqualSid(info.User.Sid, expected_info.User.Sid), TRUE);
			assert_eq!(info.User.Attributes, expected_info.User.Attributes);
		} else {
			panic!("unexpected signal type");
		}
	});
}

#[test]
fn can_get_operation_info() {
	with_test_drive(|context| unsafe {
		let hf = open_file("Z:\\test_operation_info");
		assert_eq_win32!(CloseHandle(hf), TRUE);
		assert_eq!(
			context.signal(),
			HandlerSignal::OperationInfo(OperationInfoDump {
				pid: process::id(),
				is_dir: false,
				delete_pending: false,
				paging_io: false,
				synchronous_io: false,
				no_cache: false,
				write_to_eof: false,
				single_thread: true,
				mount_flags: test_flags(),
				mount_point: Some(convert_str("Z:\\")),
				unc_name: None,
				timeout: Duration::from_secs(15),
				allocation_unit_size: 1024,
				sector_size: 1024,
			})
		);
	});
}

#[test]
fn supports_null_ptrs() {
	with_test_drive(|_context| unsafe {
		let path = convert_str("Z:\\");
		assert_eq_win32!(
			GetDiskFreeSpaceExW(
				path.as_ptr(),
				ptr::null_mut(),
				ptr::null_mut(),
				ptr::null_mut(),
			),
			TRUE
		);
		assert_eq_win32!(
			GetVolumeInformationW(
				path.as_ptr(),
				ptr::null_mut(),
				0,
				ptr::null_mut(),
				ptr::null_mut(),
				ptr::null_mut(),
				ptr::null_mut(),
				0,
			),
			TRUE
		);
	});
}

struct DirectoryChangeIterator {
	hd: OwnedHandle,
	buf: AlignedBuffer,
	offset: usize,
	valid_len: usize,
	// Simply reuse the safe handle type as events are closed by CloseHandle as well.
	he: OwnedHandle,
	overlapped: Pin<Box<OVERLAPPED>>,
}

impl DirectoryChangeIterator {
	fn new(path: impl AsRef<U16CStr>) -> DirectoryChangeIterator {
		unsafe {
			let hd = CreateFileW(
				path.as_ref().as_ptr(),
				GENERIC_READ,
				FILE_SHARE_READ,
				ptr::null_mut(),
				OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
				ptr::null_mut(),
			);
			assert_ne_win32!(hd, INVALID_HANDLE_VALUE);
			let he = CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null());
			assert_ne_win32!(he, INVALID_HANDLE_VALUE);
			let mut result = DirectoryChangeIterator {
				hd: OwnedHandle::from_raw_handle(hd),
				buf: AlignedBuffer::zeroed(
					mem::size_of::<FILE_NOTIFY_INFORMATION>() + MAX_PATH * mem::size_of::<u16>(),
				),
				offset: 0,
				valid_len: 0,
				he: OwnedHandle::from_raw_handle(he),
				overlapped: Box::pin(mem::zeroed()),
			};
			result.begin_read();
			result
		}
	}

	fn begin_read(&mut self) {
		unsafe {
			self.valid_len = 0;
			*self.overlapped = mem::zeroed();
			self.overlapped.hEvent = self.he.as_raw_handle();
			let result = ReadDirectoryChangesW(
				self.hd.as_raw_handle(),
				self.buf.as_mut_ptr(),
				len_u32(self.buf.len()),
				FALSE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES,
				ptr::null_mut(),
				&raw mut *self.overlapped,
				None,
			);
			if result == FALSE {
				assert_eq!(GetLastError(), ERROR_IO_PENDING);
			}
		}
	}
}

impl Iterator for DirectoryChangeIterator {
	type Item = (u32, U16CString);

	fn next(&mut self) -> Option<Self::Item> {
		unsafe {
			if self.offset == 0 {
				let mut ret_len = 0;
				assert_eq_win32!(
					GetOverlappedResult(
						self.hd.as_raw_handle(),
						&raw mut *self.overlapped,
						&raw mut ret_len,
						TRUE,
					),
					TRUE
				);
				assert_eq!(self.overlapped.Internal, 0);
				self.valid_len =
					usize::try_from(ret_len).expect("a directory-change length fits in usize");
				assert_eq!(self.overlapped.InternalHigh, self.valid_len);
				assert!(self.valid_len <= self.buf.len());
				assert_ne!(ret_len, 0);
			}
			let header_len = mem::offset_of!(FILE_NOTIFY_INFORMATION, FileName);
			assert!(self.offset <= self.valid_len.saturating_sub(header_len));
			let info = &*self
				.buf
				.as_ptr::<FILE_NOTIFY_INFORMATION>()
				.byte_add(self.offset);
			let name_bytes =
				usize::try_from(info.FileNameLength).expect("a filename length fits in usize");
			assert_eq!(name_bytes % mem::size_of::<u16>(), 0);
			let entry_len = header_len
				.checked_add(name_bytes)
				.expect("directory-change entry length overflow");
			assert!(
				self.offset
					.checked_add(entry_len)
					.is_some_and(|end| end <= self.valid_len)
			);
			let name = U16CString::from_vec(
				slice::from_raw_parts(info.FileName.as_ptr(), name_bytes / mem::size_of::<u16>())
					.to_vec(),
			)
			.expect("directory-change names do not contain NUL");
			let item = (info.Action, name);
			self.offset = if info.NextEntryOffset == 0 {
				0
			} else {
				let next = usize::try_from(info.NextEntryOffset)
					.expect("a directory-change offset fits in usize");
				assert!(next >= entry_len);
				self.offset
					.checked_add(next)
					.filter(|offset| *offset < self.valid_len)
					.expect("directory-change offset outside the completed buffer")
			};
			if self.offset == 0 {
				self.begin_read();
			}
			Some(item)
		}
	}
}

#[test]
fn can_notify() {
	with_test_drive(|context| {
		let (tx, rx) = mpsc::channel();
		let handle = thread::spawn(move || {
			let mut iter = DirectoryChangeIterator::new(convert_str("Z:\\"));
			tx.send(None).unwrap();
			for _ in 0..6 {
				let info = iter.next().unwrap();
				tx.send(Some(info)).unwrap();
			}
		});
		assert_eq!(rx.recv().unwrap(), None);
		let instance = context.instance();
		assert!(notify_create(
			&instance,
			convert_str("Z:\\test_notify_create"),
			false
		));
		assert_eq!(
			rx.recv().unwrap(),
			Some((FILE_ACTION_ADDED, convert_str("test_notify_create")))
		);
		assert!(notify_delete(
			&instance,
			convert_str("Z:\\test_notify_delete"),
			false
		));
		assert_eq!(
			rx.recv().unwrap(),
			Some((FILE_ACTION_REMOVED, convert_str("test_notify_delete")))
		);
		assert!(notify_update(
			&instance,
			convert_str("Z:\\test_notify_update")
		));
		assert_eq!(
			rx.recv().unwrap(),
			Some((FILE_ACTION_MODIFIED, convert_str("test_notify_update")))
		);
		assert!(notify_xattr_update(
			&instance,
			convert_str("Z:\\test_notify_xattr_update")
		));
		assert_eq!(
			rx.recv().unwrap(),
			Some((
				FILE_ACTION_MODIFIED,
				convert_str("test_notify_xattr_update")
			))
		);
		assert!(notify_rename(
			&instance,
			convert_str("Z:\\test_notify_rename_old"),
			convert_str("Z:\\test_notify_rename_new"),
			false,
			true,
		));
		assert_eq!(
			rx.recv().unwrap(),
			Some((
				FILE_ACTION_RENAMED_OLD_NAME,
				convert_str("test_notify_rename_old")
			))
		);
		assert_eq!(
			rx.recv().unwrap(),
			Some((
				FILE_ACTION_RENAMED_NEW_NAME,
				convert_str("test_notify_rename_new")
			))
		);
		handle.join().unwrap();
	});
}

#[test]
fn can_list_mount_points_for_mounted_filesystem() {
	with_test_drive(|_| unsafe {
		let mount_points = list_mount_points(false).unwrap();
		let list: Vec<_> = mount_points.into_iter().collect();
		assert_eq!(list.len(), 1);

		let info = &list[0];
		assert_eq!(info.device_type, DeviceType::Disk);
		assert_eq!(
			info.mount_point,
			Some(convert_str("\\DosDevices\\Z:").as_ref())
		);
		assert_eq!(info.unc_name, None);
		assert!(
			regex::Regex::new(r"^\\Device\\Volume\{[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}$")
				.unwrap()
				.is_match(&info.device_name.to_string_lossy())
		);

		let mut session_id = 0;
		assert_eq!(
			ProcessIdToSessionId(process::id(), &raw mut session_id),
			TRUE
		);
		assert_eq!(info.session_id, session_id);
	});
}

#[test]
fn invalid_mount_point_fails() {
	let (tx, _rx) = mpsc::sync_channel(1);
	let result = FileSystemMounter::new(
		TestHandler::new(tx),
		convert_str("0"),
		MountOptions::default(),
	)
	.mount();

	assert!(matches!(result, Err(FileSystemMountError::Mount)));
}
