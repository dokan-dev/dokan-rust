use std::pin::Pin;
use std::process;
use std::sync::mpsc::{self, SyncSender, Receiver};
use std::thread;

use parking_lot::Mutex;
use regex::Regex;
use winapi::shared::minwindef::{FALSE, HLOCAL};
use winapi::shared::ntdef::{HANDLE, NULL};
use winapi::shared::ntstatus::{STATUS_ACCESS_DENIED, STATUS_NOT_IMPLEMENTED};
use winapi::shared::sddl::ConvertSidToStringSidW;
use winapi::shared::winerror::{ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER, ERROR_INTERNAL_ERROR, ERROR_IO_PENDING, ERROR_NO_MORE_FILES, ERROR_SUCCESS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::*;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken, ProcessIdToSessionId};
use winapi::um::securitybaseapi::*;
use winapi::um::synchapi::CreateEventW;
use winapi::um::winbase::*;
use winapi::um::winnt::*;

use super::*;

const FILE_OPEN: u32 = 1;
const FILE_WRITE_THROUGH: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 32;
const FILE_NON_DIRECTORY_FILE: u32 = 64;
const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 8;

#[test]
fn test_version() {
	assert_eq!(MAJOR_API_VERSION, (lib_version() / 100).to_string());
	assert!(driver_version() < 1000);
	assert_eq!(DRIVER_NAME, format!("dokan{}.sys", MAJOR_API_VERSION));
	assert_eq!(NP_NAME, format!("Dokan{}", MAJOR_API_VERSION));
}

fn convert_str(s: impl AsRef<str>) -> U16CString {
	unsafe { U16CString::from_str_unchecked(s) }
}

#[test]
fn test_name_in_expression() {
	assert!(is_name_in_expression(convert_str("foo"), convert_str("foo"), true));
	assert!(is_name_in_expression(convert_str("*"), convert_str("foo"), true));
	assert!(is_name_in_expression(convert_str("?"), convert_str("x"), true));
	assert!(!is_name_in_expression(convert_str("?"), convert_str("foo"), true));
	assert!(is_name_in_expression(convert_str("F*"), convert_str("foo"), true));
	assert!(!is_name_in_expression(convert_str("F*"), convert_str("foo"), false));
}

#[test]
fn test_map_flags() {
	let result = map_kernel_to_user_create_file_flags(
		FILE_ALL_ACCESS,
		FILE_ATTRIBUTE_NORMAL,
		FILE_WRITE_THROUGH,
		FILE_OPEN);
	assert_eq!(result.desired_access, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
	assert_eq!(result.flags_and_attributes, FILE_FLAG_WRITE_THROUGH | FILE_ATTRIBUTE_NORMAL);
	assert_eq!(result.creation_disposition, OPEN_EXISTING);
}

#[test]
fn test_ntstatus() {
	assert_eq!(OperationError::NtStatus(STATUS_SUCCESS).ntstatus(), STATUS_INTERNAL_ERROR);
	assert_eq!(OperationError::Win32(ERROR_SUCCESS).ntstatus(), STATUS_INTERNAL_ERROR);

	let err_nt = OperationError::NtStatus(STATUS_INTERNAL_ERROR);
	let err_win32 = OperationError::Win32(ERROR_INTERNAL_ERROR);
	assert_eq!(err_nt.ntstatus(), err_win32.ntstatus());

	assert_eq!(Ok::<(), OperationError>(()).ntstatus(), STATUS_SUCCESS);
	assert_eq!(Err::<(), OperationError>(err_nt).ntstatus(), STATUS_INTERNAL_ERROR);
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
struct OperationInfoDump {
	pid: u32,
	is_dir: bool,
	delete_on_close: bool,
	paging_io: bool,
	synchronous_io: bool,
	no_cache: bool,
	write_to_eof: bool,
	thread_count: u16,
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
	ReadFile(i64, usize),
	WriteFile(i64, Vec<u8>),
	FlushFileBuffers,
	FindFilesWithPattern(U16CString),
	SetFileAttributes(u32),
	SetFileTime(SystemTime, SystemTime, SystemTime),
	DeleteFile(bool),
	DeleteDirectory(bool),
	MoveFile(U16CString, bool),
	SetEndOfFile(i64),
	SetAllocationSize(i64),
	LockFile(i64, i64),
	UnlockFile(i64, i64),
	GetFileSecurity(u32, u32),
	SetFileSecurity(u32, u32, U16CString, i32),
	OpenRequesterToken(Pin<Box<Vec<u8>>>),
	OperationInfo(OperationInfoDump),
}

#[derive(Debug)]
struct TestHandler {
	tx: SyncSender<HandlerSignal>,
}

fn check_pid(pid: u32) -> Result<(), OperationError> {
	if process::id() == pid {
		Ok(())
	} else {
		Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
	}
}

fn get_descriptor_owner(desc: PSECURITY_DESCRIPTOR) -> (U16CString, BOOL) {
	unsafe {
		let mut psid = ptr::null_mut();
		let mut owner_defaulted = 0;
		GetSecurityDescriptorOwner(desc, &mut psid, &mut owner_defaulted);
		let mut ps = ptr::null_mut();
		assert_eq!(ConvertSidToStringSidW(psid, &mut ps), TRUE);
		let sid = U16CStr::from_ptr_str(ps).to_owned();
		assert_eq!(LocalFree(ps as HLOCAL), NULL);
		(sid, owner_defaulted)
	}
}

fn get_user_info(token: HANDLE) -> Pin<Box<Vec<u8>>> {
	unsafe {
		let mut user_info_len = 0;
		assert_eq!(GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut user_info_len), FALSE);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		let mut user_info_buffer = Box::pin(vec![0; user_info_len as usize]);
		assert_eq!(GetTokenInformation(
			token,
			TokenUser,
			user_info_buffer.as_mut_ptr() as LPVOID,
			user_info_len,
			&mut user_info_len,
		), TRUE);
		assert_eq!(user_info_len as usize, user_info_buffer.len());
		user_info_buffer
	}
}

fn get_current_user_info() -> Pin<Box<Vec<u8>>> {
	unsafe {
		let mut token = ptr::null_mut();
		assert_eq!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token), TRUE);
		let info = get_user_info(token);
		assert_eq!(CloseHandle(token), TRUE);
		info
	}
}

fn create_test_descriptor() -> Vec<u8> {
	unsafe {
		let mut user_info_buffer = get_current_user_info();
		let user_info = &*(user_info_buffer.as_mut_ptr() as PTOKEN_USER);
		let mut abs_desc = mem::zeroed::<SECURITY_DESCRIPTOR>();
		let abs_desc_ptr = &mut abs_desc as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR;
		assert_eq!(InitializeSecurityDescriptor(abs_desc_ptr, SECURITY_DESCRIPTOR_REVISION), TRUE);
		assert_eq!(SetSecurityDescriptorOwner(abs_desc_ptr, user_info.User.Sid, FALSE), TRUE);
		let mut rel_desc_len = 0;
		assert_eq!(MakeSelfRelativeSD(abs_desc_ptr, ptr::null_mut(), &mut rel_desc_len), FALSE);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		let mut rel_desc_buffer = vec![0; rel_desc_len as usize];
		assert_eq!(MakeSelfRelativeSD(
			abs_desc_ptr,
			rel_desc_buffer.as_mut_ptr() as PSECURITY_DESCRIPTOR,
			&mut rel_desc_len,
		), TRUE);
		assert_eq!(rel_desc_len as usize, rel_desc_buffer.len());
		rel_desc_buffer
	}
}

impl<'a, 'b: 'a> FileSystemHandler<'a, 'b> for TestHandler {
	type Context = Option<TestContext>;

	fn create_file(
		&'b self,
		file_name: &U16CStr,
		_security_context: PDOKAN_IO_SECURITY_CONTEXT,
		desired_access: u32,
		file_attributes: u32,
		share_access: u32,
		create_disposition: u32,
		create_options: u32,
		info: &mut OperationInfo<'a, 'b, Self>,
	) -> Result<CreateFileInfo<Self::Context>, OperationError> {
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_file_io" | "\\test_get_file_information" | "\\test_set_file_attributes" | "\\test_set_file_time" | "\\test_delete_file" | "\\test_move_file" | "\\test_set_end_of_file" | "\\test_set_allocation_size" | "\\test_lock_unlock_file" | "\\test_get_file_security" | "\\test_get_file_security_overflow" | "\\test_set_file_security" | "\\test_find_streams" => Ok(CreateFileInfo {
				context: None,
				is_dir: false,
				new_file_created: false,
			}),
			"\\" | "\\test_delete_directory" | "\\test_find_files" | "\\test_find_files_with_pattern" => {
				Ok(CreateFileInfo {
					context: None,
					is_dir: true,
					new_file_created: false,
				})
			}
			"\\test_open_requester_token" => {
				let token = info.requester_token().unwrap();
				self.tx.send(HandlerSignal::OpenRequesterToken(get_user_info(token.value()))).unwrap();
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
				self.tx.send(HandlerSignal::OperationInfo(OperationInfoDump {
					pid: info.pid(),
					is_dir: info.is_dir(),
					delete_on_close: info.delete_on_close(),
					paging_io: info.paging_io(),
					synchronous_io: info.synchronous_io(),
					no_cache: info.no_cache(),
					write_to_eof: info.write_to_eof(),
					thread_count: info.thread_count(),
					mount_flags: info.mount_flags(),
					mount_point: info.mount_point().map(|s| s.to_owned()),
					unc_name: info.unc_name().map(|s| s.to_owned()),
					timeout: info.timeout(),
					allocation_unit_size: info.allocation_unit_size(),
					sector_size: info.sector_size(),
				})).unwrap();
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_create_file" => {
				self.tx.send(HandlerSignal::CreateFile(
					desired_access,
					file_attributes,
					share_access,
					create_disposition,
					create_options,
				)).unwrap();
				Ok(CreateFileInfo {
					context: None,
					is_dir: false,
					new_file_created: false,
				})
			}
			"\\test_panic" => panic!(),
			"\\test_close_file" => Ok(CreateFileInfo {
				context: Some(TestContext { tx: self.tx.clone() }),
				is_dir: false,
				new_file_created: false,
			}),
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn cleanup(
		&'b self,
		file_name: &U16CStr,
		_info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) {
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_close_file" {
			self.tx.send(HandlerSignal::Cleanup).unwrap();
		}
	}

	fn close_file(
		&'b self,
		file_name: &U16CStr,
		_info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) {
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_close_file" {
			self.tx.send(HandlerSignal::CloseFile).unwrap();
		}
	}

	fn read_file(
		&'b self,
		file_name: &U16CStr,
		offset: i64,
		buffer: &mut [u8],
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			let data = "test data".as_bytes();
			assert!(data.len() <= buffer.len());
			buffer[..data.len()].copy_from_slice(data);
			self.tx.send(HandlerSignal::ReadFile(offset, buffer.len())).unwrap();
			Ok(data.len() as u32)
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn write_file(
		&'b self,
		file_name: &U16CStr,
		offset: i64,
		buffer: &[u8],
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			self.tx.send(HandlerSignal::WriteFile(offset, Vec::from(buffer))).unwrap();
			Ok(buffer.len() as u32)
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn flush_file_buffers(
		&'b self,
		file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_file_io" {
			self.tx.send(HandlerSignal::FlushFileBuffers).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn get_file_information(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<FileInfo, OperationError> {
		check_pid(info.pid())?;
		Ok(FileInfo {
			attributes: if info.is_dir() { FILE_ATTRIBUTE_DIRECTORY } else { FILE_ATTRIBUTE_NORMAL },
			creation_time: UNIX_EPOCH,
			last_access_time: UNIX_EPOCH + Duration::from_secs(1),
			last_write_time: UNIX_EPOCH + Duration::from_secs(2),
			file_size: (1 << 32) + 2,
			number_of_links: 2,
			file_index: (2 << 32) + 3,
		})
	}

	fn find_files(
		&'b self,
		file_name: &U16CStr,
		mut fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_find_files" => {
				fill_find_data(&FindData {
					attributes: FILE_ATTRIBUTE_NORMAL,
					creation_time: UNIX_EPOCH,
					last_access_time: UNIX_EPOCH + Duration::from_secs(1),
					last_write_time: UNIX_EPOCH + Duration::from_secs(2),
					file_size: (1 << 32) + 2,
					file_name: convert_str("test_inner_file"),
				})?;
				Ok(())
			}
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn find_files_with_pattern(
		&'b self,
		file_name: &U16CStr,
		pattern: &U16CStr,
		mut fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_find_files" => Err(OperationError::NtStatus(STATUS_NOT_IMPLEMENTED)),
			"\\test_find_files_with_pattern" => {
				fill_find_data(&FindData {
					attributes: FILE_ATTRIBUTE_NORMAL,
					creation_time: UNIX_EPOCH,
					last_access_time: UNIX_EPOCH + Duration::from_secs(1),
					last_write_time: UNIX_EPOCH + Duration::from_secs(2),
					file_size: (1 << 32) + 2,
					file_name: convert_str("test_inner_file_with_pattern"),
				})?;
				self.tx.send(HandlerSignal::FindFilesWithPattern(pattern.to_owned())).unwrap();
				Ok(())
			}
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn set_file_attributes(
		&'b self,
		file_name: &U16CStr,
		file_attributes: u32,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_file_attributes" => {
				self.tx.send(HandlerSignal::SetFileAttributes(file_attributes)).unwrap();
				Ok(())
			}
			"\\test_set_file_time" => Ok(()),
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn set_file_time(
		&'b self,
		file_name: &U16CStr,
		creation_time: SystemTime,
		last_access_time: SystemTime,
		last_write_time: SystemTime,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_file_time" => {
				self.tx.send(HandlerSignal::SetFileTime(creation_time, last_access_time, last_write_time)).unwrap();
				Ok(())
			}
			"\\test_set_file_attributes" => Ok(()),
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn delete_file(
		&'b self,
		file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_delete_file" {
			self.tx.send(HandlerSignal::DeleteFile(info.delete_on_close())).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn delete_directory(
		&'b self,
		file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_delete_directory" {
			self.tx.send(HandlerSignal::DeleteDirectory(info.delete_on_close())).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn move_file(
		&'b self,
		file_name: &U16CStr,
		new_file_name: &U16CStr,
		replace_if_existing: bool,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_move_file" {
			self.tx.send(HandlerSignal::MoveFile(new_file_name.to_owned(), replace_if_existing)).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn set_end_of_file(
		&'b self,
		file_name: &U16CStr,
		offset: i64,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_set_end_of_file" => {
				self.tx.send(HandlerSignal::SetEndOfFile(offset)).unwrap();
				Ok(())
			}
			"\\test_set_allocation_size" => Ok(()),
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn set_allocation_size(
		&'b self,
		file_name: &U16CStr,
		alloc_size: i64,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_set_allocation_size" {
			self.tx.send(HandlerSignal::SetAllocationSize(alloc_size)).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn lock_file(
		&'b self,
		file_name: &U16CStr,
		offset: i64,
		length: i64,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_lock_unlock_file" {
			self.tx.send(HandlerSignal::LockFile(offset, length)).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn unlock_file(
		&'b self,
		file_name: &U16CStr,
		offset: i64,
		length: i64,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_lock_unlock_file" {
			self.tx.send(HandlerSignal::UnlockFile(offset, length)).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn get_disk_free_space(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<DiskSpaceInfo, OperationError> {
		Ok(DiskSpaceInfo {
			byte_count: 2 * 1024 * 1024,
			free_byte_count: 1024 * 1024,
			available_byte_count: 512 * 1024,
		})
	}

	fn get_volume_information(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<VolumeInfo, OperationError> {
		Ok(VolumeInfo {
			name: convert_str("Test Drive"),
			serial_number: 1,
			max_component_length: 255,
			fs_flags: FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_UNICODE_ON_DISK | FILE_NAMED_STREAMS,
			fs_name: convert_str("TESTFS"),
		})
	}

	fn mounted(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<(), OperationError> {
		self.tx.send(HandlerSignal::Mounted).unwrap();
		Ok(())
	}

	fn unmounted(&'b self, _info: &OperationInfo<'a, 'b, Self>) -> Result<(), OperationError> {
		self.tx.send(HandlerSignal::Unmounted).unwrap();
		Ok(())
	}

	fn get_file_security(
		&'b self,
		file_name: &U16CStr,
		security_information: SECURITY_INFORMATION,
		security_descriptor: PSECURITY_DESCRIPTOR,
		buffer_length: u32,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		match file_name.as_ref() {
			"\\test_get_file_security" => {
				self.tx.send(HandlerSignal::GetFileSecurity(security_information, buffer_length)).unwrap();
				let desc = create_test_descriptor();
				let result = Ok(desc.len() as u32);
				if desc.len() <= buffer_length as usize {
					unsafe {
						desc.as_ptr().copy_to_nonoverlapping(
							security_descriptor as *mut u8,
							desc.len(),
						);
					}
				}
				result
			}
			"\\test_get_file_security_overflow" => Ok(buffer_length + 1),
			_ => Err(OperationError::NtStatus(STATUS_ACCESS_DENIED)),
		}
	}

	fn set_file_security(
		&'b self,
		file_name: &U16CStr,
		security_information: SECURITY_INFORMATION,
		security_descriptor: PSECURITY_DESCRIPTOR,
		buffer_length: u32,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_set_file_security" {
			let (sid, owner_defaulted) = get_descriptor_owner(security_descriptor);
			self.tx.send(HandlerSignal::SetFileSecurity(buffer_length, security_information, sid, owner_defaulted)).unwrap();
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}

	fn find_streams(
		&'b self,
		file_name: &U16CStr,
		mut fill_find_stream_data: impl FnMut(&FindStreamData) -> Result<(), FillDataError>,
		info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		check_pid(info.pid())?;
		let file_name = file_name.to_string_lossy();
		if &file_name == "\\test_find_streams" {
			fill_find_stream_data(&FindStreamData {
				size: 42,
				name: convert_str("::$DATA"),
			})?;
			Ok(())
		} else {
			Err(OperationError::NtStatus(STATUS_ACCESS_DENIED))
		}
	}
}

#[test]
fn test_mount_error() {
	let (tx, _rx) = mpsc::sync_channel(1024);
	let result = Drive::new()
		.mount_point(&convert_str("0"))
		.mount(&TestHandler { tx });
	assert_eq!(result, Err(MountError::MountError));
}

lazy_static! {
	static ref TEST_DRIVE_LOCK: Mutex<()> = Mutex::new(());
}

#[allow(unused_must_use)]
fn with_test_drive(f: impl FnOnce(&Receiver<HandlerSignal>)) {
	let _guard = TEST_DRIVE_LOCK.lock();

	// In case previous tests failed and didn't unmount the drive.
	unmount(convert_str("Z:\\"));

	let (tx, rx) = mpsc::sync_channel(1024);
	let handle = thread::spawn(move || {
		Drive::new()
			.thread_count(4)
			.flags(MountFlags::CURRENT_SESSION | MountFlags::FILELOCK_USER_MODE | MountFlags::ALT_STREAM | MountFlags::ENABLE_NOTIFICATION_API)
			.mount_point(&convert_str("Z:\\"))
			// Min value specified by DOKAN_IRP_PENDING_TIMEOUT.
			.timeout(Duration::from_secs(15))
			.allocation_unit_size(1024)
			.sector_size(1024)
			.mount(&TestHandler { tx })
	});
	assert_eq!(rx.recv().unwrap(), HandlerSignal::Mounted);
	f(&rx);
	assert!(unmount(convert_str("Z:\\")));
	assert_eq!(rx.recv().unwrap(), HandlerSignal::Unmounted);
	handle.join().unwrap().unwrap();
}

#[test]
fn test_get_mount_point_list() {
	with_test_drive(|_rx| unsafe {
		let list = get_mount_point_list(false).unwrap();
		assert_eq!(list.len(), 1);
		let info = &list[0];
		assert_eq!(info.device_type, FILE_DEVICE_DISK_FILE_SYSTEM);
		assert_eq!(info.mount_point, Some(convert_str("\\DosDevices\\Z:")));
		assert_eq!(info.unc_name, None);
		assert!(
			Regex::new("^\\\\Device\\\\Volume\\{[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}}$").unwrap()
				.is_match(&info.device_name.to_string_lossy())
		);
		let mut session_id = 0;
		assert_eq!(ProcessIdToSessionId(process::id(), &mut session_id), TRUE);
		assert_eq!(info.session_id, session_id);
	});
}

#[test]
fn test_panic() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\test_panic");
		assert_eq!(CreateFileW(path.as_ptr(), 0, 0, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut()), INVALID_HANDLE_VALUE);
		assert_eq!(GetLastError(), ERROR_INTERNAL_ERROR);
	});
}

#[test]
fn test_get_volume_information() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\");
		let mut volume_name = [0; MAX_PATH + 1];
		let mut fs_name = [0; MAX_PATH + 1];
		let mut serial_number = 0;
		let mut max_component_length = 0;
		let mut fs_flags = 0;
		assert_ne!(GetVolumeInformationW(
			path.as_ptr(),
			volume_name.as_mut_ptr(),
			volume_name.len() as u32,
			&mut serial_number,
			&mut max_component_length,
			&mut fs_flags,
			fs_name.as_mut_ptr(),
			fs_name.len() as u32,
		), 0);
		assert_eq!(U16CStr::from_slice_with_nul(&volume_name).unwrap(), convert_str("Test Drive").as_ref());
		assert_eq!(U16CStr::from_slice_with_nul(&fs_name).unwrap(), convert_str("TESTFS").as_ref());
		assert_eq!(serial_number, 1);
		assert_eq!(max_component_length, 255);
		assert_eq!(fs_flags, FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_UNICODE_ON_DISK | FILE_NAMED_STREAMS);
	});
}

#[test]
fn test_get_disk_free_space() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\");
		let mut free_bytes_available = 0u64;
		let mut total_number_of_bytes = 0u64;
		let mut total_number_of_free_bytes = 0u64;
		assert_eq!(GetDiskFreeSpaceExW(
			path.as_ptr(),
			&mut free_bytes_available as *mut u64 as PULARGE_INTEGER,
			&mut total_number_of_bytes as *mut u64 as PULARGE_INTEGER,
			&mut total_number_of_free_bytes as *mut u64 as PULARGE_INTEGER,
		), TRUE);
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
		assert_ne!(hf, INVALID_HANDLE_VALUE);
		hf
	}
}

#[test]
fn test_create_file() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_create_file");
		assert_eq!(CloseHandle(hf), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::CreateFile(
			FILE_ALL_ACCESS,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		));
	});
}

#[test]
fn test_close_file() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_close_file");
		assert_eq!(CloseHandle(hf), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::Cleanup);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::CloseFile);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::ContextDropped);
	});
}

#[test]
fn test_file_io() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_file_io");
		let mut buf = [0u8; 255];
		let mut len = 0;
		assert_eq!(ReadFile(hf, buf.as_mut_ptr() as LPVOID, buf.len() as u32, &mut len, ptr::null_mut()), TRUE);
		assert_eq!(String::from_utf8(Vec::from(&buf[..len as usize])).unwrap(), "test data");
		assert_eq!(rx.recv().unwrap(), HandlerSignal::ReadFile(0, buf.len()));
		let mut bytes_written = 0;
		assert_eq!(WriteFile(hf, buf.as_ptr() as LPCVOID, len, &mut bytes_written, ptr::null_mut()), TRUE);
		assert_eq!(bytes_written, len);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::WriteFile(len as i64, Vec::from(&buf[0..len as usize])));
		assert_eq!(FlushFileBuffers(hf), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::FlushFileBuffers);
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_get_file_information() {
	with_test_drive(|_rx| unsafe {
		let hf = open_file("Z:\\test_get_file_information");
		let mut info = mem::zeroed();
		assert_eq!(GetFileInformationByHandle(hf, &mut info), TRUE);
		assert_eq!(CloseHandle(hf), TRUE);

		let ft_epoch = UNIX_EPOCH.to_filetime();
		assert_eq!(info.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
		assert_eq!(info.ftCreationTime.dwLowDateTime, ft_epoch.dwLowDateTime);
		assert_eq!(info.ftCreationTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(info.ftLastAccessTime.dwLowDateTime, ft_epoch.dwLowDateTime + 1000 * 1000 * 10);
		assert_eq!(info.ftLastAccessTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(info.ftLastWriteTime.dwLowDateTime, ft_epoch.dwLowDateTime + 2000 * 1000 * 10);
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
		let hf = FindFirstFileW(pattern.as_ptr(), &mut data);
		let ft_epoch = UNIX_EPOCH.to_filetime();
		assert_ne!(hf, INVALID_HANDLE_VALUE);
		assert_eq!(U16CStr::from_slice_with_nul(&data.cFileName).unwrap(), convert_str(".").as_ref());
		assert_eq!(FindNextFileW(hf, &mut data), TRUE);
		assert_eq!(U16CStr::from_slice_with_nul(&data.cFileName).unwrap(), convert_str("..").as_ref());
		assert_eq!(FindNextFileW(hf, &mut data), TRUE);
		assert_eq!(data.dwFileAttributes, FILE_ATTRIBUTE_NORMAL);
		assert_eq!(data.ftCreationTime.dwLowDateTime, ft_epoch.dwLowDateTime);
		assert_eq!(data.ftCreationTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(data.ftLastAccessTime.dwLowDateTime, ft_epoch.dwLowDateTime + 1000 * 1000 * 10);
		assert_eq!(data.ftLastAccessTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(data.ftLastWriteTime.dwLowDateTime, ft_epoch.dwLowDateTime + 2000 * 1000 * 10);
		assert_eq!(data.ftLastWriteTime.dwHighDateTime, ft_epoch.dwHighDateTime);
		assert_eq!(data.nFileSizeLow, 2);
		assert_eq!(data.nFileSizeHigh, 1);
		assert_eq!(U16CStr::from_slice_with_nul(&data.cFileName).unwrap(), convert_str(file_name).as_ref());
		assert_eq!(data.dwReserved0, 0);
		assert_eq!(data.dwReserved1, 0);
		assert_eq!(U16CStr::from_slice_with_nul(&data.cAlternateFileName).unwrap(), convert_str("").as_ref());
		assert_eq!(FindNextFileW(hf, &mut data), FALSE);
		assert_eq!(GetLastError(), ERROR_NO_MORE_FILES);
		assert_eq!(FindClose(hf), TRUE);
	}
}

#[test]
fn test_find_files() {
	with_test_drive(|rx| {
		check_dir_content("Z:\\test_find_files\\*", "test_inner_file");
		check_dir_content("Z:\\test_find_files_with_pattern\\*", "test_inner_file_with_pattern");
		assert_eq!(rx.recv().unwrap(), HandlerSignal::FindFilesWithPattern(convert_str("*")));
	});
}

#[test]
fn test_set_file_attributes() {
	with_test_drive(|rx| unsafe {
		let path = convert_str("Z:\\test_set_file_attributes");
		assert_eq!(SetFileAttributesW(path.as_ptr(), FILE_ATTRIBUTE_READONLY), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::SetFileAttributes(FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY));
	});
}

#[test]
fn test_set_file_time() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_set_file_time");
		let ctime = UNIX_EPOCH;
		let atime = UNIX_EPOCH + Duration::from_secs(1);
		let mtime = UNIX_EPOCH + Duration::from_secs(2);
		assert_eq!(SetFileTime(hf, &ctime.to_filetime(), &atime.to_filetime(), &mtime.to_filetime()), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::SetFileTime(ctime, atime, mtime));
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_delete_file() {
	with_test_drive(|rx| unsafe {
		let path = convert_str("Z:\\test_delete_file");
		assert_eq!(DeleteFileW(path.as_ptr()), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::DeleteFile(true));
	});
}

#[test]
fn test_delete_directory() {
	with_test_drive(|rx| unsafe {
		let path = convert_str("Z:\\test_delete_directory");
		assert_eq!(RemoveDirectoryW(path.as_ptr()), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::DeleteDirectory(true));
	});
}

#[test]
fn test_move_file() {
	with_test_drive(|rx| unsafe {
		let path = convert_str("Z:\\test_move_file");
		let new_path = convert_str("Z:\\test_move_file_new");
		assert_eq!(MoveFileExW(path.as_ptr(), new_path.as_ptr(), MOVEFILE_REPLACE_EXISTING), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::MoveFile(convert_str("\\test_move_file_new"), true));
	});
}

#[test]
fn test_set_end_of_file() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_set_end_of_file");
		assert_eq!(SetFileValidData(hf, std::i64::MAX), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::SetEndOfFile(std::i64::MAX));
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_set_allocation_size() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_set_allocation_size");
		let dist_low = 42;
		let mut dist_high = 42;
		assert_eq!(SetFilePointer(hf, dist_low, &mut dist_high, FILE_BEGIN), 42);
		assert_eq!(dist_high, 42);
		assert_eq!(SetEndOfFile(hf), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::SetAllocationSize(dist_low as i64 + ((dist_high as i64) << 32)));
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_lock_unlock_file() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_lock_unlock_file");
		assert_eq!(LockFile(hf, 0, 0, 1, 0), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::LockFile(0, 1));
		assert_eq!(UnlockFile(hf, 0, 0, 1, 0), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::UnlockFile(0, 1));
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_get_file_security() {
	with_test_drive(|rx| unsafe {
		let expected_desc = create_test_descriptor();
		let path = convert_str("Z:\\test_get_file_security");
		let mut desc_len = 0;
		assert_eq!(GetFileSecurityW(path.as_ptr(), OWNER_SECURITY_INFORMATION, ptr::null_mut(), 0, &mut desc_len), FALSE);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::GetFileSecurity(OWNER_SECURITY_INFORMATION, 0));
		let mut desc = vec![0u8; desc_len as usize];
		assert_eq!(GetFileSecurityW(
			path.as_ptr(),
			OWNER_SECURITY_INFORMATION,
			desc.as_mut_ptr() as PSECURITY_DESCRIPTOR,
			desc.len() as u32,
			&mut desc_len,
		), TRUE);
		assert_eq!(desc.len(), desc_len as usize);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::GetFileSecurity(OWNER_SECURITY_INFORMATION, desc_len));
		assert_eq!(desc, expected_desc);
	});
}

#[test]
fn test_get_file_security_overflow() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\test_get_file_security_overflow");
		let mut ret_len = 0;
		assert_eq!(GetFileSecurityW(
			path.as_ptr(),
			OWNER_SECURITY_INFORMATION,
			ptr::null_mut(),
			0,
			&mut ret_len,
		), FALSE);
		assert_eq!(ret_len, 1);
		assert_eq!(GetLastError(), ERROR_INSUFFICIENT_BUFFER);
	});
}

#[test]
fn test_set_file_security() {
	with_test_drive(|rx| unsafe {
		let path = convert_str("Z:\\test_set_file_security");
		let mut desc = create_test_descriptor();
		let desc_ptr = desc.as_mut_ptr() as PSECURITY_DESCRIPTOR;
		assert_eq!(SetFileSecurityW(path.as_ptr(), OWNER_SECURITY_INFORMATION, desc_ptr), TRUE);
		let (sid, owner_defaulted) = get_descriptor_owner(desc_ptr);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::SetFileSecurity(desc.len() as u32, OWNER_SECURITY_INFORMATION, sid, owner_defaulted));
	});
}

#[test]
fn test_find_streams() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\test_find_streams");
		let mut data = mem::zeroed::<WIN32_FIND_STREAM_DATA>();
		let hf = FindFirstStreamW(
			path.as_ptr(),
			FindStreamInfoStandard,
			&mut data as *mut WIN32_FIND_STREAM_DATA as LPVOID,
			0,
		);
		assert_ne!(hf, INVALID_HANDLE_VALUE);
		assert_eq!(data.StreamSize.QuadPart(), &42);
		assert_eq!(U16CStr::from_slice_with_nul(&data.cStreamName).unwrap(), convert_str("::$DATA").as_ref());
		assert_eq!(FindNextStreamW(hf, &mut data as *mut WIN32_FIND_STREAM_DATA as LPVOID), FALSE);
		assert_eq!(GetLastError(), ERROR_HANDLE_EOF);
		assert_eq!(FindClose(hf), TRUE);
	});
}

#[test]
#[ignore]
fn test_reset_timeout() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\test_reset_timeout");
		let hf = CreateFileW(path.as_ptr(), 0, 0, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut());
		assert_ne!(hf, INVALID_HANDLE_VALUE);
		assert_eq!(CloseHandle(hf), TRUE);
	});
}

#[test]
fn test_open_requester_token() {
	with_test_drive(|rx| unsafe {
		let expected_info_buffer = get_current_user_info();
		let hf = open_file("Z:\\test_open_requester_token");
		assert_eq!(CloseHandle(hf), TRUE);
		if let HandlerSignal::OpenRequesterToken(info_buffer) = rx.recv().unwrap() {
			let expected_info = &*(expected_info_buffer.as_ptr() as *const TOKEN_USER);
			let info = &*(info_buffer.as_ptr() as *const TOKEN_USER);
			assert_eq!(EqualSid(info.User.Sid, expected_info.User.Sid), TRUE);
			assert_eq!(info.User.Attributes, expected_info.User.Attributes);
		} else {
			panic!("unexpected signal type");
		}
	});
}

#[test]
fn test_operation_info() {
	with_test_drive(|rx| unsafe {
		let hf = open_file("Z:\\test_operation_info");
		assert_eq!(CloseHandle(hf), TRUE);
		assert_eq!(rx.recv().unwrap(), HandlerSignal::OperationInfo(OperationInfoDump {
			pid: process::id(),
			is_dir: false,
			delete_on_close: false,
			paging_io: false,
			synchronous_io: false,
			no_cache: false,
			write_to_eof: false,
			thread_count: 4,
			mount_flags: MountFlags::CURRENT_SESSION | MountFlags::FILELOCK_USER_MODE | MountFlags::ALT_STREAM | MountFlags::ENABLE_NOTIFICATION_API,
			mount_point: Some(convert_str("Z:\\")),
			unc_name: None,
			timeout: Duration::from_secs(15),
			allocation_unit_size: 1024,
			sector_size: 1024,
		}));
	});
}

#[test]
fn test_output_ptr_null() {
	with_test_drive(|_rx| unsafe {
		let path = convert_str("Z:\\");
		assert_eq!(GetDiskFreeSpaceExW(
			path.as_ptr(),
			ptr::null_mut(),
			ptr::null_mut(),
			ptr::null_mut(),
		), TRUE);
		assert_eq!(GetVolumeInformationW(
			path.as_ptr(),
			ptr::null_mut(),
			0,
			ptr::null_mut(),
			ptr::null_mut(),
			ptr::null_mut(),
			ptr::null_mut(),
			0,
		), TRUE);
	})
}

struct ToRawStructStub {
	should_fail: bool,
}

impl ToRawStruct<()> for ToRawStructStub {
	fn to_raw_struct(&self) -> Option<()> {
		if self.should_fail {
			None
		} else {
			Some(())
		}
	}
}

extern "stdcall" fn fill_data_stub(_data: *mut (), _info: PDOKAN_FILE_INFO) -> c_int { 0 }

extern "stdcall" fn failing_fill_data_stub(_data: *mut (), _info: PDOKAN_FILE_INFO) -> c_int { 1 }

#[test]
fn test_fill_data_error() {
	let mut wrapper = fill_data_wrapper(fill_data_stub, ptr::null_mut());
	assert_eq!(wrapper(&ToRawStructStub { should_fail: true }), Err(FillDataError::NameTooLong));
	let mut wrapper = fill_data_wrapper(failing_fill_data_stub, ptr::null_mut());
	assert_eq!(wrapper(&ToRawStructStub { should_fail: false }), Err(FillDataError::BufferFull));
}

struct DirectoryChangeIterator {
	hd: Handle,
	buf: Pin<Box<Vec<u8>>>,
	offset: usize,
	he: Handle,
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
			assert_ne!(hd, INVALID_HANDLE_VALUE);
			let he = CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null());
			assert_ne!(he, INVALID_HANDLE_VALUE);
			let mut result = DirectoryChangeIterator {
				hd: Handle { value: hd },
				buf: Box::pin(vec![0; mem::size_of::<FILE_NOTIFY_INFORMATION>() + MAX_PATH]),
				offset: 0,
				he: Handle { value: he },
				overlapped: Box::pin(mem::zeroed()),
			};
			result.begin_read();
			result
		}
	}

	fn begin_read(&mut self) {
		unsafe {
			*self.overlapped = mem::zeroed();
			self.overlapped.hEvent = self.he.value();
			let result = ReadDirectoryChangesW(
				self.hd.value(),
				self.buf.as_mut_ptr() as LPVOID,
				self.buf.len() as u32,
				FALSE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES,
				ptr::null_mut(),
				&mut *self.overlapped,
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
				assert_eq!(GetOverlappedResult(
					self.hd.value(),
					&mut *self.overlapped,
					&mut ret_len,
					TRUE,
				), TRUE);
				assert_eq!(self.overlapped.Internal, STATUS_SUCCESS as usize);
				assert_eq!(self.overlapped.InternalHigh, ret_len as usize);
				assert_ne!(ret_len, 0);
			}
			let info = &*(self.buf.as_ptr().offset(self.offset as isize) as *const FILE_NOTIFY_INFORMATION);
			self.offset = if info.NextEntryOffset == 0 { 0 } else { self.offset + info.NextEntryOffset as usize };
			if self.offset == 0 { self.begin_read(); }
			Some((info.Action, U16CStr::from_ptr_str(info.FileName.as_ptr()).to_owned()))
		}
	}
}

#[test]
fn test_notify() {
	with_test_drive(|_rx| {
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
		assert!(notify_create(convert_str("Z:\\test_notify_create"), false));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_ADDED, convert_str("test_notify_create"))));
		assert!(notify_delete(convert_str("Z:\\test_notify_delete"), false));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_REMOVED, convert_str("test_notify_delete"))));
		assert!(notify_update(convert_str("Z:\\test_notify_update")));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_MODIFIED, convert_str("test_notify_update"))));
		assert!(notify_xattr_update(convert_str("Z:\\test_notify_xattr_update")));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_MODIFIED, convert_str("test_notify_xattr_update"))));
		assert!(notify_rename(
			convert_str("Z:\\test_notify_rename_old"),
			convert_str("Z:\\test_notify_rename_new"),
			false,
			true,
		));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_RENAMED_OLD_NAME, convert_str("test_notify_rename_old"))));
		assert_eq!(rx.recv().unwrap(), Some((FILE_ACTION_RENAMED_NEW_NAME, convert_str("test_notify_rename_new"))));
		handle.join().unwrap();
	})
}
