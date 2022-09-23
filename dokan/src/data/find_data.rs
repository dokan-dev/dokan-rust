use std::{mem::transmute, time::SystemTime};

use dokan_sys::win32::WIN32_FIND_STREAM_DATA;
use widestring::U16CString;
use winapi::{shared::minwindef::MAX_PATH, um::minwinbase::WIN32_FIND_DATAW};

use crate::{to_file_time::ToFileTime, FillDataError, FillDataResult};

pub(crate) trait ToRawStruct<T> {
	fn to_raw_struct(&self) -> Option<T>;
}

/// Information about a file provided by [`FileSystemHandler::find_files`] or
/// [`FileSystemHandler::find_files_with_pattern`].
///
/// [`FileSystemHandler::find_files`]: crate::FileSystemHandler::find_files
/// [`FileSystemHandler::find_files_with_pattern`]: crate::FileSystemHandler::find_files_with_pattern
#[derive(Debug, Clone)]
pub struct FindData {
	/// Attribute flags of the file.
	///
	/// It can be combination of one or more [file attribute constants] defined by Windows.
	///
	/// [file attribute constants]: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
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
		let name_slice = self.file_name.as_slice_with_nul();
		if name_slice.len() <= MAX_PATH {
			let mut c_file_name = [0; MAX_PATH];
			c_file_name[..name_slice.len()].copy_from_slice(name_slice);
			Some(WIN32_FIND_DATAW {
				dwFileAttributes: self.attributes,
				ftCreationTime: self.creation_time.to_filetime(),
				ftLastAccessTime: self.last_access_time.to_filetime(),
				ftLastWriteTime: self.last_write_time.to_filetime(),
				nFileSizeHigh: (self.file_size >> 32) as u32,
				nFileSizeLow: self.file_size as u32,
				dwReserved0: 0,
				dwReserved1: 0,
				cFileName: c_file_name,
				cAlternateFileName: [0; 14],
			})
		} else {
			None
		}
	}
}

/// Information about an alternative stream provided by [`FileSystemHandler::find_streams`].
///
/// [`FileSystemHandler::find_streams`]: crate::FileSystemHandler::find_streams
#[derive(Debug, Clone)]
pub struct FindStreamData {
	/// Size of the stream.
	pub size: i64,

	/// Name of stream.
	///
	/// The format of this name should be `:streamname:$streamtype`. See [NTFS Streams] for more
	/// information.
	///
	/// [NTFS Streams]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3
	pub name: U16CString,
}

const MAX_STREAM_NAME: usize = MAX_PATH + 36;

impl ToRawStruct<WIN32_FIND_STREAM_DATA> for FindStreamData {
	fn to_raw_struct(&self) -> Option<WIN32_FIND_STREAM_DATA> {
		let name_slice = self.name.as_slice_with_nul();
		if name_slice.len() <= MAX_STREAM_NAME {
			let mut c_stream_name = [0; MAX_STREAM_NAME];
			c_stream_name[..name_slice.len()].copy_from_slice(name_slice);
			Some(WIN32_FIND_STREAM_DATA {
				StreamSize: unsafe { transmute(self.size) },
				cStreamName: c_stream_name,
			})
		} else {
			None
		}
	}
}

pub(crate) fn wrap_fill_data<T, U: ToRawStruct<T>, TArg: Copy, TResult: PartialEq>(
	fill_data: unsafe extern "stdcall" fn(*mut T, TArg) -> TResult,
	fill_data_arg: TArg,
	success_value: TResult,
) -> impl FnMut(&U) -> FillDataResult {
	move |data| {
		let mut ffi_data = data.to_raw_struct().ok_or(FillDataError::NameTooLong)?;
		if unsafe { fill_data(&mut ffi_data, fill_data_arg) == success_value } {
			Ok(())
		} else {
			Err(FillDataError::BufferFull)
		}
	}
}

#[cfg(test)]
mod tests {
	use std::ptr;

	use dokan_sys::PDOKAN_FILE_INFO;
	use winapi::ctypes::c_int;

	use super::*;

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

	extern "stdcall" fn fill_data_stub(_data: *mut (), _info: PDOKAN_FILE_INFO) -> c_int {
		0
	}

	extern "stdcall" fn failing_fill_data_stub(_data: *mut (), _info: PDOKAN_FILE_INFO) -> c_int {
		1
	}

	#[test]
	fn test_wrap_fill_data() {
		let mut wrapper = wrap_fill_data(fill_data_stub, ptr::null_mut(), 0);
		assert_eq!(
			wrapper(&ToRawStructStub { should_fail: true }),
			Err(FillDataError::NameTooLong)
		);
		let mut wrapper = wrap_fill_data(failing_fill_data_stub, ptr::null_mut(), 0);
		assert_eq!(
			wrapper(&ToRawStructStub { should_fail: false }),
			Err(FillDataError::BufferFull)
		);
	}
}
