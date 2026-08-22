use std::{ffi::c_int, marker::PhantomData, time::SystemTime};

use dokan_sys::{
	BOOL, LARGE_INTEGER, PDOKAN_FILE_INFO, PFillFindData, PFillFindStreamData, PVOID,
	win32::{WIN32_FIND_DATAW, WIN32_FIND_STREAM_DATA},
};

use crate::{
	FileAttributes, FillDataError, FillDataResult, FillDataStatus, WideStringCopyError,
	WideStringRef,
	to_file_time::{ToFileTime, split_u64},
};

const MAX_PATH: usize = 260;
const MAX_STREAM_NAME: usize = MAX_PATH + 36;

pub(crate) trait ToRawStruct<T> {
	fn to_raw_struct(&self) -> Result<T, FillDataError>;
}

impl From<WideStringCopyError> for FillDataError {
	fn from(error: WideStringCopyError) -> Self {
		match error {
			WideStringCopyError::EmbeddedNull => Self::EmbeddedNull,
			WideStringCopyError::TooLong => Self::NameTooLong,
		}
	}
}

/// Information about a file provided by [`FileSystemHandler::find_files`] or
/// [`FileSystemHandler::find_files_with_pattern`].
///
/// The file name is borrowed and is copied directly into Dokany's output
/// buffer when it is submitted to a [`DirectoryFiller`].
///
/// [`FileSystemHandler::find_files`]: crate::FileSystemHandler::find_files
/// [`FileSystemHandler::find_files_with_pattern`]: crate::FileSystemHandler::find_files_with_pattern
#[derive(Debug, Clone, Copy)]
pub struct FindData<'a> {
	/// Attribute flags of the file.
	///
	/// It can be combination of one or more [file attribute constants] defined by Windows.
	///
	/// [file attribute constants]: https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
	pub attributes: FileAttributes,

	/// The time when the file was created.
	pub creation_time: SystemTime,

	/// The time when the file was last accessed.
	pub last_access_time: SystemTime,

	/// The time when the file was last written to.
	pub last_write_time: SystemTime,

	/// Size of the file.
	pub file_size: u64,

	/// Name of the file.
	pub file_name: WideStringRef<'a>,
}

impl ToRawStruct<WIN32_FIND_DATAW> for FindData<'_> {
	fn to_raw_struct(&self) -> Result<WIN32_FIND_DATAW, FillDataError> {
		let (file_size_low, file_size_high) = split_u64(self.file_size);
		let mut c_file_name = [0; MAX_PATH];
		self.file_name.copy_exact(&mut c_file_name)?;
		Ok(WIN32_FIND_DATAW {
			dwFileAttributes: self.attributes.bits(),
			ftCreationTime: self.creation_time.to_filetime(),
			ftLastAccessTime: self.last_access_time.to_filetime(),
			ftLastWriteTime: self.last_write_time.to_filetime(),
			nFileSizeHigh: file_size_high,
			nFileSizeLow: file_size_low,
			dwReserved0: 0,
			dwReserved1: 0,
			cFileName: c_file_name,
			cAlternateFileName: [0; 14],
		})
	}
}

/// Information about an alternative stream provided by [`FileSystemHandler::find_streams`].
///
/// [`FileSystemHandler::find_streams`]: crate::FileSystemHandler::find_streams
#[derive(Debug, Clone, Copy)]
pub struct FindStreamData<'a> {
	/// Size of the stream.
	pub size: i64,

	/// Name of stream.
	///
	/// The format of this name should be `:streamname:$streamtype`. See [NTFS Streams] for more
	/// information.
	///
	/// [NTFS Streams]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3
	pub name: WideStringRef<'a>,
}

impl ToRawStruct<WIN32_FIND_STREAM_DATA> for FindStreamData<'_> {
	fn to_raw_struct(&self) -> Result<WIN32_FIND_STREAM_DATA, FillDataError> {
		let mut c_stream_name = [0; MAX_STREAM_NAME];
		self.name.copy_exact(&mut c_stream_name)?;
		Ok(WIN32_FIND_STREAM_DATA {
			// LARGE_INTEGER is represented as a signed 64-bit quad part by winapi.
			StreamSize: LARGE_INTEGER {
				QuadPart: self.size,
			},
			cStreamName: c_stream_name,
		})
	}
}

type FillDirectoryCallback =
	unsafe extern "system" fn(*mut WIN32_FIND_DATAW, PDOKAN_FILE_INFO) -> c_int;
type FillStreamCallback = unsafe extern "system" fn(*mut WIN32_FIND_STREAM_DATA, PVOID) -> BOOL;

struct RawFiller<'callback, T, TArg, TResult> {
	callback: unsafe extern "system" fn(*mut T, TArg) -> TResult,
	argument: TArg,
	success: TResult,
	full: bool,
	_callback_lifetime: PhantomData<&'callback mut ()>,
}

impl<T, TArg: Copy, TResult: PartialEq> RawFiller<'_, T, TArg, TResult> {
	fn push<U: ToRawStruct<T>>(&mut self, data: &U) -> FillDataResult {
		if self.full {
			return Ok(FillDataStatus::BufferFull);
		}
		let mut raw_data = data.to_raw_struct()?;
		let result = unsafe { (self.callback)(&raw mut raw_data, self.argument) };
		if result == self.success {
			Ok(FillDataStatus::Continue)
		} else {
			self.full = true;
			Ok(FillDataStatus::BufferFull)
		}
	}
}

/// Supplies directory entries to Dokany during a directory enumeration.
///
/// The filler remembers when Dokany's output buffer becomes full. Further
/// submissions then return [`FillDataStatus::BufferFull`] without encoding or
/// invoking the native callback.
pub struct DirectoryFiller<'callback> {
	raw: RawFiller<'callback, WIN32_FIND_DATAW, PDOKAN_FILE_INFO, c_int>,
}

impl DirectoryFiller<'_> {
	pub(crate) fn new(callback: PFillFindData, argument: PDOKAN_FILE_INFO) -> Option<Self> {
		let callback: FillDirectoryCallback = callback?;
		Some(Self {
			raw: RawFiller {
				callback,
				argument,
				success: 0,
				full: false,
				_callback_lifetime: PhantomData,
			},
		})
	}

	pub(crate) const fn is_full(&self) -> bool {
		self.raw.full
	}

	/// Submits one directory entry.
	///
	/// # Errors
	///
	/// Returns an error when the entry's name contains an embedded null or does
	/// not fit in Dokany's fixed-size name buffer.
	pub fn push(&mut self, data: &FindData<'_>) -> FillDataResult {
		self.raw.push(data)
	}

	/// Submits entries until the iterator is exhausted or Dokany's buffer is full.
	///
	/// # Errors
	///
	/// Returns an error when an entry's name contains an embedded null or does
	/// not fit in Dokany's fixed-size name buffer.
	pub fn fill<'a>(&mut self, entries: impl IntoIterator<Item = FindData<'a>>) -> FillDataResult {
		for entry in entries {
			let status = self.push(&entry)?;
			if status.is_full() {
				return Ok(status);
			}
		}
		Ok(FillDataStatus::Continue)
	}
}

/// Supplies stream entries to Dokany during a stream enumeration.
///
/// The filler remembers when Dokany's output buffer becomes full. Further
/// submissions then return [`FillDataStatus::BufferFull`] without encoding or
/// invoking the native callback.
pub struct StreamFiller<'callback> {
	raw: RawFiller<'callback, WIN32_FIND_STREAM_DATA, PVOID, BOOL>,
}

impl StreamFiller<'_> {
	pub(crate) fn new(callback: PFillFindStreamData, argument: PVOID) -> Option<Self> {
		let callback: FillStreamCallback = callback?;
		Some(Self {
			raw: RawFiller {
				callback,
				argument,
				success: 1,
				full: false,
				_callback_lifetime: PhantomData,
			},
		})
	}

	pub(crate) const fn is_full(&self) -> bool {
		self.raw.full
	}

	/// Submits one stream entry.
	///
	/// # Errors
	///
	/// Returns an error when the stream name contains an embedded null or does
	/// not fit in Dokany's fixed-size name buffer.
	pub fn push(&mut self, data: &FindStreamData<'_>) -> FillDataResult {
		self.raw.push(data)
	}

	/// Submits entries until the iterator is exhausted or Dokany's buffer is full.
	///
	/// # Errors
	///
	/// Returns an error when a stream name contains an embedded null or does not
	/// fit in Dokany's fixed-size name buffer.
	pub fn fill<'a>(
		&mut self,
		entries: impl IntoIterator<Item = FindStreamData<'a>>,
	) -> FillDataResult {
		for entry in entries {
			let status = self.push(&entry)?;
			if status.is_full() {
				return Ok(status);
			}
		}
		Ok(FillDataStatus::Continue)
	}
}

#[cfg(test)]
mod tests {
	use std::{
		ptr,
		sync::atomic::{AtomicUsize, Ordering},
	};

	use super::*;

	static CALLBACK_COUNT: AtomicUsize = AtomicUsize::new(0);

	unsafe extern "system" fn full_directory_callback(
		_data: *mut WIN32_FIND_DATAW,
		_info: PDOKAN_FILE_INFO,
	) -> c_int {
		CALLBACK_COUNT.fetch_add(1, Ordering::Relaxed);
		1
	}

	unsafe extern "system" fn accepting_stream_callback(
		data: *mut WIN32_FIND_STREAM_DATA,
		_context: PVOID,
	) -> BOOL {
		let expected = [
			u16::from(b':'),
			u16::from(b':'),
			u16::from(b'$'),
			u16::from(b'D'),
			u16::from(b'A'),
			u16::from(b'T'),
			u16::from(b'A'),
			0,
		];
		let data = unsafe { &*data };
		i32::from(data.cStreamName.starts_with(&expected))
	}

	fn find_data(file_name: &str) -> FindData<'_> {
		FindData {
			attributes: FileAttributes::NORMAL,
			creation_time: SystemTime::UNIX_EPOCH,
			last_access_time: SystemTime::UNIX_EPOCH,
			last_write_time: SystemTime::UNIX_EPOCH,
			file_size: u64::MAX,
			file_name: file_name.into(),
		}
	}

	#[test]
	fn find_data_accepts_the_largest_terminated_name() {
		let file_name = "a".repeat(MAX_PATH - 1);
		let raw = find_data(&file_name)
			.to_raw_struct()
			.expect("a MAX_PATH-sized terminated name must fit");

		assert_eq!(raw.cFileName[MAX_PATH - 1], 0);
		assert_eq!(raw.nFileSizeLow, u32::MAX);
		assert_eq!(raw.nFileSizeHigh, u32::MAX);
	}

	#[test]
	fn find_data_rejects_invalid_names() {
		let too_large = "a".repeat(MAX_PATH);
		assert!(matches!(
			find_data(&too_large).to_raw_struct(),
			Err(FillDataError::NameTooLong)
		));
		assert!(matches!(
			find_data("a\0b").to_raw_struct(),
			Err(FillDataError::EmbeddedNull)
		));
	}

	#[test]
	fn stream_data_checks_its_independent_name_limit() {
		let largest = "s".repeat(MAX_STREAM_NAME - 1);
		let too_large = "s".repeat(MAX_STREAM_NAME);

		assert!(
			FindStreamData {
				size: i64::MAX,
				name: largest.as_str().into(),
			}
			.to_raw_struct()
			.is_ok()
		);
		assert!(matches!(
			FindStreamData {
				size: 0,
				name: too_large.as_str().into(),
			}
			.to_raw_struct(),
			Err(FillDataError::NameTooLong)
		));
	}

	#[test]
	fn directory_filler_stops_after_the_native_buffer_is_full() {
		CALLBACK_COUNT.store(0, Ordering::Relaxed);
		let mut filler = DirectoryFiller::new(Some(full_directory_callback), ptr::null_mut())
			.expect("callback is present");
		let data = find_data("entry");

		assert_eq!(filler.fill([data, data]), Ok(FillDataStatus::BufferFull));
		assert_eq!(filler.push(&data), Ok(FillDataStatus::BufferFull));
		assert_eq!(CALLBACK_COUNT.load(Ordering::Relaxed), 1);
	}

	#[test]
	fn stream_filler_encodes_and_submits_a_borrowed_name() {
		let mut filler = StreamFiller::new(Some(accepting_stream_callback), ptr::null_mut())
			.expect("callback is present");
		let data = FindStreamData {
			size: 42,
			name: "::$DATA".into(),
		};

		assert_eq!(filler.push(&data), Ok(FillDataStatus::Continue));
		assert!(!filler.is_full());
	}
}
