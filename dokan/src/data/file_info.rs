use std::time::SystemTime;

use winapi::um::fileapi::BY_HANDLE_FILE_INFORMATION;

use crate::to_file_time::ToFileTime;

/// Information about a file returned by [`FileSystemHandler::get_file_information`].
///
/// [`FileSystemHandler::get_file_information`]: crate::FileSystemHandler::get_file_information
#[derive(Debug, Clone)]
pub struct FileInfo {
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

	/// Number of hardlinks to the file.
	pub number_of_links: u32,

	/// The index that uniquely identifies the file in a volume.
	pub file_index: u64,
}

impl FileInfo {
	pub fn to_raw_struct(&self) -> BY_HANDLE_FILE_INFORMATION {
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
