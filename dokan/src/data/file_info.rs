use std::time::SystemTime;

use dokan_sys::win32::BY_HANDLE_FILE_INFORMATION;

use crate::{
	FileAttributes,
	to_file_time::{ToFileTime, split_u64},
};

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
	pub attributes: FileAttributes,

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
	pub(crate) fn to_raw_struct(&self) -> BY_HANDLE_FILE_INFORMATION {
		let (file_size_low, file_size_high) = split_u64(self.file_size);
		let (file_index_low, file_index_high) = split_u64(self.file_index);
		BY_HANDLE_FILE_INFORMATION {
			dwFileAttributes: self.attributes.bits(),
			ftCreationTime: self.creation_time.to_filetime(),
			ftLastAccessTime: self.last_access_time.to_filetime(),
			ftLastWriteTime: self.last_write_time.to_filetime(),
			dwVolumeSerialNumber: 0,
			nFileSizeHigh: file_size_high,
			nFileSizeLow: file_size_low,
			nNumberOfLinks: self.number_of_links,
			nFileIndexHigh: file_index_high,
			nFileIndexLow: file_index_low,
		}
	}
}

#[cfg(test)]
mod tests {
	use std::time::UNIX_EPOCH;

	use super::*;

	#[test]
	fn splits_large_file_sizes_and_indexes_into_raw_words() {
		let raw = FileInfo {
			attributes: FileAttributes::ARCHIVE,
			creation_time: UNIX_EPOCH,
			last_access_time: UNIX_EPOCH,
			last_write_time: UNIX_EPOCH,
			file_size: 0xFEDC_BA98_7654_3210,
			number_of_links: 7,
			file_index: 0x0123_4567_89AB_CDEF,
		}
		.to_raw_struct();

		assert_eq!(raw.dwFileAttributes, FileAttributes::ARCHIVE.bits());
		assert_eq!(raw.nFileSizeHigh, 0xFEDC_BA98);
		assert_eq!(raw.nFileSizeLow, 0x7654_3210);
		assert_eq!(raw.nNumberOfLinks, 7);
		assert_eq!(raw.nFileIndexHigh, 0x0123_4567);
		assert_eq!(raw.nFileIndexLow, 0x89AB_CDEF);
	}
}
