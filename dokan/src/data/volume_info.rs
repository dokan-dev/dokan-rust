use widestring::U16CString;

/// Information about volume returned by [`FileSystemHandler::get_volume_information`].
///
/// [`FileSystemHandler::get_volume_information`]: crate::FileSystemHandler::get_volume_information
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
	/// It can be combination of one or more [flags] defined by Windows.
	///
	/// `FILE_READ_ONLY_VOLUME` is automatically added if
	/// [`MountFlags::WRITE_PROTECT`] was specified when mounting the volume.
	///
	/// [flags]: https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw#parameters
	/// [`MountFlags::WRITE_PROTECT`]: crate::MountFlags::WRITE_PROTECT
	pub fs_flags: u32,

	/// Name of the file system.
	///
	/// Windows checks feature availability based on file system name, so it is recommended to set
	/// it to well-known names like NTFS or FAT.
	pub fs_name: U16CString,
}
