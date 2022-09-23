/// Information about disk space returned by [`FileSystemHandler::get_disk_free_space`].
///
/// [`FileSystemHandler::get_disk_free_space`]: crate::FileSystemHandler::get_disk_free_space
#[derive(Debug, Clone)]
pub struct DiskSpaceInfo {
	/// Total number of bytes that are available to the calling user.
	pub byte_count: u64,

	/// Total number of free bytes on the disk.
	pub free_byte_count: u64,

	/// Total number of free bytes that are available to the calling user.
	pub available_byte_count: u64,
}
