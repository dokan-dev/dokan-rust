/// Information about the created or opened file returned by [`FileSystemHandler::create_file`].
///
/// [`FileSystemHandler::create_file`]: crate::FileSystemHandler::create_file
#[derive(Debug, Clone)]
pub struct CreateFileInfo<T> {
	/// The context to be associated with the new file object.
	pub context: T,

	/// Indicates whether the file is a directory.
	pub is_dir: bool,

	/// Indicates whether a new file has been created.
	pub new_file_created: bool,
}
