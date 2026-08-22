use std::{error::Error, ffi::c_void, fmt, ptr::NonNull};

use bitflags::bitflags;
use dokan_sys::DOKAN_IO_SECURITY_CONTEXT;

/// Native NT status returned to Dokany.
///
/// This crate-owned transparent wrapper keeps the public API independent from
/// `windows`, `windows-sys`, and `winapi`. Use [`from_raw`](Self::from_raw) and
/// [`into_raw`](Self::into_raw) when interoperating with any C-style binding.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NtStatus(i32);

impl NtStatus {
	/// Creates a status from its native signed 32-bit representation.
	#[must_use]
	pub const fn from_raw(value: i32) -> Self {
		Self(value)
	}

	/// Returns the native signed 32-bit representation.
	#[must_use]
	pub const fn into_raw(self) -> i32 {
		self.0
	}

	/// Whether the status represents success according to NT semantics.
	#[must_use]
	pub const fn is_success(self) -> bool {
		self.0 >= 0
	}
}

impl From<i32> for NtStatus {
	fn from(value: i32) -> Self {
		Self::from_raw(value)
	}
}

impl From<NtStatus> for i32 {
	fn from(value: NtStatus) -> Self {
		value.into_raw()
	}
}

#[cfg(feature = "windows-interop")]
impl From<windows::Win32::Foundation::NTSTATUS> for NtStatus {
	fn from(value: windows::Win32::Foundation::NTSTATUS) -> Self {
		Self::from_raw(value.0)
	}
}

#[cfg(feature = "windows-interop")]
impl From<NtStatus> for windows::Win32::Foundation::NTSTATUS {
	fn from(value: NtStatus) -> Self {
		Self(value.into_raw())
	}
}

impl fmt::Debug for NtStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let bits = u32::from_ne_bytes(self.0.to_ne_bytes());
		write!(f, "NtStatus(0x{bits:08X})")
	}
}

impl fmt::Display for NtStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let bits = u32::from_ne_bytes(self.0.to_ne_bytes());
		write!(f, "NT status 0x{bits:08X}")
	}
}

impl Error for NtStatus {}

/// Raw Windows access-mask value.
///
/// Use [`AccessRights`] when inspecting the standard file access rights. The
/// raw value is retained because file systems may define additional bits.
pub type AccessMask = u32;

bitflags! {
	/// Standard and file-specific access rights requested by Windows.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct AccessRights: AccessMask {
		/// Read file data.
		const READ_DATA = 0x0000_0001;
		/// List the entries in a directory.
		const LIST_DIRECTORY = Self::READ_DATA.bits();
		/// Write file data.
		const WRITE_DATA = 0x0000_0002;
		/// Add a file to a directory.
		const ADD_FILE = Self::WRITE_DATA.bits();
		/// Append data to a file.
		const APPEND_DATA = 0x0000_0004;
		/// Add a subdirectory.
		const ADD_SUBDIRECTORY = Self::APPEND_DATA.bits();
		/// Read extended attributes.
		const READ_EXTENDED_ATTRIBUTES = 0x0000_0008;
		/// Write extended attributes.
		const WRITE_EXTENDED_ATTRIBUTES = 0x0000_0010;
		/// Execute a file.
		const EXECUTE = 0x0000_0020;
		/// Traverse a directory.
		const TRAVERSE = Self::EXECUTE.bits();
		/// Delete children of a directory.
		const DELETE_CHILD = 0x0000_0040;
		/// Read file attributes.
		const READ_ATTRIBUTES = 0x0000_0080;
		/// Write file attributes.
		const WRITE_ATTRIBUTES = 0x0000_0100;
		/// Delete the object.
		const DELETE = 0x0001_0000;
		/// Read the object's security descriptor.
		const READ_CONTROL = 0x0002_0000;
		/// Modify the object's discretionary access control list.
		const WRITE_DAC = 0x0004_0000;
		/// Change the object's owner.
		const WRITE_OWNER = 0x0008_0000;
		/// Use the object for synchronization.
		const SYNCHRONIZE = 0x0010_0000;
		/// Request all available access rights.
		const GENERIC_ALL = 0x1000_0000;
		/// Request the rights normally needed to execute.
		const GENERIC_EXECUTE = 0x2000_0000;
		/// Request the rights normally needed to write.
		const GENERIC_WRITE = 0x4000_0000;
		/// Request the rights normally needed to read.
		const GENERIC_READ = 0x8000_0000;
	}
}

bitflags! {
	/// Capabilities reported for a mounted filesystem.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct VolumeFeatures: u32 {
		/// The filesystem supports case-sensitive lookup.
		const CASE_SENSITIVE_SEARCH = 0x0000_0001;
		/// The filesystem preserves the case of names.
		const CASE_PRESERVED_NAMES = 0x0000_0002;
		/// The filesystem stores Unicode names.
		const UNICODE_ON_DISK = 0x0000_0004;
		/// The filesystem preserves access-control lists.
		const PERSISTENT_ACLS = 0x0000_0008;
		/// The filesystem supports per-file compression.
		const FILE_COMPRESSION = 0x0000_0010;
		/// The filesystem supports disk quotas.
		const VOLUME_QUOTAS = 0x0000_0020;
		/// The filesystem supports sparse files.
		const SUPPORTS_SPARSE_FILES = 0x0000_0040;
		/// The filesystem supports reparse points.
		const SUPPORTS_REPARSE_POINTS = 0x0000_0080;
		/// The filesystem supports remote storage.
		const SUPPORTS_REMOTE_STORAGE = 0x0000_0100;
		/// Cleanup callbacks may return additional result information.
		const RETURNS_CLEANUP_RESULT_INFO = 0x0000_0200;
		/// The filesystem supports POSIX-style unlink and rename operations.
		const SUPPORTS_POSIX_UNLINK_RENAME = 0x0000_0400;
		/// The entire volume is compressed.
		const VOLUME_IS_COMPRESSED = 0x0000_8000;
		/// The filesystem supports object identifiers.
		const SUPPORTS_OBJECT_IDS = 0x0001_0000;
		/// The filesystem supports encryption.
		const SUPPORTS_ENCRYPTION = 0x0002_0000;
		/// The filesystem supports named data streams.
		const NAMED_STREAMS = 0x0004_0000;
		/// The volume is read-only.
		const READ_ONLY_VOLUME = 0x0008_0000;
		/// The volume supports only a single sequential write.
		const SEQUENTIAL_WRITE_ONCE = 0x0010_0000;
		/// The filesystem supports transactions.
		const SUPPORTS_TRANSACTIONS = 0x0020_0000;
		/// The filesystem supports hard links.
		const SUPPORTS_HARD_LINKS = 0x0040_0000;
		/// The filesystem supports extended attributes.
		const SUPPORTS_EXTENDED_ATTRIBUTES = 0x0080_0000;
		/// The filesystem supports opening objects by file identifier.
		const SUPPORTS_OPEN_BY_FILE_ID = 0x0100_0000;
		/// The filesystem supports an update sequence number journal.
		const SUPPORTS_USN_JOURNAL = 0x0200_0000;
		/// The filesystem supports integrity streams.
		const SUPPORTS_INTEGRITY_STREAMS = 0x0400_0000;
		/// The filesystem supports block reference counting.
		const SUPPORTS_BLOCK_REFCOUNTING = 0x0800_0000;
		/// The filesystem supports sparse valid-data length.
		const SUPPORTS_SPARSE_VDL = 0x1000_0000;
		/// The volume supports direct-access storage.
		const DAX_VOLUME = 0x2000_0000;
		/// The filesystem supports ghosted files.
		const SUPPORTS_GHOSTING = 0x4000_0000;
	}
}

bitflags! {
	/// Requested sharing modes for an opened file.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct ShareAccess: u32 {
		/// Allow other handles to read the object.
		const READ = 0x0000_0001;
		/// Allow other handles to write the object.
		const WRITE = 0x0000_0002;
		/// Allow other handles to delete the object.
		const DELETE = 0x0000_0004;
	}
}

bitflags! {
	/// File attributes supplied by Windows.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct FileAttributes: u32 {
		/// The file is read-only.
		const READ_ONLY = 0x0000_0001;
		/// The file is hidden.
		const HIDDEN = 0x0000_0002;
		/// The file is used by the operating system.
		const SYSTEM = 0x0000_0004;
		/// The object is a directory.
		const DIRECTORY = 0x0000_0010;
		/// The file should be archived.
		const ARCHIVE = 0x0000_0020;
		/// The object is a device.
		const DEVICE = 0x0000_0040;
		/// The file has no other attributes set.
		const NORMAL = 0x0000_0080;
		/// The file is intended for temporary storage.
		const TEMPORARY = 0x0000_0100;
		/// The file is sparse.
		const SPARSE_FILE = 0x0000_0200;
		/// The file or directory contains a reparse point.
		const REPARSE_POINT = 0x0000_0400;
		/// The file is compressed.
		const COMPRESSED = 0x0000_0800;
		/// The file data is not immediately available.
		const OFFLINE = 0x0000_1000;
		/// Content indexing should skip the file.
		const NOT_CONTENT_INDEXED = 0x0000_2000;
		/// The file or directory is encrypted.
		const ENCRYPTED = 0x0000_4000;
		/// The file or directory has an integrity stream.
		const INTEGRITY_STREAM = 0x0000_8000;
		/// Background data-integrity scrubbing should skip the object.
		const NO_SCRUB_DATA = 0x0002_0000;
		/// Opening the file may recall it from remote storage.
		const RECALL_ON_OPEN = 0x0004_0000;
		/// The file should remain fully present locally.
		const PINNED = 0x0008_0000;
		/// The file should not remain fully present locally.
		const UNPINNED = 0x0010_0000;
		/// Reading the file may recall it from remote storage.
		const RECALL_ON_DATA_ACCESS = 0x0040_0000;
	}
}

bitflags! {
	/// Kernel create options supplied to a create/open request.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct CreateOptions: u32 {
		/// The target must be a directory.
		const DIRECTORY_FILE = 0x0000_0001;
		/// Writes must pass through intermediate caches.
		const WRITE_THROUGH = 0x0000_0002;
		/// Access is expected to be sequential.
		const SEQUENTIAL_ONLY = 0x0000_0004;
		/// Do not use intermediate buffering.
		const NO_INTERMEDIATE_BUFFERING = 0x0000_0008;
		/// Perform synchronous I/O that may deliver alerts.
		const SYNCHRONOUS_IO_ALERT = 0x0000_0010;
		/// Perform synchronous I/O without delivering alerts.
		const SYNCHRONOUS_IO_NONALERT = 0x0000_0020;
		/// The target must not be a directory.
		const NON_DIRECTORY_FILE = 0x0000_0040;
		/// Create a tree connection for a remote target.
		const CREATE_TREE_CONNECTION = 0x0000_0080;
		/// Complete the open immediately if the target is oplocked.
		const COMPLETE_IF_OPLOCKED = 0x0000_0100;
		/// Fail if extended attributes cannot be understood.
		const NO_EA_KNOWLEDGE = 0x0000_0200;
		/// Open a remote instance of the object.
		const OPEN_REMOTE_INSTANCE = 0x0000_0400;
		/// Access is expected to be random.
		const RANDOM_ACCESS = 0x0000_0800;
		/// Delete the object when its final handle closes.
		const DELETE_ON_CLOSE = 0x0000_1000;
		/// Interpret the supplied name as a file identifier.
		const OPEN_BY_FILE_ID = 0x0000_2000;
		/// Open the object for backup or restore.
		const OPEN_FOR_BACKUP_INTENT = 0x0000_4000;
		/// Do not inherit compression from the parent directory.
		const NO_COMPRESSION = 0x0000_8000;
		/// Request an oplock as part of the open.
		const OPEN_REQUIRING_OPLOCK = 0x0001_0000;
		/// Fail if another handle already has the object open.
		const DISALLOW_EXCLUSIVE = 0x0002_0000;
		/// The open is aware of Windows sessions.
		const SESSION_AWARE = 0x0004_0000;
		/// Reserve an opportunistic-lock filter.
		const RESERVE_OPFILTER = 0x0010_0000;
		/// Open the reparse point itself.
		const OPEN_REPARSE_POINT = 0x0020_0000;
		/// Do not recall the file from remote storage.
		const OPEN_NO_RECALL = 0x0040_0000;
		/// Open the file for a free-space query.
		const OPEN_FOR_FREE_SPACE_QUERY = 0x0080_0000;
	}
}

/// Action requested when a path exists or does not exist.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum CreateDisposition {
	/// Replace an existing object, or create it if absent.
	Supersede = 0,
	/// Open an existing object and fail if it is absent.
	Open = 1,
	/// Create a new object and fail if it already exists.
	Create = 2,
	/// Open an existing object, or create it if absent.
	OpenIf = 3,
	/// Replace data in an existing object and fail if it is absent.
	Overwrite = 4,
	/// Replace data in an existing object, or create it if absent.
	OverwriteIf = 5,
}

impl TryFrom<u32> for CreateDisposition {
	type Error = u32;

	fn try_from(value: u32) -> Result<Self, Self::Error> {
		Ok(match value {
			0 => Self::Supersede,
			1 => Self::Open,
			2 => Self::Create,
			3 => Self::OpenIf,
			4 => Self::Overwrite,
			5 => Self::OverwriteIf,
			other => return Err(other),
		})
	}
}

bitflags! {
	/// Parts of a Windows security descriptor requested by an operation.
	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
	pub struct SecurityInformation: u32 {
		/// Owner information.
		const OWNER = 0x0000_0001;
		/// Primary group information.
		const GROUP = 0x0000_0002;
		/// Discretionary access control list.
		const DACL = 0x0000_0004;
		/// System access control list.
		const SACL = 0x0000_0008;
		/// Mandatory integrity label.
		const LABEL = 0x0000_0010;
		/// Resource attributes.
		const ATTRIBUTE = 0x0000_0020;
		/// Central access-policy identifier.
		const SCOPE = 0x0000_0040;
		/// Process trust label.
		const PROCESS_TRUST_LABEL = 0x0000_0080;
		/// Retrieve the descriptor for backup purposes.
		const BACKUP = 0x0001_0000;
		/// Mark the discretionary ACL as protected.
		const PROTECTED_DACL = 0x8000_0000;
		/// Mark the system ACL as protected.
		const PROTECTED_SACL = 0x4000_0000;
		/// Allow the discretionary ACL to inherit from its parent.
		const UNPROTECTED_DACL = 0x2000_0000;
		/// Allow the system ACL to inherit from its parent.
		const UNPROTECTED_SACL = 0x1000_0000;
	}
}

/// Borrowed security descriptor supplied as part of an open request.
#[derive(Copy, Clone)]
pub struct SecurityDescriptorRef<'a> {
	ptr: NonNull<c_void>,
	_marker: std::marker::PhantomData<&'a c_void>,
}

impl fmt::Debug for SecurityDescriptorRef<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_tuple("SecurityDescriptorRef")
			.field(&self.ptr)
			.finish()
	}
}

impl SecurityDescriptorRef<'_> {
	/// Exposes the descriptor for interoperability with Windows security APIs.
	#[must_use]
	pub const fn as_ptr(self) -> *const c_void {
		self.ptr.as_ptr()
	}
}

/// Safe view over the security information accompanying an open request.
#[derive(Debug, Copy, Clone)]
pub struct SecurityContext<'a> {
	raw: &'a DOKAN_IO_SECURITY_CONTEXT,
}

impl<'a> SecurityContext<'a> {
	pub(crate) const fn new(raw: &'a DOKAN_IO_SECURITY_CONTEXT) -> Self {
		Self { raw }
	}

	/// Returns the access rights requested by the caller.
	#[must_use]
	pub const fn desired_access(self) -> AccessRights {
		AccessRights::from_bits_retain(self.raw.DesiredAccess)
	}

	/// Returns the security descriptor supplied with the request, if present.
	#[must_use]
	pub fn security_descriptor(self) -> Option<SecurityDescriptorRef<'a>> {
		NonNull::new(self.raw.AccessState.SecurityDescriptor).map(|ptr| SecurityDescriptorRef {
			ptr: ptr.cast(),
			_marker: std::marker::PhantomData,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::{CreateDisposition, NtStatus};

	#[test]
	fn nt_status_preserves_raw_bits_and_semantics() {
		let success = NtStatus::from_raw(0);
		let failure = NtStatus::from_raw(i32::from_ne_bytes(0xC000_0022_u32.to_ne_bytes()));

		assert!(success.is_success());
		assert!(!failure.is_success());
		assert_eq!(
			u32::from_ne_bytes(failure.into_raw().to_ne_bytes()),
			0xC000_0022
		);
		assert_eq!(format!("{failure}"), "NT status 0xC0000022");
		assert_eq!(format!("{failure:?}"), "NtStatus(0xC0000022)");
	}

	#[test]
	fn create_disposition_validates_native_values() {
		let expected = [
			CreateDisposition::Supersede,
			CreateDisposition::Open,
			CreateDisposition::Create,
			CreateDisposition::OpenIf,
			CreateDisposition::Overwrite,
			CreateDisposition::OverwriteIf,
		];

		for (raw, disposition) in (0_u32..).zip(expected) {
			assert_eq!(CreateDisposition::try_from(raw), Ok(disposition));
			assert_eq!(disposition as u32, raw);
		}
		assert_eq!(CreateDisposition::try_from(6), Err(6));
		assert_eq!(CreateDisposition::try_from(u32::MAX), Err(u32::MAX));
	}

	#[cfg(feature = "windows-interop")]
	#[test]
	fn nt_status_converts_to_projected_windows_type() {
		let status = NtStatus::from_raw(i32::from_ne_bytes(0xC000_0022_u32.to_ne_bytes()));
		let windows_status: windows::Win32::Foundation::NTSTATUS = status.into();
		assert_eq!(NtStatus::from(windows_status), status);
	}
}
