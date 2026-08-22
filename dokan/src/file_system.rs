use std::{
	any::Any,
	error::Error,
	fmt::{self, Display, Formatter},
	ptr,
	sync::{Arc, RwLock},
	time::Duration,
};

use crate::{RuntimeGuard, WRAPPER_VERSION, file_system_handler::FileSystemHandler, operations};
use bitflags::bitflags;
use dokan_sys::{
	DOKAN_DRIVE_LETTER_ERROR, DOKAN_DRIVER_INSTALL_ERROR, DOKAN_ERROR, DOKAN_HANDLE,
	DOKAN_MOUNT_ERROR, DOKAN_MOUNT_POINT_ERROR, DOKAN_OPERATIONS, DOKAN_OPTION_ALLOW_IPC_BATCHING,
	DOKAN_OPTION_ALT_STREAM, DOKAN_OPTION_CASE_SENSITIVE, DOKAN_OPTION_CURRENT_SESSION,
	DOKAN_OPTION_DEBUG, DOKAN_OPTION_DISPATCH_DRIVER_LOGS,
	DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE, DOKAN_OPTION_FILELOCK_USER_MODE,
	DOKAN_OPTION_MOUNT_MANAGER, DOKAN_OPTION_NETWORK, DOKAN_OPTION_REMOVABLE, DOKAN_OPTION_STDERR,
	DOKAN_OPTION_WRITE_PROTECT, DOKAN_OPTIONS, DOKAN_START_ERROR, DOKAN_SUCCESS,
	DOKAN_VERSION_ERROR, DokanCloseHandle, DokanCreateFileSystem, DokanWaitForFileSystemClosed,
	VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE,
};
use widestring::{U16CStr, U16CString};

const INFINITE: u32 = u32::MAX;

bitflags! {
	/// Flags that control behavior of the mounted volume, as part of [`MountOptions`].
	#[derive(Debug, Clone, Eq, PartialEq)]
	pub struct MountFlags : u32 {
		/// Enable debug message output.
		const DEBUG = DOKAN_OPTION_DEBUG;

		/// Write debug messages to stderr.
		const STDERR = DOKAN_OPTION_STDERR;

		/// Enable support for alternative streams.
		///
		/// The driver will fail any attempts to access a path with a colon (`:`).
		const ALT_STREAM = DOKAN_OPTION_ALT_STREAM;

		/// Make the mounted volume write-protected (i.e. read-only).
		const WRITE_PROTECT = DOKAN_OPTION_WRITE_PROTECT;

		/// Mount as a network drive.
		///
		/// Dokan network provider must be installed for this to work.
		const NETWORK = DOKAN_OPTION_NETWORK;

		/// Mount as a removable device.
		const REMOVABLE = DOKAN_OPTION_REMOVABLE;

		/// Use Mount Manager to mount the volume.
		const MOUNT_MANAGER = DOKAN_OPTION_MOUNT_MANAGER;

		/// Mount the volume on current session only.
		const CURRENT_SESSION = DOKAN_OPTION_CURRENT_SESSION;

		/// Use [`FileSystemHandler::lock_file`] and [`FileSystemHandler::unlock_file`] to handle
		/// file locking.
		///
		/// Dokan will take care of file locking if this flags is not present.
		const FILELOCK_USER_MODE = DOKAN_OPTION_FILELOCK_USER_MODE;

		/// Case sensitive path.
		///
		///	By default all paths are case insensitive.
		///
		///	For case sensitive: `\dir\File` & `\diR\file` are different files,
		///	but for case insensitive they are the same.
		const CASE_SENSITIVE = DOKAN_OPTION_CASE_SENSITIVE;

		/// Allow unmounting network drives from Windows Explorer.
		const ENABLE_UNMOUNT_NETWORK_DRIVE = DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE;

		/// Forward the kernel driver global and volume logs to the userland.
		const DISPATCH_DRIVER_LOGS = DOKAN_OPTION_DISPATCH_DRIVER_LOGS;

		/// Pull batches of events from the driver instead of a single one and execute them parallelly.
		/// This option should only be used on computers with low cpu count
		/// and userland filesystem taking time to process requests (like remote storage).
		const ALLOW_IPC_BATCHING = DOKAN_OPTION_ALLOW_IPC_BATCHING;
	}
}

/// Options for [`FileSystemMounter::new`].
#[derive(Clone)]
pub struct MountOptions {
	/// Only use a single thread to process events. This is highly not recommended as can easily create a bottleneck.
	pub single_thread: bool,

	/// Controls behavior of the volume.
	pub flags: MountFlags,

	/// UNC Name for the Network Redirector.
	///
	/// See [Support for UNC Naming].
	///
	/// [Support for UNC Naming]: https://msdn.microsoft.com/en-us/library/windows/hardware/ff556761(v=vs.85).aspx
	pub unc_name: Option<U16CString>,

	/// Max timeout of each request before Dokan gives up to wait events to complete.
	/// Timeout request is a sign that the userland implementation is no longer able to properly manage requests in time.
	/// The driver will therefore unmount the device when a timeout trigger in order to keep the system stable.
	///
	/// This timeout can be temporarily extended for an operation with
	/// [`OperationInfo::reset_timeout`].
	///
	/// If zero, defaults to 15 seconds.
	///
	/// [`OperationInfo::reset_timeout`]: crate::OperationInfo::reset_timeout
	pub timeout: Duration,

	/// Allocation Unit Size of the volume. This will affect the file size.
	pub allocation_unit_size: u32,

	/// Sector Size of the volume. This will affect the file size.
	pub sector_size: u32,

	/// Optional Volume Security descriptor.
	///
	/// See [`InitializeSecurityDescriptor`].
	///
	/// [`InitializeSecurityDescriptor`]: https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-initializesecuritydescriptor
	/// The descriptor must be self-relative and no larger than
	/// [`VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE`] bytes.
	pub volume_security_descriptor: Option<Vec<u8>>,
}

impl Default for MountOptions {
	fn default() -> Self {
		Self {
			single_thread: false,
			flags: MountFlags::empty(),
			unc_name: None,
			timeout: Duration::ZERO,
			allocation_unit_size: 0,
			sector_size: 0,
			volume_security_descriptor: None,
		}
	}
}

/// Error type for [`FileSystemMounter::mount`].
#[repr(i32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileSystemMountError {
	/// A general error.
	General = DOKAN_ERROR,

	/// Bad drive letter.
	DriveLetter = DOKAN_DRIVE_LETTER_ERROR,

	/// Can't install the Dokan driver.
	DriverInstall = DOKAN_DRIVER_INSTALL_ERROR,

	/// The driver responds that something is wrong.
	Start = DOKAN_START_ERROR,

	/// Can't assign a drive letter or mount point.
	///
	/// This probably means that the mount point is already used by another volume.
	Mount = DOKAN_MOUNT_ERROR,

	/// The mount point is invalid.
	MountPoint = DOKAN_MOUNT_POINT_ERROR,

	/// The Dokan version that this wrapper is targeting is incompatible with the loaded Dokan
	/// library.
	Version = DOKAN_VERSION_ERROR,
}

impl From<i32> for FileSystemMountError {
	fn from(value: i32) -> Self {
		match value {
			DOKAN_DRIVE_LETTER_ERROR => Self::DriveLetter,
			DOKAN_DRIVER_INSTALL_ERROR => Self::DriverInstall,
			DOKAN_START_ERROR => Self::Start,
			DOKAN_MOUNT_ERROR => Self::Mount,
			DOKAN_MOUNT_POINT_ERROR => Self::MountPoint,
			DOKAN_VERSION_ERROR => Self::Version,
			_ => Self::General,
		}
	}
}

impl Error for FileSystemMountError {}

impl Display for FileSystemMountError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			FileSystemMountError::General => "general error",
			FileSystemMountError::DriveLetter => "bad drive letter",
			FileSystemMountError::DriverInstall => "can't install driver",
			FileSystemMountError::Start => "the driver responds that something is wrong",
			FileSystemMountError::Mount => {
				"can't assign a drive letter or mount point, probably already used by another volume"
			}
			FileSystemMountError::MountPoint => "the mount point is invalid",
			FileSystemMountError::Version => "requested an incompatible version",
		};
		write!(f, "{msg}")
	}
}

struct MountState<FSH: FileSystemHandler> {
	_runtime: RuntimeGuard,
	// Boxed separately so the pointer stored in GlobalContext is stable.
	_handler: Arc<FSH>,
	_mount_point: U16CString,
	_unc_name: Option<U16CString>,
	options: DOKAN_OPTIONS,
	operations: DOKAN_OPERATIONS,
}

/// An owned, configured filesystem ready to mount.
///
/// All strings and callback state are owned by this value. Nothing passed to
/// [`new`](Self::new) is borrowed by Dokany.
pub struct FileSystemMounter<FSH: FileSystemHandler> {
	state: Box<MountState<FSH>>,
}

impl<FSH: FileSystemHandler> FileSystemMounter<FSH> {
	/// Creates an owned filesystem configuration.
	///
	/// # Arguments
	///
	/// * `handler` - Implements [`FileSystemHandler`].
	/// * `mount_point`- Can be a driver letter like `"M"` or a folder path `"C:\mount\dokan"` on a NTFS partition.
	/// * `options` - Customizes behavior.
	///
	/// # Panics
	///
	/// Panics if the volume security descriptor is larger than
	/// [`VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE`].
	pub fn new(handler: FSH, mount_point: impl AsRef<U16CStr>, options: MountOptions) -> Self {
		let handler = Arc::new(handler);
		let mount_point = mount_point.as_ref().to_owned();
		let unc_name = options.unc_name;
		let mut volume_security_descriptor = [0; VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE];
		let volume_security_descriptor_length = options
			.volume_security_descriptor
			.as_ref()
			.map_or(0, Vec::len);
		assert!(
			volume_security_descriptor_length <= VOLUME_SECURITY_DESCRIPTOR_MAX_SIZE,
			"volume security descriptor exceeds Dokany's maximum size"
		);
		if let Some(descriptor) = options.volume_security_descriptor {
			for (destination, source) in volume_security_descriptor.iter_mut().zip(descriptor) {
				*destination = i8::from_ne_bytes([source]);
			}
		}
		let raw_options = DOKAN_OPTIONS {
			Version: u16::try_from(WRAPPER_VERSION)
				.expect("the bundled Dokany version must fit in DOKAN_OPTIONS::Version"),
			SingleThread: options.single_thread.into(),
			Options: options.flags.bits(),
			GlobalContext: Arc::as_ptr(&handler) as u64,
			MountPoint: mount_point.as_ptr(),
			UNCName: unc_name.as_ref().map_or(ptr::null(), |name| name.as_ptr()),
			Timeout: duration_millis(options.timeout),
			AllocationUnitSize: options.allocation_unit_size,
			SectorSize: options.sector_size,
			VolumeSecurityDescriptorLength: u32::try_from(volume_security_descriptor_length)
				.expect("Dokany's maximum security descriptor size fits in u32"),
			VolumeSecurityDescriptor: volume_security_descriptor,
		};
		let operations = DOKAN_OPERATIONS {
			ZwCreateFile: Some(operations::create_file::<FSH>),
			Cleanup: Some(operations::cleanup::<FSH>),
			CloseFile: Some(operations::close_file::<FSH>),
			ReadFile: Some(operations::read_file::<FSH>),
			WriteFile: Some(operations::write_file::<FSH>),
			FlushFileBuffers: Some(operations::flush_file_buffers::<FSH>),
			GetFileInformation: Some(operations::get_file_information::<FSH>),
			FindFiles: Some(operations::find_files::<FSH>),
			FindFilesWithPattern: Some(operations::find_files_with_pattern::<FSH>),
			SetFileAttributesW: Some(operations::set_file_attributes::<FSH>),
			SetFileTime: Some(operations::set_file_time::<FSH>),
			DeleteFileW: Some(operations::delete_file::<FSH>),
			DeleteDirectory: Some(operations::delete_directory::<FSH>),
			MoveFileW: Some(operations::move_file::<FSH>),
			SetEndOfFile: Some(operations::set_end_of_file::<FSH>),
			SetAllocationSize: Some(operations::set_allocation_size::<FSH>),
			LockFile: Some(operations::lock_file::<FSH>),
			UnlockFile: Some(operations::unlock_file::<FSH>),
			GetDiskFreeSpaceW: Some(operations::get_disk_free_space::<FSH>),
			GetVolumeInformationW: Some(operations::get_volume_information::<FSH>),
			Mounted: Some(operations::mounted::<FSH>),
			Unmounted: Some(operations::unmounted::<FSH>),
			GetFileSecurityW: Some(operations::get_file_security::<FSH>),
			SetFileSecurityW: Some(operations::set_file_security::<FSH>),
			FindStreams: Some(operations::find_streams::<FSH>),
		};
		Self {
			state: Box::new(MountState {
				_runtime: RuntimeGuard::acquire(),
				_handler: handler,
				_mount_point: mount_point,
				_unc_name: unc_name,
				options: raw_options,
				operations,
			}),
		}
	}

	/// Mounts the filesystem without blocking the calling thread.
	///
	/// # Errors
	///
	/// Returns a [`FileSystemMountError`] when Dokany cannot create or mount the
	/// configured filesystem.
	pub fn mount(mut self) -> Result<FileSystem, FileSystemMountError> {
		let mut instance = ptr::null_mut();

		let result = unsafe {
			DokanCreateFileSystem(
				&raw mut self.state.options,
				&raw mut self.state.operations,
				&raw mut instance,
			)
		};

		if result == DOKAN_SUCCESS {
			Ok(FileSystem {
				instance: Arc::new(FileSystemInstance {
					raw: RwLock::new(Some(instance as usize)),
					_state: self.state,
				}),
			})
		} else {
			Err(result.into())
		}
	}
}

fn duration_millis(duration: Duration) -> u32 {
	u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

unsafe impl<FSH: FileSystemHandler> Send for MountState<FSH> {}
unsafe impl<FSH: FileSystemHandler> Sync for MountState<FSH> {}

/// A successfully mounted file system.
///
/// When dropped, the current thread will block until the file system gets unmounted.
pub struct FileSystem {
	instance: Arc<FileSystemInstance>,
}

impl FileSystem {
	/// Returns a cloneable handle used by notification functions.
	#[must_use]
	pub fn instance(&self) -> FileSystemHandle {
		FileSystemHandle(Arc::clone(&self.instance))
	}
}

impl PartialEq for FileSystem {
	fn eq(&self, other: &Self) -> bool {
		Arc::ptr_eq(&self.instance, &other.instance)
	}
}

impl Drop for FileSystem {
	fn drop(&mut self) {
		unsafe {
			DokanWaitForFileSystemClosed(self.instance.raw(), INFINITE);
		}
		self.instance.close();
	}
}

/// A handle to a [`FileSystem`] instance, to be passed to `notify_*` functions.
///
struct FileSystemInstance {
	raw: RwLock<Option<usize>>,
	_state: Box<dyn Any + Send + Sync>,
}

// Dokany explicitly supports using an instance from multiple threads.
unsafe impl Send for FileSystemInstance {}
unsafe impl Sync for FileSystemInstance {}

impl FileSystemInstance {
	fn raw(&self) -> DOKAN_HANDLE {
		self.raw
			.read()
			.expect("filesystem handle lock poisoned")
			.expect("filesystem handle already closed") as DOKAN_HANDLE
	}

	fn close(&self) {
		if let Some(raw) = self
			.raw
			.write()
			.expect("filesystem handle lock poisoned")
			.take()
		{
			unsafe { DokanCloseHandle(raw as DOKAN_HANDLE) }
		}
	}
}

/// A shared, owning handle to a filesystem instance.
///
/// Clones keep the native Dokany handle allocated. Once the filesystem is
/// unmounted, notification calls safely fail instead of accessing freed memory.
#[derive(Clone)]
pub struct FileSystemHandle(Arc<FileSystemInstance>);

impl FileSystemHandle {
	pub(crate) fn with_raw(&self, f: impl FnOnce(DOKAN_HANDLE) -> bool) -> bool {
		let raw = self.0.raw.read().expect("filesystem handle lock poisoned");
		raw.is_some_and(|raw| f(raw as DOKAN_HANDLE))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn timeout_conversion_saturates_at_the_native_limit() {
		assert_eq!(duration_millis(Duration::ZERO), 0);
		assert_eq!(duration_millis(Duration::from_millis(42)), 42);
		assert_eq!(
			duration_millis(Duration::from_millis(u64::from(u32::MAX) + 1)),
			u32::MAX
		);
	}

	#[test]
	fn mount_errors_have_stable_native_mappings() {
		assert_eq!(
			FileSystemMountError::from(DOKAN_DRIVE_LETTER_ERROR),
			FileSystemMountError::DriveLetter
		);
		assert_eq!(
			FileSystemMountError::from(DOKAN_VERSION_ERROR),
			FileSystemMountError::Version
		);
		assert_eq!(
			FileSystemMountError::from(i32::MAX),
			FileSystemMountError::General
		);
		assert_eq!(
			FileSystemMountError::MountPoint.to_string(),
			"the mount point is invalid"
		);
	}
}
