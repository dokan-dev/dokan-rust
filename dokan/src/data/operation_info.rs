use std::{
	marker::PhantomData,
	os::windows::prelude::{FromRawHandle, OwnedHandle},
	ptr::NonNull,
	time::Duration,
};

use crate::{MountFlags, NtStatus, file_system_handler::FileSystemHandler, status};
use dokan_sys::{
	DOKAN_FILE_INFO, DOKAN_OPTIONS, DokanOpenRequestorToken, DokanResetTimeout, PDOKAN_FILE_INFO,
};
use widestring::U16CStr;

/// Information about the current operation.
#[derive(Debug)]
pub struct OperationInfo<'a, FSH: FileSystemHandler> {
	file_info: NonNull<DOKAN_FILE_INFO>,
	_callback: PhantomData<&'a FSH>,
}

impl<FSH: FileSystemHandler> OperationInfo<'_, FSH> {
	/// Wraps the operation record supplied by Dokany.
	///
	/// This constructor is crate-private because validity is guaranteed only
	/// while Dokany is executing a callback.
	pub(crate) fn new(file_info: PDOKAN_FILE_INFO) -> Self {
		OperationInfo {
			file_info: NonNull::new(file_info).expect("Dokany supplied a null DOKAN_FILE_INFO"),
			_callback: PhantomData,
		}
	}

	pub(crate) fn file_info(&self) -> &DOKAN_FILE_INFO {
		unsafe { self.file_info.as_ref() }
	}

	pub(crate) fn mount_options(&self) -> &DOKAN_OPTIONS {
		unsafe { &*self.file_info().DokanOptions }
	}

	pub(crate) fn handler(&self) -> &FSH {
		unsafe { &*(self.mount_options().GlobalContext as *const _) }
	}

	pub(crate) fn context(&self) -> Result<&FSH::Context, NtStatus> {
		NonNull::new(self.file_info().Context as *mut FSH::Context)
			.map(|context| unsafe { context.as_ref() })
			.ok_or(status::INVALID_HANDLE)
	}

	pub(crate) fn drop_context(&mut self) {
		unsafe {
			let info = self.file_info.as_mut();
			let ptr = info.Context as *mut FSH::Context;
			if !ptr.is_null() {
				drop(Box::from_raw(ptr));
				info.Context = 0;
			}
		}
	}

	/// Gets process ID of the calling process.
	#[must_use]
	pub fn pid(&self) -> u32 {
		self.file_info().ProcessId
	}

	/// Gets whether the target file is a directory.
	#[must_use]
	pub fn is_dir(&self) -> bool {
		self.file_info().IsDirectory != 0
	}

	/// Gets whether the file should be deleted when it is closed.
	#[must_use]
	pub fn delete_pending(&self) -> bool {
		self.file_info().DeletePending != 0
	}

	/// Gets whether it is a paging I/O operation.
	#[must_use]
	pub fn paging_io(&self) -> bool {
		self.file_info().PagingIo != 0
	}

	/// Gets whether it is a synchronous I/O operation.
	#[must_use]
	pub fn synchronous_io(&self) -> bool {
		self.file_info().SynchronousIo != 0
	}

	/// Gets whether it is a non-cached I/O operation.
	#[must_use]
	pub fn no_cache(&self) -> bool {
		self.file_info().Nocache != 0
	}

	/// Gets whether the current write operation should write to end of file instead of the
	/// position specified by the offset argument.
	#[must_use]
	pub fn write_to_eof(&self) -> bool {
		self.file_info().WriteToEndOfFile != 0
	}

	/// Gets the number of threads used to handle file system operations.
	#[must_use]
	pub fn single_thread(&self) -> bool {
		self.mount_options().SingleThread != 0
	}

	/// Gets flags that controls behavior of the mounted volume.
	#[must_use]
	pub fn mount_flags(&self) -> MountFlags {
		MountFlags::from_bits_truncate(self.mount_options().Options)
	}

	/// Gets mount point path.
	#[must_use]
	pub fn mount_point(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().MountPoint;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	/// Gets UNC name of the network drive.
	#[must_use]
	pub fn unc_name(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().UNCName;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	/// Gets the time that Dokan will wait for an operation to complete.
	///
	/// See [`MountOptions::timeout`] for more information.
	///
	/// [`MountOptions::timeout`]: crate::MountOptions::timeout
	#[must_use]
	pub fn timeout(&self) -> Duration {
		Duration::from_millis(self.mount_options().Timeout.into())
	}

	/// Gets allocation unit size of the volume.
	#[must_use]
	pub fn allocation_unit_size(&self) -> u32 {
		self.mount_options().AllocationUnitSize
	}

	/// Gets sector size of the volume.
	#[must_use]
	pub fn sector_size(&self) -> u32 {
		self.mount_options().SectorSize
	}

	/// Temporarily extend the timeout of the current operation.
	///
	/// Returns `true` on success.
	#[must_use]
	pub fn reset_timeout(&self, timeout: Duration) -> bool {
		let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
		unsafe { DokanResetTimeout(millis, self.file_info.as_ptr()) != 0 }
	}

	/// Gets the access token associated with the calling process.
	///
	/// Returns `None` on error.
	#[must_use]
	pub fn requester_token(&self) -> Option<OwnedHandle> {
		unsafe {
			let value = DokanOpenRequestorToken(self.file_info.as_ptr());
			if value == (-1_isize as std::os::windows::io::RawHandle) {
				None
			} else {
				Some(OwnedHandle::from_raw_handle(value))
			}
		}
	}
}
