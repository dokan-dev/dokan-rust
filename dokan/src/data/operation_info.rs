use std::{
	marker::PhantomData,
	os::windows::prelude::{FromRawHandle, OwnedHandle},
	time::Duration,
};

use dokan_sys::{
	DokanOpenRequestorToken, DokanResetTimeout, DOKAN_FILE_INFO, DOKAN_OPTIONS, PDOKAN_FILE_INFO,
};
use widestring::U16CStr;
use winapi::{shared::minwindef::TRUE, um::handleapi::INVALID_HANDLE_VALUE};

use crate::{file_system_handler::FileSystemHandler, MountFlags};

/// Information about the current operation.
#[derive(Debug)]
pub struct OperationInfo<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h> {
	file_info: PDOKAN_FILE_INFO,
	phantom_handler: PhantomData<&'h FSH>,
	phantom_context: PhantomData<&'c FSH::Context>,
}

impl<'c, 'h: 'c, FSH: FileSystemHandler<'c, 'h> + 'h> OperationInfo<'c, 'h, FSH> {
	pub fn new(file_info: PDOKAN_FILE_INFO) -> Self {
		OperationInfo {
			file_info,
			phantom_handler: PhantomData,
			phantom_context: PhantomData,
		}
	}

	pub fn file_info(&self) -> &DOKAN_FILE_INFO {
		unsafe { &*self.file_info }
	}

	pub fn mount_options(&self) -> &DOKAN_OPTIONS {
		unsafe { &*self.file_info().DokanOptions }
	}

	pub fn handler(&self) -> &'h FSH {
		unsafe { &*(self.mount_options().GlobalContext as *const _) }
	}

	pub fn context(&self) -> &'c FSH::Context {
		unsafe { &*(self.file_info().Context as *const _) }
	}

	pub fn drop_context(&mut self) {
		unsafe {
			let info = &mut *self.file_info;
			let ptr = info.Context as *mut FSH::Context;
			if !ptr.is_null() {
				drop(Box::from_raw(ptr));
				info.Context = 0;
			}
		}
	}

	/// Gets process ID of the calling process.
	pub fn pid(&self) -> u32 {
		self.file_info().ProcessId
	}

	/// Gets whether the target file is a directory.
	pub fn is_dir(&self) -> bool {
		self.file_info().IsDirectory != 0
	}

	/// Gets whether the file should be deleted when it is closed.
	pub fn delete_on_close(&self) -> bool {
		self.file_info().DeleteOnClose != 0
	}

	/// Gets whether it is a paging I/O operation.
	pub fn paging_io(&self) -> bool {
		self.file_info().PagingIo != 0
	}

	/// Gets whether it is a synchronous I/O operation.
	pub fn synchronous_io(&self) -> bool {
		self.file_info().SynchronousIo != 0
	}

	/// Gets whether it is a non-cached I/O operation.
	pub fn no_cache(&self) -> bool {
		self.file_info().Nocache != 0
	}

	/// Gets whether the current write operation should write to end of file instead of the
	/// position specified by the offset argument.
	pub fn write_to_eof(&self) -> bool {
		self.file_info().WriteToEndOfFile != 0
	}

	/// Gets the number of threads used to handle file system operations.
	pub fn single_thread(&self) -> bool {
		self.mount_options().SingleThread != 0
	}

	/// Gets flags that controls behavior of the mounted volume.
	pub fn mount_flags(&self) -> MountFlags {
		MountFlags::from_bits_truncate(self.mount_options().Options)
	}

	/// Gets mount point path.
	pub fn mount_point(&self) -> Option<&U16CStr> {
		let ptr = self.mount_options().MountPoint;
		if ptr.is_null() {
			None
		} else {
			unsafe { Some(U16CStr::from_ptr_str(ptr)) }
		}
	}

	/// Gets UNC name of the network drive.
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
	pub fn timeout(&self) -> Duration {
		Duration::from_millis(self.mount_options().Timeout.into())
	}

	/// Gets allocation unit size of the volume.
	pub fn allocation_unit_size(&self) -> u32 {
		self.mount_options().AllocationUnitSize
	}

	/// Gets sector size of the volume.
	pub fn sector_size(&self) -> u32 {
		self.mount_options().SectorSize
	}

	/// Temporarily extend the timeout of the current operation.
	///
	/// Returns `true` on success.
	#[must_use]
	pub fn reset_timeout(&self, timeout: Duration) -> bool {
		unsafe { DokanResetTimeout(timeout.as_millis() as u32, self.file_info) == TRUE }
	}

	/// Gets the access token associated with the calling process.
	///
	/// Returns `None` on error.
	pub fn requester_token(&self) -> Option<OwnedHandle> {
		unsafe {
			let value = DokanOpenRequestorToken(self.file_info);
			if value == INVALID_HANDLE_VALUE {
				None
			} else {
				Some(OwnedHandle::from_raw_handle(value))
			}
		}
	}
}
