use std::{iter::Map, slice};

use dokan_sys::{
	DOKAN_MOUNT_POINT_INFO, DokanGetMountPointList, DokanReleaseMountPointList,
	PDOKAN_MOUNT_POINT_INFO,
	win32::{FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_NETWORK_FILE_SYSTEM},
};
use widestring::U16CStr;

/// Mount point device type.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
	/// A local disk filesystem.
	Disk,
	/// A network filesystem.
	Network,
	/// A device type introduced by a newer or nonstandard Dokany build.
	Unknown(u32),
}

impl From<u32> for DeviceType {
	fn from(value: u32) -> Self {
		match value {
			FILE_DEVICE_DISK_FILE_SYSTEM => Self::Disk,
			FILE_DEVICE_NETWORK_FILE_SYSTEM => Self::Network,
			value => Self::Unknown(value),
		}
	}
}

/// Information about a mount point listed by [`list_mount_points`].
#[derive(Debug, Clone)]
pub struct MountPointInfo<'a> {
	/// File system type of the mounted volume.
	pub device_type: DeviceType,

	/// Mount point path.
	pub mount_point: Option<&'a U16CStr>,

	/// UNC name of the network volume.
	pub unc_name: Option<&'a U16CStr>,

	/// Device name of the mounted volume.
	pub device_name: &'a U16CStr,

	/// The session in which the volume is mounted.
	///
	/// It will be `-1` if the volume is mounted globally.
	pub session_id: u32,
}

impl<'a> From<&'a DOKAN_MOUNT_POINT_INFO> for MountPointInfo<'a> {
	fn from(info: &'a DOKAN_MOUNT_POINT_INFO) -> Self {
		let mount_point = if info.MountPoint[0] == 0 {
			None
		} else {
			Some(U16CStr::from_slice_truncate(&info.MountPoint).unwrap())
		};

		let unc_name = if info.UNCName[0] == 0 {
			None
		} else {
			Some(U16CStr::from_slice_truncate(&info.UNCName).unwrap())
		};

		MountPointInfo {
			device_type: info.Type.into(),
			mount_point,
			unc_name,
			device_name: U16CStr::from_slice_truncate(&info.DeviceName).unwrap(),
			session_id: info.SessionId,
		}
	}
}

/// A list of [`MountPointInfo`] provided by [`list_mount_points`].
pub struct MountPointList {
	list_ptr: PDOKAN_MOUNT_POINT_INFO,
	len: usize,
}

impl MountPointList {
	/// Iterates over the mount-point information owned by this list.
	pub fn iter(&self) -> impl ExactSizeIterator<Item = MountPointInfo<'_>> {
		unsafe { slice::from_raw_parts(self.list_ptr, self.len) }
			.iter()
			.map(Into::into)
	}
}

impl<'a> IntoIterator for &'a MountPointList {
	type Item = MountPointInfo<'a>;

	type IntoIter = Map<
		slice::Iter<'a, DOKAN_MOUNT_POINT_INFO>,
		fn(&'a DOKAN_MOUNT_POINT_INFO) -> MountPointInfo<'a>,
	>;

	fn into_iter(self) -> Self::IntoIter {
		unsafe { slice::from_raw_parts(self.list_ptr, self.len) }
			.iter()
			.map(Into::into)
	}
}

impl Drop for MountPointList {
	fn drop(&mut self) {
		unsafe {
			DokanReleaseMountPointList(self.list_ptr);
		}
	}
}

/// Lists of active Dokan mount points.
///
/// Returns `None` in case of error.
#[must_use]
pub fn list_mount_points(unc_only: bool) -> Option<MountPointList> {
	unsafe {
		let mut len: u32 = 0;
		let list_ptr = DokanGetMountPointList(unc_only.into(), &raw mut len);
		if list_ptr.is_null() {
			None
		} else {
			let len = len as usize;
			Some(MountPointList { list_ptr, len })
		}
	}
}
