use std::{iter::Map, mem::transmute, slice};

use dokan_sys::{
	win32::{FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_NETWORK_FILE_SYSTEM},
	*,
};
use widestring::U16CStr;
use winapi::shared::minwindef::ULONG;

/// Mount point device type.
#[repr(u32)]
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceType {
	Disk = FILE_DEVICE_DISK_FILE_SYSTEM,
	Network = FILE_DEVICE_NETWORK_FILE_SYSTEM,
}

impl From<u32> for DeviceType {
	fn from(value: u32) -> Self {
		unsafe { transmute(value) }
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
			Some(U16CStr::from_slice_with_nul(&info.MountPoint).unwrap())
		};

		let unc_name = if info.UNCName[0] == 0 {
			None
		} else {
			Some(U16CStr::from_slice_with_nul(&info.UNCName).unwrap())
		};

		MountPointInfo {
			device_type: info.Type.into(),
			mount_point,
			unc_name,
			device_name: U16CStr::from_slice_with_nul(&info.DeviceName).unwrap(),
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
	pub fn len(&self) -> usize {
		self.len
	}
}

impl<'a> IntoIterator for &'a MountPointList {
	type Item = MountPointInfo<'a>;

	type IntoIter = Map<
		slice::Iter<'a, DOKAN_MOUNT_POINT_INFO>,
		fn(&'a DOKAN_MOUNT_POINT_INFO) -> MountPointInfo,
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
pub fn list_mount_points<'a>(unc_only: bool) -> Option<MountPointList> {
	unsafe {
		let mut len: ULONG = 0;
		let list_ptr = DokanGetMountPointList(unc_only.into(), &mut len);
		if list_ptr.is_null() {
			None
		} else {
			let len = len as usize;
			Some(MountPointList { list_ptr, len })
		}
	}
}

#[test]
fn can_list_mount_points() {
	use std::process;

	use regex::Regex;
	use winapi::{shared::minwindef::TRUE, um::processthreadsapi::ProcessIdToSessionId};

	use crate::usage_tests::{convert_str, with_test_drive};

	with_test_drive(|_| unsafe {
		let list = list_mount_points(false).unwrap();
		let list_as_vec: Vec<_> = list.into_iter().collect();
		assert_eq!(list_as_vec.len(), 1);
		let info = &list_as_vec[0];
		assert_eq!(info.device_type, DeviceType::Disk);
		assert_eq!(
			info.mount_point,
			Some(convert_str("\\DosDevices\\Z:").as_ref())
		);
		assert_eq!(info.unc_name, None);
		assert!(
			Regex::new(r"^\\Device\\Volume\{[0-9a-z]{8}-([0-9a-z]{4}-){3}[0-9a-z]{12}\}$")
				.unwrap()
				.is_match(&info.device_name.to_string_lossy())
		);
		let mut session_id = 0;
		assert_eq!(ProcessIdToSessionId(process::id(), &mut session_id), TRUE);
		assert_eq!(info.session_id, session_id);
	});
}
