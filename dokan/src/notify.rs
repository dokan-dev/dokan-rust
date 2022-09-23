use dokan_sys::{
	DokanNotifyCreate, DokanNotifyDelete, DokanNotifyRename, DokanNotifyUpdate,
	DokanNotifyXAttrUpdate,
};
use widestring::U16CStr;
use winapi::shared::minwindef::TRUE;

use crate::FileSystemHandle;

/// Notifies Dokan that a file or directory has been created.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_create(instance: FileSystemHandle, path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyCreate(instance.0, path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

/// Notifies Dokan that a file or directory has been deleted.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_delete(instance: FileSystemHandle, path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	unsafe { DokanNotifyDelete(instance.0, path.as_ref().as_ptr(), is_dir.into()) == TRUE }
}

/// Notifies Dokan that attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_update(instance: FileSystemHandle, path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyUpdate(instance.0, path.as_ref().as_ptr()) == TRUE }
}

/// Notifies Dokan that extended attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_xattr_update(instance: FileSystemHandle, path: impl AsRef<U16CStr>) -> bool {
	unsafe { DokanNotifyXAttrUpdate(instance.0, path.as_ref().as_ptr()) == TRUE }
}

/// Notifies Dokan that a file or directory has been renamed.
///
/// `is_same_dir` indicates if the new file or directory is in the same directory as the old one.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_rename(
	instance: FileSystemHandle,
	old_path: impl AsRef<U16CStr>,
	new_path: impl AsRef<U16CStr>,
	is_dir: bool,
	is_same_dir: bool,
) -> bool {
	unsafe {
		DokanNotifyRename(
			instance.0,
			old_path.as_ref().as_ptr(),
			new_path.as_ref().as_ptr(),
			is_dir.into(),
			is_same_dir.into(),
		) == TRUE
	}
}
