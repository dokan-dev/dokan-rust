use crate::FileSystemHandle;
use dokan_sys::{
	DokanNotifyCreate, DokanNotifyDelete, DokanNotifyRename, DokanNotifyUpdate,
	DokanNotifyXAttrUpdate,
};
use widestring::U16CStr;

const TRUE: i32 = 1;

/// Notifies Dokan that a file or directory has been created.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_create(instance: &FileSystemHandle, path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	instance.with_raw(|raw| unsafe {
		DokanNotifyCreate(raw, path.as_ref().as_ptr(), is_dir.into()) == TRUE
	})
}

/// Notifies Dokan that a file or directory has been deleted.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_delete(instance: &FileSystemHandle, path: impl AsRef<U16CStr>, is_dir: bool) -> bool {
	instance.with_raw(|raw| unsafe {
		DokanNotifyDelete(raw, path.as_ref().as_ptr(), is_dir.into()) == TRUE
	})
}

/// Notifies Dokan that attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_update(instance: &FileSystemHandle, path: impl AsRef<U16CStr>) -> bool {
	instance.with_raw(|raw| unsafe { DokanNotifyUpdate(raw, path.as_ref().as_ptr()) == TRUE })
}

/// Notifies Dokan that extended attributes of a file or directory has been changed.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_xattr_update(instance: &FileSystemHandle, path: impl AsRef<U16CStr>) -> bool {
	instance.with_raw(|raw| unsafe { DokanNotifyXAttrUpdate(raw, path.as_ref().as_ptr()) == TRUE })
}

/// Notifies Dokan that a file or directory has been renamed.
///
/// `is_same_dir` indicates if the new file or directory is in the same directory as the old one.
///
/// Returns `true` on success.
#[must_use]
pub fn notify_rename(
	instance: &FileSystemHandle,
	old_path: impl AsRef<U16CStr>,
	new_path: impl AsRef<U16CStr>,
	is_dir: bool,
	is_same_dir: bool,
) -> bool {
	instance.with_raw(|raw| unsafe {
		DokanNotifyRename(
			raw,
			old_path.as_ref().as_ptr(),
			new_path.as_ref().as_ptr(),
			is_dir.into(),
			is_same_dir.into(),
		) == TRUE
	})
}
