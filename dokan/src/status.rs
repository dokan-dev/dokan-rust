//! Common NT status values returned by filesystem operations.
//!
//! The constants use the stable [`NtStatus`] representation,
//! so callers do not need a Windows binding crate merely to report errors.

use crate::NtStatus;

const fn from_u32_bits(value: u32) -> NtStatus {
	NtStatus::from_raw(i32::from_ne_bytes(value.to_ne_bytes()))
}

/// The operation completed successfully.
pub const SUCCESS: NtStatus = NtStatus::from_raw(0x0000_0000);
/// The output buffer was too small to contain all available data.
pub const BUFFER_OVERFLOW: NtStatus = from_u32_bits(0x8000_0005);
/// The caller does not have permission to perform the operation.
pub const ACCESS_DENIED: NtStatus = from_u32_bits(0xC000_0022);
/// The supplied handle is invalid.
pub const INVALID_HANDLE: NtStatus = from_u32_bits(0xC000_0008);
/// One or more operation parameters are invalid.
pub const INVALID_PARAMETER: NtStatus = from_u32_bits(0xC000_000D);
/// The requested operation is not implemented.
pub const NOT_IMPLEMENTED: NtStatus = from_u32_bits(0xC000_0002);
/// The operation failed without a more specific status.
pub const UNSUCCESSFUL: NtStatus = from_u32_bits(0xC000_0001);
/// The request is not valid for this device.
pub const INVALID_DEVICE_REQUEST: NtStatus = from_u32_bits(0xC000_0010);
/// The supplied object name is invalid.
pub const OBJECT_NAME_INVALID: NtStatus = from_u32_bits(0xC000_0033);
/// The requested object name does not exist.
pub const OBJECT_NAME_NOT_FOUND: NtStatus = from_u32_bits(0xC000_0034);
/// The requested object name already exists.
pub const OBJECT_NAME_COLLISION: NtStatus = from_u32_bits(0xC000_0035);
/// A component of the requested path does not exist.
pub const OBJECT_PATH_NOT_FOUND: NtStatus = from_u32_bits(0xC000_003A);
/// Existing sharing modes prevent the requested access.
pub const SHARING_VIOLATION: NtStatus = from_u32_bits(0xC000_0043);
/// The object is already pending deletion.
pub const DELETE_PENDING: NtStatus = from_u32_bits(0xC000_0056);
/// The object cannot be deleted.
pub const CANNOT_DELETE: NtStatus = from_u32_bits(0xC000_0121);
/// A file operation targeted a directory.
pub const FILE_IS_A_DIRECTORY: NtStatus = from_u32_bits(0xC000_00BA);
/// A directory operation targeted a non-directory.
pub const NOT_A_DIRECTORY: NtStatus = from_u32_bits(0xC000_0103);
/// The directory cannot be removed because it contains entries.
pub const DIRECTORY_NOT_EMPTY: NtStatus = from_u32_bits(0xC000_0101);
/// An unexpected internal error occurred.
pub const INTERNAL_ERROR: NtStatus = from_u32_bits(0xC000_00E5);

// Windows-compatible spellings ease migration without exposing a binding crate.
/// Windows-compatible alias for [`SUCCESS`].
pub const STATUS_SUCCESS: NtStatus = SUCCESS;
/// Windows-compatible alias for [`BUFFER_OVERFLOW`].
pub const STATUS_BUFFER_OVERFLOW: NtStatus = BUFFER_OVERFLOW;
/// Windows-compatible alias for [`ACCESS_DENIED`].
pub const STATUS_ACCESS_DENIED: NtStatus = ACCESS_DENIED;
/// Windows-compatible alias for [`INVALID_HANDLE`].
pub const STATUS_INVALID_HANDLE: NtStatus = INVALID_HANDLE;
/// Windows-compatible alias for [`INVALID_PARAMETER`].
pub const STATUS_INVALID_PARAMETER: NtStatus = INVALID_PARAMETER;
/// Windows-compatible alias for [`NOT_IMPLEMENTED`].
pub const STATUS_NOT_IMPLEMENTED: NtStatus = NOT_IMPLEMENTED;
/// Windows-compatible alias for [`UNSUCCESSFUL`].
pub const STATUS_UNSUCCESSFUL: NtStatus = UNSUCCESSFUL;
/// Windows-compatible alias for [`INVALID_DEVICE_REQUEST`].
pub const STATUS_INVALID_DEVICE_REQUEST: NtStatus = INVALID_DEVICE_REQUEST;
/// Windows-compatible alias for [`OBJECT_NAME_INVALID`].
pub const STATUS_OBJECT_NAME_INVALID: NtStatus = OBJECT_NAME_INVALID;
/// Windows-compatible alias for [`OBJECT_NAME_NOT_FOUND`].
pub const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = OBJECT_NAME_NOT_FOUND;
/// Windows-compatible alias for [`OBJECT_NAME_COLLISION`].
pub const STATUS_OBJECT_NAME_COLLISION: NtStatus = OBJECT_NAME_COLLISION;
/// Windows-compatible alias for [`OBJECT_PATH_NOT_FOUND`].
pub const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = OBJECT_PATH_NOT_FOUND;
/// Windows-compatible alias for [`SHARING_VIOLATION`].
pub const STATUS_SHARING_VIOLATION: NtStatus = SHARING_VIOLATION;
/// Windows-compatible alias for [`DELETE_PENDING`].
pub const STATUS_DELETE_PENDING: NtStatus = DELETE_PENDING;
/// Windows-compatible alias for [`CANNOT_DELETE`].
pub const STATUS_CANNOT_DELETE: NtStatus = CANNOT_DELETE;
/// Windows-compatible alias for [`FILE_IS_A_DIRECTORY`].
pub const STATUS_FILE_IS_A_DIRECTORY: NtStatus = FILE_IS_A_DIRECTORY;
/// Windows-compatible alias for [`NOT_A_DIRECTORY`].
pub const STATUS_NOT_A_DIRECTORY: NtStatus = NOT_A_DIRECTORY;
/// Windows-compatible alias for [`DIRECTORY_NOT_EMPTY`].
pub const STATUS_DIRECTORY_NOT_EMPTY: NtStatus = DIRECTORY_NOT_EMPTY;
/// Windows-compatible alias for [`INTERNAL_ERROR`].
pub const STATUS_INTERNAL_ERROR: NtStatus = INTERNAL_ERROR;
