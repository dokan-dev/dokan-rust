use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dokan_sys::FILETIME;

use crate::to_file_time::FILETIME_OFFSET;

/// Operation to perform on a file's corresponding time information.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FileTimeOperation {
	/// Set corresponding time information of the file.
	SetTime(SystemTime),
	/// Don't change corresponding time information of the file.
	DontChange,
	/// Disable update of corresponding time information caused by further operations on the file handle.
	DisableUpdate,
	/// Resume update of corresponding time information caused by further operations on the file handle.
	ResumeUpdate,
}

impl FileTimeOperation {
	/// Converts the nullable `FILETIME` pointer supplied by Dokany.
	///
	/// # Safety
	///
	/// A non-null `time` must point to a readable, initialized [`FILETIME`].
	pub(crate) unsafe fn from_raw(time: *const FILETIME) -> Self {
		if time.is_null() {
			return Self::DontChange;
		}

		// FILETIME is two little-endian 32-bit words. Reading its fields avoids
		// relying on the layout of LARGE_INTEGER or using a transmute.
		let time = unsafe { &*time };
		let bits = u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32);
		match bits {
			0 => Self::DontChange,
			u64::MAX => Self::DisableUpdate,
			value if value == u64::MAX - 1 => Self::ResumeUpdate,
			_ => {
				let ticks = bits;
				Self::SetTime(
					UNIX_EPOCH - FILETIME_OFFSET
						+ Duration::from_micros(ticks / 10)
						+ Duration::from_nanos(ticks % 10 * 100),
				)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use std::ptr;

	use super::*;
	use crate::to_file_time::split_u64;

	fn raw_filetime(bits: u64) -> FILETIME {
		let (low, high) = split_u64(bits);
		FILETIME {
			dwLowDateTime: low,
			dwHighDateTime: high,
		}
	}

	#[test]
	fn recognizes_filetime_control_values() {
		let unchanged = raw_filetime(0);
		let disabled = raw_filetime(u64::MAX);
		let resumed = raw_filetime(u64::MAX - 1);

		// SAFETY: Each non-null pointer refers to an initialized FILETIME that
		// remains alive for the duration of the call.
		unsafe {
			assert_eq!(
				FileTimeOperation::from_raw(ptr::null()),
				FileTimeOperation::DontChange
			);
			assert_eq!(
				FileTimeOperation::from_raw(&raw const unchanged),
				FileTimeOperation::DontChange
			);
			assert_eq!(
				FileTimeOperation::from_raw(&raw const disabled),
				FileTimeOperation::DisableUpdate
			);
			assert_eq!(
				FileTimeOperation::from_raw(&raw const resumed),
				FileTimeOperation::ResumeUpdate
			);
		}
	}

	#[test]
	fn converts_regular_filetime_ticks() {
		let unix_epoch_ticks = FILETIME_OFFSET.as_secs() * 10_000_000;
		let unix_epoch = raw_filetime(unix_epoch_ticks);
		let one_tick_later = raw_filetime(unix_epoch_ticks + 1);

		// SAFETY: Both pointers refer to initialized FILETIME values.
		unsafe {
			assert_eq!(
				FileTimeOperation::from_raw(&raw const unix_epoch),
				FileTimeOperation::SetTime(UNIX_EPOCH)
			);
			assert_eq!(
				FileTimeOperation::from_raw(&raw const one_tick_later),
				FileTimeOperation::SetTime(UNIX_EPOCH + Duration::from_nanos(100))
			);
		}
	}
}
