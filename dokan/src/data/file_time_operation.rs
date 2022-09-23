use std::{
	mem::transmute_copy,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use winapi::shared::minwindef::FILETIME;

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

impl From<*const FILETIME> for FileTimeOperation {
	fn from(time: *const FILETIME) -> Self {
		unsafe {
			let time_val = transmute_copy::<_, i64>(&*time);
			match time_val {
				0 => FileTimeOperation::DontChange,
				-1 => FileTimeOperation::DisableUpdate,
				-2 => FileTimeOperation::ResumeUpdate,
				_ => {
					let time_val = time_val as u64;
					FileTimeOperation::SetTime(
						UNIX_EPOCH - FILETIME_OFFSET
							+ Duration::from_micros(time_val / 10)
							+ Duration::from_nanos(time_val % 10 * 100),
					)
				}
			}
		}
	}
}
