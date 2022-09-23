use std::time::{Duration, SystemTime, UNIX_EPOCH};

use winapi::shared::minwindef::FILETIME;

pub const FILETIME_OFFSET: Duration = Duration::from_secs(11644473600);

pub trait ToFileTime {
	fn to_filetime(&self) -> FILETIME;
}

impl ToFileTime for SystemTime {
	fn to_filetime(&self) -> FILETIME {
		let intervals = self
			.duration_since(UNIX_EPOCH - FILETIME_OFFSET)
			.unwrap_or(Duration::from_secs(0))
			.as_nanos() / 100;
		FILETIME {
			dwLowDateTime: intervals as u32,
			dwHighDateTime: (intervals >> 32) as u32,
		}
	}
}
