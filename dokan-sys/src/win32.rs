use winapi::shared::minwindef::MAX_PATH;
use winapi::shared::ntdef::{LARGE_INTEGER, WCHAR};

#[repr(C)]
pub struct WIN32_FIND_STREAM_DATA {
	pub StreamSize: LARGE_INTEGER,
	pub cStreamName: [WCHAR; MAX_PATH + 36],
}

pub type PWIN32_FIND_STREAM_DATA = *mut WIN32_FIND_STREAM_DATA;
