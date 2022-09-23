use std::{
	error::Error,
	fmt::{self, Display, Formatter},
};

use winapi::shared::{
	ntdef::NTSTATUS,
	ntstatus::{STATUS_BUFFER_OVERFLOW, STATUS_INTERNAL_ERROR},
};

/// Error type for the `fill_data` callbacks.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FillDataError {
	/// File name exceeds the limit of [`MAX_PATH`].
	///
	/// [`MAX_PATH`]: winapi::shared::minwindef::MAX_PATH
	NameTooLong,

	/// Buffer is full.
	BufferFull,
}

impl Into<NTSTATUS> for FillDataError {
	fn into(self) -> NTSTATUS {
		match self {
			FillDataError::NameTooLong => STATUS_INTERNAL_ERROR,
			FillDataError::BufferFull => STATUS_BUFFER_OVERFLOW,
		}
	}
}

impl Error for FillDataError {}

impl Display for FillDataError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			FillDataError::NameTooLong => "file name length exceeds the limit of MAX_PATH",
			FillDataError::BufferFull => "buffer is full",
		};
		write!(f, "{}", msg)
	}
}

/// Returned by `fill_data` callbacks.
pub type FillDataResult = Result<(), FillDataError>;
