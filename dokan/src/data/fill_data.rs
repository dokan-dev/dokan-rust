use std::{
	error::Error,
	fmt::{self, Display, Formatter},
};

use crate::{NtStatus, status};

/// Error type for the `fill_data` callbacks.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FillDataError {
	/// File name exceeds the limit of [`MAX_PATH`].
	///
	/// [`MAX_PATH`]: https://learn.microsoft.com/windows/win32/fileio/maximum-file-path-limitation
	NameTooLong,

	/// File or stream name contains an embedded null.
	EmbeddedNull,
}

impl From<FillDataError> for NtStatus {
	fn from(err: FillDataError) -> NtStatus {
		match err {
			FillDataError::NameTooLong => status::INTERNAL_ERROR,
			FillDataError::EmbeddedNull => status::INVALID_PARAMETER,
		}
	}
}

impl Error for FillDataError {}

impl Display for FillDataError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let msg = match self {
			FillDataError::NameTooLong => "file name length exceeds the limit of MAX_PATH",
			FillDataError::EmbeddedNull => "file name contains an embedded null",
		};
		write!(f, "{msg}")
	}
}

/// Whether Dokany accepted an entry or filled the caller's output buffer.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[must_use]
pub enum FillDataStatus {
	/// The entry was accepted and more entries may be supplied.
	Continue,
	/// The output buffer is full; no more entries should be supplied.
	BufferFull,
}

impl FillDataStatus {
	/// Returns whether the caller's output buffer is full.
	#[must_use]
	pub const fn is_full(self) -> bool {
		matches!(self, Self::BufferFull)
	}
}

/// Result returned when an entry is supplied to a Dokany data filler.
pub type FillDataResult = Result<FillDataStatus, FillDataError>;
