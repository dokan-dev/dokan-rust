use widestring::{U16CStr, U16CString, U16Str, U16String};

/// Borrowed text that is encoded as UTF-16 only when Dokany needs it.
///
/// Accepting both UTF-8 and UTF-16 lets filesystem implementations pass names
/// in their native representation without first allocating a
/// [`U16CString`]. Embedded nulls are rejected when the value is copied into a
/// null-terminated Windows buffer.
#[derive(Debug, Clone, Copy)]
pub enum WideStringRef<'a> {
	/// A Rust UTF-8 string.
	Utf8(&'a str),
	/// A potentially non-null-terminated UTF-16 string.
	Utf16(&'a U16Str),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum WideStringCopyError {
	EmbeddedNull,
	TooLong,
}

impl WideStringRef<'_> {
	pub(crate) fn copy_exact(self, destination: &mut [u16]) -> Result<(), WideStringCopyError> {
		match self {
			Self::Utf8(value) => copy_utf8_exact(value, destination),
			Self::Utf16(value) => copy_utf16_exact(value, destination),
		}
	}

	pub(crate) fn copy_truncated(self, destination: &mut [u16]) -> Result<(), WideStringCopyError> {
		if destination.is_empty() {
			return Ok(());
		}
		match self {
			Self::Utf8(value) => copy_utf8_truncated(value, destination),
			Self::Utf16(value) => copy_utf16_truncated(value, destination),
		}
	}
}

impl<'a> From<&'a str> for WideStringRef<'a> {
	fn from(value: &'a str) -> Self {
		Self::Utf8(value)
	}
}

impl<'a> From<&'a String> for WideStringRef<'a> {
	fn from(value: &'a String) -> Self {
		Self::Utf8(value)
	}
}

impl<'a> From<&'a U16Str> for WideStringRef<'a> {
	fn from(value: &'a U16Str) -> Self {
		Self::Utf16(value)
	}
}

impl<'a> From<&'a U16String> for WideStringRef<'a> {
	fn from(value: &'a U16String) -> Self {
		Self::Utf16(value.as_ustr())
	}
}

impl<'a> From<&'a U16CStr> for WideStringRef<'a> {
	fn from(value: &'a U16CStr) -> Self {
		Self::Utf16(value.as_ustr())
	}
}

impl<'a> From<&'a U16CString> for WideStringRef<'a> {
	fn from(value: &'a U16CString) -> Self {
		Self::Utf16(value.as_ustr())
	}
}

fn copy_utf8_exact(value: &str, destination: &mut [u16]) -> Result<(), WideStringCopyError> {
	if value.contains('\0') {
		return Err(WideStringCopyError::EmbeddedNull);
	}
	let mut written = 0;
	for character in value.chars() {
		let mut encoded = [0; 2];
		let units = character.encode_utf16(&mut encoded);
		let end = written + units.len();
		if end >= destination.len() {
			return Err(WideStringCopyError::TooLong);
		}
		destination[written..end].copy_from_slice(units);
		written = end;
	}
	let terminator = destination
		.get_mut(written)
		.ok_or(WideStringCopyError::TooLong)?;
	*terminator = 0;
	Ok(())
}

fn copy_utf16_exact(value: &U16Str, destination: &mut [u16]) -> Result<(), WideStringCopyError> {
	let source = value.as_slice();
	if source.contains(&0) {
		return Err(WideStringCopyError::EmbeddedNull);
	}
	if source.len() >= destination.len() {
		return Err(WideStringCopyError::TooLong);
	}
	destination[..source.len()].copy_from_slice(source);
	destination[source.len()] = 0;
	Ok(())
}

fn copy_utf8_truncated(value: &str, destination: &mut [u16]) -> Result<(), WideStringCopyError> {
	if value.contains('\0') {
		return Err(WideStringCopyError::EmbeddedNull);
	}
	let capacity = destination.len() - 1;
	let mut written = 0;
	for character in value.chars() {
		let mut encoded = [0; 2];
		let units = character.encode_utf16(&mut encoded);
		let end = written + units.len();
		if end > capacity {
			break;
		}
		destination[written..end].copy_from_slice(units);
		written = end;
	}
	destination[written] = 0;
	Ok(())
}

fn copy_utf16_truncated(
	value: &U16Str,
	destination: &mut [u16],
) -> Result<(), WideStringCopyError> {
	let source = value.as_slice();
	if source.contains(&0) {
		return Err(WideStringCopyError::EmbeddedNull);
	}
	let count = source.len().min(destination.len() - 1);
	destination[..count].copy_from_slice(&source[..count]);
	destination[count] = 0;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn utf8_is_encoded_directly_into_a_terminated_buffer() {
		let mut output = [u16::MAX; 8];
		WideStringRef::from("café")
			.copy_exact(&mut output)
			.expect("name fits");
		assert_eq!(
			&output[..5],
			&[b'c'.into(), b'a'.into(), b'f'.into(), 0xE9, 0]
		);
	}

	#[test]
	fn exact_copy_rejects_overflow_and_embedded_nulls() {
		let mut output = [0; 4];
		assert_eq!(
			WideStringRef::from("four").copy_exact(&mut output),
			Err(WideStringCopyError::TooLong)
		);
		assert_eq!(
			WideStringRef::from("a\0b").copy_exact(&mut output),
			Err(WideStringCopyError::EmbeddedNull)
		);
	}

	#[test]
	fn truncated_copy_preserves_character_boundaries_and_termination() {
		let mut output = [u16::MAX; 3];
		WideStringRef::from("😀x")
			.copy_truncated(&mut output)
			.expect("valid text");
		assert_eq!(output, [0xD83D, 0xDE00, 0]);
	}
}
