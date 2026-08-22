//! Shared input exercisers used by fuzz engines and property tests.

use dokan::{
	AccessRights, CreateDisposition, CreateOptions, FileAttributes, NtStatus,
	map_kernel_to_user_create_file_flags,
};
use widestring::U16CString;

fn word(data: &[u8], offset: usize) -> u32 {
	let mut bytes = [0; 4];
	let available = data.len().saturating_sub(offset).min(bytes.len());
	if available != 0 {
		bytes[..available].copy_from_slice(&data[offset..offset + available]);
	}
	u32::from_le_bytes(bytes)
}

/// Exercises typed flag conversion and NT-status round trips with arbitrary bytes.
///
/// # Panics
///
/// Panics if a public API violates its documented round-trip or determinism
/// invariants.
pub fn exercise_api_inputs(data: &[u8]) {
	let access = AccessRights::from_bits_retain(word(data, 0));
	let attributes = FileAttributes::from_bits_retain(word(data, 4));
	let options = CreateOptions::from_bits_retain(word(data, 8));
	let disposition_raw = word(data, 12);

	if let Ok(disposition) = CreateDisposition::try_from(disposition_raw) {
		assert_eq!(disposition as u32, disposition_raw);
	}

	let disposition =
		CreateDisposition::try_from(disposition_raw % 6).expect("modulo produces a valid value");
	let first = map_kernel_to_user_create_file_flags(access, attributes, options, disposition);
	let second = map_kernel_to_user_create_file_flags(access, attributes, options, disposition);
	assert_eq!(first, second);

	let status_bits = word(data, 16);
	let status = NtStatus::from_raw(i32::from_ne_bytes(status_bits.to_ne_bytes()));
	assert_eq!(
		u32::from_ne_bytes(status.into_raw().to_ne_bytes()),
		status_bits
	);
	assert_eq!(status.is_success(), status.into_raw() >= 0);
	let _ = format!("{status:?} {status}");
}

/// Exercises Dokany's UTF-16 filename-expression matcher with arbitrary bytes.
///
/// # Panics
///
/// Panics if matching the same expression twice produces inconsistent results.
pub fn exercise_name_expression(data: &[u8]) {
	if data.is_empty() {
		return;
	}

	let units = data[1..]
		.chunks(2)
		.map(|chunk| {
			let low = chunk[0];
			let high = chunk.get(1).copied().unwrap_or_default();
			u16::from_le_bytes([low, high]).max(1)
		})
		.collect::<Vec<_>>();
	let split = usize::from(data[0]) % (units.len() + 1);
	let expression =
		U16CString::from_vec(units[..split].to_vec()).expect("input contains no NUL units");
	let name = U16CString::from_vec(units[split..].to_vec()).expect("input contains no NUL units");

	let case_sensitive = dokan::is_name_in_expression(&expression, &name, false);
	let case_insensitive = dokan::is_name_in_expression(&expression, &name, true);
	assert_eq!(
		case_sensitive,
		dokan::is_name_in_expression(&expression, &name, false)
	);
	assert_eq!(
		case_insensitive,
		dokan::is_name_in_expression(&expression, &name, true)
	);
}
