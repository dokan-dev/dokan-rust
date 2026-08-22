use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dokan_sys::FILETIME;

pub const FILETIME_OFFSET: Duration = Duration::from_secs(11_644_473_600);

pub(crate) const fn split_u64(value: u64) -> (u32, u32) {
	let bytes = value.to_le_bytes();
	(
		u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
		u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
	)
}

pub trait ToFileTime {
	fn to_filetime(&self) -> FILETIME;
}

impl ToFileTime for SystemTime {
	fn to_filetime(&self) -> FILETIME {
		let intervals =
			self.duration_since(UNIX_EPOCH - FILETIME_OFFSET)
				.unwrap_or(Duration::from_secs(0))
				.as_nanos() / 100;
		let intervals = u64::try_from(intervals).unwrap_or(u64::MAX);
		let (low, high) = split_u64(intervals);
		FILETIME {
			dwLowDateTime: low,
			dwHighDateTime: high,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn filetime_bits(time: FILETIME) -> u64 {
		u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32)
	}

	#[test]
	fn split_u64_preserves_both_words() {
		assert_eq!(split_u64(0xFEDC_BA98_7654_3210), (0x7654_3210, 0xFEDC_BA98));
		assert_eq!(split_u64(u64::MAX), (u32::MAX, u32::MAX));
	}

	#[test]
	fn system_time_conversion_uses_filetime_epoch_and_precision() {
		let filetime_epoch = UNIX_EPOCH - FILETIME_OFFSET;

		assert_eq!(filetime_bits(filetime_epoch.to_filetime()), 0);
		assert_eq!(
			filetime_bits((filetime_epoch + Duration::from_nanos(99)).to_filetime()),
			0
		);
		assert_eq!(
			filetime_bits((filetime_epoch + Duration::from_nanos(100)).to_filetime()),
			1
		);
		assert_eq!(
			filetime_bits(UNIX_EPOCH.to_filetime()),
			FILETIME_OFFSET.as_secs() * 10_000_000
		);
		if let Some(before_filetime_epoch) = filetime_epoch.checked_sub(Duration::from_nanos(100)) {
			assert_eq!(filetime_bits(before_filetime_epoch.to_filetime()), 0);
		}
	}
}
