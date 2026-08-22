use std::panic::{self, AssertUnwindSafe};

use crate::{NtStatus, status};

pub type NtResult = Result<(), NtStatus>;

pub fn wrap_nt_result<F: FnOnce() -> NtResult>(f: F) -> i32 {
	// Unwind safety is not a safety property here: the callback is abandoned
	// after a panic and Dokany receives an error. Requiring user state to
	// implement RefUnwindSafe incorrectly rejected normal mutex-based handlers.
	panic::catch_unwind(AssertUnwindSafe(f))
		.map_or(status::INTERNAL_ERROR, |result| match result {
			Ok(()) => status::SUCCESS,
			Err(nt_status) => nt_status,
		})
		.into_raw()
}

pub fn wrap_unit<F: FnOnce()>(f: F) {
	let _ = panic::catch_unwind(AssertUnwindSafe(f));
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn converts_callback_results_to_native_statuses() {
		assert_eq!(wrap_nt_result(|| Ok(())), status::SUCCESS.into_raw());
		assert_eq!(
			wrap_nt_result(|| Err(status::ACCESS_DENIED)),
			status::ACCESS_DENIED.into_raw()
		);
	}

	#[test]
	fn contains_panics_at_the_ffi_boundary() {
		assert_eq!(
			wrap_nt_result(|| panic!("test callback panic")),
			status::INTERNAL_ERROR.into_raw()
		);
		wrap_unit(|| panic!("test unit callback panic"));
	}
}
