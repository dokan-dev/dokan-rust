use std::panic::{self, UnwindSafe};

use winapi::shared::{
	ntdef::NTSTATUS,
	ntstatus::{STATUS_INTERNAL_ERROR, STATUS_SUCCESS},
};

pub type NtResult = Result<(), NTSTATUS>;

pub fn wrap_nt_result<F: FnOnce() -> NtResult + UnwindSafe>(f: F) -> NTSTATUS {
	panic::catch_unwind(f)
		.map(|result| match result {
			Ok(_) => STATUS_SUCCESS,
			Err(nt_status) => nt_status,
		})
		.unwrap_or(STATUS_INTERNAL_ERROR)
}

#[allow(unused_must_use)]
pub fn wrap_unit<F: FnOnce() + UnwindSafe>(f: F) {
	panic::catch_unwind(f);
}
