//! Fuzzes typed flag conversion and NT-status round trips.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
	dokan_fuzz::exercise_api_inputs(data);
});

#[cfg(not(fuzzing))]
fn main() {}
