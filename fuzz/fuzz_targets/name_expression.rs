//! Fuzzes Dokany's UTF-16 filename-expression matcher.
#![cfg_attr(fuzzing, no_main)]

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
	dokan_fuzz::exercise_name_expression(data);
});

#[cfg(not(fuzzing))]
fn main() {}
