//! Property-fuzz smoke tests that run on Windows through the normal test runner.

use dokan_fuzz::{exercise_api_inputs, exercise_name_expression};

#[test]
fn generated_api_inputs_preserve_invariants() {
	bolero::check!()
		.with_type::<[u8; 20]>()
		.cloned()
		.for_each(|data| {
			exercise_api_inputs(&data);
			true
		});
}

#[test]
fn generated_name_expressions_are_deterministic() {
	bolero::check!()
		.with_type::<([u8; 64], u8)>()
		.cloned()
		.for_each(|(data, len)| {
			let len = usize::from(len) % (data.len() + 1);
			exercise_name_expression(&data[..len]);
			true
		});
}
