extern crate cc;

use std::env;
use std::fs;
use std::process::Command;

use cc::Build;

fn run_generator() -> String {
	let out_dir = env::var("OUT_DIR").unwrap();
	let compiler = Build::new().get_compiler();
	let mut compiler_cmd = compiler.to_command();
	let compiler_output = if compiler.is_like_msvc() {
		compiler_cmd
			.arg("/Isrc/dokany/dokan")
			.arg("/Isrc/dokany/sys")
			.arg(format!("/Fo{}/", out_dir))
			.arg("src/generate_version.c")
			.arg("/link")
			.arg(format!("/OUT:{}/generate_version.exe", out_dir))
			.output().unwrap()
	} else {
		compiler_cmd
			.arg("-Isrc/dokany/dokan")
			.arg("-Isrc/dokany/sys")
			.arg(format!("-o{}/generate_version.exe", out_dir))
			.arg("src/generate_version.c")
			.output().unwrap()
	};
	assert!(compiler_output.status.success());
	let generate_output = Command::new(format!("{}/generate_version.exe", out_dir))
		.current_dir(&out_dir)
		.output().unwrap();
	assert!(generate_output.status.success());
	println!("cargo:rerun-if-changed=src/generate_version.c");

	String::from_utf8(fs::read(format!("{}/version_major.txt", out_dir)).unwrap()).unwrap()
}

fn check_dokan_env(version_major: &str) -> bool {
	let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_ref() {
		"x86" => "x86",
		"x86_64" => "x64",
		_ => panic!("Unsupported target architecture!"),
	};
	let env_name = format!("DokanLibrary{}_LibraryPath_{}", version_major, arch);
	println!("cargo:rerun-if-env-changed={}", env_name);
	if let Ok(lib_path) = env::var(&env_name) {
		println!("cargo:rustc-link-search=native={}", lib_path);
		true
	} else {
		println!("cargo:warning=Environment variable {} not found, building Dokan from source.", env_name);
		false
	}
}

fn build_dokan(version_major: &str) {
	let out_dir = env::var("OUT_DIR").unwrap();
	let src = fs::read_dir("src/dokany/dokan").unwrap()
		.map(|d| d.unwrap().path())
		.filter(|p| if let Some(ext) = p.extension() { ext == "c" } else { false });
	let compiler = Build::new().get_compiler();
	let mut compiler_cmd = compiler.to_command();
	let compiler_output = if compiler.is_like_msvc() {
		compiler_cmd
			.arg("/D_WINDLL")
			.arg("/D_EXPORTING")
			.arg("/DUNICODE")
			.arg("/D_UNICODE")
			.arg("/Isrc/dokany/sys")
			.arg(format!("/Fo{}/", out_dir))
			.args(src)
			.arg("/link")
			.arg("/DLL")
			.arg("/DEF:src/dokany/dokan/dokan.def")
			.arg(format!("/OUT:{}/dokan{}.dll", out_dir, version_major))
			.arg(format!("/IMPLIB:{}/dokan{}.lib", out_dir, version_major))
			.arg("advapi32.lib")
			.arg("shell32.lib")
			.arg("user32.lib")
			.output().unwrap()
	} else {
		compiler_cmd
			.arg("-D_WINDLL")
			.arg("-D_EXPORTING")
			.arg("-DUNICODE")
			.arg("-D_UNICODE")
			.arg("-Isrc/dokany/sys")
			.arg("-shared")
			.arg(format!("-o{}/dokan{}.dll", out_dir, version_major))
			.args(src)
			.arg(format!("-Wl,--out-implib,{}/dokan{}.lib", out_dir, version_major))
			.output().unwrap()
	};
	assert!(compiler_output.status.success());
	println!("cargo:rustc-link-search=native={}", out_dir);
	println!("cargo:rerun-if-changed=src/dokany");
}

fn main() {
	let version_major = run_generator();
	println!("cargo:rustc-link-lib=dylib=dokan{}", version_major);
	if !check_dokan_env(&version_major) {
		build_dokan(&version_major)
	};
}
