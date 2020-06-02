extern crate cc;

use std::env;
use std::fs;
use std::process::{Command, Stdio};

use cc::{Build, Tool};

fn print_env(compiler: &Tool) {
	eprintln!("Environment variables:");
	for (k, v) in env::vars() {
		eprintln!("{}={}", k, v);
	}
	eprintln!("\nCompiler:\n{}", compiler.path().to_string_lossy());
	eprintln!("\nCompiler arguments:");
	for arg in compiler.args().iter() {
		eprintln!("{}", arg.to_string_lossy());
	}
	eprintln!("\nCompiler environment variables:");
	for (k, v) in compiler.env().iter() {
		eprintln!("{}={}", k.to_string_lossy(), v.to_string_lossy());
	}
}

fn run_generator(compiler: &Tool) -> String {
	let out_dir = env::var("OUT_DIR").unwrap();
	let mut compiler_cmd = compiler.to_command();
	compiler_cmd
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.arg("-Isrc/dokany/dokan")
		.arg("-Isrc/dokany/sys");
	if compiler.is_like_msvc() {
		compiler_cmd
			.arg(format!("/Fo{}/", out_dir))
			.arg("src/generate_version.c")
			.arg("/link")
			.arg(format!("/OUT:{}/generate_version.exe", out_dir))
	} else {
		compiler_cmd
			.arg(format!("-o{}/generate_version.exe", out_dir))
			.arg("src/generate_version.c")
	};
	assert!(compiler_cmd.output().unwrap().status.success());
	let generate_output = Command::new(format!("{}/generate_version.exe", out_dir))
		.current_dir(&out_dir)
		.output().unwrap();
	assert!(generate_output.status.success());
	println!("cargo:rerun-if-changed=src/generate_version.c");

	String::from_utf8(fs::read(format!("{}/version.txt", out_dir)).unwrap()).unwrap()
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

fn build_dokan(compiler: &Tool, version_major: &str) {
	let out_dir = env::var("OUT_DIR").unwrap();
	let src = fs::read_dir("src/dokany/dokan").unwrap()
		.map(|d| d.unwrap().path())
		.filter(|p| if let Some(ext) = p.extension() { ext == "c" } else { false });
	let dll_name = format!("dokan{}.dll", version_major);
	let dll_path = format!("{}/{}", out_dir, dll_name);
	let mut compiler_cmd = compiler.to_command();
	compiler_cmd
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.arg("-D_WINDLL")
		.arg("-D_EXPORTING")
		.arg("-DUNICODE")
		.arg("-D_UNICODE")
		.arg("-Isrc/dokany/sys");
	if compiler.is_like_msvc() {
		compiler_cmd
			.arg(format!("/Fo{}/", out_dir))
			.args(src)
			.arg("/link")
			.arg("/DLL")
			.arg("/DEF:src/dokany/dokan/dokan.def")
			.arg(format!("/OUT:{}", dll_path))
			.arg(format!("/IMPLIB:{}/dokan{}.lib", out_dir, version_major))
			.arg("advapi32.lib")
			.arg("shell32.lib")
			.arg("user32.lib")
	} else {
		compiler_cmd
			.arg("-shared")
			.arg(format!("-o{}", dll_path))
			.args(src)
			.arg(format!("-Wl,--out-implib,{}/dokan{}.lib", out_dir, version_major))
	};
	assert!(compiler_cmd.output().unwrap().status.success());
	if let Ok(output_path) = env::var("DOKAN_DLL_OUTPUT_PATH") {
		fs::copy(dll_path, format!("{}/{}", output_path, dll_name)).unwrap();
	}
	println!("cargo:rerun-if-env-changed=DOKAN_DLL_OUTPUT_PATH");
	println!("cargo:rustc-link-search=native={}", out_dir);
	println!("cargo:rerun-if-changed=src/dokany");
}

fn main() {
	let compiler = Build::new().get_compiler();
	print_env(&compiler);
	let version = run_generator(&compiler);
	assert_eq!(
		format!("dokan{}", version),
		env::var("CARGO_PKG_VERSION").unwrap().split('+').last().unwrap(),
		"Mismatch detected between crate version and bundled Dokan source version.",
	);
	let version_major = &version[..1];
	println!("cargo:rustc-link-lib=dylib=dokan{}", version_major);
	if !check_dokan_env(version_major) {
		build_dokan(&compiler, version_major);
	};
}
