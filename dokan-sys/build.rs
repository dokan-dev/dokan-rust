//! Builds or locates the native Dokany user-mode library used by `dokan-sys`.

extern crate cc;

use std::{
	env, fs,
	process::{Command, Stdio},
};

use cc::{Build, Tool};

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
			.arg(format!("/Fo{out_dir}/"))
			.arg("src/generate_version.c")
			.arg("/link")
			.arg(format!("/OUT:{out_dir}/generate_version.exe"))
	} else {
		compiler_cmd
			.arg(format!("-o{out_dir}/generate_version.exe"))
			.arg("src/generate_version.c")
	};
	assert!(compiler_cmd.output().unwrap().status.success());
	let generate_output = Command::new(format!("{out_dir}/generate_version.exe"))
		.current_dir(&out_dir)
		.output()
		.unwrap();
	assert!(generate_output.status.success());
	println!("cargo:rerun-if-changed=src/generate_version.c");

	String::from_utf8(fs::read(format!("{out_dir}/version.txt")).unwrap()).unwrap()
}

fn check_dokan_env(version_major: &str) -> bool {
	let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_ref() {
		"x86" => "x86",
		"x86_64" => "x64",
		_ => panic!("Unsupported target architecture!"),
	};
	let env_name = format!("DokanLibrary{version_major}_LibraryPath_{arch}");
	println!("cargo:rerun-if-env-changed={env_name}");
	if let Ok(lib_path) = env::var(&env_name) {
		println!("cargo:rustc-link-search=native={lib_path}");
		true
	} else {
		println!(
			"cargo:warning=Environment variable {env_name} not found, building Dokan from source."
		);
		false
	}
}

fn build_dokan(compiler: &Tool, version_major: &str, output_path: Option<&str>) {
	let out_dir = env::var("OUT_DIR").unwrap();
	let src = fs::read_dir("src/dokany/dokan")
		.unwrap()
		.map(|d| d.unwrap().path())
		.filter(|p| {
			if let Some(ext) = p.extension() {
				ext == "c"
			} else {
				false
			}
		});
	let dll_name = format!("dokan{version_major}.dll");
	let dll_path = format!("{out_dir}/{dll_name}");
	let mut compiler_cmd = compiler.to_command();
	compiler_cmd
		.stdout(Stdio::inherit())
		.stderr(Stdio::inherit())
		.arg("-D_WINDLL")
		.arg("-D_EXPORTING")
		.arg("-DUNICODE")
		.arg("-D_UNICODE")
		.arg("-DWINVER=0x0A00")
		.arg("-D_WIN32_WINNT=0x0A00")
		.arg("-Isrc/dokany/sys");
	if compiler.is_like_msvc() {
		compiler_cmd
			.arg(format!("/Fo{out_dir}/"))
			.args(src)
			.arg("/link")
			.arg("/DLL")
			.arg("/DEF:src/dokany/dokan/dokan.def")
			.arg(format!("/OUT:{dll_path}"))
			.arg(format!("/IMPLIB:{out_dir}/dokan{version_major}.lib"))
			.arg("advapi32.lib")
			.arg("shell32.lib")
			.arg("user32.lib")
	} else {
		compiler_cmd
			.arg("-shared")
			.arg(format!("-o{dll_path}"))
			.args(src)
			.arg(format!(
				"-Wl,--out-implib,{out_dir}/dokan{version_major}.lib"
			))
	};
	assert!(compiler_cmd.output().unwrap().status.success());
	if let Some(output_path) = output_path {
		fs::create_dir_all(output_path).unwrap();
		fs::copy(dll_path, format!("{output_path}/{dll_name}")).unwrap();
	}
	println!("cargo:rerun-if-env-changed=DOKAN_DLL_OUTPUT_PATH");
	println!("cargo:rustc-link-search=native={out_dir}");
	println!("cargo:rerun-if-changed=src/dokany");
}

fn main() {
	let compiler = Build::new().get_compiler();
	let version = run_generator(&compiler);
	assert_eq!(
		format!("dokan{version}"),
		env::var("CARGO_PKG_VERSION")
			.unwrap()
			.split('+')
			.next_back()
			.unwrap(),
		"Mismatch detected between crate version and bundled Dokan source version.",
	);
	let version_major = &version[..1];
	println!("cargo:rustc-link-lib=dylib=dokan{version_major}");
	let output_path = env::var("DOKAN_DLL_OUTPUT_PATH").ok();
	if !check_dokan_env(version_major) || output_path.is_some() {
		build_dokan(&compiler, version_major, output_path.as_deref());
	}
}
