use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn get_git_version() -> String {
    let version = env::var("CARGO_PKG_VERSION").unwrap();

    let child = Command::new("git").args(["describe", "--always"]).output();
    match child {
        Ok(child) => {
            version
                + "-"
                + String::from_utf8(child.stdout)
                    .expect("failed to read stdout")
                    .as_str()
        }
        Err(_) => version,
    }
}

fn main() {
    // Build the x64 patch first, then embed those exact bytes in the x86 launcher.
    // An unqualified Cargo artifact dependency would build an x86 patch instead.
    // OUT_DIR reflects --target-dir, Cargo config, and custom profiles too.
    let out_dir = std::path::PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("Unexpected Cargo OUT_DIR");
    let target = env::var("TARGET").unwrap();
    let mut target_dir = profile_dir.parent().unwrap();
    if target_dir.file_name().and_then(|name| name.to_str()) == Some(target.as_str()) {
        target_dir = target_dir.parent().unwrap();
    }
    let patch = target_dir
        .join("x86_64-pc-windows-msvc")
        .join(profile_dir.file_name().unwrap())
        .join("version.dll");
    assert!(
        patch.is_file(),
        "Build the x64 version DLL first (see build-release.bat): {}",
        patch.display()
    );
    // Keep the displayed commit current even if only launcher sources changed.
    for name in ["HEAD", "refs", "packed-refs"] {
        if let Ok(output) = Command::new("git")
            .args(["rev-parse", "--git-path", name])
            .output()
        {
            if output.status.success() {
                println!(
                    "cargo:rerun-if-changed={}",
                    String::from_utf8_lossy(&output.stdout).trim()
                );
            }
        }
    }
    println!("cargo:rerun-if-changed={}", patch.display());
    println!("cargo:rustc-env=PC_MANAGER_PATCH_DLL={}", patch.display());
    let version = get_git_version();
    let mut version_file =
        File::create(Path::new(&env::var("OUT_DIR").unwrap()).join("VERSION")).unwrap();
    version_file.write_all(version.trim().as_bytes()).unwrap();
}
