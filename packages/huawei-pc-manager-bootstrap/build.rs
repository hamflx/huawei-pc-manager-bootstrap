use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn get_git_version() -> String {
    let version = env::var("CARGO_PKG_VERSION").unwrap();

    let child = Command::new("git").args(&["describe", "--always"]).output();
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
    let version = get_git_version();
    let mut version_file =
        File::create(Path::new(&env::var("OUT_DIR").unwrap()).join("VERSION")).unwrap();
    version_file.write_all(version.trim().as_bytes()).unwrap();
}
