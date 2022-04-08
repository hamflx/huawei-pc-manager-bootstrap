#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //Hide console window in release builds on Windows, this blocks stdout.

use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteA};

mod app;
mod common;
mod communication;

// When compiling natively:
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    let is_admin = unsafe { IsUserAnAdmin() != 0 };
    let ensure_admin = std::env::args().any(|a| a == "--ensure-admin");
    if !is_admin {
        if ensure_admin {
            println!("No administrator");
            return;
        }
        let executable_file_null_ter =
            format!("{}\0", std::env::current_exe().unwrap().to_str().unwrap());
        unsafe {
            ShellExecuteA(
                0,
                "runas\0".as_ptr(),
                executable_file_null_ter.as_ptr(),
                "--ensure-admin\0".as_ptr(),
                0 as *const u8,
                5,
            )
        };
        return;
    }

    let app = app::BootstrapApp::default();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(app), native_options);
}
