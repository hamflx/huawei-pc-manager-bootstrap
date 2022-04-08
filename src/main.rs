#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //Hide console window in release builds on Windows, this blocks stdout.

use std::{
    env,
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

// use communication::InterProcessComServer;
use log::info;
use simple_logger::SimpleLogger;
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

// use crate::common::InjectOptions;

mod app;
mod common;
mod communication;

// When compiling natively:
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use windows_sys::Win32::UI::Shell::ShellExecuteA;

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

// fn main() {
//     SimpleLogger::new().init().unwrap();

//     let server = InterProcessComServer::listen("127.0.0.1:0").unwrap();
//     let address = server.get_address().unwrap();
//     server.start();

//     info!("Listening on {}", address.to_string());

//     common::enable_hook(Some(InjectOptions {
//         server_address: Some(address.to_string()),
//     }));

//     let self_args: Vec<String> = env::args().skip(1).collect();
//     let command_name = self_args.get(0).unwrap().to_owned();
//     let command_args = self_args.into_iter().skip(1).collect::<Vec<String>>();
//     info!(
//         "Executing {} with args: {}",
//         command_name,
//         command_args.join(" ")
//     );
//     let command = Command::new(command_name)
//         .args(command_args)
//         .spawn()
//         .unwrap();

//     let command_for_wait = Arc::new(Mutex::new(command));
//     let command_for_exit = command_for_wait.clone();
//     ctrlc::set_handler(move || {
//         info!("Exiting...");
//         command_for_exit.lock().unwrap().kill().unwrap();
//         std::process::exit(0);
//     })
//     .expect("Error setting Ctrl-C handler");

//     while let Ok(exit_status) = command_for_wait.lock().unwrap().try_wait() {
//         if let Some(exit_code) = exit_status {
//             info!("Command exited with {}", exit_code);
//             break;
//         }
//         thread::sleep(Duration::from_millis(50));
//     }
// }
