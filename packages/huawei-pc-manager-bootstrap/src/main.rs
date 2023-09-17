#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //Hide console window in release builds on Windows, this blocks stdout.
#![feature(iter_intersperse)]

use app::BootstrapApp;
use clap::Parser;
use iced::{Application, Font, Settings};
use widestring::WideCString;
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};

mod app;
mod logger;
mod version;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    ensure_admin: bool,

    #[clap(long)]
    install: Option<String>,

    #[clap(long)]
    install_patch: bool,

    #[clap(long)]
    terminate: bool,
}

fn main() {
    let args = Args::parse();

    let is_admin = unsafe { IsUserAnAdmin() != 0 };
    if !is_admin {
        if args.ensure_admin {
            println!("No administrator");
            return;
        }
        let executable_file_null_ter = WideCString::from_str(format!(
            "{}\0",
            std::env::current_exe().unwrap().to_str().unwrap()
        ))
        .unwrap();

        let mut cmd_line: String = std::env::args()
            .skip(1)
            .map(|s| {
                if s.contains(' ') && !s.starts_with('"') {
                    format!("\"{}\"", s)
                } else {
                    s
                }
            })
            .intersperse(" ".to_string())
            .collect();
        cmd_line.push_str(" --ensure-admin");

        let cmd_line = WideCString::from_str(cmd_line).unwrap();
        unsafe {
            ShellExecuteW(
                0,
                WideCString::from_str("runas\0").unwrap().as_ptr(),
                executable_file_null_ter.as_ptr(),
                cmd_line.as_ptr(),
                0 as _,
                5,
            )
        };
        return;
    }

    if args.terminate {
        app::BootstrapApp::terminate_all_processes().unwrap();
    }

    if args.install_patch {
        app::BootstrapApp::install_patch().unwrap();
    }

    if let Some(path) = args.install {
        let mut app = app::BootstrapApp::default();
        app.setup_logger(false).unwrap();
        app.start_ipc_logger().unwrap();
        app.install_hooks().unwrap();
        app.set_executable_file_path(path);
        app.start_install(true).unwrap();
    } else if !args.terminate && !args.install_patch {
        BootstrapApp::run(Settings {
            default_font: Font::with_name("微软雅黑"),
            ..Default::default()
        })
        .unwrap();
    }
}
