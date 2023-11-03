#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //Hide console window in release builds on Windows, this blocks stdout.
#![feature(iter_intersperse)]

use std::{cell::RefCell, io::Write, panic::catch_unwind};

use app::{AppInitializationParams, BootstrapApp};
use backtrace::Backtrace;
use clap::Parser;
use common::config::{get_log_path, get_panics_log_path};
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

thread_local! {
    static BACKTRACE: RefCell<Option<Backtrace>> = RefCell::new(None);
}

fn main() {
    std::panic::set_hook(Box::new(|_| {
        let trace = Backtrace::new();
        BACKTRACE.with(move |b| b.borrow_mut().replace(trace));
    }));
    match catch_unwind(|| app_main()) {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            if let Ok(log_file_path) = get_panics_log_path() {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(log_file_path)
                {
                    let _ = file.write_all(format!("{err:?}").as_bytes());
                }
            }
        }
        Err(_) => {
            if let Ok(log_file_path) = get_panics_log_path() {
                let bt = BACKTRACE.with(|b| b.borrow_mut().take()).unwrap();
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(log_file_path)
                {
                    let _ = file.write_all(format!("{bt:?}").as_bytes());
                }
            }
        }
    }
}

fn app_main() -> anyhow::Result<()> {
    let args = Args::parse();

    let is_admin = unsafe { IsUserAnAdmin() != 0 };
    if !is_admin {
        if args.ensure_admin {
            println!("No administrator");
            return Ok(());
        }
        let executable_file_null_ter = WideCString::from_str(format!(
            "{}\0",
            std::env::current_exe()?
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("No current exe"))?
        ))?;

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

        let cmd_line = WideCString::from_str(cmd_line)?;
        unsafe {
            ShellExecuteW(
                0,
                WideCString::from_str("runas\0")?.as_ptr(),
                executable_file_null_ter.as_ptr(),
                cmd_line.as_ptr(),
                0 as _,
                5,
            )
        };
        return Ok(());
    }

    if args.terminate {
        app::BootstrapApp::terminate_all_processes()?;
    }

    if args.install_patch {
        app::BootstrapApp::install_patch()?;
    }

    if let Some(path) = args.install {
        let mut app = app::BootstrapApp::new_default_config()?;
        app.setup_logger(false)?;
        app.start_ipc_logger()?;
        app.install_hooks()?;
        app.set_executable_file_path(path);
        app.start_install(true)?;
    } else if !args.terminate && !args.install_patch {
        let log_file_path = get_log_path()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert to str"))?
            .to_owned();
        BootstrapApp::run(Settings {
            default_font: Font::with_name("微软雅黑"),
            flags: AppInitializationParams { log_file_path },
            ..Default::default()
        })?;
    }

    Ok(())
}
