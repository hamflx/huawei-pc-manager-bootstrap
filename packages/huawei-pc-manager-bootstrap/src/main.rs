#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] //Hide console window in release builds on Windows, this blocks stdout.

use std::{cell::RefCell, io::Write, panic::catch_unwind, process::ExitCode};

use anyhow::Context;
use app::{AppInitializationParams, BootstrapApp};
use backtrace::Backtrace;
use clap::Parser;
use common::config::{get_log_path, get_panics_log_path};
use iced::{Application, Font, Settings};
use windows_sys::Win32::UI::{
    Shell::IsUserAnAdmin,
    WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK},
};

mod app;
mod elevation;
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

impl Args {
    fn is_cli(&self) -> bool {
        self.install.is_some() || self.install_patch || self.terminate
    }
}

thread_local! {
    static PANIC_REPORT: RefCell<Option<String>> = RefCell::new(None);
}

fn main() -> ExitCode {
    // Release builds use the GUI subsystem. Attach to an existing terminal so
    // command-line diagnostics (including clap's help/errors) remain visible.
    elevation::attach_parent_console();
    let args = Args::parse();
    let show_dialog = !args.is_cli();
    std::panic::set_hook(Box::new(|info| {
        let report = format!("{info}\n\n{:?}", Backtrace::new());
        PANIC_REPORT.with(move |saved| saved.borrow_mut().replace(report));
    }));

    if let Some(message) = failure_message(catch_unwind(|| app_main(args))) {
        report_failure(&message, show_dialog);
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn failure_message(result: std::thread::Result<anyhow::Result<()>>) -> Option<String> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(format!("Application failed:\n{err:#}")),
        Err(payload) => {
            let report = PANIC_REPORT.with(|saved| saved.borrow_mut().take());
            let report = report.unwrap_or_else(|| {
                payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("Unknown panic payload")
                    .to_owned()
            });
            Some(format!("Application panicked:\n{report}"))
        }
    }
}

fn report_failure(message: &str, show_dialog: bool) {
    let log_result = (|| -> anyhow::Result<_> {
        let path = get_panics_log_path()?;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)?;
        writeln!(file, "{message}")?;
        Ok(path)
    })();
    let message = match log_result {
        Ok(path) => format!("{message}\n\nDiagnostic log: {}", path.display()),
        Err(err) => format!("{message}\n\nCould not save the diagnostic log: {err:#}"),
    };
    // Diagnostic reporting must not panic if stderr is unavailable.
    let _ = writeln!(std::io::stderr().lock(), "{message}");
    if show_dialog {
        // Error text may contain arbitrary data, so replace interior NULs rather
        // than letting a failed string conversion hide the original failure.
        let message: Vec<u16> = message
            .replace('\0', "\u{fffd}")
            .encode_utf16()
            .chain([0])
            .collect();
        let title: Vec<u16> = "华为电脑管家安装器 - Error"
            .encode_utf16()
            .chain([0])
            .collect();
        unsafe {
            MessageBoxW(0, message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }
}

fn app_main(args: Args) -> anyhow::Result<()> {
    let is_admin = unsafe { IsUserAnAdmin() != 0 };
    if !is_admin {
        anyhow::ensure!(
            !args.ensure_admin,
            "Administrator privileges are required, but the elevated process is not running as administrator."
        );
        return elevation::relaunch_as_admin(args.is_cli());
    }

    if args.terminate {
        app::BootstrapApp::terminate_all_processes()
            .context("Failed to terminate Huawei PC Manager processes")?;
    }

    if args.install_patch {
        app::BootstrapApp::install_patch().context("Failed to install the PC Manager patch")?;
    }

    if let Some(path) = args.install {
        let mut app = app::BootstrapApp::new_default_config()
            .context("Failed to initialize the installer")?;
        app.setup_logger(false)
            .context("Failed to initialize logging")?;
        app.start_ipc_logger()
            .context("Failed to start the IPC logger")?;
        app.install_hooks()
            .context("Failed to install Windows hooks")?;
        app.set_executable_file_path(path);
        app.start_install()
            .context("PC Manager installation failed")?;
    } else if !args.terminate && !args.install_patch {
        let log_file_path = get_log_path()
            .context("Failed to create the application log path")?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert to str"))?
            .to_owned();
        BootstrapApp::run(Settings {
            default_font: Font::with_name("微软雅黑"),
            flags: AppInitializationParams { log_file_path },
            ..Default::default()
        })
        .context("Failed to start the application window")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{failure_message, Args};
    use clap::Parser;

    #[test]
    fn successful_completion_has_no_failure() {
        assert!(failure_message(Ok(Ok(()))).is_none());
    }

    #[test]
    fn startup_failure_preserves_error_context() {
        let error = anyhow::anyhow!("access denied").context("Failed to initialize logging");
        let message = failure_message(Ok(Err(error))).unwrap();
        assert!(message.contains("Failed to initialize logging"));
        assert!(message.contains("access denied"));
    }

    #[test]
    fn panic_without_a_captured_backtrace_still_reports_the_cause() {
        let message = failure_message(Err(Box::new("startup panic"))).unwrap();
        assert!(message.contains("startup panic"));
    }

    #[test]
    fn command_line_actions_do_not_require_a_gui_error_dialog() {
        for arguments in [
            vec!["bootstrap", "--install", "setup.exe"],
            vec!["bootstrap", "--install-patch"],
            vec!["bootstrap", "--terminate"],
        ] {
            assert!(Args::try_parse_from(arguments).unwrap().is_cli());
        }
        assert!(!Args::try_parse_from(["bootstrap"]).unwrap().is_cli());
        assert!(!Args::try_parse_from(["bootstrap", "--ensure-admin"])
            .unwrap()
            .is_cli());
    }
}
