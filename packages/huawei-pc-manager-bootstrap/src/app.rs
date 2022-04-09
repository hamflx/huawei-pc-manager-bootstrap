use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::common::InjectOptions;
use common::communication::InterProcessComServer;
use eframe::{egui, epi};
use log::info;
use rfd::FileDialog;
use simple_logger::SimpleLogger;

pub struct BootstrapApp {
    executable_file_path: String,
    status_text: String,
}

impl BootstrapApp {
    fn select_file(&mut self) {
        let executable_file = FileDialog::new()
            .add_filter("exe", &["exe"])
            .set_directory(std::env::current_exe().unwrap().parent().unwrap())
            .pick_file();
        if let Some(executable_file) = executable_file {
            self.executable_file_path = executable_file.to_str().unwrap().to_owned();
        }
    }

    fn start_install(&self) -> anyhow::Result<()> {
        SimpleLogger::new().init()?;

        let server = InterProcessComServer::listen("127.0.0.1:0")?;
        let address = server.get_address()?;
        server.start();

        info!("Listening on {}", address.to_string());

        common::common::enable_hook(Some(InjectOptions {
            server_address: Some(address.to_string()),
            inject_sub_process: true,
        }));

        info!("Executing {}", self.executable_file_path);
        let command = Command::new(&self.executable_file_path).spawn()?;

        let command_for_wait = Arc::new(Mutex::new(command));
        let command_for_exit = command_for_wait.clone();
        ctrlc::set_handler(move || {
            info!("Exiting...");
            command_for_exit.lock().unwrap().kill().unwrap();
            std::process::exit(0);
        })
        .expect("Error setting Ctrl-C handler");

        while let Ok(exit_status) = command_for_wait.lock().unwrap().try_wait() {
            if let Some(exit_code) = exit_status {
                info!("Command exited with {}", exit_code);
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        Ok(())
    }
}

impl Default for BootstrapApp {
    fn default() -> Self {
        Self {
            executable_file_path: String::new(),
            status_text: String::from("Browse executable file and click install"),
        }
    }
}

impl epi::App for BootstrapApp {
    fn name(&self) -> &str {
        "eframe template"
    }

    /// Called once before the first frame.
    fn setup(
        &mut self,
        _ctx: &egui::Context,
        _frame: &epi::Frame,
        _storage: Option<&dyn epi::Storage>,
    ) {
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    /// Put your widgets into a `SidePanel`, `TopPanel`, `CentralPanel`, `Window` or `Area`.
    fn update(&mut self, ctx: &egui::Context, _frame: &epi::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's

            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.executable_file_path);
                    if ui.button("Browse").clicked() {
                        self.select_file();
                    }
                    if ui.button("install").clicked() {
                        if let Err(err) = self.start_install() {
                            self.status_text = format!("{:?}", err);
                        } else {
                            self.status_text = String::new();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(&self.status_text);
                });
            });
        });
    }
}
