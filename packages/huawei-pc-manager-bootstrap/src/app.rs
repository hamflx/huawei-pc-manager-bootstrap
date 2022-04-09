use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use common::common::InjectOptions;
use common::communication::InterProcessComServer;
use eframe::egui::FontDefinitions;
use eframe::epaint::FontFamily;
use eframe::{egui, epi};
use log::{info, warn, LevelFilter};
use rfd::FileDialog;
use simplelog::{ConfigBuilder, WriteLogger};

pub struct BootstrapApp {
    log_file_path: String,
    executable_file_path: String,
    status_text: String,
    log_text: String,
}

impl BootstrapApp {
    fn select_file(&mut self) {
        let executable_file = FileDialog::new()
            .add_filter("exe", &["exe"])
            .set_directory(std::env::current_exe().unwrap().parent().unwrap())
            .pick_file();

        if let Some(executable_file) = executable_file {
            self.executable_file_path = executable_file.to_str().unwrap().to_owned();
            info!("Selected file: {}", self.executable_file_path);
        }
    }

    fn setup_logger(&self) -> anyhow::Result<()> {
        let config = ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .build();
        WriteLogger::init(
            LevelFilter::Debug,
            config,
            File::create(&self.log_file_path)?,
        )?;
        info!("Logger setup successfully");

        Ok(())
    }

    fn start_install(&self) -> anyhow::Result<()> {
        let server = InterProcessComServer::listen("127.0.0.1:0")?;
        let address = server.get_address()?;
        server.start();

        info!("Listening on {}", address.to_string());

        common::common::enable_hook(Some(InjectOptions {
            server_address: Some(address.to_string()),
            inject_sub_process: true,
        }))?;

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

    fn open_log_file(&self) {
        let _ = Command::new("notepad").arg(&self.log_file_path).spawn();
    }

    fn open_log_file_dir(&self) -> anyhow::Result<()> {
        let log_file_path = PathBuf::from_str(self.log_file_path.as_str())?;
        let log_dir = log_file_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("No parent dir"))?;
        let _ = Command::new("explorer").arg(log_dir).spawn()?;
        Ok(())
    }
}

impl Default for BootstrapApp {
    fn default() -> Self {
        let project_dir =
            directories::ProjectDirs::from("cn", "hamflx", "huawei_pc_manager_bootstrap")
                .ok_or_else(|| anyhow::anyhow!("No project dir"))
                .unwrap();
        let cache_dir = project_dir.cache_dir();
        std::fs::create_dir_all(cache_dir).unwrap();

        let mut log_file_path = cache_dir.to_path_buf();
        let now = chrono::Local::now();
        log_file_path.push(format!("app-{}.log", now.format("%Y%m%d%H%M%S")));
        let log_file_path = log_file_path.to_str().unwrap().to_owned();
        let status_text= String::from("点击“浏览”按钮选择华为电脑管家安装包（如：PCManager_Setup_12.0.1.26(C233D003).exe），然后点击“安装”。") ;
        let log_text = format!("这里是日志区域，但是我跟编译器搏斗了半天，仍然是没能把日志输出到这里，只能把日志输出到文件：\n{}", log_file_path);

        Self {
            log_file_path,
            executable_file_path: String::new(),
            status_text,
            log_text,
        }
    }
}

impl epi::App for BootstrapApp {
    fn name(&self) -> &str {
        "华为电脑管家安装器"
    }

    /// Called once before the first frame.
    fn setup(
        &mut self,
        ctx: &egui::Context,
        _frame: &epi::Frame,
        _storage: Option<&dyn epi::Storage>,
    ) {
        let mut fonts = FontDefinitions::default();
        let sys_font = std::fs::read("c:/Windows/Fonts/msyh.ttc").unwrap();
        fonts
            .font_data
            .insert("msyh".to_owned(), egui::FontData::from_owned(sys_font));

        fonts
            .families
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "msyh".to_owned());
        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "msyh".to_owned());
        ctx.set_fonts(fonts);

        ctx.set_pixels_per_point(2.0);

        if let Err(err) = self.setup_logger() {
            self.status_text = format!("Error: {}", err);
        }
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    /// Put your widgets into a `SidePanel`, `TopPanel`, `CentralPanel`, `Window` or `Area`.
    fn update(&mut self, ctx: &egui::Context, _frame: &epi::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.label("安装包位置：");
                });
                ui.horizontal(|ui| {
                    ui.with_layout(
                        egui::Layout::left_to_right().with_main_justify(true),
                        |ui| {
                            ui.text_edit_singleline(&mut self.executable_file_path);
                        },
                    );
                });
                ui.horizontal(|ui| {
                    if ui.button("浏览").clicked() {
                        self.select_file();
                    }
                    if ui.button("安装").clicked() {
                        if let Err(err) = self.start_install() {
                            self.status_text = format!("Installing failed: {}", err);
                            warn!("Installing failed: {}", err);
                        }
                    }
                    if ui.button("打开日志").clicked() {
                        self.open_log_file();
                    }
                    if ui.button("打开日志文件夹").clicked() {
                        if let Err(err) = self.open_log_file_dir() {
                            self.status_text = format!("Opening log dir failed: {}", err);
                            warn!("Opening log dir failed: {}", err);
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.add(egui::Label::new(&self.status_text).wrap(true));
                });
                ui.centered_and_justified(|ui| {
                    ui.text_edit_multiline(&mut self.log_text);
                });
            });
        });
    }
}
