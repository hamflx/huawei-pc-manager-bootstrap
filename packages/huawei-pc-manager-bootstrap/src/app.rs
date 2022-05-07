use std::ffi::CStr;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::thread;

use common::common::InjectOptions;
use common::communication::InterProcessComServer;
use eframe::egui::FontDefinitions;
use eframe::epaint::{vec2, FontFamily};
use eframe::{egui, epi};
use log::{error, info, warn, LevelFilter};
use rfd::FileDialog;
use simplelog::{ConfigBuilder, WriteLogger};
use sysinfo::{ProcessExt, SystemExt};
use windows_sys::Win32::UI::Shell::{SHGetSpecialFolderPathA, CSIDL_PROGRAM_FILES};

pub struct BootstrapApp {
    log_file_path: String,
    executable_file_path: String,
    status_text: String,
    log_text: String,
    ipc_logger_address: Option<String>,
}

macro_rules! GET_VERSION {
    () => {
        include_str!(concat!(env!("OUT_DIR"), "/VERSION"))
    };
}
pub const VERSION: &'static str = GET_VERSION!();

const TIPS_BROWSE: &'static str = "点击“浏览”按钮选择华为电脑管家安装包（如：PCManager_Setup_12.0.1.26(C233D003).exe），然后点击“安装”。";
const TIPS_AUTO_SCAN: &'static str =
    "自动扫描当前目录下的华为电脑管家安装包，找到安装包后，需要点击“安装”按钮进行安装。";
const TIPS_AUTO_SCAN_FOUND: &'static str = "已找到安装包，点击“安装”按钮进行安装。";
const TIPS_AUTO_SCAN_NOT_FOUND: &'static str = "未找到安装包！";

impl BootstrapApp {
    pub fn set_executable_file_path(&mut self, path: String) {
        self.executable_file_path = path;
    }

    fn auto_scan(&mut self) -> anyhow::Result<bool> {
        let dirs = [
            std::env::current_exe()?
                .parent()
                .ok_or_else(|| anyhow::anyhow!("current_exe() failed"))?
                .to_path_buf(),
            std::env::current_dir()?,
        ];
        for dir in dirs {
            for file in std::fs::read_dir(dir)? {
                let file = file?;
                let file_path = file.path();
                if let Some(file_name) = file_path.file_name() {
                    if let Some(file_name) = file_name.to_str() {
                        if file_name
                            .to_lowercase()
                            .contains(&"PCManager_Setup".to_lowercase())
                        {
                            if let Some(file_path) = file_path.to_str() {
                                self.executable_file_path = file_path.to_owned();
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    pub fn terminate_all_processes() -> anyhow::Result<()> {
        let hw_process = [
            r"WeLook.exe",
            r"WebViewer.exe",
            r"UninstallGuide.exe",
            r"UltraSoundUI.exe",
            r"ScreenSnipper.exe",
            r"RepairPCManager.exe",
            r"PerfWndMonHelper_x86.exe",
            r"PerfWndMonHelper.exe",
            r"PCManager.exe",
            r"PairDeviceDes.exe",
            r"OTAWndShow.exe",
            r"OpenDir.exe",
            r"OobeMain.exe",
            r"OneKeyReset.exe",
            r"OfficeFileMonitor.exe",
            r"NPSPopwnd.exe",
            r"MessageCenterUI.exe",
            r"MBAMessageCenter.exe",
            r"MBAInstallPre.exe",
            r"MateBookService.exe",
            r"HWVCR.exe",
            r"HwTrayWndHelper.exe",
            r"HwshareUI.exe",
            r"HwSmartAudio.exe",
            r"HwSettings.exe",
            r"HwPhotoViewer.exe",
            r"HwMirrorDragDropWnd.exe",
            r"HwMirror.exe",
            r"HwMdcUI.exe",
            r"HwMdcCenter.exe",
            r"HwFeaPromoUI.exe",
            r"HwExScreen.exe",
            r"HWAccountUI.exe",
            r"hmdfsservice.exe",
            r"HiboardDataReport.exe",
            r"GetClipContent.exe",
            r"FreeTouchUI.exe",
            r"DumpReport.exe",
            r"DragFileProgress.exe",
            r"distributedfileservice.exe",
            r"DFSSearchUI.exe",
            r"DFSSearchService.exe",
            r"AdvancedService.exe",
        ];
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        for (_pid, process) in system.processes() {
            let process_name = process.name();
            let is_hw_process = hw_process
                .iter()
                .any(|name| name.eq_ignore_ascii_case(process_name));
            if is_hw_process {
                info!("Found hw process: {}", process_name);
                process.kill();
            }
        }
        Ok(())
    }

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

    pub fn setup_logger(&self) -> anyhow::Result<()> {
        let config = ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .build();
        WriteLogger::init(
            LevelFilter::Debug,
            config,
            File::create(&self.log_file_path)?,
        )?;
        info!("Logger setup successfully");
        info!("Installer version {}", VERSION);
        let sys = sysinfo::System::new_all();
        info!(
            "OS: {} {}",
            sys.name().unwrap_or_default(),
            sys.os_version().unwrap_or_default()
        );

        Ok(())
    }

    pub fn install_hooks(&self) -> anyhow::Result<()> {
        common::common::enable_hook(Some(InjectOptions {
            server_address: self.ipc_logger_address.clone(),
            inject_sub_process: true,
            includes_system_process: false,
        }))
    }

    pub fn start_ipc_logger(&mut self) -> anyhow::Result<()> {
        let server = InterProcessComServer::listen("127.0.0.1:0")?;
        let address = server.get_address()?;
        server.start();

        self.ipc_logger_address = Some(address.to_string());
        info!("Listening on {}", self.ipc_logger_address.as_ref().unwrap());

        Ok(())
    }

    pub fn start_install(&self, wait: bool) -> anyhow::Result<()> {
        let executable_file_path = self.executable_file_path.clone();
        let install_thread = thread::spawn(move || {
            info!("Executing {}", executable_file_path);
            match Command::new(&executable_file_path).spawn() {
                Ok(mut wait_handle) => {
                    let mut is_patch_installed = false;
                    info!("Executed {}", executable_file_path);
                    loop {
                        match wait_handle.try_wait() {
                            Ok(Some(exit_status)) => {
                                info!(
                                    "{} exited with status {}",
                                    executable_file_path, exit_status
                                );
                                break;
                            }
                            Ok(None) => {
                                if !is_patch_installed {
                                    match Self::check_pc_manager_installed() {
                                        Ok(true) => match Self::install_patch() {
                                            Ok(_) => {
                                                is_patch_installed = true;
                                                info!("Installed patch successfully");
                                            }
                                            Err(e) => {
                                                warn!("Failed to install patch: {}", e);
                                            }
                                        },
                                        Ok(false) => {
                                            info!("PCManager is not installed, wating ...");
                                        }
                                        Err(err) => {
                                            warn!("Failed to check PC Manager installed: {}", err);
                                        }
                                    }
                                }
                                thread::sleep(std::time::Duration::from_millis(100));
                            }
                            Err(e) => {
                                warn!("{} exited with error: {}", executable_file_path, e);
                                break;
                            }
                        }
                    }
                }
                Err(e) => warn!("Failed to execute {}: {}", executable_file_path, e),
            }
        });

        if wait {
            install_thread.join().unwrap();
        }

        Ok(())
    }

    pub fn install_patch() -> anyhow::Result<()> {
        #[cfg(debug_assertions)]
        let patch_file_bytes =
            include_bytes!("../../../target/x86_64-pc-windows-msvc/debug/version.dll");
        #[cfg(not(debug_assertions))]
        let patch_file_bytes =
            include_bytes!("../../../target/x86_64-pc-windows-msvc/release/version.dll");

        let pc_manager_dir: PathBuf = Self::get_pc_manager_dir()?;
        let target_version_dll_path = pc_manager_dir.join("version.dll");
        std::fs::write(&target_version_dll_path, patch_file_bytes)?;

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

    fn check_pc_manager_installed() -> anyhow::Result<bool> {
        let pc_manager_exe: PathBuf = Self::get_pc_manager_dir()?.join("PCManager.exe");
        Ok(pc_manager_exe.exists())
    }

    fn get_pc_manager_dir() -> anyhow::Result<PathBuf> {
        let mut path_buffer = [0; 4096];
        let get_dir_success = unsafe {
            SHGetSpecialFolderPathA(
                0,
                path_buffer.as_mut_ptr(),
                CSIDL_PROGRAM_FILES.try_into().unwrap(),
                0,
            )
        } != 0;
        if !get_dir_success {
            return Err(anyhow::anyhow!(
                "SHGetSpecialFolderPathA failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let program_files_dir =
            unsafe { CStr::from_ptr(path_buffer.as_ptr() as *const i8).to_str()? };
        let x86_suffix = " (x86)";
        let program_files_dir = if program_files_dir.ends_with(x86_suffix) {
            &program_files_dir[..program_files_dir.len() - x86_suffix.len()]
        } else {
            program_files_dir
        };

        Ok([program_files_dir, "Huawei", "PCManager"].iter().collect())
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
        let status_text = String::from(TIPS_BROWSE);
        let log_text = format!("这里是日志区域，但是我跟编译器搏斗了半天，仍然是没能把日志输出到这里，只能把日志输出到文件：\n{}", log_file_path);

        Self {
            log_file_path,
            executable_file_path: String::new(),
            status_text,
            log_text,
            ipc_logger_address: None,
        }
    }
}

impl epi::App for BootstrapApp {
    fn name(&self) -> &str {
        concat!("华为电脑管家安装器 v", GET_VERSION!())
    }

    /// Called once before the first frame.
    fn setup(
        &mut self,
        ctx: &egui::Context,
        frame: &epi::Frame,
        _storage: Option<&dyn epi::Storage>,
    ) {
        frame.set_window_size(vec2(862f32, 562f32));
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
            error!("Failed to setup logger: {}", err);
            return;
        }

        if let Err(err) = self.start_ipc_logger() {
            self.status_text = format!("Error: {}", err);
            error!("Failed to start ipc logger: {}", err);
            return;
        }

        if let Err(err) = self.install_hooks() {
            self.status_text = format!("Error: {}", err);
            error!("Failed to install hooks: {}", err);
            return;
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
                    let auto_scan_button = ui.button("自动扫描").on_hover_text(TIPS_AUTO_SCAN);
                    if auto_scan_button.clicked() {
                        match self.auto_scan() {
                            Ok(true) => {
                                self.status_text = String::from(TIPS_AUTO_SCAN_FOUND);
                            }
                            Ok(false) => {
                                self.status_text = String::from(TIPS_AUTO_SCAN_NOT_FOUND);
                            }
                            Err(err) => {
                                self.status_text = format!("Error: {}", err);
                                warn!("Error: {}", err);
                            }
                        }
                    }

                    let browse_button = ui.button("浏览").on_hover_text(TIPS_BROWSE);
                    if browse_button.clicked() {
                        self.select_file();
                    }

                    if ui.button("安装").clicked() {
                        if let Err(err) = self.start_install(false) {
                            self.status_text = format!("Installing failed: {}", err);
                            warn!("Installing failed: {}", err);
                        } else {
                            self.status_text = "安装成功。".to_owned();
                            info!("PCManager installed successfully.");
                        }
                    }

                    if ui.button("安装补丁").clicked() {
                        if let Err(err) = Self::install_patch() {
                            self.status_text = format!("Installing failed: {}", err);
                            warn!("Installing failed: {}", err);
                        } else {
                            self.status_text = "安装成功。".to_owned();
                            info!("Patch installed successfully");
                        }
                    }

                    if ui.button("终止所有进程").clicked() {
                        if let Err(err) = Self::terminate_all_processes() {
                            self.status_text = format!("Failed to kill all processes: {}", err);
                            warn!("Failed to kill all processes: {}", err);
                        } else {
                            self.status_text = "执行成功。".to_owned();
                            info!("Huawei process terminated successfully");
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
