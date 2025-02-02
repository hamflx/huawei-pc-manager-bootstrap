use std::cell::RefCell;
use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::thread;

use common::communication::InterProcessComServer;
use common::config::{
    get_config_dir, get_config_file_path, get_log_path, save_firmware_config, Config,
};
use iced::futures::SinkExt;
use iced::widget::scrollable::{Direction, Properties};
use iced::widget::{container, row, scrollable, text_input};
use iced::{executor, Application, Length, Theme};
use iced::{
    widget::{button, column, text},
    Element,
};
use injectors::options::InjectOptions;
use regex::Regex;
use rfd::FileDialog;
use sysinfo::{ProcessExt, SystemExt};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{error, info, warn};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;
use widestring::WideCStr;
use windows_sys::Win32::UI::Shell::{SHGetSpecialFolderPathW, CSIDL_PROGRAM_FILES};

use crate::logger::CustomLayer;
use crate::version::SetupVersion;

#[derive(Debug, Clone)]
pub enum Message {
    ChangeSetupFilePath(String),
    AutoScanSetup,
    BrowserSetup,
    Install,
    InstallPatch,
    TerminateAllProcesses,
    OpenConfigFile,
    OpenLogFile,
    OpenLogFileDir,
    UpdateLogContent(String),
}

macro_rules! GET_VERSION {
    () => {
        include_str!(concat!(env!("OUT_DIR"), "/VERSION"))
    };
}
pub const VERSION: &str = GET_VERSION!();

#[derive(Default)]
pub(crate) struct AppInitializationParams {
    pub(crate) log_file_path: String,
}

pub(crate) struct BootstrapApp {
    log_file_path: String,
    log_receiver: RefCell<Option<Receiver<String>>>,
    log_sender: Sender<String>,
    executable_file_path: String,
    status_text: String,
    log_text: String,
    ipc_logger_address: Option<String>,
}

impl Application for BootstrapApp {
    type Message = Message;
    type Executor = executor::Default;
    type Theme = Theme;
    type Flags = AppInitializationParams;

    fn new(params: AppInitializationParams) -> (Self, iced::Command<Message>) {
        let mut inst = Self::new_with_config(params);

        if let Err(err) = inst.setup_logger(true) {
            inst.status_text = format!("Error: {}", err);
            error!("Failed to setup logger: {}", err);
        }

        if let Err(err) = inst.start_ipc_logger() {
            inst.status_text = format!("Error: {}", err);
            error!("Failed to start ipc logger: {}", err);
        }

        if let Err(err) = inst.install_hooks() {
            inst.status_text = format!("Error: {}", err);
            error!("Failed to install hooks: {}", err);
        }

        (inst, iced::Command::none())
    }

    fn title(&self) -> String {
        concat!("华为电脑管家安装器 v", GET_VERSION!()).into()
    }

    fn update(&mut self, message: Message) -> iced::Command<Message> {
        match message {
            Message::ChangeSetupFilePath(path) => self.executable_file_path = path,
            Message::AutoScanSetup => match self.auto_scan() {
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
            },
            Message::BrowserSetup => self.select_file(),
            Message::Install => {
                if let Err(err) = self.start_install(false) {
                    self.status_text = format!("Installing failed: {}", err);
                    warn!("Installing failed: {}", err);
                } else {
                    self.status_text = "安装成功。".to_owned();
                    info!("PCManager installed successfully.");
                }
            }
            Message::InstallPatch => {
                if let Err(err) = Self::install_patch() {
                    self.status_text = format!("Installing failed: {}", err);
                    warn!("Installing failed: {}", err);
                } else {
                    self.status_text = "安装成功。".to_owned();
                    info!("Patch installed successfully");
                }
            }
            Message::TerminateAllProcesses => {
                if let Err(err) = Self::terminate_all_processes() {
                    self.status_text = format!("Failed to kill all processes: {}", err);
                    warn!("Failed to kill all processes: {}", err);
                } else {
                    self.status_text = "执行成功。".to_owned();
                    info!("Huawei process terminated successfully");
                }
            }
            Message::OpenConfigFile => {
                if let Err(err) = self.open_config_file() {
                    self.status_text = format!("Opening config file failed: {}", err);
                    warn!("Opening config file failed: {}", err);
                }
            }
            Message::OpenLogFile => self.open_log_file(),
            Message::OpenLogFileDir => {
                if let Err(err) = self.open_log_file_dir() {
                    self.status_text = format!("Opening log dir failed: {}", err);
                    warn!("Opening log dir failed: {}", err);
                }
            }
            Message::UpdateLogContent(msg) => {
                self.log_text.push_str(&msg);
                self.log_text.push_str("\n");
            }
        }

        iced::Command::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let toolbar = row![
            button("自动扫描").on_press(Message::AutoScanSetup),
            button("浏览").on_press(Message::BrowserSetup),
            button("安装").on_press(Message::Install),
            button("安装补丁").on_press(Message::InstallPatch),
            button("终止所有进程").on_press(Message::TerminateAllProcesses),
            button("打开配置").on_press(Message::OpenConfigFile),
            button("打开日志").on_press(Message::OpenLogFile),
            button("打开日志文件夹").on_press(Message::OpenLogFileDir),
        ]
        .spacing(8);

        container(
            column![
                text("安装包位置"),
                text_input("", &self.executable_file_path).on_input(Message::ChangeSetupFilePath),
                toolbar,
                text(&self.status_text),
                scrollable(text(&self.log_text))
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .direction(Direction::Vertical(
                        Properties::default().alignment(scrollable::Alignment::End),
                    ))
            ]
            .padding(8)
            .spacing(8),
        )
        .padding(4)
        .into()
    }

    fn subscription(&self) -> iced::Subscription<Self::Message> {
        if let Some(mut receiver) = self.log_receiver.take() {
            iced::subscription::channel("check_log", 500, |mut output| async move {
                loop {
                    match receiver.recv().await {
                        Some(msg) => {
                            let _ = output.send(Message::UpdateLogContent(msg)).await;
                        }
                        _ => futures::future::pending().await,
                    }
                }
            })
        } else {
            iced::subscription::channel("check_log", 500, |_| futures::future::pending())
        }
    }
}

const TIPS_BROWSE: & str = "点击“浏览”按钮选择华为电脑管家安装包（如：PCManager_Setup_12.0.1.26(C233D003).exe），然后点击“安装”。";
const TIPS_AUTO_SCAN_FOUND: &str = "已找到安装包，点击“安装”按钮进行安装。";
const TIPS_AUTO_SCAN_NOT_FOUND: &str = "未找到安装包！";

impl BootstrapApp {
    pub(crate) fn new_default_config() -> anyhow::Result<Self> {
        let log_file_path = get_log_path()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Failed to convert to str"))?
            .to_owned();
        let status_text = String::from(TIPS_BROWSE);
        let log_text = format!("日志文件路径：\n{}\n\n", log_file_path);
        let (tx, rx) = channel(500);
        Ok(Self {
            log_file_path,
            executable_file_path: String::new(),
            status_text,
            log_text,
            ipc_logger_address: None,
            log_receiver: RefCell::new(Some(rx)),
            log_sender: tx,
        })
    }

    pub(crate) fn new_with_config(params: AppInitializationParams) -> Self {
        let status_text = String::from(TIPS_BROWSE);
        let log_text = format!("日志文件路径：\n{}\n\n", params.log_file_path);
        let (tx, rx) = channel(500);
        Self {
            log_file_path: params.log_file_path,
            executable_file_path: String::new(),
            status_text,
            log_text,
            ipc_logger_address: None,
            log_receiver: RefCell::new(Some(rx)),
            log_sender: tx,
        }
    }

    pub fn set_executable_file_path(&mut self, path: String) {
        self.executable_file_path = path;
    }

    fn auto_scan(&mut self) -> anyhow::Result<bool> {
        let dirs: HashSet<_> = [
            std::env::current_exe()?
                .parent()
                .ok_or_else(|| anyhow::anyhow!("current_exe() failed"))?
                .to_path_buf(),
            std::env::current_dir()?,
        ]
        .into();
        let version_re = Regex::new(r"([0-9]+)(?:\.([0-9]+))*")?;
        let mut setup_file_list = Vec::new();
        for dir in dirs {
            info!("扫描目录：{}", dir.display());
            for file in std::fs::read_dir(dir)? {
                let file = file?;
                let file_path = file.path();
                if let Some(file_name) = file_path.file_name().and_then(|f| f.to_str()) {
                    let lower_file_name = file_name.to_lowercase();
                    if lower_file_name.contains(&"PCManager_Setup".to_lowercase())
                        && lower_file_name.ends_with(".exe")
                    {
                        if let Some(file_path) = file_path.to_str() {
                            if let Some(found) = version_re.captures(file_name) {
                                let matched = found.get(0).unwrap().as_str();
                                match SetupVersion::from_str(matched) {
                                    Ok(parsed_ver) => {
                                        info!("  找到安装包：{}", file_path);
                                        setup_file_list.push((file_path.to_owned(), parsed_ver));
                                    }
                                    Err(err) => {
                                        warn!(
                                            "Parse setup file version ({}) failed: {}",
                                            matched, err
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let latest_setup_file = setup_file_list
            .into_iter()
            .max_by(|(_, a_ver), (_, b_ver)| Ord::cmp(a_ver, b_ver));

        match latest_setup_file {
            Some((latest_setup_file, _)) => {
                info!("找到最匹配的安装包：{}", latest_setup_file);
                self.executable_file_path = latest_setup_file;
                Ok(true)
            }
            _ => {
                warn!("没有找到安装包！");
                Ok(false)
            }
        }
    }

    pub fn terminate_all_processes() -> anyhow::Result<()> {
        let pc_manager_dir = Self::get_pc_manager_dir()?
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("未找到华为电脑管家安装目录。"))?
            .to_ascii_lowercase();
        info!("Pc Manager installed dir: {}", pc_manager_dir);
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        for process in system.processes().values() {
            if let Some(exe) = process.exe().to_str() {
                if exe.to_ascii_lowercase().starts_with(&pc_manager_dir) {
                    info!("Found hw process: {}", exe);
                    process.kill();
                }
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

    pub fn setup_logger(&mut self, with_gui: bool) -> anyhow::Result<()> {
        let tx = self.log_sender.clone();
        let common_layer = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(File::create(&self.log_file_path)?)
                .with_filter(LevelFilter::DEBUG),
        );
        if with_gui {
            common_layer.with(CustomLayer::new(tx)).try_init()?;
        } else {
            common_layer.try_init()?;
        }
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
        info!(
            "Listening on {}",
            self.ipc_logger_address.as_deref().unwrap_or_default()
        );

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
        let patch_file_bytes = include_bytes!(env!("CARGO_CDYLIB_FILE_VERSION_version"));

        let pc_manager_dir: PathBuf = Self::get_pc_manager_dir()?;
        let target_version_dll_path = pc_manager_dir.join("version.dll");
        std::fs::write(target_version_dll_path, patch_file_bytes)?;

        let mut config_file_path = get_config_dir()?;
        config_file_path.push("config.json");
        if !config_file_path.exists() {
            save_firmware_config(&Config::default())?;
        }

        Ok(())
    }

    fn open_log_file(&self) {
        let _ = Command::new("notepad").arg(&self.log_file_path).spawn();
    }

    fn open_config_file(&self) -> anyhow::Result<()> {
        let config_file_path = get_config_file_path()?;
        let _ = Command::new("notepad").arg(config_file_path).spawn();
        Ok(())
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
            SHGetSpecialFolderPathW(0, path_buffer.as_mut_ptr(), CSIDL_PROGRAM_FILES as _, 0)
        } != 0;
        if !get_dir_success {
            return Err(anyhow::anyhow!(
                "SHGetSpecialFolderPathA failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let program_files_dir =
            unsafe { WideCStr::from_ptr_str(path_buffer.as_ptr()).to_string()? };
        let x86_suffix = " (x86)";
        let program_files_dir = if program_files_dir.ends_with(x86_suffix) {
            &program_files_dir[..program_files_dir.len() - x86_suffix.len()]
        } else {
            &program_files_dir
        };

        Ok([program_files_dir, "Huawei", "PCManager"].iter().collect())
    }
}
