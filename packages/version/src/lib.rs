use std::fs::OpenOptions;

use common::common::InjectOptions;
use log::{error, info};
use simplelog::{Config, LevelFilter, WriteLogger};

forward_dll::forward_dll!(
    "C:\\Windows\\system32\\version.dll",
    DLL_VERSION_FORWARDER,
    GetFileVersionInfoA
    GetFileVersionInfoByHandle
    GetFileVersionInfoExA
    GetFileVersionInfoExW
    GetFileVersionInfoSizeA
    GetFileVersionInfoSizeExA
    GetFileVersionInfoSizeExW
    GetFileVersionInfoSizeW
    GetFileVersionInfoW
    VerFindFileA
    VerFindFileW
    VerInstallFileA
    VerInstallFileW
    VerLanguageNameA
    VerLanguageNameW
    VerQueryValueA
    VerQueryValueW
);

#[no_mangle]
pub extern "system" fn DllMain(_inst: isize, reason: u32, _: *const u8) -> u32 {
    if reason == 1 {
        if let Err(err) = initialize() {
            error!("{}", err);
            return 0;
        } else {
            info!("Version Injector initialized");
        }
    }
    1
}

pub fn initialize() -> anyhow::Result<bool> {
    forward_dll::load_library("C:\\Windows\\system32\\version.dll")?;

    let result_of_install_jumpers = unsafe { DLL_VERSION_FORWARDER.forward_all() };

    if let Err(err) = initialize_logger() {
        eprintln!("Failed to initialize logger: {}", err);
    }

    if let Err(err) = &result_of_install_jumpers {
        error!("{}", err);
    } else {
        info!("All jumpers installed");
        // unsafe {
        //     windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxA(
        //         0,
        //         "Success\0".as_ptr(),
        //         "Jump\0".as_ptr(),
        //         0,
        //     )
        // };
    }

    match common::common::enable_hook(Some(InjectOptions {
        server_address: None,
        inject_sub_process: false,
        includes_system_process: false,
    })) {
        Ok(_) => {
            info!("Version hooks installed");
        }
        Err(err) => {
            error!("Enabling hook failed: {}", err);
        }
    }

    Ok(result_of_install_jumpers.map(|_| true)?)
}

fn initialize_logger() -> anyhow::Result<()> {
    let project_dir = directories::ProjectDirs::from("cn", "hamflx", "huawei_pc_manager_bootstrap")
        .ok_or_else(|| anyhow::anyhow!("No project dir"))?;
    let cache_dir = project_dir.cache_dir();
    std::fs::create_dir_all(cache_dir)?;

    let mut log_file_path = cache_dir.to_path_buf();
    let now = chrono::Local::now();
    let exe_path_buf = std::env::current_exe()?;
    let exe_name = exe_path_buf
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("NoExeName");
    let pid = std::process::id();
    log_file_path.push(format!(
        "hijacking-{}-{}-{}.log",
        exe_name,
        pid,
        now.format("%Y%m%d%H%M%S")
    ));

    WriteLogger::init(
        LevelFilter::Info,
        Config::default(),
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(log_file_path)?,
    )?;

    Ok(())
}
