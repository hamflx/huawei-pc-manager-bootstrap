use std::{arch::asm, ffi::CString, fs::OpenOptions};

use common::common::InjectOptions;
use log::{error, info};
use simplelog::{Config, LevelFilter, WriteLogger};
use windows_sys::Win32::{
    Foundation::{GetLastError, HINSTANCE},
    System::LibraryLoader::{FreeLibrary, GetProcAddress, LoadLibraryA},
};

static mut TARGET_FUNC_ADDRESS: [usize; 17] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

macro_rules! export_function {
    ($($proc:ident $index:expr)*) => {
        $(
            #[no_mangle]
            pub extern "system" fn $proc() -> u32 {
                unsafe {
                    asm!(
                        "jmp rax",
                        in("rax") TARGET_FUNC_ADDRESS[$index],
                        options(nostack)
                    );
                }
                1
            }
        )*
    };
}

#[no_mangle]
pub extern "system" fn DllMain(_inst: HINSTANCE, reason: u32, _: *const u8) -> u32 {
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
    let result_of_install_jumpers = install_all_jumpers();

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

    result_of_install_jumpers.map(|_| true)
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
        .map_or(None, |s| s.to_str())
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

export_function!(GetFileVersionInfoA 0);
export_function!(GetFileVersionInfoByHandle 1);
export_function!(GetFileVersionInfoExA 2);
export_function!(GetFileVersionInfoExW 3);
export_function!(GetFileVersionInfoSizeA 4);
export_function!(GetFileVersionInfoSizeExA 5);
export_function!(GetFileVersionInfoSizeExW 6);
export_function!(GetFileVersionInfoSizeW 7);
export_function!(GetFileVersionInfoW 8);
export_function!(VerFindFileA 9);
export_function!(VerFindFileW 10);
export_function!(VerInstallFileA 11);
export_function!(VerInstallFileW 12);
export_function!(VerLanguageNameA 13);
export_function!(VerLanguageNameW 14);
export_function!(VerQueryValueA 15);
export_function!(VerQueryValueW 16);

pub fn install_all_jumpers() -> anyhow::Result<()> {
    make_proc_jump_to_real_address("version.dll", 0, "GetFileVersionInfoA")?;
    make_proc_jump_to_real_address("version.dll", 1, "GetFileVersionInfoByHandle")?;
    make_proc_jump_to_real_address("version.dll", 2, "GetFileVersionInfoExA")?;
    make_proc_jump_to_real_address("version.dll", 3, "GetFileVersionInfoExW")?;
    make_proc_jump_to_real_address("version.dll", 4, "GetFileVersionInfoSizeA")?;
    make_proc_jump_to_real_address("version.dll", 5, "GetFileVersionInfoSizeExA")?;
    make_proc_jump_to_real_address("version.dll", 6, "GetFileVersionInfoSizeExW")?;
    make_proc_jump_to_real_address("version.dll", 7, "GetFileVersionInfoSizeW")?;
    make_proc_jump_to_real_address("version.dll", 8, "GetFileVersionInfoW")?;
    make_proc_jump_to_real_address("version.dll", 9, "VerFindFileA")?;
    make_proc_jump_to_real_address("version.dll", 10, "VerFindFileW")?;
    make_proc_jump_to_real_address("version.dll", 11, "VerInstallFileA")?;
    make_proc_jump_to_real_address("version.dll", 12, "VerInstallFileW")?;
    make_proc_jump_to_real_address("version.dll", 13, "VerLanguageNameA")?;
    make_proc_jump_to_real_address("version.dll", 14, "VerLanguageNameW")?;
    make_proc_jump_to_real_address("version.dll", 15, "VerQueryValueA")?;
    make_proc_jump_to_real_address("version.dll", 16, "VerQueryValueW")?;

    Ok(())
}

pub fn make_proc_jump_to_real_address(
    target_module: &str,
    index: usize,
    proc_name: &str,
) -> anyhow::Result<()> {
    let load_module_dir = "C:\\Windows\\System32\\";
    let module_full_path = format!("{}{}", load_module_dir, target_module);
    let addr_in_remote_module = get_proc_address(module_full_path.as_str(), proc_name)?;

    unsafe {
        TARGET_FUNC_ADDRESS[index] = addr_in_remote_module as *const usize as usize;
    }

    Ok(())
}

pub fn get_proc_address_by_module(
    inst: HINSTANCE,
    proc_name: &str,
) -> anyhow::Result<unsafe extern "system" fn() -> isize> {
    let proc_name = CString::new(proc_name)?;
    unsafe {
        GetProcAddress(inst, proc_name.as_ptr() as *const u8)
            .ok_or_else(|| anyhow::anyhow!("GetProcAddress failed: {:x}", GetLastError()))
    }
}

pub fn get_proc_address(
    module_name: &str,
    proc_name: &str,
) -> anyhow::Result<unsafe extern "system" fn() -> isize> {
    let module_name = CString::new(module_name)?;

    unsafe {
        let module_handle = LoadLibraryA(module_name.as_ptr() as *const u8);
        if module_handle == 0 {
            return Err(anyhow::anyhow!("LoadLibraryA failed: {:x}", GetLastError()));
        }
        let proc_address = get_proc_address_by_module(module_handle, proc_name);
        FreeLibrary(module_handle);
        proc_address
    }
}
