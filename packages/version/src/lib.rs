use std::{
    ffi::{c_void, CString},
    fs::File,
    slice::from_raw_parts_mut,
};

use log::{error, info};
use simplelog::{Config, LevelFilter, WriteLogger};
use windows_sys::Win32::{
    Foundation::{GetLastError, HINSTANCE},
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
    },
};

macro_rules! export_function {
    ($($proc:ident)*) => {
        $(
            #[no_mangle]
            pub extern "system" fn $proc() -> u32 {
                println!("==> do sth.");
                1
            }
        )*
    };
}

#[no_mangle]
pub extern "system" fn DllMain(inst: HINSTANCE, reason: u32, _: *const u8) -> u32 {
    if reason == 1 {
        if let Err(err) = initialize(inst) {
            println!("{}", err);
            return 0;
        }
    }
    1
}

pub fn initialize(inst: HINSTANCE) -> anyhow::Result<()> {
    let project_dir = directories::ProjectDirs::from("cn", "hamflx", "huawei_pc_manager_bootstrap")
        .ok_or_else(|| anyhow::anyhow!("No project dir"))?;
    let cache_dir = project_dir.cache_dir();
    std::fs::create_dir_all(cache_dir)?;

    let mut log_file_path = cache_dir.to_path_buf();
    let now = chrono::Local::now();
    log_file_path.push(format!("hijacking-{}.log", now.format("%Y%m%d%H%M%S")));

    WriteLogger::init(
        LevelFilter::Info,
        Config::default(),
        File::create(log_file_path)?,
    )?;

    if let Err(err) = install_all_jumpers(inst) {
        error!("{}", err);
    } else {
        // unsafe {
        //     windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxA(
        //         0,
        //         "Success\0".as_ptr(),
        //         "Jump\0".as_ptr(),
        //         0,
        //     )
        // };
    }

    common::common::enable_hook(None);

    Ok(())
}

export_function!(GetFileVersionInfoA);
export_function!(GetFileVersionInfoByHandle);
export_function!(GetFileVersionInfoExA);
export_function!(GetFileVersionInfoExW);
export_function!(GetFileVersionInfoSizeA);
export_function!(GetFileVersionInfoSizeExA);
export_function!(GetFileVersionInfoSizeExW);
export_function!(GetFileVersionInfoSizeW);
export_function!(GetFileVersionInfoW);
export_function!(VerFindFileA);
export_function!(VerFindFileW);
export_function!(VerInstallFileA);
export_function!(VerInstallFileW);
export_function!(VerLanguageNameA);
export_function!(VerLanguageNameW);
export_function!(VerQueryValueA);
export_function!(VerQueryValueW);

pub fn install_all_jumpers(inst: HINSTANCE) -> anyhow::Result<()> {
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoByHandle")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoExA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoExW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoSizeA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoSizeExA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoSizeExW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoSizeW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "GetFileVersionInfoW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerFindFileA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerFindFileW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerInstallFileA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerInstallFileW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerLanguageNameA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerLanguageNameW")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerQueryValueA")?;
    make_proc_jump_to_real_address(inst, "version.dll", "VerQueryValueW")?;

    Ok(())
}

pub fn make_proc_jump_to_real_address(
    inst: HINSTANCE,
    target_module: &str,
    proc_name: &str,
) -> anyhow::Result<()> {
    info!("Installing jumper for {}", proc_name);
    let load_module_dir = "C:\\Windows\\System32\\";
    let module_full_path = format!("{}{}", load_module_dir, target_module);
    let addr_in_current_module = get_proc_address_by_module(inst, proc_name)?;
    let addr_in_remote_module = get_proc_address(module_full_path.as_str(), proc_name)?;
    let protect_success = unsafe {
        let mut old_protect = 0;
        VirtualProtect(
            addr_in_current_module as *const c_void,
            12,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    } != 0;
    if !protect_success {
        return Err(anyhow::anyhow!("VirtualProtect failed: {}", unsafe {
            GetLastError()
        }));
    }
    unsafe {
        let mut bytes: [u8; 12] = [0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0];
        bytes[2..10].copy_from_slice((addr_in_remote_module as u64).to_le_bytes().as_slice());
        from_raw_parts_mut(addr_in_current_module as *mut _, 12).copy_from_slice(&bytes);
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
        get_proc_address_by_module(module_handle, proc_name)
    }
}
