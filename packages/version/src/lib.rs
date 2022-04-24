use std::{arch::asm, ffi::CString, fs::OpenOptions};

use common::common::InjectOptions;
use log::{error, info};
use simplelog::{Config, LevelFilter, WriteLogger};
use windows_sys::Win32::{
    Foundation::{GetLastError, HINSTANCE},
    System::LibraryLoader::{
        GetModuleHandleExA, GetProcAddress, LoadLibraryA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_PIN,
    },
};

#[no_mangle]
pub extern "system" fn DllMain(inst: HINSTANCE, reason: u32, _: *const u8) -> u32 {
    if reason == 1 {
        if let Err(err) = initialize(inst) {
            error!("{}", err);
            return 0;
        } else {
            info!("Version Injector initialized");
        }
    }
    1
}

pub fn initialize(inst: HINSTANCE) -> anyhow::Result<bool> {
    let mut module_handle = 0;
    let pin_success = unsafe {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            inst as *const u8,
            &mut module_handle,
        )
    } != 0;
    if !pin_success {
        return Err(anyhow::anyhow!(
            "Failed to pin module handle: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result_of_install_jumpers = unsafe { EXPORT_VERSION_FUNCTIONS.install_all_jumpers() };

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

macro_rules! count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
}

macro_rules! define_functions {
    ($lib:expr, $name:ident, $($proc:ident)*) => {
        static mut $name: ExportFunctions<{ count!($($proc)*) }> = ExportFunctions{
            lib_name: $lib,
            target_functions_address: [
                0;
                count!($($proc)*)
            ],
            target_function_names: [
                $(stringify!($proc),)*
            ]
        };
        define_function!($name, 0, $($proc)*);
    };
}

macro_rules! define_function {
    ($name:ident, $index:expr, ) => {};
    ($name:ident, $index:expr, $proc:ident $($procs:ident)*) => {
        #[no_mangle]
        pub extern "system" fn $proc() -> u32 {
            unsafe {
                asm!(
                    "jmp rax",
                    in("rax") $name.target_functions_address[$index],
                    options(nostack)
                );
            }
            1
        }
        define_function!($name, ($index + 1), $($procs)*);
    };
}

define_functions!(
    "version.dll",
    EXPORT_VERSION_FUNCTIONS,
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

pub struct ExportFunctions<const N: usize> {
    pub target_functions_address: [usize; N],
    pub target_function_names: [&'static str; N],
    pub lib_name: &'static str,
}

impl<const N: usize> ExportFunctions<N> {
    pub fn make_proc_jump_to_real_address(&mut self, index: usize) -> anyhow::Result<()> {
        let load_module_dir = "C:\\Windows\\System32\\";
        let module_full_path = format!("{}{}", load_module_dir, self.lib_name);
        let addr_in_remote_module =
            get_proc_address(module_full_path.as_str(), self.target_function_names[index])?;

        self.target_functions_address[index] = addr_in_remote_module as *const usize as usize;

        Ok(())
    }

    pub fn install_all_jumpers(&mut self) -> anyhow::Result<()> {
        for index in 0..self.target_functions_address.len() {
            self.make_proc_jump_to_real_address(index)?;
        }
        Ok(())
    }
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
        proc_address
    }
}
