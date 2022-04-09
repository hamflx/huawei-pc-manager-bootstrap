use detour::static_detour;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{c_void, CStr, CString},
    intrinsics::transmute,
    mem::MaybeUninit,
    ptr,
    slice::from_raw_parts,
};
use widestring::U16CString;
use windows_sys::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{GetLastError, BOOL, FARPROC, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::{WriteProcessMemory, PROCESSOR_ARCHITECTURE_INTEL},
            LibraryLoader::{GetModuleFileNameA, GetProcAddress, LoadLibraryA},
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            SystemInformation::{
                GetNativeSystemInfo, FIRMWARE_TABLE_ID, FIRMWARE_TABLE_PROVIDER, SYSTEM_INFO,
            },
            Threading::{
                CreateRemoteThread, GetCurrentProcess, GetExitCodeThread, GetThreadId,
                IsWow64Process, ResumeThread, TerminateProcess, WaitForSingleObject,
                CREATE_SUSPENDED, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};

#[derive(Serialize, Deserialize, Clone)]
pub struct InjectOptions {
    pub server_address: Option<String>,
    pub inject_sub_process: bool,
}

#[repr(C)]
#[derive(Serialize, Deserialize)]
pub struct INJECT_OPTIONS_WRAPPER {
    pub len: usize,
    pub ptr: u64,
}

#[repr(C)]
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct RawSMBIOSData {
    pub Used20CallingMethod: u8,
    pub SMBIOSMajorVersion: u8,
    pub SMBIOSMinorVersion: u8,
    pub DmiRevision: u8,
    pub Length: u32,
    pub SMBIOSTableData: [u8; 0],
}

#[repr(C)]
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct SMBIOSHEADER {
    pub Type: u8,
    pub Length: u8,
    pub Handle: u16,
}

#[repr(C)]
#[derive(Clone)]
#[allow(non_snake_case)]
pub struct SystemInfo {
    pub Header: SMBIOSHEADER,
    pub Manufacturer: u8,
    pub ProductName: u8,
    pub Version: u8,
    pub SN: u8,
    pub UUID: [u8; 16],
    pub WakeUpType: u8,
    pub SKUNumber: u8,
    pub Family: u8,
}

type FnCreateProcessW = unsafe extern "system" fn(
    PCWSTR,
    PWSTR,
    *const SECURITY_ATTRIBUTES,
    *const SECURITY_ATTRIBUTES,
    BOOL,
    PROCESS_CREATION_FLAGS,
    *const c_void,
    PCWSTR,
    *const STARTUPINFOW,
    *mut PROCESS_INFORMATION,
) -> BOOL;
type FnGetSystemFirmwareTable = unsafe extern "system" fn(
    FIRMWARE_TABLE_PROVIDER,
    FIRMWARE_TABLE_ID,
    *mut ::core::ffi::c_void,
    u32,
) -> u32;
type FnEnumSystemFirmwareTables = unsafe extern "system" fn(
    firmwaretableprovidersignature: FIRMWARE_TABLE_PROVIDER,
    pfirmwaretableenumbuffer: *mut FIRMWARE_TABLE_ID,
    buffersize: u32,
) -> u32;

static_detour! {
    static HookCreateProcessW: unsafe extern "system" fn(
        PCWSTR,
        PWSTR,
        *const SECURITY_ATTRIBUTES,
        *const SECURITY_ATTRIBUTES,
        BOOL,
        PROCESS_CREATION_FLAGS,
        *const c_void,
        PCWSTR,
        *const STARTUPINFOW,
        *mut PROCESS_INFORMATION
    ) -> BOOL;
  static HookGetSystemFirmwareTable: unsafe extern "system" fn(
        u32,
        u32,
        *mut c_void,
        u32
    ) -> u32;
  static HookEnumSystemFirmwareTables: unsafe extern "system" fn(
        u32,
        *mut u32,
        u32
    ) -> u32;
}

static LIBRARY_NAME: &str = "huawei_pc_manager_bootstrap_core.dll";

fn detour_get_system_firmware_table(
    firmwaretableprovidersignature: FIRMWARE_TABLE_PROVIDER,
    firmwaretableid: FIRMWARE_TABLE_ID,
    pfirmwaretablebuffer: *mut ::core::ffi::c_void,
    buffersize: u32,
) -> u32 {
    let sig_name = get_firmware_table_provider_signature(firmwaretableprovidersignature);
    let id_name = get_firmware_table_provider_signature(firmwaretableid);
    info!(
        "Calling GetSystemFirmwareTable: {}({}), {}({}), 0x{:x}, {}",
        firmwaretableprovidersignature,
        sig_name,
        firmwaretableid,
        id_name,
        pfirmwaretablebuffer as usize,
        buffersize
    );

    let result = unsafe {
        HookGetSystemFirmwareTable.call(
            firmwaretableprovidersignature,
            firmwaretableid,
            pfirmwaretablebuffer,
            buffersize,
        )
    };
    if result != 0 && !pfirmwaretablebuffer.is_null() {
        unsafe {
            let raw_bios_ptr = pfirmwaretablebuffer as *mut RawSMBIOSData;
            let start_ptr: *mut u8 = transmute(&(*raw_bios_ptr).SMBIOSTableData);
            let end_ptr = start_ptr.add((*raw_bios_ptr).Length as usize);
            let mut header_ptr: *mut SMBIOSHEADER = transmute(start_ptr as *mut u8);

            loop {
                if (*header_ptr).Type == 1 {
                    // http://huaweisn.com/
                    let new_sys_info = construct_own_sys_info(
                        header_ptr as *mut SystemInfo,
                        "HUAWEI",
                        "HKD-WXX",
                        "1.0",
                        "5EKPM18320000397",
                        "C233",
                    );
                    let first_str_ptr = (header_ptr as *mut u8).add((*header_ptr).Length as usize);
                    new_sys_info
                        .iter()
                        .enumerate()
                        .for_each(|(i, ch)| *(first_str_ptr.add(i)) = *ch);

                    dump_sys_info(header_ptr);
                }

                if (*header_ptr).Type == 127 && (*header_ptr).Length == 4 {
                    break;
                }

                let mut next_header = (header_ptr as *const u8).offset((*header_ptr).Length.into());
                while 0 != (*next_header | *(next_header.offset(1))) {
                    next_header = next_header.offset(1);
                }
                next_header = next_header.offset(2);
                if next_header >= end_ptr {
                    break;
                }
                header_ptr = next_header as *mut SMBIOSHEADER;
            }
        }
    }
    result
}

fn dump_sys_info(header_ptr: *const SMBIOSHEADER) {
    let system_info_ptr = header_ptr as *const SystemInfo;
    let first_str_ptr = unsafe { (header_ptr as *const u8).add((*header_ptr).Length as usize) };
    info!(
        "Manufacturer: {}",
        locate_string(first_str_ptr, unsafe { (*system_info_ptr).Manufacturer })
            .unwrap_or_else(|| String::from("No Manufacturer"))
    );
    info!(
        "ProductName: {}",
        locate_string(first_str_ptr, unsafe { (*system_info_ptr).ProductName })
            .unwrap_or_else(|| String::from("No ProductName"))
    );
    info!(
        "Version: {}",
        locate_string(first_str_ptr, unsafe { (*system_info_ptr).Version })
            .unwrap_or_else(|| String::from("No Version"))
    );
    info!(
        "SN: {}",
        locate_string(first_str_ptr, unsafe { (*system_info_ptr).SN })
            .unwrap_or_else(|| String::from("No SN"))
    );
    info!(
        "SysInfoData: {:?}",
        String::from_utf8_lossy(unsafe { from_raw_parts(first_str_ptr, 100) })
    );
}

fn construct_own_sys_info(
    sys_info_header: *mut SystemInfo,
    manufacture: &str,
    product_name: &str,
    version: &str,
    sn: &str,
    _sku: &str,
) -> Vec<u8> {
    let sys_info_data = format!("{}\0{}\0{}\0{}\0", manufacture, product_name, version, sn);

    unsafe {
        (*sys_info_header).Manufacturer = 1;
        (*sys_info_header).ProductName = 2;
        (*sys_info_header).Version = 3;
        (*sys_info_header).SN = 4;

        (*sys_info_header).WakeUpType = 0;
        (*sys_info_header).SKUNumber = 0;
        (*sys_info_header).Family = 0;
    }

    sys_info_data.as_bytes().to_vec()
}

fn locate_string(oem_str: *const u8, index: u8) -> Option<String> {
    if index == 0 || unsafe { *oem_str } == 0 {
        return None;
    }
    let mut i = index;
    let mut str_ptr = oem_str;
    loop {
        i -= 1;
        if i == 0 {
            break;
        }
        str_ptr = unsafe { str_ptr.add(str_len(str_ptr) as usize + 1) }
    }
    Some(
        unsafe { CStr::from_ptr(str_ptr as *const i8) }
            .to_str()
            .unwrap()
            .to_string(),
    )
}

fn str_len(cstr: *const u8) -> usize {
    let mut current_ptr = cstr;
    let mut count = 0;
    while unsafe { *current_ptr != 0 } {
        count += 1;
        current_ptr = unsafe { current_ptr.offset(1) };
    }
    return count;
}

fn detour_enum_system_firmware_tables(
    firmwaretableprovidersignature: FIRMWARE_TABLE_PROVIDER,
    pfirmwaretableenumbuffer: *mut FIRMWARE_TABLE_ID,
    buffersize: u32,
) -> u32 {
    let sig_name = get_firmware_table_provider_signature(firmwaretableprovidersignature);
    info!(
        "Calling EnumSystemFirmwareTables: {}, 0x{:x}, {}",
        sig_name, pfirmwaretableenumbuffer as usize, buffersize
    );

    let result = unsafe {
        HookEnumSystemFirmwareTables.call(
            firmwaretableprovidersignature,
            pfirmwaretableenumbuffer,
            buffersize,
        )
    };
    result
}

#[allow(clippy::too_many_arguments)]
fn detour_create_process(
    opts: &Option<InjectOptions>,
    app_name: PCWSTR,
    cmd_line: PWSTR,
    proc_attrs: *const SECURITY_ATTRIBUTES,
    th_attrs: *const SECURITY_ATTRIBUTES,
    inherit: BOOL,
    flags: PROCESS_CREATION_FLAGS,
    env: *const c_void,
    cur_dir: PCWSTR,
    startup_info: *const STARTUPINFOW,
    proc_info: *mut PROCESS_INFORMATION,
) -> BOOL {
    unsafe {
        let app_name_string = if app_name.is_null() {
            String::new()
        } else {
            U16CString::from_ptr_str(app_name).to_string().unwrap()
        };
        let cmd_line_string = if cmd_line.is_null() {
            String::new()
        } else {
            U16CString::from_ptr_str(cmd_line).to_string().unwrap()
        };
        info!("CreateProcessW: {} {}", app_name_string, cmd_line_string);
        let flags_with_suspend = CREATE_SUSPENDED | flags;
        let creating_res = HookCreateProcessW.call(
            app_name,
            cmd_line,
            proc_attrs,
            th_attrs,
            inherit,
            flags_with_suspend,
            env,
            cur_dir,
            startup_info,
            proc_info,
        );

        if creating_res != 0 {
            info!("New process id: {:?}", (*proc_info).dwProcessId);
            if cmd_line_string.contains("isSupportDevice") {
                info!("Command line contains isSupportDevice, exit with 1");
                TerminateProcess((*proc_info).hProcess, 1);
                return creating_res;
            }
            if cmd_line_string.contains("IsSupportBaZhang") {
                info!("Command line contains IsSupportBaZhang, exit with 2");
                TerminateProcess((*proc_info).hProcess, 2);
                return creating_res;
            }
            if let Err(err) = inject_to_process((*proc_info).hProcess, opts) {
                warn!("inject_to_process error: {}", err);
            }
            if flags & CREATE_SUSPENDED == 0 {
                if ResumeThread((*proc_info).hThread) == u32::MAX {
                    warn!("ResumeThread error: {}", GetLastError());
                }
            }
        } else {
            warn!("CreateProcessW failed: {}", GetLastError());
        }

        creating_res
    }
}

pub fn enable_hook(opts: Option<InjectOptions>) {
    let inject_sub_process = opts
        .as_ref()
        .map(|opts| opts.inject_sub_process)
        .unwrap_or(false);
    unsafe {
        let fp_create_process: FnCreateProcessW =
            transmute(get_proc_address("CreateProcessW", "kernel32.dll").unwrap());
        let fp_get_system_firmware_table: FnGetSystemFirmwareTable =
            transmute(get_proc_address("GetSystemFirmwareTable", "kernel32.dll").unwrap());
        let fp_enum_system_firmware_tables: FnEnumSystemFirmwareTables =
            transmute(get_proc_address("EnumSystemFirmwareTables", "kernel32.dll").unwrap());

        let opts = Box::leak(Box::new(opts));
        HookGetSystemFirmwareTable
            .initialize(
                fp_get_system_firmware_table,
                detour_get_system_firmware_table,
            )
            .unwrap();
        HookEnumSystemFirmwareTables
            .initialize(
                fp_enum_system_firmware_tables,
                detour_enum_system_firmware_tables,
            )
            .unwrap();
        HookCreateProcessW
            .initialize(
                fp_create_process,
                |app_name,
                 cmd_line,
                 proc_attrs,
                 th_attrs,
                 inherit,
                 flags,
                 env,
                 cur_dir,
                 startup_info,
                 proc_info| {
                    detour_create_process(
                        opts,
                        app_name,
                        cmd_line,
                        proc_attrs,
                        th_attrs,
                        inherit,
                        flags,
                        env,
                        cur_dir,
                        startup_info,
                        proc_info,
                    )
                },
            )
            .unwrap();
        HookGetSystemFirmwareTable.enable().unwrap();
        HookEnumSystemFirmwareTables.enable().unwrap();
        if inject_sub_process {
            HookCreateProcessW.enable().unwrap();
        }
    }
}

unsafe fn get_proc_address(proc_name: &str, module_name: &str) -> FARPROC {
    let module_name_cstr = CString::new(module_name).ok()?;
    let proc_name_cstr = CString::new(proc_name).ok()?;
    let h_inst = LoadLibraryA(module_name_cstr.as_ptr() as PCSTR);

    if h_inst == 0 {
        panic!("LoadLibraryA failed: {}", GetLastError());
    }

    GetProcAddress(h_inst, proc_name_cstr.as_ptr() as PCSTR)
}

unsafe fn inject_to_process(
    process_handle: HANDLE,
    opts: &Option<InjectOptions>,
) -> anyhow::Result<()> {
    let is_target_x86 = is_process_x86(process_handle)?;
    let is_self_x86 = is_process_x86(GetCurrentProcess())?;
    if is_target_x86 != is_self_x86 {
        return Err(anyhow::anyhow!(
            "Process architecture mismatch, expect {} got {}",
            if is_target_x86 { "x86" } else { "x64" },
            if is_self_x86 { "x86" } else { "x64" }
        ));
    }

    let mut lib_full_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow::anyhow!("No path content"))?
        .to_path_buf();
    lib_full_path.push(LIBRARY_NAME);
    let lib_full_path = lib_full_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("No path content"))?;
    info!("Get enable_hook address from {}", lib_full_path);
    let fp_enable_hook = get_proc_address("enable_hook", lib_full_path)
        .ok_or_else(|| anyhow::anyhow!("No enable_hook function found"))?;

    let library_name_with_null = format!("{}\0", LIBRARY_NAME);
    let core_module_handle = LoadLibraryA(library_name_with_null.as_ptr() as PCSTR);
    let mut core_full_name_buffer = [0u8; 4096];
    if core_module_handle == 0
        || GetModuleFileNameA(
            core_module_handle,
            core_full_name_buffer.as_mut_ptr(),
            core_full_name_buffer.len() as u32,
        ) == 0
    {
        return Err(anyhow::anyhow!(
            "GetModuleFileNameA failed: {}",
            GetLastError()
        ));
    }
    let library_name_addr = write_process_memory(process_handle, &core_full_name_buffer)?;
    let fp_load_library = get_proc_address("LoadLibraryA", "kernel32.dll")
        .ok_or_else(|| anyhow::anyhow!("No LoadLibraryA function found"))?;
    let load_library_thread = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_load_library)),
        library_name_addr,
        0,
        ptr::null_mut(),
    );
    if load_library_thread == 0 {
        return Err(anyhow::anyhow!(
            "CreateRemoteThread failed: {}",
            GetLastError()
        ));
    }
    info!(
        "Created LoadLibraryA thread with id: {}",
        GetThreadId(load_library_thread)
    );
    let wait_result = WaitForSingleObject(load_library_thread, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(anyhow::anyhow!(
            "WaitForSingleObject failed: {}",
            wait_result
        ));
    }
    let mut module_handle: u32 = 0;
    if GetExitCodeThread(load_library_thread, &mut module_handle as *mut u32) != 0
        && module_handle == 0
    {
        return Err(anyhow::anyhow!("Remote LoadLibraryA failed"));
    }

    let enable_hook_params = if let Some(opts) = opts {
        let opts_bytes = bincode::serialize(opts)?;
        let opts_ptr = write_process_memory(process_handle, opts_bytes.as_slice())?;
        info!("Write options to address {:?}", opts_ptr);
        let opts_wrapper = INJECT_OPTIONS_WRAPPER {
            len: opts_bytes.len(),
            ptr: opts_ptr as u64,
        };
        let opts_wrapper_bytes = bincode::serialize(&opts_wrapper)?;
        let opts_wrapper_ptr = write_process_memory(process_handle, opts_wrapper_bytes.as_slice())?;
        info!("Write options wrapper to address {:?}", opts_wrapper_ptr);
        opts_wrapper_ptr
    } else {
        ptr::null()
    };
    let thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_enable_hook)),
        enable_hook_params,
        0,
        ptr::null_mut(),
    );
    if thread_handle == 0 {
        return Err(anyhow::anyhow!(
            "CreateRemoteThread failed: {}",
            GetLastError()
        ));
    }
    info!(
        "Created enable_hook thread with id: {}",
        GetThreadId(thread_handle)
    );
    let wait_result = WaitForSingleObject(thread_handle, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(anyhow::anyhow!(
            "WaitForSingleObject failed: {}",
            wait_result
        ));
    }

    Ok(())
}

fn is_process_x86(process_handle: HANDLE) -> anyhow::Result<bool> {
    let sys_info = unsafe {
        let mut sys_info = MaybeUninit::<SYSTEM_INFO>::uninit();
        GetNativeSystemInfo(sys_info.as_mut_ptr());
        sys_info.assume_init()
    };
    let processor_arch = unsafe { sys_info.Anonymous.Anonymous.wProcessorArchitecture };
    Ok(processor_arch == PROCESSOR_ARCHITECTURE_INTEL || is_wow64_process(process_handle)?)
}

fn is_wow64_process(process_handle: HANDLE) -> anyhow::Result<bool> {
    let mut is_wow64 = 0;
    unsafe {
        if IsWow64Process(process_handle, &mut is_wow64) == 0 {
            return Err(anyhow::anyhow!("IsWow64Process failed: {}", GetLastError()));
        }
    }
    Ok(is_wow64 != 0)
}

unsafe fn write_process_memory(
    process_handle: HANDLE,
    content: &[u8],
) -> anyhow::Result<*mut c_void> {
    let target_address = VirtualAllocEx(
        process_handle,
        ptr::null(),
        content.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if target_address.is_null() {
        return Err(anyhow::anyhow!("VirtualAllocEx failed: {}", GetLastError()));
    }
    let success = WriteProcessMemory(
        process_handle,
        target_address,
        content.as_ptr() as *const c_void,
        content.len(),
        ptr::null_mut(),
    );
    if success == 0 {
        return Err(anyhow::anyhow!(
            "WriteProcessMemory failed: {}",
            GetLastError()
        ));
    }
    Ok(target_address)
}

fn get_firmware_table_provider_signature(firmwaretableprovidersignature: u32) -> String {
    let mut sig_name_bytes = unsafe {
        from_raw_parts(
            &firmwaretableprovidersignature as *const u32 as *const u8,
            4,
        )
    }
    .to_vec();
    sig_name_bytes.reverse();
    let sig_name = String::from_utf8(sig_name_bytes).unwrap_or_else(|e| format!("Error({})", e));
    sig_name
}
