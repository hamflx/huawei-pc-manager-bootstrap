use detour::static_detour;
use std::{
    ffi::{c_void, CString},
    intrinsics::transmute,
    ptr,
};
use widestring::U16CString;
use windows_sys::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{GetLastError, BOOL, FARPROC, HANDLE},
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
            Threading::{
                CreateRemoteThread, ResumeThread, WaitForSingleObject, CREATE_SUSPENDED,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};

#[repr(C)]
pub struct INJECT_OPTIONS {
    pub main_process: HANDLE,
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
}

static LIBRARY_NAME: &str = "program_bootstrap_core.dll";

#[allow(clippy::too_many_arguments)]
fn detour_create_process(
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
        println!(
            "==> CreateProcessW: {} {}",
            app_name_string, cmd_line_string
        );
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
            println!("==> New process handle: {:?}", (*proc_info).hProcess);
            if let Err(err) = inject_to_process((*proc_info).hProcess) {
                println!("==> inject_to_process error: {}", err);
            }
            ResumeThread((*proc_info).hThread);
        } else {
            println!("==> CreateProcessW failed: {}", GetLastError());
        }

        creating_res
    }
}

pub fn enable_hook(_opts: Option<INJECT_OPTIONS>) {
    unsafe {
        let fp_create_process: FnCreateProcessW =
            transmute(get_proc_address("CreateProcessW", "kernel32.dll").unwrap());

        HookCreateProcessW
            .initialize(fp_create_process, detour_create_process)
            .unwrap();
        HookCreateProcessW.enable().unwrap();
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

unsafe fn inject_to_process(process_handle: HANDLE) -> anyhow::Result<()> {
    let fp_enable_hook = get_proc_address("enable_hook", LIBRARY_NAME)
        .ok_or_else(|| anyhow::anyhow!("No enable_hook function found"))?;

    let dll_name_addr = VirtualAllocEx(
        process_handle,
        ptr::null(),
        1024,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if dll_name_addr.is_null() {
        return Err(anyhow::anyhow!("VirtualAllocEx failed: {}", GetLastError()));
    }

    let library_name_with_null = format!("{}\0", LIBRARY_NAME);
    let library_name_addr =
        write_process_memory(process_handle, library_name_with_null.as_bytes())?;
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
    let wait_result = WaitForSingleObject(load_library_thread, 0xFFFFFFFF);
    if wait_result != 0 {
        return Err(anyhow::anyhow!(
            "WaitForSingleObject failed: {}",
            wait_result
        ));
    }

    let thread_handle = CreateRemoteThread(
        process_handle,
        ptr::null(),
        0,
        Some(transmute(fp_enable_hook)),
        ptr::null(),
        0,
        ptr::null_mut(),
    );
    if thread_handle == 0 {
        return Err(anyhow::anyhow!(
            "CreateRemoteThread failed: {}",
            GetLastError()
        ));
    }

    Ok(())
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
