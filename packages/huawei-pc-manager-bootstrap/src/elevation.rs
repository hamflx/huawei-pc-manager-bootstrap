//! Elevation uses a checked launch and keeps CLI callers waiting for the result.
//! The quoting helpers are platform-independent so tests never request UAC.

/// Quote a single argument using Windows' backslash-before-quote rules.
/// Always quoting also preserves empty arguments, tabs and trailing backslashes.
fn append_argument(command_line: &mut Vec<u16>, argument: &[u16]) {
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;

    if !command_line.is_empty() {
        command_line.push(b' ' as u16);
    }
    command_line.push(QUOTE);
    let mut backslashes = 0;
    for &character in argument {
        if character == BACKSLASH {
            backslashes += 1;
            continue;
        }
        if character == QUOTE {
            command_line.extend(std::iter::repeat(BACKSLASH).take(backslashes * 2 + 1));
        } else {
            command_line.extend(std::iter::repeat(BACKSLASH).take(backslashes));
        }
        backslashes = 0;
        command_line.push(character);
    }
    command_line.extend(std::iter::repeat(BACKSLASH).take(backslashes * 2));
    command_line.push(QUOTE);
}

fn elevation_parameters(
    arguments: impl IntoIterator<Item = Vec<u16>>,
) -> Result<Vec<u16>, &'static str> {
    let mut command_line = Vec::new();
    for argument in arguments {
        if argument.contains(&0) {
            return Err("An elevation argument contains an interior NUL");
        }
        append_argument(&mut command_line, &argument);
    }
    append_argument(
        &mut command_line,
        &"--ensure-admin".encode_utf16().collect::<Vec<_>>(),
    );
    Ok(command_line)
}

fn check_elevation_launch(
    succeeded: bool,
    last_error: impl FnOnce() -> std::io::Error,
) -> Result<(), String> {
    if succeeded {
        return Ok(());
    }
    // Read the OS error immediately after a failed launch, never on success.
    let error = last_error();
    let context = if error.raw_os_error() == Some(1223) {
        // ERROR_CANCELLED from WinError.h.
        "Administrator permission was cancelled. Approve the Windows UAC prompt to continue."
    } else {
        "Failed to restart the application as administrator"
    };
    Err(format!("{context}: {error}"))
}

fn check_child_exit_code(exit_code: u32) -> Result<(), String> {
    if exit_code == 0 {
        Ok(())
    } else {
        Err(format!(
            "The elevated command failed with exit code {exit_code}. See its diagnostic log for details."
        ))
    }
}

#[cfg(windows)]
pub use platform::{attach_parent_console, relaunch_as_admin};

#[cfg(windows)]
mod platform {
    use std::os::windows::ffi::OsStrExt;

    use anyhow::Context;
    use widestring::WideCString;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0},
        System::{
            Console::{
                AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE,
                STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            },
            Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE},
        },
        UI::{
            Shell::{
                ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
                SHELLEXECUTEINFOW,
            },
            WindowsAndMessaging::SW_SHOWNORMAL,
        },
    };

    pub fn attach_parent_console() {
        // A GUI launch may have no parent console; failure is harmless. Do not
        // create a new console, and leave redirected handles untouched.
        unsafe {
            let handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE]
                .map(|kind| (kind, GetStdHandle(kind)));
            if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                for (kind, handle) in handles {
                    if handle != 0 && handle != INVALID_HANDLE_VALUE {
                        SetStdHandle(kind, handle);
                    }
                }
            }
        }
    }

    struct ProcessHandle(HANDLE);

    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub fn relaunch_as_admin(wait_for_exit: bool) -> anyhow::Result<()> {
        let executable =
            std::env::current_exe().context("Failed to find the current executable")?;
        let executable = WideCString::from_os_str(executable.as_os_str())
            .context("Failed to encode the current executable path")?;
        let directory = std::env::current_dir().context("Failed to find the working directory")?;
        let directory = WideCString::from_os_str(directory.as_os_str())
            .context("Failed to encode the working directory")?;
        let parameters = super::elevation_parameters(
            std::env::args_os()
                .skip(1)
                .map(|arg| arg.encode_wide().collect()),
        )
        .map_err(anyhow::Error::msg)?;
        let parameters = WideCString::from_vec(parameters)
            .context("Failed to encode the elevation command line")?;
        let operation = WideCString::from_str("runas")?;
        // All unused fields are optional and must be zero. These owned strings
        // stay alive until the synchronous ShellExecuteExW call has returned.
        let mut launch: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        launch.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        launch.lpVerb = operation.as_ptr();
        launch.lpFile = executable.as_ptr();
        launch.lpParameters = parameters.as_ptr();
        launch.lpDirectory = directory.as_ptr();
        launch.nShow = SW_SHOWNORMAL as i32;
        let succeeded = unsafe { ShellExecuteExW(&mut launch) } != 0;
        super::check_elevation_launch(succeeded, std::io::Error::last_os_error)
            .map_err(anyhow::Error::msg)?;

        if launch.hProcess == 0 {
            anyhow::ensure!(
                !wait_for_exit,
                "Windows did not return a process handle; the elevated command result is unknown"
            );
            return Ok(());
        }
        let process = ProcessHandle(launch.hProcess);
        if !wait_for_exit {
            return Ok(());
        }
        // GUI launches remain detached, but scripts must see the actual command
        // result rather than success merely because the UAC launch succeeded.
        let wait_result = unsafe { WaitForSingleObject(process.0, INFINITE) };
        if wait_result == WAIT_FAILED {
            return Err(std::io::Error::last_os_error())
                .context("Failed to wait for the elevated command");
        }
        anyhow::ensure!(
            wait_result == WAIT_OBJECT_0,
            "Unexpected wait result for the elevated command: {wait_result}"
        );
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to read the elevated command's exit code");
        }
        super::check_child_exit_code(exit_code).map_err(anyhow::Error::msg)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_argument, check_child_exit_code, check_elevation_launch, elevation_parameters,
    };

    fn quote(argument: &str) -> String {
        let mut result = Vec::new();
        append_argument(&mut result, &argument.encode_utf16().collect::<Vec<_>>());
        String::from_utf16(&result).unwrap()
    }

    #[test]
    fn quotes_empty_arguments_spaces_and_tabs() {
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote("a\tb"), "\"a\tb\"");
    }

    #[test]
    fn escapes_embedded_quotes_and_their_preceding_backslashes() {
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(quote("\"already quoted\""), "\"\\\"already quoted\\\"\"");
    }

    #[test]
    fn preserves_windows_paths_and_doubles_trailing_backslashes() {
        assert_eq!(
            quote(r"C:\Program Files\setup.exe"),
            r#""C:\Program Files\setup.exe""#
        );
        assert_eq!(quote(r"C:\folder name\"), r#""C:\folder name\\""#);
        assert_eq!(quote(r"C:\folder name\\"), r#""C:\folder name\\\\""#);
    }

    #[test]
    fn preserves_unicode_and_unpaired_utf16_surrogates() {
        assert_eq!(quote("华为 📦.exe"), "\"华为 📦.exe\"");
        let mut result = Vec::new();
        append_argument(&mut result, &[0xd800, b' ' as u16, 0xdc00]);
        assert_eq!(
            result,
            [b'"' as u16, 0xd800, b' ' as u16, 0xdc00, b'"' as u16]
        );
    }

    #[test]
    fn adds_the_admin_guard_and_leaves_nul_termination_to_the_c_string() {
        let parameters = elevation_parameters(
            ["--install", "C:\\华为 files\\setup.exe"]
                .into_iter()
                .map(|arg| arg.encode_utf16().collect()),
        )
        .unwrap();
        assert!(!parameters.contains(&0));
        assert_eq!(
            String::from_utf16(&parameters).unwrap(),
            "\"--install\" \"C:\\华为 files\\setup.exe\" \"--ensure-admin\""
        );
        assert_eq!(
            String::from_utf16(&elevation_parameters([]).unwrap()).unwrap(),
            "\"--ensure-admin\""
        );
    }

    #[test]
    fn rejects_nuls_instead_of_silently_truncating_arguments() {
        assert!(elevation_parameters([vec![b'a' as u16, 0, b'b' as u16]]).is_err());
    }

    #[test]
    fn successful_launch_does_not_read_a_stale_os_error() {
        assert!(check_elevation_launch(true, || panic!("must not read last error")).is_ok());
    }

    #[test]
    fn cancelled_uac_and_failed_launches_are_errors() {
        let cancellation =
            check_elevation_launch(false, || std::io::Error::from_raw_os_error(1223)).unwrap_err();
        assert!(cancellation.contains("Administrator permission was cancelled"));
        assert!(cancellation.contains("1223"));
        let failure =
            check_elevation_launch(false, || std::io::Error::from_raw_os_error(2)).unwrap_err();
        assert!(failure.contains("Failed to restart the application as administrator"));
        assert!(failure.contains("2"));
    }

    #[test]
    fn unsuccessful_elevated_commands_are_not_reported_as_success() {
        assert!(check_child_exit_code(0).is_ok());
        for exit_code in [1, 2, 3010, u32::MAX] {
            let error = check_child_exit_code(exit_code).unwrap_err();
            assert!(error.contains(&exit_code.to_string()));
        }
    }
}
