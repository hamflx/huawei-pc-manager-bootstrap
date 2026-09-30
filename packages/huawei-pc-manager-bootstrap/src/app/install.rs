//! Installer orchestration, separated from the Windows UI for side-effect-free
//! regression tests with a fake process and fake filesystem/patch operations.

use std::io;
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::Duration;

type InstallResult<T> = Result<T, String>;

trait InstallerProcess {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>>;
}

impl InstallerProcess for Child {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        Child::try_wait(self)
    }
}

pub(crate) fn run(
    executable_file_path: &str,
    check_installed: impl FnMut() -> InstallResult<bool>,
    install_patch: impl FnMut() -> InstallResult<()>,
    log: impl FnMut(&str),
) -> InstallResult<()> {
    run_with(
        executable_file_path,
        || Command::new(executable_file_path).spawn(),
        check_installed,
        install_patch,
        || thread::sleep(Duration::from_millis(100)),
        log,
    )
}

fn run_with<P: InstallerProcess>(
    executable_file_path: &str,
    spawn: impl FnOnce() -> io::Result<P>,
    mut check_installed: impl FnMut() -> InstallResult<bool>,
    mut install_patch: impl FnMut() -> InstallResult<()>,
    mut pause: impl FnMut(),
    mut log: impl FnMut(&str),
) -> InstallResult<()> {
    log(&format!("Executing {}", executable_file_path));
    let mut installer =
        spawn().map_err(|err| format!("Failed to execute {}: {}", executable_file_path, err))?;
    let mut patch_installed = false;

    loop {
        let status = installer
            .try_wait()
            .map_err(|err| format!("Failed to wait for {}: {}", executable_file_path, err))?;
        if let Some(status) = status {
            log(&format!(
                "{} exited with status {}",
                executable_file_path, status
            ));
            if !status.success() {
                return Err(format!(
                    "Installer {} exited unsuccessfully: {}",
                    executable_file_path, status
                ));
            }
            break;
        }

        // Preserve early patching, before the setup program launches PCManager.
        // Transient file locks may recover while setup is running. A final
        // attempt below must succeed before reporting installation success.
        if !patch_installed {
            match check_installed() {
                Ok(true) => match install_patch() {
                    Ok(()) => {
                        patch_installed = true;
                        log("Installed patch successfully");
                    }
                    Err(err) => log(&format!("Failed to install patch; will retry: {}", err)),
                },
                Ok(false) => {}
                Err(err) => log(&format!(
                    "Failed to check PCManager installation; will retry: {}",
                    err
                )),
            }
        }
        pause();
    }

    // A successful exit can also mean cancellation or an already-closed setup
    // stub. Never call those success unless the expected executable exists.
    if !check_installed()
        .map_err(|err| format!("Failed to check PCManager installation: {}", err))?
    {
        return Err("Installer exited successfully, but PCManager.exe was not found".into());
    }

    // Also handles installers that exit before the first polling interval.
    // Do not rewrite an already-installed DLL that PCManager may have loaded.
    if !patch_installed {
        install_patch().map_err(|err| format!("Failed to install patch: {}", err))?;
        log("Installed patch successfully");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct FakeInstaller {
        polls: VecDeque<io::Result<Option<ExitStatus>>>,
    }

    impl InstallerProcess for FakeInstaller {
        fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            self.polls.pop_front().expect("unexpected process poll")
        }
    }

    fn fake(polls: impl IntoIterator<Item = io::Result<Option<ExitStatus>>>) -> FakeInstaller {
        FakeInstaller {
            polls: polls.into_iter().collect(),
        }
    }

    fn status(code: u32) -> ExitStatus {
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            ExitStatus::from_raw(code)
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            ExitStatus::from_raw((code as i32) << 8)
        }
    }

    fn failure(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::Other, message)
    }

    #[test]
    fn spawn_failure_is_returned() {
        let result = run_with(
            "setup.exe",
            || Err::<FakeInstaller, _>(failure("spawn failed")),
            || panic!("must not inspect installation after spawn failure"),
            || panic!("must not patch after spawn failure"),
            || panic!("must not wait after spawn failure"),
            |_| {},
        );
        assert_eq!(
            result,
            Err("Failed to execute setup.exe: spawn failed".into())
        );
    }

    #[test]
    fn wait_failure_is_returned() {
        let result = run_with(
            "setup.exe",
            || Ok(fake([Err(failure("wait failed"))])),
            || panic!("must not inspect installation after wait failure"),
            || panic!("must not patch after wait failure"),
            || panic!("must not sleep after wait failure"),
            |_| {},
        );
        assert_eq!(
            result,
            Err("Failed to wait for setup.exe: wait failed".into())
        );
    }

    #[test]
    fn nonzero_exit_is_returned_even_when_pc_manager_was_already_installed() {
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(Some(status(17)))])),
            || Ok(true),
            || Ok(()),
            || {},
            |_| {},
        );
        let error = result.unwrap_err();
        assert!(error.contains("exited unsuccessfully"));
        assert!(error.contains("17"));
    }

    #[test]
    fn successful_exit_without_installed_executable_is_failure() {
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(Some(status(0)))])),
            || Ok(false),
            || panic!("must not patch without PCManager.exe"),
            || {},
            |_| {},
        );
        assert_eq!(
            result,
            Err("Installer exited successfully, but PCManager.exe was not found".into())
        );
    }

    #[test]
    fn final_installation_check_failure_is_returned() {
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(Some(status(0)))])),
            || Err("access denied".into()),
            || panic!("must not patch when installation cannot be checked"),
            || {},
            |_| {},
        );
        assert_eq!(
            result,
            Err("Failed to check PCManager installation: access denied".into())
        );
    }

    #[test]
    fn immediate_successful_exit_still_installs_patch() {
        let mut patch_calls = 0;
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(Some(status(0)))])),
            || Ok(true),
            || {
                patch_calls += 1;
                Ok(())
            },
            || panic!("an exited installer must not sleep"),
            |_| {},
        );
        assert_eq!(result, Ok(()));
        assert_eq!(patch_calls, 1);
    }

    #[test]
    fn final_patch_failure_is_returned() {
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(Some(status(0)))])),
            || Ok(true),
            || Err("DLL is locked".into()),
            || {},
            |_| {},
        );
        assert_eq!(result, Err("Failed to install patch: DLL is locked".into()));
    }

    #[test]
    fn early_patch_does_not_finish_installation_before_process_exit() {
        let mut patch_calls = 0;
        let mut sleeps = 0;
        let mut check_calls = 0;
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(None), Ok(None), Ok(Some(status(0)))])),
            || {
                check_calls += 1;
                Ok(true)
            },
            || {
                patch_calls += 1;
                Ok(())
            },
            || sleeps += 1,
            |_| {},
        );
        assert_eq!(result, Ok(()));
        assert_eq!(patch_calls, 1);
        assert_eq!(check_calls, 2); // early patch and post-exit verification
        assert_eq!(sleeps, 2);
    }

    #[test]
    fn successful_early_patch_does_not_hide_failed_exit() {
        let mut patch_calls = 0;
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(None), Ok(Some(status(2)))])),
            || Ok(true),
            || {
                patch_calls += 1;
                Ok(())
            },
            || {},
            |_| {},
        );
        assert_eq!(patch_calls, 1);
        assert!(result.unwrap_err().contains("exited unsuccessfully"));
    }

    #[test]
    fn persistent_early_patch_failure_is_not_swallowed() {
        let mut patch_calls = 0;
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(None), Ok(Some(status(0)))])),
            || Ok(true),
            || {
                patch_calls += 1;
                Err("access denied".into())
            },
            || {},
            |_| {},
        );
        assert_eq!(patch_calls, 2);
        assert_eq!(result, Err("Failed to install patch: access denied".into()));
    }

    #[test]
    fn transient_patch_failure_can_recover() {
        let mut patch_calls = 0;
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(None), Ok(None), Ok(Some(status(0)))])),
            || Ok(true),
            || {
                patch_calls += 1;
                if patch_calls == 1 {
                    Err("file temporarily locked".into())
                } else {
                    Ok(())
                }
            },
            || {},
            |_| {},
        );
        assert_eq!(patch_calls, 2);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn installer_can_remove_executable_after_early_patch() {
        let mut checks = [Ok(true), Ok(false)].into_iter();
        let result = run_with(
            "setup.exe",
            || Ok(fake([Ok(None), Ok(Some(status(0)))])),
            || checks.next().unwrap(),
            || Ok(()),
            || {},
            |_| {},
        );
        assert!(result.unwrap_err().contains("PCManager.exe was not found"));
    }
}
