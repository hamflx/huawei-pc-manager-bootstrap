# Windows verification checklist

These checks distinguish a successful build from a verified installation. Do not close
issues #22 or #43 solely because CI passes: their reported machines and installers
have not been reproduced by the automated tests.

## Automated checks

The Windows workflow targets `master`, builds with the pinned nightly and locked
dependencies, runs installer/elevation regression tests, and verifies:

- `version.dll` is AMD64 (x64) and the embedded patch regression test agrees
- the launcher EXE and injected core DLL are I386 (x86)
- both distribution files exist before artifact upload

The workflow does not run an actual Huawei installer, request UAC elevation, or test
PCManager/multi-screen functionality.

## Manual checks on a disposable Windows test machine

Use an ordinary non-administrator launch and the two files from the same CI artifact.
Keep logs and note Windows version, hardware and the exact Huawei installer version.

1. Launch normally, accept UAC, and confirm that the elevated GUI opens once
2. Cancel UAC and confirm that a visible cancellation/error message appears
3. Launch with `--ensure-admin` without elevation and confirm that it fails visibly
4. Select a nonexistent installer: the GUI must show failure, never success
5. Start an installer and keep it open: status must remain in progress; repeated
   Install/Patch/process-termination actions must not start concurrent work
6. Cancel or fail the installer: a nonzero result must be shown as failure
7. Complete the supported installer: success requires successful process exit,
   `PCManager.exe` present and patch installation completed
8. Make the patch destination unwritable/in use in a controlled test: the error must
   reach the GUI or CLI rather than being logged as success
9. Repeat a failed attempt with valid inputs and verify recovery
10. Invoke CLI installation from a terminal; verify nonzero failure exit status,
    including when an elevated child fails
11. Test file paths containing spaces and non-ASCII characters
12. Close the launcher during an active installation and document behavior; this
    patch does not promise process cancellation or rollback on window close

For #43, distinguish a bootstrap elevation failure from a message emitted by Huawei's
installer itself. For #22, collect the startup error/log from the reported AMD Windows
11 machine before claiming a specific root cause.
