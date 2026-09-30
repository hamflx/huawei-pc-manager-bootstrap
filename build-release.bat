@echo off
setlocal
cd /d "%~dp0"

cargo +nightly-2025-02-01-x86_64-pc-windows-msvc build --locked --release -p version --target=x86_64-pc-windows-msvc || exit /b 1
cargo +nightly-2025-02-01-i686-pc-windows-msvc build --locked --release -p huawei-pc-manager-bootstrap-core -p huawei-pc-manager-bootstrap --target=i686-pc-windows-msvc || exit /b 1

if not exist dist mkdir dist
copy /y target\i686-pc-windows-msvc\release\huawei_pc_manager_bootstrap_core.dll dist\ || exit /b 1
copy /y target\i686-pc-windows-msvc\release\huawei-pc-manager-bootstrap.exe dist\ || exit /b 1
