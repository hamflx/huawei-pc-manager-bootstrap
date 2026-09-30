@echo off
setlocal
cd /d "%~dp0"

cargo +nightly-2025-02-01-x86_64-pc-windows-msvc build --locked -p version --target=x86_64-pc-windows-msvc || exit /b 1
cargo +nightly-2025-02-01-i686-pc-windows-msvc build --locked -p huawei-pc-manager-bootstrap-core -p huawei-pc-manager-bootstrap --target=i686-pc-windows-msvc || exit /b 1
