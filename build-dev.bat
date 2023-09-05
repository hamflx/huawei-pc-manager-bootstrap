if not exist dist mkdir dist

cargo +nightly build -p version --target=x86_64-pc-windows-msvc || exit 1
cargo +nightly-i686-pc-windows-msvc build -p huawei-pc-manager-bootstrap-core -p huawei-pc-manager-bootstrap --target=i686-pc-windows-msvc || exit 1
