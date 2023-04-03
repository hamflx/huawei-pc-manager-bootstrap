use forward_dll::forward_dll;

fn main() {
    forward_dll("C:\\Windows\\system32\\version.dll").unwrap();
}
