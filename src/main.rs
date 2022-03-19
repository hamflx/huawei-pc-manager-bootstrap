#[macro_use]
extern crate minhook;
extern crate user32;
extern crate winapi;

use std::ptr;

use winapi::{c_int, HWND, LPCSTR, UINT};

static_hooks! {
    // Create a hook for user32::MessageBoxA.
    impl MessageBoxA for user32::MessageBoxA: unsafe extern "system" fn(HWND, LPCSTR, LPCSTR, UINT) -> c_int;
}

fn main() {
    // Create a detour closure. This closure can capture any Sync variables.
    let detour =
        |wnd, text, caption, flags| unsafe { MessageBoxA.call_real(wnd, caption, text, flags) };

    // Install the hook.
    unsafe {
        MessageBoxA.initialize(detour).unwrap();
    }

    let hello = b"Hello\0".as_ptr() as LPCSTR;
    let world = b"World\0".as_ptr() as LPCSTR;

    // Call the function.
    unsafe {
        user32::MessageBoxA(ptr::null_mut(), hello, world, winapi::MB_OK);
    }

    // Enable the hook.
    MessageBoxA.enable().unwrap();

    // Call the - now hooked - function.
    unsafe {
        user32::MessageBoxA(ptr::null_mut(), hello, world, winapi::MB_OK);
    }
}
