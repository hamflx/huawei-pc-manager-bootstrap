use common::INJECT_OPTIONS;

mod common;

#[no_mangle]
pub extern "C" fn enable_hook(opts: INJECT_OPTIONS) {
    common::enable_hook(Some(opts));
}
