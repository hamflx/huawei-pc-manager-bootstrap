#![feature(ptr_const_cast)]

use std::slice::from_raw_parts;

use common::{InjectOptions, INJECT_OPTIONS_WRAPPER};
use communication::InterProcessComClient;
use log::{info, LevelFilter};
use simple_logger::SimpleLogger;

mod common;
mod communication;

#[no_mangle]
pub unsafe extern "system" fn enable_hook(opts_ptr: *const INJECT_OPTIONS_WRAPPER) {
    let opts: Option<InjectOptions> = if opts_ptr.is_null() || (*opts_ptr).len == 0 {
        None
    } else {
        let ptr = (*opts_ptr).ptr as *const u8;
        bincode::deserialize(from_raw_parts(ptr, (*opts_ptr).len)).ok()
    };

    if let Some(opts) = &opts {
        if let Some(address) = &opts.server_address {
            if let Ok(client) = InterProcessComClient::connect(address) {
                log::set_max_level(LevelFilter::Info);
                log::set_logger(Box::leak(Box::new(client))).ok()
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
    .or_else(|| SimpleLogger::new().init().ok());

    info!("Enabling hook ...");
    common::enable_hook(opts);
}
