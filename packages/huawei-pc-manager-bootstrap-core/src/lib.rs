#![feature(ptr_const_cast)]

use std::fs::File;
use std::slice::from_raw_parts;

use common::common::{InjectOptions, INJECT_OPTIONS_WRAPPER};
use common::communication::InterProcessComClient;
use log::{error, info, LevelFilter};
use simplelog::{Config, WriteLogger};

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
    .or_else(|| initialize_file_logger().ok());

    info!("Enabling hook ...");
    if let Err(err) = common::common::enable_hook(opts) {
        error!("{}", err);
    }
}

pub fn initialize_file_logger() -> anyhow::Result<()> {
    let project_dir = directories::ProjectDirs::from("cn", "hamflx", "huawei_pc_manager_bootstrap")
        .ok_or_else(|| anyhow::anyhow!("No project dir"))?;
    let cache_dir = project_dir.cache_dir();
    std::fs::create_dir_all(cache_dir)?;

    let mut log_file_path = cache_dir.to_path_buf();
    let now = chrono::Local::now();
    log_file_path.push(format!("core-{}.log", now.format("%Y%m%d%H%M%S")));

    WriteLogger::init(
        LevelFilter::Info,
        Config::default(),
        File::create(log_file_path)?,
    )?;
    Ok(())
}
