use std::fs::File;
use std::slice::from_raw_parts;

use common::communication::InterProcessComClient;
use injectors::options::{InjectOptions, INJECT_OPTIONS_WRAPPER};
use tracing::{error, info};
use tracing_subscriber::{prelude::*, util::SubscriberInitExt};

#[no_mangle]
pub unsafe extern "system" fn enable_hook(opts_ptr: *const INJECT_OPTIONS_WRAPPER) {
    let opts: Option<InjectOptions> = if opts_ptr.is_null() || (*opts_ptr).len == 0 {
        None
    } else {
        let ptr = (*opts_ptr).ptr as *const u8;
        bincode::deserialize(from_raw_parts(ptr, (*opts_ptr).len)).ok()
    };

    opts.as_ref()
        .and_then(|opts| opts.server_address.as_ref())
        .and_then(|addr| InterProcessComClient::connect(addr).ok())
        .map(|client| {
            // log::set_max_level(LevelFilter::Info);
            tracing_subscriber::registry().with(client).init();
        })
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

    tracing_subscriber::fmt::fmt()
        .with_writer(File::create(log_file_path)?)
        .try_init()
        .map_err(|err| anyhow::anyhow!("error: {}", err))?;

    Ok(())
}
