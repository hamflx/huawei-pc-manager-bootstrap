use std::{env, process::Command};

use communication::InterProcessComServer;
use log::info;
use simple_logger::SimpleLogger;

use crate::common::InjectOptions;

mod common;
mod communication;

fn main() {
    SimpleLogger::new().init().unwrap();

    let server = InterProcessComServer::listen("127.0.0.1:0").unwrap();
    let address = server.get_address().unwrap();
    server.start();

    info!("Listening on {}", address.to_string());

    common::enable_hook(Some(InjectOptions {
        server_address: Some(address.to_string()),
    }));

    let self_args: Vec<String> = env::args().skip(1).collect();
    let command_name = self_args.get(0).unwrap().to_owned();
    let command_args = self_args.into_iter().skip(1).collect::<Vec<String>>();
    let mut command = Command::new(command_name)
        .args(command_args)
        .spawn()
        .unwrap();

    command.wait().unwrap();
}
