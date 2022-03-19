use std::{env, process::Command};

mod common;

fn main() {
    common::enable_hook(None);

    let self_args: Vec<String> = env::args().skip(1).collect();
    let command_name = self_args.get(0).unwrap().to_owned();
    let command_args = self_args.into_iter().skip(1).collect::<Vec<String>>();
    let mut command = Command::new(command_name)
        .args(command_args)
        .spawn()
        .unwrap();

    command.wait().unwrap();
}
