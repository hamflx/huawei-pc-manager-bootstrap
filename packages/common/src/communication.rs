use std::{
    env,
    ffi::OsStr,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    thread::{self, JoinHandle},
};

use log::{info, Level, Metadata, Record};
use serde::{Deserialize, Serialize};

pub struct InterProcessComServer {
    listener: TcpListener,
    threads: Vec<JoinHandle<()>>,
}

impl InterProcessComServer {
    pub fn listen(address: &str) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(address)?;
        Ok(InterProcessComServer {
            listener,
            threads: Vec::new(),
        })
    }

    pub fn get_address(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn run(mut self) -> anyhow::Result<()> {
        for stream_res in self.listener.incoming() {
            let stream = stream_res?;
            let handle = thread::spawn(move || {
                let _ = InterProcessComServer::handle_client(stream);
            });
            self.threads.push(handle);
        }
        Ok(())
    }

    pub fn start(self) -> JoinHandle<anyhow::Result<()>> {
        thread::spawn(move || self.run())
    }

    fn handle_client(stream: TcpStream) -> anyhow::Result<()> {
        let peer_addr = stream.peer_addr()?.to_string();
        info!("New client connected from {}", peer_addr);

        while let Ok(log_item) = bincode::deserialize_from::<_, LogItem>(&stream) {
            let level = level_from_usize(log_item.level).unwrap_or(Level::Info);
            log::log!(target: log_item.target.as_str(), level, "{}", log_item.message);
        }

        Ok(())
    }
}

pub struct InterProcessComClient {
    stream: TcpStream,
}

impl InterProcessComClient {
    pub fn connect(address: &str) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(address)?;
        Ok(InterProcessComClient { stream })
    }
}

impl log::Log for InterProcessComClient {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Ok(mut stream) = self.stream.try_clone() {
                let target = env::args()
                    .next()
                    .as_ref()
                    .map(Path::new)
                    .and_then(Path::file_name)
                    .and_then(OsStr::to_str)
                    .map(String::from)
                    .unwrap_or_else(String::new);
                let _ = bincode::serialize(&LogItem {
                    target,
                    level: record.level() as usize,
                    message: record.args().to_string(),
                })
                .map(|bytes| stream.write_all(&bytes));
            }
        }
    }

    fn flush(&self) {}
}

#[derive(Serialize, Deserialize)]
struct LogItem {
    level: usize,
    target: String,
    message: String,
}

fn level_from_usize(level: usize) -> Option<Level> {
    match level {
        1 => Some(Level::Error),
        2 => Some(Level::Warn),
        3 => Some(Level::Info),
        4 => Some(Level::Debug),
        5 => Some(Level::Trace),
        _ => None,
    }
}
