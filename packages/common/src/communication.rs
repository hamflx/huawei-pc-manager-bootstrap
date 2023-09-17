use std::{
    env,
    ffi::OsStr,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    str::FromStr,
    thread::{self, JoinHandle},
};

use serde::{Deserialize, Serialize};
use tracing::{field::Visit, info, Level, Subscriber};
use tracing_subscriber::Layer;

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
            let level = Level::from_str(&log_item.level).unwrap_or(Level::INFO);
            let target = log_item.target;
            info!(target: "REMOTE", "{} [{}]: {}", target, level, log_item.message);
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

impl<S> Layer<S> for InterProcessComClient
where
    S: Subscriber,
{
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        *metadata.level() <= Level::INFO
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: tracing_subscriber::layer::Context<'_, S>) {
        let metadata = event.metadata();
        if self.enabled(metadata, ctx) {
            if let Ok(mut stream) = self.stream.try_clone() {
                let target = env::args()
                    .next()
                    .as_ref()
                    .map(Path::new)
                    .and_then(Path::file_name)
                    .and_then(OsStr::to_str)
                    .map(String::from)
                    .unwrap_or_default();
                let mut visitor = EventMessageVisitor(String::new());
                event.record(&mut visitor);
                let _ = bincode::serialize(&LogItem {
                    target,
                    level: metadata.level().as_str().to_string(),
                    message: visitor.0,
                })
                .map(|bytes| stream.write_all(&bytes));
            }
        }
    }
}

struct EventMessageVisitor(String);

impl Visit for EventMessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = format!("{}", value);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct LogItem {
    level: String,
    target: String,
    message: String,
}
