use std::sync::mpsc::Sender;

use tracing_subscriber::Layer;

pub struct CustomLayer(Sender<String>);

impl CustomLayer {
    pub fn new(tx: Sender<String>) -> Self {
        CustomLayer(tx)
    }
}

impl<S> Layer<S> for CustomLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let self_crate_name = env!("CARGO_CRATE_NAME");
        let meta = event.metadata();
        if !meta.target().starts_with(self_crate_name) {
            return;
        }

        let mut visitor = CustomVisitor(String::new());
        event.record(&mut visitor);
        let msg = format!("[{}] {} {}", meta.target(), meta.name(), visitor.0);
        self.0.send(msg).unwrap();
    }
}

struct CustomVisitor(String);

impl tracing::field::Visit for CustomVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }
}
