use eframe::{egui, epi};
use rfd::FileDialog;
use windows_sys::{
    core::PCSTR,
    Win32::{Foundation::HWND, UI::Shell::ShellExecuteA},
};

pub struct BootstrapApp {}

impl Default for BootstrapApp {
    fn default() -> Self {
        Self {}
    }
}

impl epi::App for BootstrapApp {
    fn name(&self) -> &str {
        "eframe template"
    }

    /// Called once before the first frame.
    fn setup(
        &mut self,
        _ctx: &egui::Context,
        _frame: &epi::Frame,
        _storage: Option<&dyn epi::Storage>,
    ) {
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    /// Put your widgets into a `SidePanel`, `TopPanel`, `CentralPanel`, `Window` or `Area`.
    fn update(&mut self, ctx: &egui::Context, frame: &epi::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's

            if ui.button("Browse").clicked() {
                let executable_file = FileDialog::new()
                    .add_filter("exe", &["exe"])
                    .set_directory(std::env::current_exe().unwrap().parent().unwrap())
                    .pick_file();
                if let Some(executable_file) = executable_file {
                    println!("{:?}", executable_file);
                }
            }

            ui.heading("eframe template");
            ui.hyperlink("https://github.com/emilk/eframe_template");
            ui.add(egui::github_link_file!(
                "https://github.com/emilk/eframe_template/blob/master/",
                "Source code."
            ));
            egui::warn_if_debug_build(ui);
        });
    }
}
