mod app;
mod backend;
mod model;
mod rdata;
mod token;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("deSec")
            .with_inner_size([1180.0, 740.0])
            .with_min_inner_size([860.0, 520.0]),
        ..Default::default()
    };

    eframe::run_native(
        "deSec",
        options,
        Box::new(|cc| Ok(Box::new(app::DesecApp::new(cc)))),
    )
}
