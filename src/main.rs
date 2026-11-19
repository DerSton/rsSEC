mod app;
mod backend;
mod model;
mod token;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("deSec")
            .with_inner_size([1100.0, 700.0])
            .with_min_inner_size([760.0, 480.0]),
        ..Default::default()
    };

    eframe::run_native(
        "deSec",
        options,
        Box::new(|cc| Ok(Box::new(app::DesecApp::new(cc)))),
    )
}
