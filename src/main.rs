mod app;
mod backend;
mod model;
mod rdata;
mod state;
mod token;
mod ui;

use eframe::egui;

const ICON_PNG: &[u8] = include_bytes!("../assets/rsSEC.png");

fn main() -> eframe::Result {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("rsSEC")
        .with_inner_size([1180.0, 740.0])
        .with_min_inner_size([860.0, 520.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(ICON_PNG) {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "rsSEC",
        options,
        Box::new(|cc| Ok(Box::new(app::DesecApp::new(cc)))),
    )
}
