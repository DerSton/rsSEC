use eframe::egui::{Color32, Ui};

use crate::model::RowStatus;

pub fn color_added(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(95, 215, 125)
    } else {
        Color32::from_rgb(20, 135, 50)
    }
}

pub fn color_modified(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(245, 195, 85)
    } else {
        Color32::from_rgb(180, 110, 0)
    }
}

pub fn color_deleted(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(245, 105, 105)
    } else {
        Color32::from_rgb(185, 30, 30)
    }
}

pub fn status_color(ui: &Ui, status: RowStatus) -> Color32 {
    match status {
        RowStatus::Synced => ui.visuals().text_color(),
        RowStatus::Added => color_added(ui),
        RowStatus::Modified => color_modified(ui),
        RowStatus::Deleted => color_deleted(ui),
    }
}
