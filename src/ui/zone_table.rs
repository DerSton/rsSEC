use std::collections::BTreeSet;

use eframe::egui::{self, RichText, Stroke, Ui};

use crate::model::{RowStatus, RrsetKey, ValueDiffKind, ZoneRow};
use crate::ui::theme::{color_added, color_deleted, color_modified, status_color};

#[derive(Default)]
pub struct TableActions {
    pub edit_row: Option<ZoneRow>,
    pub delete_key: Option<RrsetKey>,
    pub revert_key: Option<RrsetKey>,
}

pub fn render_zone_table(
    ui: &mut Ui,
    rows: &[ZoneRow],
    selected_keys: &mut BTreeSet<RrsetKey>,
    busy: bool,
) -> TableActions {
    let mut actions = TableActions::default();

    render_select_all_bar(ui, rows, selected_keys);
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let card_min_width = (ui.available_width() - 16.0).max(200.0);

            for row in rows {
                let border_color = status_color(ui, row.status);
                let mut frame = egui::Frame::group(ui.style());
                if row.status.is_changed() {
                    frame = frame.stroke(Stroke::new(1.0, border_color));
                }

                frame.show(ui, |ui| {
                    ui.set_min_width(card_min_width);
                    render_card_header(ui, row, selected_keys, busy, &mut actions);
                    ui.separator();
                    render_card_records(ui, row);
                });

                ui.add_space(6.0);
            }
        });

    actions
}

fn render_select_all_bar(ui: &mut Ui, rows: &[ZoneRow], selected_keys: &mut BTreeSet<RrsetKey>) {
    let all_selected = !rows.is_empty() && rows.iter().all(|r| selected_keys.contains(&r.key));
    let mut toggle_all = all_selected;

    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut toggle_all, format!("Select all ({})", rows.len()))
            .changed()
        {
            for row in rows {
                if toggle_all {
                    selected_keys.insert(row.key.clone());
                } else {
                    selected_keys.remove(&row.key);
                }
            }
        }
    });
}

fn render_card_header(
    ui: &mut Ui,
    row: &ZoneRow,
    selected_keys: &mut BTreeSet<RrsetKey>,
    busy: bool,
    actions: &mut TableActions,
) {
    ui.horizontal(|ui| {
        let mut is_selected = selected_keys.contains(&row.key);
        if ui.checkbox(&mut is_selected, "").changed() {
            if is_selected {
                selected_keys.insert(row.key.clone());
            } else {
                selected_keys.remove(&row.key);
            }
        }

        ui.label(style_key_text(ui, row.key.display_subname(), row.status));
        ui.separator();
        ui.label(style_key_text(ui, &row.key.rtype, row.status));
        ui.separator();
        render_ttl_label(ui, row);
        ui.separator();

        let status_text = RichText::new(row.status.label()).color(status_color(ui, row.status));
        if row.status.is_changed() {
            ui.label(status_text.strong());
        } else {
            ui.label(status_text);
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                let can_delete = row.status != RowStatus::Deleted;
                if ui
                    .add_enabled(can_delete, egui::Button::new("Delete"))
                    .clicked()
                {
                    actions.delete_key = Some(row.key.clone());
                }
                if ui.button("Edit").clicked() {
                    actions.edit_row = Some(row.clone());
                }
                if row.status.is_changed() && ui.button("Revert").clicked() {
                    actions.revert_key = Some(row.key.clone());
                }
            });
        });
    });
}

fn style_key_text(ui: &Ui, text: &str, status: RowStatus) -> RichText {
    let mut rich = RichText::new(text).monospace().strong();
    match status {
        RowStatus::Added => rich = rich.color(color_added(ui)),
        RowStatus::Deleted => rich = rich.color(color_deleted(ui)).strikethrough(),
        RowStatus::Synced | RowStatus::Modified => {}
    }
    rich
}

fn render_ttl_label(ui: &mut Ui, row: &ZoneRow) {
    match (&row.remote, &row.local) {
        (Some(rem), Some(loc)) if rem.ttl != loc.ttl => {
            ui.label(
                RichText::new(format!("TTL {} -> {}", rem.ttl, loc.ttl))
                    .monospace()
                    .color(color_modified(ui))
                    .strong(),
            );
        }
        (None, Some(loc)) => {
            ui.label(
                RichText::new(format!("TTL {}", loc.ttl))
                    .monospace()
                    .color(color_added(ui)),
            );
        }
        (Some(rem), None) => {
            ui.label(
                RichText::new(format!("TTL {}", rem.ttl))
                    .monospace()
                    .color(color_deleted(ui))
                    .strikethrough(),
            );
        }
        (_, Some(loc)) => {
            ui.monospace(format!("TTL {}", loc.ttl));
        }
        (None, None) => {}
    }
}

fn render_card_records(ui: &mut Ui, row: &ZoneRow) {
    ui.vertical(|ui| {
        for item in row.record_diffs() {
            match item.kind {
                ValueDiffKind::Unchanged => {
                    ui.monospace(&item.value);
                }
                ValueDiffKind::Added => {
                    ui.label(
                        RichText::new(format!("+ {}", item.value))
                            .monospace()
                            .color(color_added(ui)),
                    );
                }
                ValueDiffKind::Removed => {
                    ui.label(
                        RichText::new(format!("- {}", item.value))
                            .monospace()
                            .color(color_deleted(ui))
                            .strikethrough(),
                    );
                }
            }
        }
    });
}
