use std::collections::BTreeSet;

use eframe::egui::{self, RichText, Stroke, Ui};

use crate::model::{RowStatus, RrsetKey, ValueDiffKind, ZoneRow};
use crate::ui::theme::{color_added, color_deleted, color_modified, status_color};

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
    let mut actions = TableActions {
        edit_row: None,
        delete_key: None,
        revert_key: None,
    };

    let all_visible_selected =
        !rows.is_empty() && rows.iter().all(|r| selected_keys.contains(&r.key));

    // Compact select-all bar above the cards
    ui.horizontal(|ui| {
        let mut toggle_all = all_visible_selected;
        if ui
            .checkbox(&mut toggle_all, format!("Select all ({})", rows.len()))
            .changed()
        {
            if toggle_all {
                for r in rows {
                    selected_keys.insert(r.key.clone());
                }
            } else {
                for r in rows {
                    selected_keys.remove(&r.key);
                }
            }
        }
    });
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let full_width = ui.available_width();

            for row in rows {
                let state_col = status_color(ui, row.status);
                let mut frame = egui::Frame::group(ui.style());
                if row.status.is_changed() {
                    frame = frame.stroke(Stroke::new(1.0, state_col));
                }

                frame.show(ui, |ui| {
                    ui.set_min_width((full_width - 16.0).max(200.0));

                    // Card Header: Left = Checkbox, Subname, Type, TTL, State | Right = Edit, Delete, Revert
                    ui.horizontal(|ui| {
                        let mut is_selected = selected_keys.contains(&row.key);
                        if ui.checkbox(&mut is_selected, "").changed() {
                            if is_selected {
                                selected_keys.insert(row.key.clone());
                            } else {
                                selected_keys.remove(&row.key);
                            }
                        }

                        // Subname
                        let mut sub_text = RichText::new(row.key.display_subname())
                            .monospace()
                            .strong();
                        match row.status {
                            RowStatus::Added => sub_text = sub_text.color(color_added(ui)),
                            RowStatus::Deleted => {
                                sub_text = sub_text.color(color_deleted(ui)).strikethrough();
                            }
                            RowStatus::Synced | RowStatus::Modified => {}
                        }
                        ui.label(sub_text);

                        ui.separator();

                        // Record Type
                        let mut type_text = RichText::new(&row.key.rtype).monospace().strong();
                        match row.status {
                            RowStatus::Added => type_text = type_text.color(color_added(ui)),
                            RowStatus::Deleted => {
                                type_text = type_text.color(color_deleted(ui)).strikethrough();
                            }
                            RowStatus::Synced | RowStatus::Modified => {}
                        }
                        ui.label(type_text);

                        ui.separator();

                        // TTL (with live cloud vs local diff)
                        if row.ttl_changed()
                            && let (Some(rem), Some(loc)) = (&row.remote, &row.local)
                        {
                            ui.label(
                                RichText::new(format!("TTL {} -> {}", rem.ttl, loc.ttl))
                                    .monospace()
                                    .color(color_modified(ui))
                                    .strong(),
                            );
                        } else if let (None, Some(loc)) = (&row.remote, &row.local) {
                            ui.label(
                                RichText::new(format!("TTL {}", loc.ttl))
                                    .monospace()
                                    .color(color_added(ui)),
                            );
                        } else if let (Some(rem), None) = (&row.remote, &row.local) {
                            ui.label(
                                RichText::new(format!("TTL {}", rem.ttl))
                                    .monospace()
                                    .color(color_deleted(ui))
                                    .strikethrough(),
                            );
                        } else if let Some(loc) = &row.local {
                            ui.monospace(format!("TTL {}", loc.ttl));
                        }

                        ui.separator();

                        // Sync Status badge
                        let status_text = RichText::new(row.status.label()).color(state_col);
                        if row.status.is_changed() {
                            ui.label(status_text.strong());
                        } else {
                            ui.label(status_text);
                        }

                        // Right-aligned actions (`Edit` and `Delete` are always visible)
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

                    ui.separator();

                    // Card Body: Full-width record values with live cloud vs local diff coloring
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
                });

                ui.add_space(6.0);
            }
        });

    actions
}
