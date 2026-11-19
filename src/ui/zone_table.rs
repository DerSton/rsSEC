use eframe::egui::{self, RichText, Ui};
use egui_extras::{Column, TableBuilder};

use crate::model::{RowStatus, RrsetKey, ValueDiffKind, ZoneRow};
use crate::ui::theme::{color_added, color_deleted, color_modified, status_color};

pub struct TableActions {
    pub edit_row: Option<ZoneRow>,
    pub delete_key: Option<RrsetKey>,
    pub revert_key: Option<RrsetKey>,
}

pub fn render_zone_table(ui: &mut Ui, rows: &[ZoneRow], busy: bool) -> TableActions {
    let mut actions = TableActions {
        edit_row: None,
        delete_key: None,
        revert_key: None,
    };

    let row_heights: Vec<f32> = rows
        .iter()
        .map(|r| {
            let lines = r.record_diffs().len().max(1) as f32;
            (lines * 18.0 + 10.0).max(28.0)
        })
        .collect();

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::TOP))
        .column(Column::initial(84.0).at_least(75.0)) // State
        .column(Column::initial(180.0).at_least(100.0)) // Subname
        .column(Column::initial(100.0).at_least(75.0)) // Type
        .column(Column::initial(110.0).at_least(70.0)) // TTL
        .column(Column::remainder().at_least(280.0)) // Records
        .column(Column::initial(180.0).at_least(170.0)) // Actions
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("State");
            });
            header.col(|ui| {
                ui.strong("Subname");
            });
            header.col(|ui| {
                ui.strong("Type");
            });
            header.col(|ui| {
                ui.strong("TTL");
            });
            header.col(|ui| {
                ui.strong("Records");
            });
            header.col(|ui| {
                ui.strong("Actions");
            });
        })
        .body(|body| {
            body.heterogeneous_rows(row_heights.into_iter(), |mut table_row| {
                let row = &rows[table_row.index()];

                // 1. State
                table_row.col(|ui| {
                    let state_col = status_color(ui, row.status);
                    let text = RichText::new(row.status.label()).color(state_col);
                    if row.status.is_changed() {
                        ui.label(text.strong());
                    } else {
                        ui.label(text);
                    }
                });

                // 2. Subname (colored if whole RRset is newly added or deleted)
                table_row.col(|ui| {
                    let mut text = RichText::new(row.key.display_subname()).monospace();
                    match row.status {
                        RowStatus::Added => text = text.color(color_added(ui)),
                        RowStatus::Deleted => {
                            text = text.color(color_deleted(ui)).strikethrough();
                        }
                        RowStatus::Synced | RowStatus::Modified => {}
                    }
                    ui.label(text);
                });

                // 3. Type
                table_row.col(|ui| {
                    let mut text = RichText::new(&row.key.rtype).monospace();
                    match row.status {
                        RowStatus::Added => text = text.color(color_added(ui)),
                        RowStatus::Deleted => {
                            text = text.color(color_deleted(ui)).strikethrough();
                        }
                        RowStatus::Synced | RowStatus::Modified => {}
                    }
                    ui.label(text);
                });

                // 4. TTL (shows `old -> new` in diff color only when TTL actually changed)
                table_row.col(|ui| {
                    if row.ttl_changed()
                        && let (Some(rem), Some(loc)) = (&row.remote, &row.local)
                    {
                        ui.label(
                            RichText::new(format!("{} -> {}", rem.ttl, loc.ttl))
                                .monospace()
                                .color(color_modified(ui))
                                .strong(),
                        );
                    } else if let (None, Some(loc)) = (&row.remote, &row.local) {
                        ui.label(
                            RichText::new(loc.ttl.to_string())
                                .monospace()
                                .color(color_added(ui)),
                        );
                    } else if let (Some(rem), None) = (&row.remote, &row.local) {
                        ui.label(
                            RichText::new(rem.ttl.to_string())
                                .monospace()
                                .color(color_deleted(ui))
                                .strikethrough(),
                        );
                    } else if let Some(loc) = &row.local {
                        ui.monospace(loc.ttl.to_string());
                    }
                });

                // 5. Records (only changed values are colored; unchanged values in a modified RRset stay normal!)
                table_row.col(|ui| {
                    let diffs = row.record_diffs();
                    ui.vertical(|ui| {
                        for item in diffs {
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

                // 6. Actions (`Edit` and `Delete` NEVER disappear)
                table_row.col(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        ui.horizontal(|ui| {
                            if ui.button("Edit").clicked() {
                                actions.edit_row = Some(row.clone());
                            }
                            let can_delete = row.status != RowStatus::Deleted;
                            if ui
                                .add_enabled(can_delete, egui::Button::new("Delete"))
                                .clicked()
                            {
                                actions.delete_key = Some(row.key.clone());
                            }
                            if row.status.is_changed() && ui.button("Revert").clicked() {
                                actions.revert_key = Some(row.key.clone());
                            }
                        });
                    });
                });
            });
        });

    actions
}
