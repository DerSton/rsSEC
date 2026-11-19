use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::model::{RECORD_TYPES, RrsetData, RrsetKey, ZoneRow, ZoneState};
use crate::rdata::{
    default_fields_for_type, parse_record_to_fields, schema_for_type, validate_and_format,
};
use crate::ui::theme::{color_added, color_modified};

const CUSTOM_TYPE_SENTINEL: &str = "CUSTOM";

#[derive(Debug, Clone)]
pub struct RecordEditorModal {
    /// `None` when adding a new RRset; `Some(key)` when editing an existing one.
    pub original_key: Option<RrsetKey>,
    pub subname: String,
    pub selected_type: String,
    pub custom_type: String,
    pub last_effective_type: String,
    pub ttl_input: String,
    /// Structured field values per record row (`rows[row_idx][field_idx]`).
    pub rows: Vec<Vec<String>>,
    /// Snapshot of remote cloud fields (if an RRset for the target key exists in deSEC cloud)
    /// used to live-highlight exact changed fields inside the editor.
    pub error: Option<String>,
}

impl RecordEditorModal {
    pub fn new_empty(default_ttl: u32) -> Self {
        let rtype = "A".to_owned();
        Self {
            original_key: None,
            subname: String::new(),
            selected_type: rtype.clone(),
            custom_type: String::new(),
            last_effective_type: rtype.clone(),
            ttl_input: default_ttl.to_string(),
            rows: vec![default_fields_for_type(&rtype)],
            error: None,
        }
    }

    pub fn from_row(row: &ZoneRow) -> Self {
        let data = row.editable_data();
        let is_known = RECORD_TYPES.contains(&row.key.rtype.as_str());
        let (selected_type, custom_type) = if is_known {
            (row.key.rtype.clone(), String::new())
        } else {
            (CUSTOM_TYPE_SENTINEL.to_owned(), row.key.rtype.clone())
        };
        let rtype = row.key.rtype.clone();
        let rows = if data.records.is_empty() {
            vec![default_fields_for_type(&rtype)]
        } else {
            data.records
                .iter()
                .map(|r| parse_record_to_fields(&rtype, r))
                .collect()
        };

        Self {
            original_key: Some(row.key.clone()),
            subname: row.key.subname.clone(),
            selected_type,
            custom_type,
            last_effective_type: rtype,
            ttl_input: data.ttl.to_string(),
            rows,
            error: None,
        }
    }

    pub fn effective_type(&self) -> String {
        if self.selected_type == CUSTOM_TYPE_SENTINEL {
            self.custom_type.trim().to_ascii_uppercase()
        } else {
            self.selected_type.clone()
        }
    }

    pub fn current_key(&self) -> RrsetKey {
        RrsetKey::new(&self.subname, self.effective_type())
    }

    pub fn sync_schema_if_type_changed(&mut self) {
        let current = self.effective_type();
        if current != self.last_effective_type {
            let expected_len = schema_for_type(&current).len();
            if self.rows.is_empty()
                || self.rows[0].len() != expected_len
                || (self.rows.len() == 1
                    && self.rows[0] == default_fields_for_type(&self.last_effective_type))
            {
                self.rows = vec![default_fields_for_type(&current)];
            }
            self.last_effective_type = current;
            self.error = None;
        }
    }
}

pub enum EditorOutcome {
    KeepOpen,
    Saved,
    Cancelled,
}

pub fn render_editor_modal(
    ctx: &egui::Context,
    modal: &mut RecordEditorModal,
    zone: &mut ZoneState,
) -> EditorOutcome {
    let min_ttl = zone.minimum_ttl;
    let title = if modal.original_key.is_some() {
        "Edit Record"
    } else {
        "New Record"
    };

    let mut outcome = EditorOutcome::KeepOpen;
    let mut save_requested = false;

    modal.sync_schema_if_type_changed();

    // Look up the authoritative deSEC cloud entry for the current (or original) key
    let target_key = modal.current_key();
    let cloud_entry = zone
        .remote
        .get(&target_key)
        .or_else(|| modal.original_key.as_ref().and_then(|k| zone.remote.get(k)));
    let cloud_ttl_str = cloud_entry.map(|c| c.ttl.to_string());
    let active_type = modal.effective_type();
    let cloud_rows: Vec<Vec<String>> = cloud_entry
        .map(|c| {
            c.records
                .iter()
                .map(|r| parse_record_to_fields(&active_type, r))
                .collect()
        })
        .unwrap_or_default();

    egui::Window::new(title)
        .collapsible(false)
        .resizable(true)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(760.0)
        .min_width(640.0)
        .show(ctx, |ui| {
            // Top row: Subname, Type, and TTL (highlighted if different from cloud)
            ui.horizontal(|ui| {
                let subname_diff = modal
                    .original_key
                    .as_ref()
                    .is_some_and(|orig| orig.subname != target_key.subname);
                ui.label(if subname_diff {
                    RichText::new("Subname").color(color_modified(ui)).strong()
                } else {
                    RichText::new("Subname")
                });
                let mut sub_edit = egui::TextEdit::singleline(&mut modal.subname)
                    .hint_text("@")
                    .desired_width(240.0);
                if subname_diff {
                    sub_edit = sub_edit.text_color(color_modified(ui));
                }
                ui.add(sub_edit);

                ui.add_space(8.0);
                ui.label("Type");
                if modal.original_key.is_some() {
                    // Record type cannot be changed when editing an existing record
                    ui.add_enabled(
                        false,
                        egui::Button::new(RichText::new(&active_type).monospace()),
                    );
                } else {
                    let selected_display = if modal.selected_type == CUSTOM_TYPE_SENTINEL {
                        "Other"
                    } else {
                        &modal.selected_type
                    };
                    egui::ComboBox::from_id_salt("editor_record_type")
                        .selected_text(selected_display)
                        .width(120.0)
                        .show_ui(ui, |ui| {
                            for &rt in RECORD_TYPES {
                                ui.selectable_value(&mut modal.selected_type, rt.to_owned(), rt);
                            }
                            ui.separator();
                            ui.selectable_value(
                                &mut modal.selected_type,
                                CUSTOM_TYPE_SENTINEL.to_owned(),
                                "Other",
                            );
                        });

                    if modal.selected_type == CUSTOM_TYPE_SENTINEL {
                        ui.add(
                            egui::TextEdit::singleline(&mut modal.custom_type)
                                .hint_text("TYPE")
                                .desired_width(90.0),
                        );
                    }
                }

                ui.add_space(8.0);
                let ttl_diff = cloud_ttl_str
                    .as_ref()
                    .is_some_and(|c_ttl| c_ttl != modal.ttl_input.trim());
                ui.label(if ttl_diff {
                    RichText::new("TTL").color(color_modified(ui)).strong()
                } else {
                    RichText::new("TTL")
                });
                let mut ttl_edit = egui::TextEdit::singleline(&mut modal.ttl_input)
                    .hint_text(min_ttl.to_string())
                    .desired_width(85.0);
                if ttl_diff {
                    ttl_edit = ttl_edit.text_color(color_modified(ui));
                }
                ui.add(ttl_edit);
            });

            modal.sync_schema_if_type_changed();
            let active_type = modal.effective_type();
            let schema = schema_for_type(&active_type);

            ui.separator();

            let mut remove_idx: Option<usize> = None;
            let can_remove = modal.rows.len() > 1;
            let last_field_idx = schema.len().saturating_sub(1);

            ui.push_id(&active_type, |ui| {
                let mut table = TableBuilder::new(ui)
                    .striped(true)
                    .vscroll(true)
                    .max_scroll_height(280.0)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center));

                for (idx, spec) in schema.iter().enumerate() {
                    if idx == last_field_idx {
                        table = table.column(Column::remainder().at_least(spec.width));
                    } else {
                        table = table
                            .column(Column::initial(spec.width).at_least(44.0).resizable(true));
                    }
                }
                if can_remove {
                    table = table.column(Column::exact(68.0));
                }

                table
                    .header(22.0, |mut header| {
                        for spec in schema {
                            header.col(|ui| {
                                ui.strong(spec.label);
                            });
                        }
                        if can_remove {
                            header.col(|_ui| {});
                        }
                    })
                    .body(|mut body| {
                        for (row_idx, row_fields) in modal.rows.iter_mut().enumerate() {
                            if row_fields.len() != schema.len() {
                                row_fields.resize(schema.len(), String::new());
                            }
                            let cloud_row = cloud_rows.get(row_idx);

                            body.row(28.0, |mut row| {
                                for (field_idx, (field_val, spec)) in
                                    row_fields.iter_mut().zip(schema.iter()).enumerate()
                                {
                                    row.col(|ui| {
                                        let w = ui.available_width().max(24.0);
                                        let trimmed_val = field_val.trim();

                                        // Compute live diff highlight color before mutably borrowing `field_val`
                                        let diff_color = if cloud_entry.is_none() {
                                            (!trimmed_val.is_empty()).then(|| color_added(ui))
                                        } else if let Some(c_row) = cloud_row {
                                            c_row
                                                .get(field_idx)
                                                .is_some_and(|c_val| c_val != trimmed_val)
                                                .then(|| color_modified(ui))
                                        } else {
                                            (!trimmed_val.is_empty()).then(|| color_added(ui))
                                        };

                                        let mut edit = egui::TextEdit::singleline(field_val)
                                            .hint_text(spec.hint)
                                            .code_editor();
                                        if let Some(col) = diff_color {
                                            edit = edit.text_color(col);
                                        }

                                        ui.add_sized([w, 22.0], edit);
                                    });
                                }
                                if can_remove {
                                    row.col(|ui| {
                                        if ui.button("Remove").clicked() {
                                            remove_idx = Some(row_idx);
                                        }
                                    });
                                }
                            });
                        }
                    });
            });

            if let Some(idx) = remove_idx {
                modal.rows.remove(idx);
            }

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Add Row").clicked() {
                    modal.rows.push(default_fields_for_type(&active_type));
                }
                if let Some(c_entry) = cloud_entry {
                    let c_ttl = c_entry.ttl.to_string();
                    if (modal.ttl_input.trim() != c_ttl || modal.rows != cloud_rows)
                        && ui.button("Reset to Cloud").clicked()
                    {
                        modal.ttl_input = c_ttl;
                        modal.rows = cloud_rows.clone();
                        modal.error = None;
                    }
                }
            });

            if let Some(err) = &modal.error {
                ui.add_space(4.0);
                ui.label(err);
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Save").clicked() {
                    save_requested = true;
                }
                if ui.button("Cancel").clicked() {
                    outcome = EditorOutcome::Cancelled;
                }
            });
        });

    if save_requested {
        match apply_modal_to_zone(modal, zone) {
            Ok(()) => outcome = EditorOutcome::Saved,
            Err(err) => modal.error = Some(err),
        }
    }

    outcome
}

fn apply_modal_to_zone(modal: &RecordEditorModal, zone: &mut ZoneState) -> Result<(), String> {
    let ttl: u32 = modal
        .ttl_input
        .trim()
        .parse()
        .map_err(|_| "Invalid TTL.".to_owned())?;

    let rtype = modal.effective_type();
    if rtype.is_empty() || !rtype.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("Invalid record type.".to_owned());
    }

    if modal.rows.is_empty() {
        return Err("At least one row is required.".to_owned());
    }

    let mut records = Vec::with_capacity(modal.rows.len());
    for (idx, row_fields) in modal.rows.iter().enumerate() {
        match validate_and_format(&rtype, row_fields) {
            Ok(formatted) => records.push(formatted),
            Err(err) => {
                if modal.rows.len() > 1 {
                    return Err(format!("Row {}: {err}", idx + 1));
                }
                return Err(err);
            }
        }
    }

    let new_key = RrsetKey::new(&modal.subname, rtype);
    let data = RrsetData::new(ttl, records);
    zone.upsert_local(modal.original_key.as_ref(), new_key, data)
}
