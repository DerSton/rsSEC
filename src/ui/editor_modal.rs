use eframe::egui::{self, RichText};

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
        .default_width(720.0)
        .min_width(580.0)
        .show(ctx, |ui| {
            ui.set_min_width(ui.available_width());

            // Top row: Subname, Type (locked when editing), and TTL
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
                    .desired_width(90.0);
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

            // Render each record value as its own full-width card without unintended wrapping
            egui::ScrollArea::vertical()
                .auto_shrink([false, true])
                .max_height(320.0)
                .show(ui, |ui| {
                    let avail_w = ui.available_width();

                    for (row_idx, row_fields) in modal.rows.iter_mut().enumerate() {
                        if row_fields.len() != schema.len() {
                            row_fields.resize(schema.len(), String::new());
                        }
                        let cloud_row = cloud_rows.get(row_idx);

                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_min_width((avail_w - 16.0).max(200.0));

                            // Split types with many fields (LOC = 10, NAPTR = 6) into 2 explicit
                            // non-wrapping rows; all 1..=4 field types stay on a single horizontal line.
                            let split_at = if schema.len() > 4 {
                                schema.len() - 2
                            } else {
                                schema.len()
                            };

                            // First line (or sole line for 1..=4 field types)
                            render_field_line(
                                ui,
                                0..split_at,
                                row_fields,
                                schema,
                                cloud_entry.is_some(),
                                cloud_row.map(Vec::as_slice),
                                if split_at == schema.len() && can_remove {
                                    Some(&mut remove_idx)
                                } else {
                                    None
                                },
                                row_idx,
                            );

                            // Second line only for 6+ field types (NAPTR, LOC)
                            if split_at < schema.len() {
                                ui.add_space(4.0);
                                render_field_line(
                                    ui,
                                    split_at..schema.len(),
                                    row_fields,
                                    schema,
                                    cloud_entry.is_some(),
                                    cloud_row.map(Vec::as_slice),
                                    if can_remove {
                                        Some(&mut remove_idx)
                                    } else {
                                        None
                                    },
                                    row_idx,
                                );
                            }
                        });

                        ui.add_space(4.0);
                    }
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

#[allow(clippy::too_many_arguments)]
fn render_field_line(
    ui: &mut egui::Ui,
    range: std::ops::Range<usize>,
    row_fields: &mut [String],
    schema: &[crate::rdata::FieldSpec],
    has_cloud_entry: bool,
    cloud_row: Option<&[String]>,
    mut remove_idx: Option<&mut Option<usize>>,
    row_idx: usize,
) {
    let last_in_line = range.end.saturating_sub(1);
    let has_remove_btn = remove_idx.is_some();

    ui.horizontal(|ui| {
        for field_idx in range {
            let spec = &schema[field_idx];
            let field_val = &mut row_fields[field_idx];
            let trimmed_val = field_val.trim();

            let diff_color = if !has_cloud_entry {
                (!trimmed_val.is_empty()).then(|| color_added(ui))
            } else if let Some(c_row) = cloud_row {
                c_row
                    .get(field_idx)
                    .is_some_and(|c_val| c_val != trimmed_val)
                    .then(|| color_modified(ui))
            } else {
                (!trimmed_val.is_empty()).then(|| color_added(ui))
            };

            let label_text = if let Some(col) = diff_color {
                RichText::new(spec.label).color(col).strong()
            } else {
                RichText::new(spec.label)
            };
            ui.label(label_text);

            let is_last = field_idx == last_in_line;
            let field_width = if is_last {
                let reserve = if has_remove_btn { 72.0 } else { 0.0 };
                (ui.available_width() - reserve).max(80.0)
            } else {
                spec.width.min(90.0)
            };

            let mut edit = egui::TextEdit::singleline(field_val)
                .hint_text(spec.hint)
                .code_editor()
                .desired_width(field_width);
            if let Some(col) = diff_color {
                edit = edit.text_color(col);
            }
            ui.add_sized([field_width, 22.0], edit);
        }

        if let Some(rem) = remove_idx.as_mut()
            && ui.button("Remove").clicked()
        {
            **rem = Some(row_idx);
        }
    });
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
