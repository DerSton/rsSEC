use std::ops::Range;

use eframe::egui::{self, Color32, RichText, Ui};

use crate::model::{RECORD_TYPES, RrsetData, RrsetKey, ZoneRow, ZoneState};
use crate::rdata::{
    FieldSpec, canonical_record, default_fields_for_type, field_values_equivalent,
    parse_record_to_fields, records_equivalent, schema_for_type, validate_and_format,
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
    pub rows: Vec<Vec<String>>,
    pub error: Option<String>,
}

impl RecordEditorModal {
    pub fn new_empty(default_ttl: u32, initial_type: Option<&str>) -> Self {
        let rtype = initial_type
            .filter(|t| RECORD_TYPES.contains(t))
            .unwrap_or("A")
            .to_owned();
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
        if current == self.last_effective_type {
            return;
        }

        let expected_len = schema_for_type(&current).len();
        let is_unchanged_default = self.rows.len() == 1
            && self.rows[0] == default_fields_for_type(&self.last_effective_type);

        if self.rows.is_empty() || self.rows[0].len() != expected_len || is_unchanged_default {
            self.rows = vec![default_fields_for_type(&current)];
        }
        self.last_effective_type = current;
        self.error = None;
    }
}

pub enum EditorOutcome {
    KeepOpen,
    Saved {
        old_key: Option<RrsetKey>,
        new_key: RrsetKey,
    },
    Cancelled,
}

pub fn render_editor_modal(
    ctx: &egui::Context,
    modal: &mut RecordEditorModal,
    zone: &mut ZoneState,
) -> EditorOutcome {
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return EditorOutcome::Cancelled;
    }

    let min_ttl = zone.minimum_ttl;
    let title = if modal.original_key.is_some() {
        "Edit Record"
    } else {
        "New Record"
    };

    let mut outcome = EditorOutcome::KeepOpen;
    let mut save_requested = false;

    modal.sync_schema_if_type_changed();

    let target_key = modal.current_key();
    let cloud_entry = zone
        .remote
        .get(&target_key)
        .or_else(|| modal.original_key.as_ref().and_then(|k| zone.remote.get(k)));
    let cloud_ttl_str = cloud_entry.map(|c| c.ttl.to_string());

    egui::Window::new(title)
        .collapsible(false)
        .resizable(true)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(720.0)
        .min_width(580.0)
        .show(ctx, |ui| {
            ui.set_min_width(ui.available_width());

            render_header_inputs(ui, modal, &target_key, cloud_ttl_str.as_deref(), min_ttl);
            modal.sync_schema_if_type_changed();

            let active_type = modal.effective_type();
            let schema = schema_for_type(&active_type);
            let cloud_rows: Vec<Vec<String>> = cloud_entry
                .map(|c| {
                    c.records
                        .iter()
                        .map(|r| parse_record_to_fields(&active_type, r))
                        .collect()
                })
                .unwrap_or_default();
            let cloud_canonical: Vec<String> = cloud_entry
                .map(|c| {
                    c.records
                        .iter()
                        .map(|r| canonical_record(&active_type, r))
                        .collect()
                })
                .unwrap_or_default();

            let row_matches = match_rows_to_cloud(
                &active_type,
                schema,
                &modal.rows,
                &cloud_rows,
                &cloud_canonical,
            );
            let rows_differ = modal.rows.len() != cloud_rows.len()
                || row_matches
                    .iter()
                    .any(|m| !matches!(m, CloudRowMatch::Exact));

            ui.separator();

            render_record_cards(
                ui,
                modal,
                schema,
                cloud_entry.is_some(),
                &cloud_rows,
                &row_matches,
            );

            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("Add Row").clicked() {
                    modal.rows.push(default_fields_for_type(&active_type));
                }
                if let Some(c_entry) = cloud_entry {
                    let c_ttl = c_entry.ttl.to_string();
                    if (modal.ttl_input.trim() != c_ttl || rows_differ)
                        && ui.button("Reset to Cloud").clicked()
                    {
                        modal.ttl_input = c_ttl;
                        modal.rows = cloud_rows;
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
            Ok(new_key) => {
                outcome = EditorOutcome::Saved {
                    old_key: modal.original_key.clone(),
                    new_key,
                };
            }
            Err(err) => modal.error = Some(err),
        }
    }

    outcome
}

fn render_header_inputs(
    ui: &mut Ui,
    modal: &mut RecordEditorModal,
    target_key: &RrsetKey,
    cloud_ttl_str: Option<&str>,
    min_ttl: u32,
) {
    let active_type = modal.effective_type();

    ui.horizontal(|ui| {
        let subname_changed = modal
            .original_key
            .as_ref()
            .is_some_and(|orig| orig.subname != target_key.subname);
        ui.label(styled_field_label(ui, "Subname", subname_changed));

        let mut sub_edit = egui::TextEdit::singleline(&mut modal.subname)
            .hint_text("@")
            .desired_width(240.0);
        if subname_changed {
            sub_edit = sub_edit.text_color(color_modified(ui));
        }
        ui.add(sub_edit);

        ui.add_space(8.0);
        ui.label("Type");
        if modal.original_key.is_some() {
            // Existing record types are locked because RDATA schemas are incompatible across types.
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
        let ttl_changed = cloud_ttl_str.is_some_and(|c_ttl| c_ttl != modal.ttl_input.trim());
        ui.label(styled_field_label(ui, "TTL", ttl_changed));

        let mut ttl_edit = egui::TextEdit::singleline(&mut modal.ttl_input)
            .hint_text(min_ttl.to_string())
            .desired_width(90.0);
        if ttl_changed {
            ttl_edit = ttl_edit.text_color(color_modified(ui));
        }
        ui.add(ttl_edit);
    });
}

fn styled_field_label(ui: &Ui, label: &str, modified: bool) -> RichText {
    if modified {
        RichText::new(label).color(color_modified(ui)).strong()
    } else {
        RichText::new(label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudRowMatch {
    /// Canonically identical to an unmatched cloud record (regardless of row order).
    Exact,
    /// Paired with an unused cloud row for field-level modification highlights.
    Modified(usize),
    /// Truly new row with no corresponding cloud record.
    Added,
}

/// Matches editor rows against cloud rows order-independently (RRsets are unordered sets).
fn match_rows_to_cloud(
    rtype: &str,
    schema: &[FieldSpec],
    local_rows: &[Vec<String>],
    cloud_rows: &[Vec<String>],
    cloud_canonical: &[String],
) -> Vec<CloudRowMatch> {
    let mut matches = vec![CloudRowMatch::Added; local_rows.len()];
    if cloud_rows.is_empty() {
        return matches;
    }

    let mut cloud_used = vec![false; cloud_rows.len()];

    // Pass 1: exact DNS-canonical match in any order.
    for (row_idx, row_fields) in local_rows.iter().enumerate() {
        let local_canon = (row_fields.len() == schema.len())
            .then(|| validate_and_format(rtype, row_fields).ok())
            .flatten()
            .map(|formatted| canonical_record(rtype, &formatted));

        let found = cloud_rows.iter().enumerate().find(|(c_idx, c_row)| {
            if cloud_used[*c_idx] {
                return false;
            }
            if let (Some(lc), Some(cc)) = (local_canon.as_deref(), cloud_canonical.get(*c_idx))
                && lc == cc
            {
                return true;
            }
            row_fields.len() == schema.len()
                && c_row.len() == schema.len()
                && schema
                    .iter()
                    .enumerate()
                    .all(|(fi, spec)| field_values_equivalent(spec.kind, &row_fields[fi], &c_row[fi]))
        });

        if let Some((c_idx, _)) = found {
            cloud_used[c_idx] = true;
            matches[row_idx] = CloudRowMatch::Exact;
        }
    }

    // Pass 2: pair remaining unmatched rows with the closest unused cloud row by shared fields.
    for (row_idx, row_fields) in local_rows.iter().enumerate() {
        if matches[row_idx] == CloudRowMatch::Exact {
            continue;
        }
        let best = cloud_rows
            .iter()
            .enumerate()
            .filter(|(c_idx, _)| !cloud_used[*c_idx])
            .max_by_key(|(c_idx, c_row)| {
                let shared = schema
                    .iter()
                    .enumerate()
                    .filter(|(fi, spec)| {
                        row_fields
                            .get(*fi)
                            .zip(c_row.get(*fi))
                            .is_some_and(|(a, b)| field_values_equivalent(spec.kind, a, b))
                    })
                    .count();
                (shared, usize::MAX - *c_idx)
            });

        if let Some((c_idx, _)) = best {
            cloud_used[c_idx] = true;
            matches[row_idx] = CloudRowMatch::Modified(c_idx);
        }
    }

    matches
}

fn render_record_cards(
    ui: &mut Ui,
    modal: &mut RecordEditorModal,
    schema: &[FieldSpec],
    has_cloud_entry: bool,
    cloud_rows: &[Vec<String>],
    row_matches: &[CloudRowMatch],
) {
    let mut remove_idx: Option<usize> = None;
    let can_remove = modal.rows.len() > 1;

    egui::ScrollArea::vertical()
        .auto_shrink([false, true])
        .max_height(320.0)
        .show(ui, |ui| {
            let card_min_width = (ui.available_width() - 16.0).max(200.0);

            for (row_idx, row_fields) in modal.rows.iter_mut().enumerate() {
                if row_fields.len() != schema.len() {
                    row_fields.resize(schema.len(), String::new());
                }
                let row_match = row_matches
                    .get(row_idx)
                    .copied()
                    .unwrap_or(CloudRowMatch::Added);

                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_min_width(card_min_width);

                    // Types with 1..=4 fields fit on a single horizontal line.
                    // Multi-part types (NAPTR = 6, LOC = 10) split cleanly across two lines.
                    let split_at = if schema.len() > 4 {
                        schema.len() - 2
                    } else {
                        schema.len()
                    };
                    let is_single_line = split_at == schema.len();

                    if render_field_line(
                        ui,
                        0..split_at,
                        row_fields,
                        schema,
                        has_cloud_entry,
                        cloud_rows,
                        row_match,
                        is_single_line && can_remove,
                    ) {
                        remove_idx = Some(row_idx);
                    }

                    if !is_single_line {
                        ui.add_space(4.0);
                        if render_field_line(
                            ui,
                            split_at..schema.len(),
                            row_fields,
                            schema,
                            has_cloud_entry,
                            cloud_rows,
                            row_match,
                            can_remove,
                        ) {
                            remove_idx = Some(row_idx);
                        }
                    }
                });

                ui.add_space(4.0);
            }
        });

    if let Some(idx) = remove_idx {
        modal.rows.remove(idx);
    }
}

/// Renders one non-wrapping horizontal row of fields and returns `true` if `Remove` was clicked.
#[allow(clippy::too_many_arguments)]
fn render_field_line(
    ui: &mut Ui,
    range: Range<usize>,
    row_fields: &mut [String],
    schema: &[FieldSpec],
    has_cloud_entry: bool,
    cloud_rows: &[Vec<String>],
    row_match: CloudRowMatch,
    show_remove_btn: bool,
) -> bool {
    let last_in_line = range.end.saturating_sub(1);
    let mut remove_clicked = false;

    ui.horizontal(|ui| {
        for field_idx in range {
            let spec = &schema[field_idx];
            let field_val = &mut row_fields[field_idx];
            let diff_color = field_diff_color(
                ui,
                spec,
                field_val.trim(),
                field_idx,
                has_cloud_entry,
                cloud_rows,
                row_match,
            );

            let label_text = match diff_color {
                Some(col) => RichText::new(spec.label).color(col).strong(),
                None => RichText::new(spec.label),
            };
            ui.label(label_text);

            let is_last = field_idx == last_in_line;
            let field_width = if is_last {
                let reserve = if show_remove_btn { 72.0 } else { 0.0 };
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

        if show_remove_btn && ui.button("Remove").clicked() {
            remove_clicked = true;
        }
    });

    remove_clicked
}

fn field_diff_color(
    ui: &Ui,
    spec: &FieldSpec,
    trimmed_val: &str,
    field_idx: usize,
    has_cloud_entry: bool,
    cloud_rows: &[Vec<String>],
    row_match: CloudRowMatch,
) -> Option<Color32> {
    if !has_cloud_entry {
        return (!trimmed_val.is_empty()).then(|| color_added(ui));
    }
    match row_match {
        CloudRowMatch::Exact => None,
        CloudRowMatch::Modified(c_idx) => cloud_rows
            .get(c_idx)
            .and_then(|c_row| c_row.get(field_idx))
            .is_some_and(|c_val| !field_values_equivalent(spec.kind, c_val, trimmed_val))
            .then(|| color_modified(ui)),
        CloudRowMatch::Added => (!trimmed_val.is_empty()).then(|| color_added(ui)),
    }
}

fn apply_modal_to_zone(
    modal: &RecordEditorModal,
    zone: &mut ZoneState,
) -> Result<RrsetKey, String> {
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

    let mut records: Vec<String> = Vec::with_capacity(modal.rows.len());
    for (idx, row_fields) in modal.rows.iter().enumerate() {
        match validate_and_format(&rtype, row_fields) {
            Ok(formatted) => {
                if !records
                    .iter()
                    .any(|existing| records_equivalent(&rtype, existing, &formatted))
                {
                    records.push(formatted);
                }
            }
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
    zone.upsert_local(modal.original_key.as_ref(), new_key.clone(), data)?;
    Ok(new_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_row_matching_ignores_rrset_order() {
        let schema = schema_for_type("MX");
        let cloud_raw = ["10 mail1.example.com.", "20 mail2.example.com."];
        let cloud_rows: Vec<Vec<String>> = cloud_raw
            .iter()
            .map(|r| parse_record_to_fields("MX", r))
            .collect();
        let cloud_canonical: Vec<String> = cloud_raw
            .iter()
            .map(|r| canonical_record("MX", r))
            .collect();

        // Reversed order + different target casing -> both Exact.
        let local_reordered = vec![
            vec!["20".to_owned(), "Mail2.Example.COM.".to_owned()],
            vec!["10".to_owned(), "mail1.example.com.".to_owned()],
        ];
        assert_eq!(
            match_rows_to_cloud("MX", schema, &local_reordered, &cloud_rows, &cloud_canonical),
            vec![CloudRowMatch::Exact, CloudRowMatch::Exact]
        );

        // Reversed order + one priority edited -> unchanged stays Exact, edited pairs with its row.
        let local_edited = vec![
            vec!["20".to_owned(), "mail2.example.com.".to_owned()],
            vec!["15".to_owned(), "mail1.example.com.".to_owned()],
        ];
        assert_eq!(
            match_rows_to_cloud("MX", schema, &local_edited, &cloud_rows, &cloud_canonical),
            vec![CloudRowMatch::Exact, CloudRowMatch::Modified(0)]
        );
    }
}
