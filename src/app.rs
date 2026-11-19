use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::backend::{BackendCommand, BackendEvent, BackendHandle};
use crate::model::{
    DiffOp, DomainSummary, RECORD_TYPES, RowStatus, RrsetData, RrsetKey, ZoneRow, ZoneState,
};
use crate::rdata::{
    default_fields_for_type, parse_record_to_fields, schema_for_type, validate_and_format,
};
use crate::token::{self, TokenSource};

const CUSTOM_TYPE_SENTINEL: &str = "CUSTOM";

#[derive(Debug, Clone)]
enum PendingNavigation {
    RefreshZone,
    SwitchDomain(String),
}

#[derive(Debug, Clone)]
struct RecordEditorModal {
    /// `None` when adding a new RRset; `Some(key)` when editing an existing one.
    original_key: Option<RrsetKey>,
    subname: String,
    selected_type: String,
    custom_type: String,
    last_effective_type: String,
    ttl_input: String,
    /// Structured field values per record row (`rows[row_idx][field_idx]`).
    rows: Vec<Vec<String>>,
    error: Option<String>,
}

impl RecordEditorModal {
    fn new_empty(default_ttl: u32) -> Self {
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

    fn from_row(row: &ZoneRow) -> Self {
        let is_known = RECORD_TYPES.contains(&row.key.rtype.as_str());
        let (selected_type, custom_type) = if is_known {
            (row.key.rtype.clone(), String::new())
        } else {
            (CUSTOM_TYPE_SENTINEL.to_owned(), row.key.rtype.clone())
        };
        let rtype = row.key.rtype.clone();
        let rows = if row.display_data.records.is_empty() {
            vec![default_fields_for_type(&rtype)]
        } else {
            row.display_data
                .records
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
            ttl_input: row.display_data.ttl.to_string(),
            rows,
            error: None,
        }
    }

    fn effective_type(&self) -> String {
        if self.selected_type == CUSTOM_TYPE_SENTINEL {
            self.custom_type.trim().to_ascii_uppercase()
        } else {
            self.selected_type.clone()
        }
    }

    fn sync_schema_if_type_changed(&mut self) {
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

pub struct DesecApp {
    backend: BackendHandle,
    connected: bool,
    busy_label: Option<String>,
    status_message: String,
    error_banner: Option<String>,

    // Token dialog state
    show_token_modal: bool,
    token_input: String,
    save_token_to_keyring: bool,
    token_source: Option<TokenSource>,

    // Domain & zone state
    domains: Vec<DomainSummary>,
    selected_domain: Option<String>,
    zone: Option<ZoneState>,

    // Filters
    search_query: String,
    type_filter: String,
    changes_only: bool,

    // Modals
    editor_modal: Option<RecordEditorModal>,
    show_review_modal: bool,
    pending_navigation: Option<PendingNavigation>,
}

impl DesecApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let backend = BackendHandle::spawn(cc.egui_ctx.clone());

        let loaded = token::load_token();
        let (show_token_modal, token_source, busy_label, status_message) = match loaded {
            Some(found) => {
                backend.send(BackendCommand::Connect { token: found.token });
                let source_label = match found.source {
                    TokenSource::Keyring => "keyring",
                    TokenSource::Env => "DESEC_TOKEN",
                };
                (
                    false,
                    Some(found.source),
                    Some("Connecting...".to_owned()),
                    format!("Connecting ({source_label})..."),
                )
            }
            None => (true, None, None, "Disconnected".to_owned()),
        };

        Self {
            backend,
            connected: false,
            busy_label,
            status_message,
            error_banner: None,
            show_token_modal,
            token_input: String::new(),
            save_token_to_keyring: true,
            token_source,
            domains: Vec::new(),
            selected_domain: None,
            zone: None,
            search_query: String::new(),
            type_filter: "All".to_owned(),
            changes_only: false,
            editor_modal: None,
            show_review_modal: false,
            pending_navigation: None,
        }
    }

    fn is_busy(&self) -> bool {
        self.busy_label.is_some()
    }

    fn domain_min_ttl(&self, name: &str) -> u32 {
        self.domains
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.minimum_ttl)
            .unwrap_or(3600)
    }

    fn request_fetch_zone(&mut self, domain: String) {
        let minimum_ttl = self.domain_min_ttl(&domain);
        self.selected_domain = Some(domain.clone());
        self.busy_label = Some(format!("Loading {domain}..."));
        self.status_message = format!("Fetching {domain}...");
        self.error_banner = None;
        self.backend.send(BackendCommand::FetchZone {
            domain,
            minimum_ttl,
        });
    }

    fn handle_backend_events(&mut self) {
        while let Some(event) = self.backend.try_recv() {
            match event {
                BackendEvent::Connected { domains } => {
                    self.connected = true;
                    self.show_token_modal = false;
                    self.token_input.clear();
                    self.error_banner = None;
                    self.domains = domains;
                    self.busy_label = None;

                    if let Some(first) = self.domains.first().map(|d| d.name.clone()) {
                        self.request_fetch_zone(first);
                    } else {
                        self.selected_domain = None;
                        self.zone = None;
                        self.status_message = "No domains in account".to_owned();
                    }
                }

                BackendEvent::DomainsLoaded { domains } => {
                    self.domains = domains;
                    self.busy_label = None;
                    self.status_message = format!("{} domains", self.domains.len());
                }

                BackendEvent::ZoneLoaded {
                    domain,
                    minimum_ttl,
                    rrsets,
                } => {
                    let count = rrsets.len();
                    self.zone = Some(ZoneState::from_remote(domain.clone(), minimum_ttl, rrsets));
                    self.selected_domain = Some(domain.clone());
                    self.busy_label = None;
                    self.show_review_modal = false;
                    self.editor_modal = None;
                    self.status_message = format!("{domain} ({count} RRsets)");
                }

                BackendEvent::ChangesApplied {
                    domain,
                    minimum_ttl,
                    applied_count,
                    rrsets,
                } => {
                    let count = rrsets.len();
                    self.zone = Some(ZoneState::from_remote(domain.clone(), minimum_ttl, rrsets));
                    self.busy_label = None;
                    self.show_review_modal = false;
                    self.error_banner = None;
                    self.status_message =
                        format!("Applied {applied_count} to {domain} ({count} RRsets)");
                }

                BackendEvent::Error { context, message } => {
                    self.busy_label = None;
                    self.error_banner = Some(format!("{context}: {message}"));
                    self.status_message = format!("{context} failed");
                    if !self.connected {
                        self.show_token_modal = true;
                    }
                }
            }
        }
    }

    fn execute_navigation(&mut self, nav: PendingNavigation) {
        match nav {
            PendingNavigation::RefreshZone => {
                if let Some(domain) = self.selected_domain.clone() {
                    self.request_fetch_zone(domain);
                } else if self.connected {
                    self.busy_label = Some("Loading...".to_owned());
                    self.backend.send(BackendCommand::FetchDomains);
                }
            }
            PendingNavigation::SwitchDomain(domain) => {
                self.request_fetch_zone(domain);
            }
        }
    }

    fn request_navigation(&mut self, nav: PendingNavigation) {
        if self.zone.as_ref().is_some_and(ZoneState::is_dirty) {
            self.pending_navigation = Some(nav);
        } else {
            self.execute_navigation(nav);
        }
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Zone");

                let current_label = self.selected_domain.as_deref().unwrap_or("None").to_owned();
                let mut switched_to: Option<String> = None;

                ui.add_enabled_ui(self.connected && !self.is_busy(), |ui| {
                    egui::ComboBox::from_id_salt("domain_selector")
                        .selected_text(&current_label)
                        .width(260.0)
                        .show_ui(ui, |ui| {
                            for domain in &self.domains {
                                let selected =
                                    self.selected_domain.as_deref() == Some(domain.name.as_str());
                                if ui.selectable_label(selected, &domain.name).clicked()
                                    && !selected
                                {
                                    switched_to = Some(domain.name.clone());
                                }
                            }
                        });

                    if ui.button("Fetch").clicked() {
                        self.request_navigation(PendingNavigation::RefreshZone);
                    }
                });

                if let Some(domain) = switched_to {
                    self.request_navigation(PendingNavigation::SwitchDomain(domain));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Token").clicked() {
                        self.show_token_modal = true;
                    }

                    let summary = self
                        .zone
                        .as_ref()
                        .map(ZoneState::summary)
                        .unwrap_or_default();
                    let dirty = !summary.is_empty();

                    ui.add_enabled_ui(dirty && !self.is_busy(), |ui| {
                        if ui.button("Apply").clicked() {
                            self.show_review_modal = true;
                        }
                        if ui.button("Discard").clicked()
                            && let Some(zone) = &mut self.zone
                        {
                            zone.discard_all();
                        }
                    });

                    if dirty {
                        ui.label(format!(
                            "+{} ~{} -{}",
                            summary.added, summary.modified, summary.deleted
                        ));
                    } else if self.zone.is_some() {
                        ui.label("Synced");
                    }
                });
            });
        });
    }

    fn render_bottom_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("bottom_bar").show(ui, |ui| {
            if let Some(err) = self.error_banner.clone() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(&err);
                    if ui.button("Dismiss").clicked() {
                        self.error_banner = None;
                    }
                });
                ui.separator();
            }

            ui.horizontal(|ui| {
                if let Some(busy) = &self.busy_label {
                    ui.spinner();
                    ui.label(busy);
                } else {
                    ui.label(&self.status_message);
                }

                if let Some(zone) = &self.zone {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("Min TTL: {}s", zone.minimum_ttl));
                    });
                }
            });
        });
    }

    fn render_zone_view(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            if !self.connected {
                ui.centered_and_justified(|ui| {
                    ui.label("No active session.");
                });
                return;
            }

            let Some((available_types, default_ttl, all_rows)) = self.zone.as_ref().map(|z| {
                (
                    z.available_record_types(),
                    z.minimum_ttl.max(3600),
                    z.rows(),
                )
            }) else {
                ui.centered_and_justified(|ui| {
                    if self.is_busy() {
                        ui.label("Loading...");
                    } else {
                        ui.label("No zone selected.");
                    }
                });
                return;
            };

            let busy = self.is_busy();

            // Compact filter & action bar
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Search")
                        .desired_width(260.0),
                );

                egui::ComboBox::from_id_salt("type_filter")
                    .selected_text(&self.type_filter)
                    .width(120.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.type_filter, "All".to_owned(), "All");
                        for rtype in &available_types {
                            ui.selectable_value(&mut self.type_filter, rtype.clone(), rtype);
                        }
                    });

                ui.checkbox(&mut self.changes_only, "Modified only");

                if (!self.search_query.is_empty() || self.type_filter != "All" || self.changes_only)
                    && ui.button("Reset").clicked()
                {
                    self.search_query.clear();
                    self.type_filter = "All".to_owned();
                    self.changes_only = false;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui.button("New Record").clicked() {
                            self.editor_modal = Some(RecordEditorModal::new_empty(default_ttl));
                        }
                    });
                });
            });

            ui.separator();

            let query = self.search_query.trim().to_ascii_lowercase();
            let rows: Vec<ZoneRow> = all_rows
                .into_iter()
                .filter(|row| {
                    if self.changes_only && !row.status.is_changed() {
                        return false;
                    }
                    if self.type_filter != "All" && row.key.rtype != self.type_filter {
                        return false;
                    }
                    if !query.is_empty() {
                        let sub_match = row
                            .key
                            .display_subname()
                            .to_ascii_lowercase()
                            .contains(&query);
                        let type_match = row.key.rtype.to_ascii_lowercase().contains(&query);
                        let val_match = row
                            .display_data
                            .records
                            .iter()
                            .any(|r| r.to_ascii_lowercase().contains(&query));
                        if !sub_match && !type_match && !val_match {
                            return false;
                        }
                    }
                    true
                })
                .collect();

            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No records.");
                });
                return;
            }

            let row_heights: Vec<f32> = rows
                .iter()
                .map(|r| {
                    let lines = r.display_data.records.len().max(1) as f32;
                    (lines * 18.0 + 10.0).max(28.0)
                })
                .collect();

            let mut edit_row: Option<ZoneRow> = None;
            let mut delete_key: Option<RrsetKey> = None;
            let mut revert_key: Option<RrsetKey> = None;

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::TOP))
                .column(Column::initial(84.0).at_least(75.0)) // State
                .column(Column::initial(180.0).at_least(100.0)) // Subname
                .column(Column::initial(105.0).at_least(80.0)) // Type
                .column(Column::initial(78.0).at_least(65.0)) // TTL
                .column(Column::remainder().at_least(280.0)) // Records
                .column(Column::initial(175.0).at_least(165.0)) // Actions
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

                        table_row.col(|ui| {
                            ui.label(row.status.label());
                        });
                        table_row.col(|ui| {
                            ui.monospace(row.key.display_subname());
                        });
                        table_row.col(|ui| {
                            ui.monospace(&row.key.rtype);
                        });
                        table_row.col(|ui| {
                            ui.monospace(row.display_data.ttl.to_string());
                        });
                        table_row.col(|ui| {
                            ui.vertical(|ui| {
                                for rec in &row.display_data.records {
                                    ui.monospace(rec);
                                }
                            });
                        });
                        table_row.col(|ui| {
                            ui.add_enabled_ui(!busy, |ui| {
                                ui.horizontal(|ui| match row.status {
                                    RowStatus::Synced | RowStatus::Added => {
                                        if ui.button("Edit").clicked() {
                                            edit_row = Some(row.clone());
                                        }
                                        if ui.button("Delete").clicked() {
                                            delete_key = Some(row.key.clone());
                                        }
                                    }
                                    RowStatus::Modified => {
                                        if ui.button("Edit").clicked() {
                                            edit_row = Some(row.clone());
                                        }
                                        if ui.button("Delete").clicked() {
                                            delete_key = Some(row.key.clone());
                                        }
                                        if ui.button("Revert").clicked() {
                                            revert_key = Some(row.key.clone());
                                        }
                                    }
                                    RowStatus::Deleted => {
                                        if ui.button("Revert").clicked() {
                                            revert_key = Some(row.key.clone());
                                        }
                                    }
                                });
                            });
                        });
                    });
                });

            if let Some(row) = edit_row {
                self.editor_modal = Some(RecordEditorModal::from_row(&row));
            }
            if let Some(key) = delete_key
                && let Some(zone) = &mut self.zone
            {
                zone.delete_local(&key);
            }
            if let Some(key) = revert_key
                && let Some(zone) = &mut self.zone
            {
                zone.revert_key(&key);
            }
        });
    }

    fn render_token_modal(&mut self, ctx: &egui::Context) {
        if !self.show_token_modal {
            return;
        }

        let mut close_modal = false;

        egui::Window::new("API Token")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(360.0)
            .show(ctx, |ui| {
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.token_input)
                        .password(true)
                        .hint_text("deSEC token")
                        .desired_width(f32::INFINITY),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                ui.checkbox(&mut self.save_token_to_keyring, "Save to keyring");
                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    let can_connect = !self.token_input.trim().is_empty() && !self.is_busy();
                    if ui
                        .add_enabled(can_connect, egui::Button::new("Connect"))
                        .clicked()
                        || (enter_pressed && can_connect)
                    {
                        let token_val = self.token_input.trim().to_owned();
                        if self.save_token_to_keyring {
                            match token::save_token(&token_val) {
                                Ok(()) => self.token_source = Some(TokenSource::Keyring),
                                Err(err) => {
                                    self.error_banner = Some(err);
                                }
                            }
                        }
                        self.busy_label = Some("Connecting...".to_owned());
                        self.backend
                            .send(BackendCommand::Connect { token: token_val });
                    }

                    if ui.button("Clear Keyring").clicked() {
                        match token::delete_token() {
                            Ok(()) => {
                                if self.token_source == Some(TokenSource::Keyring) {
                                    self.token_source = None;
                                }
                                self.status_message = "Cleared saved token".to_owned();
                            }
                            Err(err) => {
                                self.error_banner = Some(err);
                            }
                        }
                    }

                    if self.connected && ui.button("Close").clicked() {
                        close_modal = true;
                    }
                });
            });

        if close_modal {
            self.show_token_modal = false;
            self.token_input.clear();
        }
    }

    fn render_editor_modal(&mut self, ctx: &egui::Context) {
        let Some(mut modal) = self.editor_modal.take() else {
            return;
        };

        let min_ttl = self.zone.as_ref().map(|z| z.minimum_ttl).unwrap_or(3600);
        let title = if modal.original_key.is_some() {
            "Edit Record"
        } else {
            "New Record"
        };

        let mut keep_open = true;
        let mut save_requested = false;

        modal.sync_schema_if_type_changed();

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(760.0)
            .min_width(640.0)
            .show(ctx, |ui| {
                // Top row: Subname, Type, and TTL
                ui.horizontal(|ui| {
                    ui.label("Subname");
                    ui.add(
                        egui::TextEdit::singleline(&mut modal.subname)
                            .hint_text("@")
                            .desired_width(240.0),
                    );

                    ui.add_space(8.0);
                    ui.label("Type");
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

                    ui.add_space(8.0);
                    ui.label("TTL");
                    ui.add(
                        egui::TextEdit::singleline(&mut modal.ttl_input)
                            .hint_text(min_ttl.to_string())
                            .desired_width(85.0),
                    );
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
                                body.row(28.0, |mut row| {
                                    for (field_val, spec) in
                                        row_fields.iter_mut().zip(schema.iter())
                                    {
                                        row.col(|ui| {
                                            let w = ui.available_width().max(24.0);
                                            ui.add_sized(
                                                [w, 22.0],
                                                egui::TextEdit::singleline(field_val)
                                                    .hint_text(spec.hint)
                                                    .code_editor(),
                                            );
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
                if ui.button("Add Row").clicked() {
                    modal.rows.push(default_fields_for_type(&active_type));
                }

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
                        keep_open = false;
                    }
                });
            });

        if save_requested {
            match self.apply_modal_to_local(&modal) {
                Ok(()) => {
                    keep_open = false;
                }
                Err(err) => {
                    modal.error = Some(err);
                }
            }
        }

        if keep_open {
            self.editor_modal = Some(modal);
        }
    }

    fn apply_modal_to_local(&mut self, modal: &RecordEditorModal) -> Result<(), String> {
        let Some(zone) = &mut self.zone else {
            return Err("No zone loaded.".to_owned());
        };

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
        zone.upsert_local(modal.original_key.as_ref(), new_key, data)?;
        Ok(())
    }

    fn render_review_modal(&mut self, ctx: &egui::Context) {
        if !self.show_review_modal {
            return;
        }

        let Some(zone) = &self.zone else {
            self.show_review_modal = false;
            return;
        };

        let ops = zone.diff();
        if ops.is_empty() {
            self.show_review_modal = false;
            return;
        }

        let domain = zone.domain.clone();
        let minimum_ttl = zone.minimum_ttl;
        let busy = self.is_busy();
        let mut close_modal = false;
        let mut apply_now = false;

        egui::Window::new(format!("Apply Changes ({})", ops.len()))
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(580.0)
            .default_height(380.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .show(ui, |ui| {
                        for op in &ops {
                            ui.group(|ui| {
                                ui.strong(format!(
                                    "{}  {}  {}",
                                    op.kind_label(),
                                    op.key().display_subname(),
                                    op.key().rtype
                                ));

                                match op {
                                    DiffOp::Create { data, .. } => {
                                        ui.label(format!("Local (TTL {})", data.ttl));
                                        for r in &data.records {
                                            ui.monospace(format!("+ {r}"));
                                        }
                                    }
                                    DiffOp::Update { old, new, .. } => {
                                        ui.label(format!(
                                            "deSEC (TTL {}) -> Local (TTL {})",
                                            old.ttl, new.ttl
                                        ));
                                        for r in &old.records {
                                            ui.monospace(format!("- {r}"));
                                        }
                                        for r in &new.records {
                                            ui.monospace(format!("+ {r}"));
                                        }
                                    }
                                    DiffOp::Delete { old, .. } => {
                                        ui.label(format!("deSEC (TTL {})", old.ttl));
                                        for r in &old.records {
                                            ui.monospace(format!("- {r}"));
                                        }
                                    }
                                }
                            });
                            ui.add_space(4.0);
                        }
                    });

                ui.separator();
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui.button("Execute").clicked() {
                            apply_now = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                    });
                });
            });

        if apply_now {
            self.busy_label = Some(format!("Applying ({})...", ops.len()));
            self.error_banner = None;
            self.backend.send(BackendCommand::ApplyChanges {
                domain,
                minimum_ttl,
                ops,
            });
        } else if close_modal {
            self.show_review_modal = false;
        }
    }

    fn render_unsaved_guard_modal(&mut self, ctx: &egui::Context) {
        let Some(nav) = self.pending_navigation.clone() else {
            return;
        };

        let mut confirm = false;
        let mut cancel = false;

        egui::Window::new("Discard Local Changes?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Discard").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if confirm {
            self.pending_navigation = None;
            self.execute_navigation(nav);
        } else if cancel {
            self.pending_navigation = None;
        }
    }
}

impl eframe::App for DesecApp {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_backend_events();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_top_bar(ui);
        self.render_bottom_bar(ui);
        self.render_zone_view(ui);

        let ctx = ui.ctx().clone();
        self.render_token_modal(&ctx);
        self.render_editor_modal(&ctx);
        self.render_review_modal(&ctx);
        self.render_unsaved_guard_modal(&ctx);
    }
}
