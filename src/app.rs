use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::backend::{BackendCommand, BackendEvent, BackendHandle};
use crate::model::{
    DiffOp, DomainSummary, RECORD_TYPES, RowStatus, RrsetData, RrsetKey, ZoneRow, ZoneState,
    record_type_hint,
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
    ttl_input: String,
    records: Vec<String>,
    error: Option<String>,
}

impl RecordEditorModal {
    fn new_empty(default_ttl: u32) -> Self {
        Self {
            original_key: None,
            subname: String::new(),
            selected_type: "A".to_owned(),
            custom_type: String::new(),
            ttl_input: default_ttl.to_string(),
            records: vec![String::new()],
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
        let records = if row.display_data.records.is_empty() {
            vec![String::new()]
        } else {
            row.display_data.records.clone()
        };

        Self {
            original_key: Some(row.key.clone()),
            subname: row.key.subname.clone(),
            selected_type,
            custom_type,
            ttl_input: row.display_data.ttl.to_string(),
            records,
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
                    format!("Connecting with token from {source_label}..."),
                )
            }
            None => (
                true,
                None,
                None,
                "Enter your deSEC API token to connect.".to_owned(),
            ),
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
        self.status_message = format!("Fetching RRsets for {domain} from deSEC...");
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
                        self.status_message = "Connected. No domains found in account.".to_owned();
                    }
                }

                BackendEvent::DomainsLoaded { domains } => {
                    self.domains = domains;
                    self.busy_label = None;
                    self.status_message = format!("Loaded {} domains.", self.domains.len());
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
                    self.status_message = format!("Synced {domain} ({count} RRsets).");
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
                    self.status_message = format!(
                        "Applied {applied_count} change(s) to {domain}. Synced ({count} RRsets)."
                    );
                }

                BackendEvent::Error { context, message } => {
                    self.busy_label = None;
                    self.error_banner = Some(format!("{context}: {message}"));
                    self.status_message = format!("{context} failed.");
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
                    self.busy_label = Some("Loading domains...".to_owned());
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
                ui.label("Domain:");

                let current_label = self.selected_domain.as_deref().unwrap_or("None").to_owned();
                let mut switched_to: Option<String> = None;

                ui.add_enabled_ui(self.connected && !self.is_busy(), |ui| {
                    egui::ComboBox::from_id_salt("domain_selector")
                        .selected_text(&current_label)
                        .width(220.0)
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

                    if ui.button("Refresh").clicked() {
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
                        if ui.button("Review & Apply").clicked() {
                            self.show_review_modal = true;
                        }
                        if ui.button("Discard").clicked()
                            && let Some(zone) = &mut self.zone
                        {
                            zone.discard_all();
                            self.status_message = "Discarded all local changes.".to_owned();
                        }
                    });

                    if dirty {
                        ui.label(format!("{} pending", summary.total()));
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
                    ui.label(format!("Error: {err}"));
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
                        let s = zone.summary();
                        ui.label(format!(
                            "Min TTL: {}s | Add: {} | Modify: {} | Delete: {}",
                            zone.minimum_ttl, s.added, s.modified, s.deleted
                        ));
                    });
                }
            });
        });
    }

    fn render_zone_view(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(ui, |ui| {
            if !self.connected {
                ui.centered_and_justified(|ui| {
                    ui.label("Not connected to deSEC. Configure your API token to begin.");
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
                        ui.label("Loading zone from deSEC...");
                    } else {
                        ui.label("Select a domain to edit its DNS zone.");
                    }
                });
                return;
            };

            let busy = self.is_busy();

            // Toolbar
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Subname, type, or value")
                        .desired_width(220.0),
                );

                ui.label("Type:");
                egui::ComboBox::from_id_salt("type_filter")
                    .selected_text(&self.type_filter)
                    .width(100.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.type_filter, "All".to_owned(), "All");
                        for rtype in &available_types {
                            ui.selectable_value(&mut self.type_filter, rtype.clone(), rtype);
                        }
                    });

                ui.checkbox(&mut self.changes_only, "Changes only");

                if (!self.search_query.is_empty() || self.type_filter != "All" || self.changes_only)
                    && ui.button("Clear filters").clicked()
                {
                    self.search_query.clear();
                    self.type_filter = "All".to_owned();
                    self.changes_only = false;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui.button("Add Record").clicked() {
                            self.editor_modal = Some(RecordEditorModal::new_empty(default_ttl));
                        }
                    });
                });
            });

            ui.separator();

            // Filtered rows
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
                    ui.label("No matching records.");
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
            let busy = self.is_busy();

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::TOP))
                .column(Column::initial(78.0).at_least(70.0)) // Status
                .column(Column::initial(150.0).at_least(80.0)) // Subname
                .column(Column::initial(95.0).at_least(65.0)) // Type
                .column(Column::initial(70.0).at_least(55.0)) // TTL
                .column(Column::remainder().at_least(220.0)) // Records
                .column(Column::initial(165.0).at_least(150.0)) // Actions
                .header(24.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Status");
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

        egui::Window::new("deSEC API Token")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(420.0)
            .show(ctx, |ui| {
                ui.label("Enter a deSEC API token to fetch and edit your DNS zones.");
                if let Some(src) = self.token_source {
                    let label = match src {
                        TokenSource::Keyring => "Currently using token from system keyring.",
                        TokenSource::Env => "Currently using token from DESEC_TOKEN.",
                    };
                    ui.label(label);
                }

                ui.add_space(6.0);
                ui.label("API Token:");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.token_input)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );
                let enter_pressed =
                    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                ui.checkbox(&mut self.save_token_to_keyring, "Save to system keyring");
                ui.add_space(8.0);

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
                        self.status_message = "Connecting to deSEC...".to_owned();
                        self.backend
                            .send(BackendCommand::Connect { token: token_val });
                    }

                    if ui.button("Clear saved token").clicked() {
                        match token::delete_token() {
                            Ok(()) => {
                                if self.token_source == Some(TokenSource::Keyring) {
                                    self.token_source = None;
                                }
                                self.status_message =
                                    "Cleared saved token from system keyring.".to_owned();
                            }
                            Err(err) => {
                                self.error_banner = Some(err);
                            }
                        }
                    }

                    if self.connected && ui.button("Cancel").clicked() {
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
            "Add Record"
        };

        let mut keep_open = true;
        let mut save_requested = false;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(520.0)
            .show(ctx, |ui| {
                egui::Grid::new("record_editor_grid")
                    .num_columns(2)
                    .spacing([10.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Subname:");
                        ui.add(
                            egui::TextEdit::singleline(&mut modal.subname)
                                .hint_text("Empty or @ for apex")
                                .desired_width(340.0),
                        );
                        ui.end_row();

                        ui.label("Type:");
                        ui.horizontal(|ui| {
                            let selected_display = if modal.selected_type == CUSTOM_TYPE_SENTINEL {
                                "Other (custom)"
                            } else {
                                &modal.selected_type
                            };
                            egui::ComboBox::from_id_salt("editor_record_type")
                                .selected_text(selected_display)
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    for &rt in RECORD_TYPES {
                                        ui.selectable_value(
                                            &mut modal.selected_type,
                                            rt.to_owned(),
                                            rt,
                                        );
                                    }
                                    ui.separator();
                                    ui.selectable_value(
                                        &mut modal.selected_type,
                                        CUSTOM_TYPE_SENTINEL.to_owned(),
                                        "Other (custom)",
                                    );
                                });

                            if modal.selected_type == CUSTOM_TYPE_SENTINEL {
                                ui.add(
                                    egui::TextEdit::singleline(&mut modal.custom_type)
                                        .hint_text("e.g. TYPE65")
                                        .desired_width(140.0),
                                );
                            }
                        });
                        ui.end_row();

                        ui.label("TTL (seconds):");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut modal.ttl_input)
                                    .desired_width(120.0),
                            );
                            ui.label(format!("Minimum: {min_ttl}s"));
                        });
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.label("Records:");
                let active_type = modal.effective_type();
                ui.small(record_type_hint(&active_type));
                ui.add_space(4.0);

                let mut remove_idx: Option<usize> = None;
                let can_remove = modal.records.len() > 1;
                egui::ScrollArea::vertical()
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for (idx, rec) in modal.records.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(rec)
                                        .code_editor()
                                        .desired_width(390.0),
                                );
                                if can_remove && ui.button("Remove").clicked() {
                                    remove_idx = Some(idx);
                                }
                            });
                        }
                    });
                if let Some(idx) = remove_idx {
                    modal.records.remove(idx);
                }

                if ui.button("Add value").clicked() {
                    modal.records.push(String::new());
                }

                if let Some(err) = &modal.error {
                    ui.add_space(6.0);
                    ui.label(format!("Error: {err}"));
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save locally").clicked() {
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
            .map_err(|_| "TTL must be a positive integer.".to_owned())?;

        let rtype = modal.effective_type();
        if rtype.is_empty() || !rtype.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err("Record type must be alphanumeric (e.g. A, TXT, MX).".to_owned());
        }

        let records: Vec<String> = modal
            .records
            .iter()
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty())
            .collect();
        if records.is_empty() {
            return Err("Enter at least one non-empty record value.".to_owned());
        }

        let new_key = RrsetKey::new(&modal.subname, rtype);
        let data = RrsetData::new(ttl, records);
        zone.upsert_local(modal.original_key.as_ref(), new_key, data)?;
        self.status_message = "Updated local zone state (not yet applied to deSEC).".to_owned();
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

        egui::Window::new("Review & Apply Changes")
            .collapsible(false)
            .resizable(true)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(640.0)
            .default_height(420.0)
            .show(ctx, |ui| {
                ui.label(format!(
                    "{} pending operation(s) will be sent atomically to deSEC for {}.",
                    ops.len(),
                    domain
                ));
                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(320.0)
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
                                        ui.label(format!("Local (TTL {}):", data.ttl));
                                        for r in &data.records {
                                            ui.monospace(format!("  + {r}"));
                                        }
                                    }
                                    DiffOp::Update { old, new, .. } => {
                                        ui.label(format!("deSEC (TTL {}):", old.ttl));
                                        for r in &old.records {
                                            ui.monospace(format!("  - {r}"));
                                        }
                                        ui.label(format!("Local (TTL {}):", new.ttl));
                                        for r in &new.records {
                                            ui.monospace(format!("  + {r}"));
                                        }
                                    }
                                    DiffOp::Delete { old, .. } => {
                                        ui.label(format!("deSEC (TTL {}):", old.ttl));
                                        for r in &old.records {
                                            ui.monospace(format!("  - {r}"));
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
                        if ui.button("Apply to deSEC").clicked() {
                            apply_now = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_modal = true;
                        }
                    });
                });
            });

        if apply_now {
            self.busy_label = Some(format!("Applying {} change(s) to {domain}...", ops.len()));
            self.status_message = format!("Sending bulk update to deSEC for {domain}...");
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

        egui::Window::new("Unsaved Local Changes")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_width(380.0)
            .show(ctx, |ui| {
                ui.label("You have unapplied local changes. Proceeding will discard them.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Discard & Continue").clicked() {
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
