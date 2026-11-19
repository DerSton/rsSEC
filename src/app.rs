use std::collections::BTreeSet;

use eframe::egui::{self, RichText};

use crate::backend::{BackendCommand, BackendEvent, BackendHandle};
use crate::model::{DomainSummary, RrsetKey, ZoneRow, ZoneState};
use crate::token::{self, TokenSource};
use crate::ui::editor_modal::{EditorOutcome, RecordEditorModal, render_editor_modal};
use crate::ui::modals::{
    ReviewModalAction, TokenModalAction, render_review_modal, render_token_modal,
};
use crate::ui::theme::{color_added, color_deleted, color_modified};
use crate::ui::zone_table::render_zone_table;

#[derive(Debug, Clone)]
enum PendingNavigation {
    RefreshZone,
    SwitchDomain(String),
}

pub struct DesecApp {
    backend: BackendHandle,
    connected: bool,
    busy_label: Option<String>,
    status_message: String,
    error_banner: Option<String>,

    show_token_modal: bool,
    token_input: String,
    save_token_to_keyring: bool,
    token_source: Option<TokenSource>,

    domains: Vec<DomainSummary>,
    selected_domain: Option<String>,
    zone: Option<ZoneState>,

    search_query: String,
    type_filter: String,
    changes_only: bool,
    selected_keys: BTreeSet<RrsetKey>,
    bulk_ttl_input: String,

    editor_modal: Option<RecordEditorModal>,
    show_review_modal: bool,
    pending_navigation: Option<PendingNavigation>,
}

impl DesecApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Work around an integer underflow in egui/epaint 0.37.0's new IME preedit underline renderer.
        cc.egui_ctx.all_styles_mut(|style| {
            style.visuals.ime_composition.legacy_visuals = true;
        });

        let backend = BackendHandle::spawn(cc.egui_ctx.clone());

        let (show_token_modal, token_source, busy_label, status_message) = match token::load_token()
        {
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
            selected_keys: BTreeSet::new(),
            bulk_ttl_input: "3600".to_owned(),
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
        self.selected_keys.clear();
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
                    self.selected_keys.clear();
                    self.bulk_ttl_input = minimum_ttl.max(3600).to_string();
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
                    self.selected_keys.clear();
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
                        if summary.deleted > 0 {
                            ui.label(
                                RichText::new(format!("-{}", summary.deleted))
                                    .color(color_deleted(ui))
                                    .strong(),
                            );
                        }
                        if summary.modified > 0 {
                            ui.label(
                                RichText::new(format!("~{}", summary.modified))
                                    .color(color_modified(ui))
                                    .strong(),
                            );
                        }
                        if summary.added > 0 {
                            ui.label(
                                RichText::new(format!("+{}", summary.added))
                                    .color(color_added(ui))
                                    .strong(),
                            );
                        }
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
                    ui.label(RichText::new(&err).color(color_deleted(ui)));
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
                    let msg = if self.is_busy() {
                        "Loading..."
                    } else {
                        "No zone selected."
                    };
                    ui.label(msg);
                });
                return;
            };

            let valid_keys: BTreeSet<RrsetKey> = all_rows.iter().map(|r| r.key.clone()).collect();
            self.selected_keys.retain(|k| valid_keys.contains(k));

            self.render_filter_bar(ui, &available_types, default_ttl);

            if !self.selected_keys.is_empty() {
                ui.separator();
                self.render_bulk_bar(ui);
            }

            ui.separator();

            let query_lower = self.search_query.trim().to_ascii_lowercase();
            let rows: Vec<ZoneRow> = all_rows
                .into_iter()
                .filter(|row| {
                    row.matches_filter(&query_lower, &self.type_filter, self.changes_only)
                })
                .collect();

            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No records.");
                });
                return;
            }

            let busy = self.is_busy();
            let actions = render_zone_table(ui, &rows, &mut self.selected_keys, busy);

            if let Some(row) = actions.edit_row {
                self.editor_modal = Some(RecordEditorModal::from_row(&row));
            }
            if let Some(key) = actions.delete_key
                && let Some(zone) = &mut self.zone
            {
                zone.delete_local(&key);
            }
            if let Some(key) = actions.revert_key
                && let Some(zone) = &mut self.zone
            {
                zone.revert_key(&key);
            }
        });
    }

    fn render_filter_bar(
        &mut self,
        ui: &mut egui::Ui,
        available_types: &[String],
        default_ttl: u32,
    ) {
        let busy = self.is_busy();

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Search")
                    .desired_width(240.0),
            );

            egui::ComboBox::from_id_salt("type_filter")
                .selected_text(&self.type_filter)
                .width(115.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.type_filter, "All".to_owned(), "All");
                    for rtype in available_types {
                        ui.selectable_value(&mut self.type_filter, rtype.clone(), rtype);
                    }
                });

            ui.checkbox(&mut self.changes_only, "Modified only");

            let has_active_filter =
                !self.search_query.is_empty() || self.type_filter != "All" || self.changes_only;
            if has_active_filter && ui.button("Reset").clicked() {
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
    }

    fn render_bulk_bar(&mut self, ui: &mut egui::Ui) {
        let busy = self.is_busy();

        ui.horizontal(|ui| {
            ui.strong(format!("{} selected", self.selected_keys.len()));
            ui.separator();

            ui.add_enabled_ui(!busy, |ui| {
                ui.label("TTL");
                let resp = ui
                    .add(egui::TextEdit::singleline(&mut self.bulk_ttl_input).desired_width(78.0));
                let enter_pressed =
                    resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if ui.button("Set TTL").clicked() || enter_pressed {
                    match self.bulk_ttl_input.trim().parse::<u32>() {
                        Ok(ttl) => {
                            if let Some(zone) = &mut self.zone {
                                match zone.set_ttl_bulk(&self.selected_keys, ttl) {
                                    Ok(_) => self.error_banner = None,
                                    Err(err) => self.error_banner = Some(err),
                                }
                            }
                        }
                        Err(_) => {
                            self.error_banner = Some("Invalid bulk TTL.".to_owned());
                        }
                    }
                }

                ui.separator();
                if ui.button("Delete Selected").clicked()
                    && let Some(zone) = &mut self.zone
                {
                    zone.delete_bulk_local(&self.selected_keys);
                }
                if ui.button("Revert Selected").clicked()
                    && let Some(zone) = &mut self.zone
                {
                    zone.revert_bulk(&self.selected_keys);
                }
            });

            if ui.button("Clear Selection").clicked() {
                self.selected_keys.clear();
            }
        });
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        if self.show_token_modal {
            let busy = self.is_busy();
            match render_token_modal(
                ctx,
                &mut self.token_input,
                &mut self.save_token_to_keyring,
                &mut self.token_source,
                self.connected,
                busy,
                &mut self.error_banner,
            ) {
                TokenModalAction::None => {}
                TokenModalAction::Connect(token_val) => {
                    self.busy_label = Some("Connecting...".to_owned());
                    self.backend
                        .send(BackendCommand::Connect { token: token_val });
                }
                TokenModalAction::ClearedKeyring => {
                    self.status_message = "Cleared saved token".to_owned();
                }
                TokenModalAction::Closed => {
                    self.show_token_modal = false;
                    self.token_input.clear();
                }
            }
        }

        if let (Some(mut modal), Some(zone)) = (self.editor_modal.take(), self.zone.as_mut()) {
            match render_editor_modal(ctx, &mut modal, zone) {
                EditorOutcome::KeepOpen => {
                    self.editor_modal = Some(modal);
                }
                EditorOutcome::Saved | EditorOutcome::Cancelled => {}
            }
        }

        if self.show_review_modal {
            if let Some(zone) = &self.zone {
                let domain = zone.domain.clone();
                let minimum_ttl = zone.minimum_ttl;
                match render_review_modal(ctx, zone, self.is_busy()) {
                    ReviewModalAction::None => {}
                    ReviewModalAction::Execute(ops) => {
                        self.busy_label = Some(format!("Applying ({})...", ops.len()));
                        self.error_banner = None;
                        self.backend.send(BackendCommand::ApplyChanges {
                            domain,
                            minimum_ttl,
                            ops,
                        });
                    }
                    ReviewModalAction::Cancel => {
                        self.show_review_modal = false;
                    }
                }
            } else {
                self.show_review_modal = false;
            }
        }

        if let Some(nav) = self.pending_navigation.clone() {
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
        self.render_modals(&ctx);
    }
}
