use std::collections::BTreeSet;

use eframe::egui::{self, RichText};

use crate::backend::{BackendCommand, BackendEvent, BackendHandle};
use crate::model::{DomainSummary, RrsetKey, ZoneRow, ZoneState};
use crate::token::{self, AccountSource, StoredAccount, StoredAccounts};
use crate::ui::accounts_modal::{
    AccountListItem, AccountsModal, AccountsModalAction, render_accounts_modal,
};
use crate::ui::editor_modal::{EditorOutcome, RecordEditorModal, render_editor_modal};
use crate::ui::modals::{ReviewModalAction, render_about_modal, render_review_modal};
use crate::ui::theme::{color_added, color_deleted, color_modified};
use crate::ui::zone_table::render_zone_table;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Failed,
}

impl ConnectionState {
    fn tag(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connecting => "Connecting...",
            Self::Connected => "Connected",
            Self::Failed => "Error",
        }
    }
}

struct AccountTab {
    id: String,
    label: String,
    email: Option<String>,
    custom_label: bool,
    source: AccountSource,
    /// Kept in memory for `Session`/`Env` accounts; `Keyring` accounts read lazily on connect.
    ephemeral_token: Option<String>,

    connection: ConnectionState,
    busy_label: Option<String>,
    status_message: String,
    error_banner: Option<String>,

    domains: Vec<DomainSummary>,
    selected_domain: Option<String>,
    zone: Option<ZoneState>,

    search_query: String,
    type_filter: String,
    changes_only: bool,
    selected_keys: BTreeSet<RrsetKey>,
    bulk_ttl_input: String,
}

impl AccountTab {
    fn from_stored(stored: StoredAccount) -> Self {
        Self {
            id: stored.id,
            label: stored.label,
            email: stored.email,
            custom_label: stored.custom_label,
            source: AccountSource::Keyring,
            ephemeral_token: None,
            connection: ConnectionState::Idle,
            busy_label: None,
            status_message: "Click to connect".to_owned(),
            error_banner: None,
            domains: Vec::new(),
            selected_domain: None,
            zone: None,
            search_query: String::new(),
            type_filter: "All".to_owned(),
            changes_only: false,
            selected_keys: BTreeSet::new(),
            bulk_ttl_input: "3600".to_owned(),
        }
    }

    fn from_env(token: String) -> Self {
        Self {
            id: "env".to_owned(),
            label: "DESEC_TOKEN".to_owned(),
            email: None,
            custom_label: false,
            source: AccountSource::Env,
            ephemeral_token: Some(token),
            connection: ConnectionState::Idle,
            busy_label: None,
            status_message: "Click to connect".to_owned(),
            error_banner: None,
            domains: Vec::new(),
            selected_domain: None,
            zone: None,
            search_query: String::new(),
            type_filter: "All".to_owned(),
            changes_only: false,
            selected_keys: BTreeSet::new(),
            bulk_ttl_input: "3600".to_owned(),
        }
    }

    fn is_busy(&self) -> bool {
        self.busy_label.is_some()
    }

    fn is_connected(&self) -> bool {
        self.connection == ConnectionState::Connected
    }

    fn is_dirty(&self) -> bool {
        self.zone.as_ref().is_some_and(ZoneState::is_dirty)
    }

    fn pending_changes(&self) -> usize {
        self.zone.as_ref().map_or(0, |z| z.summary().total())
    }

    fn domain_min_ttl(&self, name: &str) -> u32 {
        self.domains
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.minimum_ttl)
            .unwrap_or(3600)
    }
}

struct PendingAddAccount {
    id: String,
    token: String,
    custom_label: Option<String>,
    save_to_keyring: bool,
}

#[derive(Debug, Clone)]
enum PendingAction {
    RefreshZone(String),
    SwitchDomain { account_id: String, domain: String },
    RemoveAccount(String),
}

pub struct DesecApp {
    backend: BackendHandle,
    tabs: Vec<AccountTab>,
    active_account_id: Option<String>,
    pending_add: Option<PendingAddAccount>,

    accounts_modal: Option<AccountsModal>,
    editor_modal: Option<RecordEditorModal>,
    show_review_modal: bool,
    show_about_modal: bool,
    pending_action: Option<PendingAction>,
}

impl DesecApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Work around an integer underflow in egui/epaint 0.37.0's new IME preedit underline renderer.
        cc.egui_ctx.all_styles_mut(|style| {
            style.visuals.ime_composition.legacy_visuals = true;
        });

        let backend = BackendHandle::spawn(cc.egui_ctx.clone());
        let stored = token::load_accounts();
        let initial_active = stored.resolved_active_id().map(str::to_owned);

        let mut tabs: Vec<AccountTab> = stored
            .accounts
            .into_iter()
            .map(AccountTab::from_stored)
            .collect();

        if let Some(env_token) = token::load_env_token() {
            let already_saved = tabs.iter().any(|t| {
                token::load_account_secret(&t.id)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(env_token.as_str())
            });
            if !already_saved {
                tabs.push(AccountTab::from_env(env_token));
            }
        }

        let active_account_id = initial_active.or_else(|| tabs.first().map(|t| t.id.clone()));
        let accounts_modal = tabs.is_empty().then(AccountsModal::new);

        let mut app = Self {
            backend,
            tabs,
            active_account_id: active_account_id.clone(),
            pending_add: None,
            accounts_modal,
            editor_modal: None,
            show_review_modal: false,
            show_about_modal: false,
            pending_action: None,
        };

        // Connect only the last active account on startup; other tabs stay idle until clicked.
        if let Some(id) = active_account_id {
            app.connect_tab(&id);
        }

        app
    }

    fn has_open_modal(&self) -> bool {
        self.accounts_modal.is_some()
            || self.editor_modal.is_some()
            || self.show_review_modal
            || self.show_about_modal
            || self.pending_action.is_some()
    }

    fn active_tab(&self) -> Option<&AccountTab> {
        let id = self.active_account_id.as_deref()?;
        self.tabs.iter().find(|t| t.id == id)
    }

    fn active_tab_mut(&mut self) -> Option<&mut AccountTab> {
        let id = self.active_account_id.as_deref()?;
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    fn tab_mut(&mut self, id: &str) -> Option<&mut AccountTab> {
        self.tabs.iter_mut().find(|t| t.id == id)
    }

    fn is_active_blocked(&self) -> bool {
        self.has_open_modal() || self.active_tab().is_some_and(AccountTab::is_busy)
    }

    fn persist_keyring_index(&self) -> Result<(), String> {
        let accounts: Vec<StoredAccount> = self
            .tabs
            .iter()
            .filter(|t| t.source == AccountSource::Keyring)
            .map(|t| StoredAccount {
                id: t.id.clone(),
                label: t.label.clone(),
                email: t.email.clone(),
                custom_label: t.custom_label,
            })
            .collect();

        let active_id = self
            .active_account_id
            .as_ref()
            .filter(|id| accounts.iter().any(|a| &a.id == *id))
            .cloned();

        token::save_accounts(&StoredAccounts {
            active_id,
            accounts,
        })
    }

    fn activate_tab(&mut self, id: &str) {
        if !self.tabs.iter().any(|t| t.id == id) {
            return;
        }
        self.active_account_id = Some(id.to_owned());
        let _ = self.persist_keyring_index();

        let needs_connect = self.tabs.iter().any(|t| {
            t.id == id && matches!(t.connection, ConnectionState::Idle | ConnectionState::Failed)
        });
        if needs_connect {
            self.connect_tab(id);
        }
    }

    fn connect_tab(&mut self, id: &str) {
        let Some(tab) = self.tab_mut(id) else {
            return;
        };

        let secret = match tab.source {
            AccountSource::Keyring => match token::load_account_secret(id) {
                Ok(Some(secret)) => secret,
                Ok(None) => {
                    tab.connection = ConnectionState::Failed;
                    tab.error_banner =
                        Some("Saved token missing from keyring. Re-add this account.".to_owned());
                    tab.status_message = "Missing keyring token".to_owned();
                    return;
                }
                Err(err) => {
                    tab.connection = ConnectionState::Failed;
                    tab.error_banner = Some(err);
                    tab.status_message = "Keyring error".to_owned();
                    return;
                }
            },
            AccountSource::Session | AccountSource::Env => match &tab.ephemeral_token {
                Some(secret) => secret.clone(),
                None => {
                    tab.connection = ConnectionState::Failed;
                    tab.error_banner = Some("Session token unavailable.".to_owned());
                    return;
                }
            },
        };

        tab.connection = ConnectionState::Connecting;
        tab.busy_label = Some("Connecting...".to_owned());
        tab.status_message = format!("Connecting ({})...", tab.source.label());
        tab.error_banner = None;

        self.backend.send(BackendCommand::Connect {
            account_id: id.to_owned(),
            token: secret,
        });
    }

    fn find_existing_account_for_token(&self, candidate: &str) -> Option<String> {
        for tab in &self.tabs {
            if tab.ephemeral_token.as_deref() == Some(candidate) {
                return Some(tab.id.clone());
            }
            if tab.source == AccountSource::Keyring
                && token::load_account_secret(&tab.id)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(candidate)
            {
                return Some(tab.id.clone());
            }
        }
        None
    }

    fn start_add_account(
        &mut self,
        token_val: String,
        custom_label: Option<String>,
        save_to_keyring: bool,
    ) {
        if let Some(existing_id) = self.find_existing_account_for_token(&token_val) {
            self.accounts_modal = None;
            self.activate_tab(&existing_id);
            if let Some(tab) = self.tab_mut(&existing_id) {
                tab.status_message = "Already added — switched to existing account".to_owned();
            }
            return;
        }

        let account_id = token::generate_account_id();
        self.pending_add = Some(PendingAddAccount {
            id: account_id.clone(),
            token: token_val.clone(),
            custom_label,
            save_to_keyring,
        });

        if let Some(modal) = &mut self.accounts_modal {
            modal.connecting = true;
            modal.error = None;
        }

        self.backend.send(BackendCommand::Connect {
            account_id,
            token: token_val,
        });
    }

    fn request_fetch_zone(&mut self, account_id: &str, domain: String) {
        let Some(tab) = self.tab_mut(account_id) else {
            return;
        };
        let minimum_ttl = tab.domain_min_ttl(&domain);
        tab.selected_domain = Some(domain.clone());
        tab.selected_keys.clear();
        tab.busy_label = Some(format!("Loading {domain}..."));
        tab.status_message = format!("Fetching {domain}...");
        tab.error_banner = None;

        self.backend.send(BackendCommand::FetchZone {
            account_id: account_id.to_owned(),
            domain,
            minimum_ttl,
        });
    }

    fn request_action(&mut self, action: PendingAction) {
        let dirty = match &action {
            PendingAction::RefreshZone(id)
            | PendingAction::SwitchDomain { account_id: id, .. }
            | PendingAction::RemoveAccount(id) => {
                self.tabs.iter().any(|t| &t.id == id && t.is_dirty())
            }
        };

        if dirty {
            self.pending_action = Some(action);
        } else {
            self.execute_action(action);
        }
    }

    fn execute_action(&mut self, action: PendingAction) {
        match action {
            PendingAction::RefreshZone(account_id) => {
                let selected = self
                    .tabs
                    .iter()
                    .find(|t| t.id == account_id)
                    .and_then(|t| t.selected_domain.clone());

                if let Some(domain) = selected {
                    self.request_fetch_zone(&account_id, domain);
                } else if let Some(tab) = self.tab_mut(&account_id)
                    && tab.is_connected()
                {
                    tab.busy_label = Some("Loading...".to_owned());
                    self.backend.send(BackendCommand::FetchDomains { account_id });
                }
            }
            PendingAction::SwitchDomain { account_id, domain } => {
                self.request_fetch_zone(&account_id, domain);
            }
            PendingAction::RemoveAccount(account_id) => {
                self.remove_account_now(&account_id);
            }
        }
    }

    fn remove_account_now(&mut self, account_id: &str) {
        let Some(pos) = self.tabs.iter().position(|t| t.id == account_id) else {
            return;
        };
        let removed = self.tabs.remove(pos);

        self.backend.send(BackendCommand::Disconnect {
            account_id: removed.id.clone(),
        });

        let mut keyring_err = None;
        if removed.source == AccountSource::Keyring {
            if let Err(err) = token::delete_account_secret(&removed.id) {
                keyring_err = Some(err);
            }
            if let Err(err) = self.persist_keyring_index() {
                keyring_err = keyring_err.or(Some(err));
            }
        }

        if self.active_account_id.as_deref() == Some(account_id) {
            let next_id = self
                .tabs
                .get(pos)
                .or_else(|| pos.checked_sub(1).and_then(|p| self.tabs.get(p)))
                .map(|t| t.id.clone());

            self.active_account_id = next_id.clone();
            self.editor_modal = None;
            self.show_review_modal = false;

            if let Some(next_id) = next_id {
                self.activate_tab(&next_id);
            } else {
                self.accounts_modal = Some(AccountsModal::new());
            }
        }

        if let Some(err) = keyring_err {
            if let Some(modal) = &mut self.accounts_modal {
                modal.error = Some(err);
            } else if let Some(tab) = self.active_tab_mut() {
                tab.error_banner = Some(err);
            }
        }
    }

    fn rename_account(&mut self, account_id: &str, new_label: String) {
        let is_keyring = if let Some(tab) = self.tab_mut(account_id) {
            tab.label = new_label;
            tab.custom_label = true;
            tab.source == AccountSource::Keyring
        } else {
            return;
        };

        if is_keyring && let Err(err) = self.persist_keyring_index() {
            if let Some(modal) = &mut self.accounts_modal {
                modal.error = Some(err);
            } else if let Some(tab) = self.active_tab_mut() {
                tab.error_banner = Some(err);
            }
        }
    }

    fn handle_backend_events(&mut self) {
        while let Some(event) = self.backend.try_recv() {
            match event {
                BackendEvent::Connected {
                    account_id,
                    email,
                    domains,
                } => self.on_connected(account_id, email, domains),

                BackendEvent::DomainsLoaded {
                    account_id,
                    domains,
                } => {
                    if let Some(tab) = self.tab_mut(&account_id) {
                        tab.domains = domains;
                        tab.busy_label = None;
                        tab.status_message = format!("{} domains", tab.domains.len());
                    }
                }

                BackendEvent::ZoneLoaded {
                    account_id,
                    domain,
                    minimum_ttl,
                    rrsets,
                } => {
                    let is_active = self.active_account_id.as_deref() == Some(account_id.as_str());
                    if let Some(tab) = self.tab_mut(&account_id) {
                        let count = rrsets.len();
                        tab.zone =
                            Some(ZoneState::from_remote(domain.clone(), minimum_ttl, rrsets));
                        tab.selected_domain = Some(domain.clone());
                        tab.selected_keys.clear();
                        tab.bulk_ttl_input = minimum_ttl.max(3600).to_string();
                        tab.busy_label = None;
                        tab.status_message = format!("{domain} ({count} RRsets)");
                    }
                    if is_active {
                        self.show_review_modal = false;
                        self.editor_modal = None;
                    }
                }

                BackendEvent::ChangesApplied {
                    account_id,
                    domain,
                    minimum_ttl,
                    applied_count,
                    rrsets,
                } => {
                    let is_active = self.active_account_id.as_deref() == Some(account_id.as_str());
                    if let Some(tab) = self.tab_mut(&account_id) {
                        let count = rrsets.len();
                        tab.zone =
                            Some(ZoneState::from_remote(domain.clone(), minimum_ttl, rrsets));
                        tab.selected_keys.clear();
                        tab.busy_label = None;
                        tab.error_banner = None;
                        tab.status_message =
                            format!("Applied {applied_count} to {domain} ({count} RRsets)");
                    }
                    if is_active {
                        self.show_review_modal = false;
                    }
                }

                BackendEvent::Error {
                    account_id,
                    context,
                    message,
                } => {
                    if self
                        .pending_add
                        .as_ref()
                        .is_some_and(|p| p.id == account_id)
                    {
                        self.pending_add = None;
                        if let Some(modal) = &mut self.accounts_modal {
                            modal.connecting = false;
                            modal.error = Some(message);
                        }
                        continue;
                    }

                    if let Some(tab) = self.tab_mut(&account_id) {
                        tab.busy_label = None;
                        if tab.connection == ConnectionState::Connecting {
                            tab.connection = ConnectionState::Failed;
                        }
                        tab.error_banner = Some(format!("{context}: {message}"));
                        tab.status_message = format!("{context} failed");
                    }
                }
            }
        }
    }

    fn on_connected(
        &mut self,
        account_id: String,
        email: Option<String>,
        domains: Vec<DomainSummary>,
    ) {
        if self
            .pending_add
            .as_ref()
            .is_some_and(|p| p.id == account_id)
        {
            let pending = self.pending_add.take().expect("checked above");
            let fallback_idx = self.tabs.len() + 1;
            let (label, custom_label) = match pending.custom_label {
                Some(custom) => (custom, true),
                None => (
                    email
                        .clone()
                        .unwrap_or_else(|| token::derive_fallback_label(&domains, fallback_idx)),
                    false,
                ),
            };

            let mut keyring_warning = None;
            let (source, ephemeral_token) = if pending.save_to_keyring {
                match token::save_account_secret(&pending.id, &pending.token) {
                    Ok(()) => (AccountSource::Keyring, None),
                    Err(err) => {
                        keyring_warning = Some(err);
                        (AccountSource::Session, Some(pending.token))
                    }
                }
            } else {
                (AccountSource::Session, Some(pending.token))
            };

            let first_domain = domains.first().map(|d| d.name.clone());
            let status_message = if domains.is_empty() {
                "No domains in account".to_owned()
            } else {
                format!("Connected ({} domains)", domains.len())
            };

            self.tabs.push(AccountTab {
                id: pending.id.clone(),
                label,
                email,
                custom_label,
                source,
                ephemeral_token,
                connection: ConnectionState::Connected,
                busy_label: None,
                status_message,
                error_banner: keyring_warning,
                domains,
                selected_domain: None,
                zone: None,
                search_query: String::new(),
                type_filter: "All".to_owned(),
                changes_only: false,
                selected_keys: BTreeSet::new(),
                bulk_ttl_input: "3600".to_owned(),
            });

            self.active_account_id = Some(pending.id.clone());
            self.accounts_modal = None;

            if source == AccountSource::Keyring
                && let Err(err) = self.persist_keyring_index()
                && let Some(tab) = self.tab_mut(&pending.id)
            {
                tab.error_banner = Some(err);
            }

            if let Some(domain) = first_domain {
                self.request_fetch_zone(&pending.id, domain);
            }
            return;
        }

        let tab_idx = self.tabs.iter().position(|t| t.id == account_id);
        let Some(idx) = tab_idx else {
            return;
        };

        let first_domain = domains.first().map(|d| d.name.clone());
        let mut persist_needed = false;
        let should_fetch_first = {
            let tab = &mut self.tabs[idx];
            tab.connection = ConnectionState::Connected;
            tab.busy_label = None;
            tab.error_banner = None;
            tab.domains = domains;

            if email.is_some() && tab.email != email {
                tab.email = email;
                persist_needed = tab.source == AccountSource::Keyring;
            }
            if !tab.custom_label {
                let detected = tab
                    .email
                    .clone()
                    .unwrap_or_else(|| token::derive_fallback_label(&tab.domains, idx + 1));
                if tab.label != detected {
                    tab.label = detected;
                    persist_needed = tab.source == AccountSource::Keyring;
                }
            }

            if first_domain.is_none() {
                tab.selected_domain = None;
                tab.zone = None;
                tab.status_message = "No domains in account".to_owned();
                false
            } else {
                tab.zone.is_none()
            }
        };

        if persist_needed {
            let _ = self.persist_keyring_index();
        }
        if should_fetch_first && let Some(domain) = first_domain {
            self.request_fetch_zone(&account_id, domain);
        }
    }

    fn render_account_tabs(&mut self, ui: &mut egui::Ui) {
        if self.tabs.is_empty() {
            return;
        }

        let modal_open = self.has_open_modal();
        let mut switch_to: Option<String> = None;
        let mut open_add = false;

        egui::Panel::top("account_tabs").show(ui, |ui| {
            ui.add_enabled_ui(!modal_open, |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("account_tabs_scroll")
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for tab in &self.tabs {
                                let is_active =
                                    self.active_account_id.as_deref() == Some(tab.id.as_str());
                                let pending = tab.pending_changes();

                                let display = if pending > 0 {
                                    format!("{} [{}]", tab.label, pending)
                                } else {
                                    tab.label.clone()
                                };

                                let mut rich = RichText::new(display);
                                if is_active {
                                    rich = rich.strong();
                                }
                                if pending > 0 {
                                    rich = rich.color(color_modified(ui));
                                } else if tab.connection == ConnectionState::Failed {
                                    rich = rich.color(color_deleted(ui));
                                } else if tab.connection == ConnectionState::Idle {
                                    rich = rich.weak();
                                }

                                let resp = ui.selectable_label(is_active, rich);
                                if resp.clicked() && !is_active {
                                    switch_to = Some(tab.id.clone());
                                }
                                resp.on_hover_ui(|ui| {
                                    if let Some(email) = &tab.email
                                        && email != &tab.label
                                    {
                                        ui.label(email);
                                    }
                                    ui.label(format!(
                                        "{} · {}",
                                        tab.source.label(),
                                        tab.connection.tag()
                                    ));
                                    if pending > 0 {
                                        ui.label(format!("{pending} pending change(s)"));
                                    }
                                });
                            }

                            if ui.button("+").on_hover_text("Add account").clicked() {
                                open_add = true;
                            }
                        });
                    });
            });
        });

        if let Some(id) = switch_to {
            self.activate_tab(&id);
        }
        if open_add {
            self.accounts_modal = Some(AccountsModal::new());
        }
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let blocked = self.is_active_blocked();
        let active_id = self.active_account_id.clone();

        let (connected, domains, selected_domain, summary, has_zone) = match self.active_tab() {
            Some(tab) => (
                tab.is_connected(),
                tab.domains.clone(),
                tab.selected_domain.clone(),
                tab.zone.as_ref().map(ZoneState::summary).unwrap_or_default(),
                tab.zone.is_some(),
            ),
            None => (false, Vec::new(), None, Default::default(), false),
        };

        let mut switched_to: Option<String> = None;
        let mut refresh_clicked = false;
        let mut discard_clicked = false;

        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Zone");

                let current_label = selected_domain.as_deref().unwrap_or("None").to_owned();

                ui.add_enabled_ui(connected && !blocked, |ui| {
                    egui::ComboBox::from_id_salt("domain_selector")
                        .selected_text(&current_label)
                        .width(260.0)
                        .show_ui(ui, |ui| {
                            for domain in &domains {
                                let selected =
                                    selected_domain.as_deref() == Some(domain.name.as_str());
                                if ui.selectable_label(selected, &domain.name).clicked()
                                    && !selected
                                {
                                    switched_to = Some(domain.name.clone());
                                }
                            }
                        });

                    if ui.button("Fetch").clicked() {
                        refresh_clicked = true;
                    }
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!blocked, egui::Button::new("About"))
                        .clicked()
                    {
                        self.show_about_modal = true;
                    }
                    if ui
                        .add_enabled(!blocked, egui::Button::new("Accounts"))
                        .clicked()
                    {
                        self.accounts_modal = Some(AccountsModal::new());
                    }

                    let dirty = !summary.is_empty();

                    ui.add_enabled_ui(dirty && !blocked, |ui| {
                        if ui.button("Apply").clicked() {
                            self.show_review_modal = true;
                        }
                        if ui.button("Discard").clicked() {
                            discard_clicked = true;
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
                    } else if has_zone {
                        ui.label("Synced");
                    }
                });
            });
        });

        if let Some(account_id) = active_id {
            if let Some(domain) = switched_to {
                self.request_action(PendingAction::SwitchDomain { account_id, domain });
            } else if refresh_clicked {
                self.request_action(PendingAction::RefreshZone(account_id));
            } else if discard_clicked
                && let Some(tab) = self.active_tab_mut()
                && let Some(zone) = &mut tab.zone
            {
                zone.discard_all();
            }
        }
    }

    fn render_bottom_bar(&mut self, ui: &mut egui::Ui) {
        let mut dismiss_error = false;
        let (error_banner, busy_label, status_message, min_ttl) = match self.active_tab() {
            Some(tab) => (
                tab.error_banner.clone(),
                tab.busy_label.clone(),
                tab.status_message.clone(),
                tab.zone.as_ref().map(|z| z.minimum_ttl),
            ),
            None => (None, None, "No account connected".to_owned(), None),
        };

        egui::Panel::bottom("bottom_bar").show(ui, |ui| {
            if let Some(err) = error_banner {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&err).color(color_deleted(ui)));
                    if ui.button("Dismiss").clicked() {
                        dismiss_error = true;
                    }
                });
                ui.separator();
            }

            ui.horizontal(|ui| {
                if let Some(busy) = busy_label {
                    ui.spinner();
                    ui.label(busy);
                } else {
                    ui.label(status_message);
                }

                if let Some(min_ttl) = min_ttl {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("Min TTL: {min_ttl}s"));
                    });
                }
            });
        });

        if dismiss_error && let Some(tab) = self.active_tab_mut() {
            tab.error_banner = None;
        }
    }

    fn render_zone_view(&mut self, ui: &mut egui::Ui) {
        let blocked = self.is_active_blocked();
        let mut open_editor: Option<RecordEditorModal> = None;
        let mut retry_account_id: Option<String> = None;

        egui::CentralPanel::default().show(ui, |ui| {
            let Some(tab) = self.active_tab_mut() else {
                ui.centered_and_justified(|ui| {
                    ui.label("No active account.");
                });
                return;
            };

            if !tab.is_connected() {
                ui.centered_and_justified(|ui| {
                    if tab.connection == ConnectionState::Failed {
                        ui.vertical_centered(|ui| {
                            ui.label("Failed to connect this account.");
                            ui.add_space(6.0);
                            if ui.button("Retry").clicked() {
                                retry_account_id = Some(tab.id.clone());
                            }
                        });
                    } else if tab.is_busy() {
                        ui.label("Connecting...");
                    } else {
                        ui.label("No active session.");
                    }
                });
                return;
            }

            let Some((available_types, default_ttl, all_rows)) = tab.zone.as_ref().map(|z| {
                (
                    z.available_record_types(),
                    z.minimum_ttl.max(3600),
                    z.rows(),
                )
            }) else {
                ui.centered_and_justified(|ui| {
                    let msg = if tab.is_busy() {
                        "Loading..."
                    } else {
                        "No zone selected."
                    };
                    ui.label(msg);
                });
                return;
            };

            let valid_keys: BTreeSet<RrsetKey> = all_rows.iter().map(|r| r.key.clone()).collect();
            tab.selected_keys.retain(|k| valid_keys.contains(k));

            if let Some(new_modal) =
                render_filter_bar(ui, tab, &available_types, default_ttl, blocked)
            {
                open_editor = Some(new_modal);
            }

            if !tab.selected_keys.is_empty() {
                ui.separator();
                render_bulk_bar(ui, tab, blocked);
            }

            ui.separator();

            let query_lower = tab.search_query.trim().to_ascii_lowercase();
            let rows: Vec<ZoneRow> = all_rows
                .into_iter()
                .filter(|row| row.matches_filter(&query_lower, &tab.type_filter, tab.changes_only))
                .collect();

            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No records.");
                });
                return;
            }

            let actions = render_zone_table(ui, &rows, &mut tab.selected_keys, blocked);

            if let Some(row) = actions.edit_row {
                open_editor = Some(RecordEditorModal::from_row(&row));
            }
            if let Some(key) = actions.delete_key
                && let Some(zone) = &mut tab.zone
            {
                zone.delete_local(&key);
            }
            if let Some(key) = actions.revert_key
                && let Some(zone) = &mut tab.zone
            {
                zone.revert_key(&key);
            }
        });

        if let Some(modal) = open_editor {
            self.editor_modal = Some(modal);
        }
        if let Some(id) = retry_account_id {
            self.connect_tab(&id);
        }
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        if self.pending_action.is_none()
            && let Some(mut modal) = self.accounts_modal.take()
        {
            let items: Vec<AccountListItem> = self
                .tabs
                .iter()
                .map(|tab| AccountListItem {
                    id: tab.id.clone(),
                    label: tab.label.clone(),
                    email: tab.email.clone(),
                    source: tab.source,
                    active: self.active_account_id.as_deref() == Some(tab.id.as_str()),
                    status_tag: tab.connection.tag(),
                    failed: tab.connection == ConnectionState::Failed,
                    pending_changes: tab.pending_changes(),
                })
                .collect();

            match render_accounts_modal(ctx, &mut modal, &items) {
                AccountsModalAction::None => {
                    self.accounts_modal = Some(modal);
                }
                AccountsModalAction::AddAccount {
                    token,
                    custom_label,
                    save_to_keyring,
                } => {
                    self.accounts_modal = Some(modal);
                    self.start_add_account(token, custom_label, save_to_keyring);
                }
                AccountsModalAction::SwitchAccount(id) => {
                    self.activate_tab(&id);
                }
                AccountsModalAction::ReconnectAccount(id) => {
                    self.activate_tab(&id);
                }
                AccountsModalAction::RenameAccount {
                    account_id,
                    new_label,
                } => {
                    self.accounts_modal = Some(modal);
                    self.rename_account(&account_id, new_label);
                }
                AccountsModalAction::RemoveAccount(id) => {
                    self.accounts_modal = Some(modal);
                    self.request_action(PendingAction::RemoveAccount(id));
                }
                AccountsModalAction::Close => {}
            }
        }

        if let Some(mut modal) = self.editor_modal.take()
            && let Some(tab) = self.active_tab_mut()
            && let Some(zone) = tab.zone.as_mut()
        {
            match render_editor_modal(ctx, &mut modal, zone) {
                EditorOutcome::KeepOpen => {
                    self.editor_modal = Some(modal);
                }
                EditorOutcome::Saved { old_key, new_key } => {
                    if let Some(old) = old_key
                        && old != new_key
                        && tab.selected_keys.remove(&old)
                    {
                        tab.selected_keys.insert(new_key);
                    }
                }
                EditorOutcome::Cancelled => {}
            }
        }

        if self.show_review_modal {
            let apply_request = if let Some(tab) = self.active_tab()
                && let Some(zone) = &tab.zone
            {
                match render_review_modal(ctx, zone, tab.is_busy()) {
                    ReviewModalAction::None => None,
                    ReviewModalAction::Execute(ops) => Some(Ok((
                        tab.id.clone(),
                        zone.domain.clone(),
                        zone.minimum_ttl,
                        ops,
                    ))),
                    ReviewModalAction::Cancel => Some(Err(())),
                }
            } else {
                Some(Err(()))
            };

            match apply_request {
                Some(Ok((account_id, domain, minimum_ttl, ops))) => {
                    if let Some(tab) = self.tab_mut(&account_id) {
                        tab.busy_label = Some(format!("Applying ({})...", ops.len()));
                        tab.error_banner = None;
                    }
                    self.backend.send(BackendCommand::ApplyChanges {
                        account_id,
                        domain,
                        minimum_ttl,
                        ops,
                    });
                }
                Some(Err(())) => {
                    self.show_review_modal = false;
                }
                None => {}
            }
        }

        if let Some(pending) = self.pending_action.clone() {
            let mut confirm = false;
            let mut cancel = ctx.input(|i| i.key_pressed(egui::Key::Escape));

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
                self.pending_action = None;
                self.execute_action(pending);
            } else if cancel {
                self.pending_action = None;
            }
        }

        if self.show_about_modal && render_about_modal(ctx) {
            self.show_about_modal = false;
        }
    }
}

fn render_filter_bar(
    ui: &mut egui::Ui,
    tab: &mut AccountTab,
    available_types: &[String],
    default_ttl: u32,
    blocked: bool,
) -> Option<RecordEditorModal> {
    let mut new_editor = None;

    ui.add_enabled_ui(!blocked, |ui| {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut tab.search_query)
                    .hint_text("Search")
                    .desired_width(240.0),
            );

            egui::ComboBox::from_id_salt("type_filter")
                .selected_text(&tab.type_filter)
                .width(115.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut tab.type_filter, "All".to_owned(), "All");
                    for rtype in available_types {
                        ui.selectable_value(&mut tab.type_filter, rtype.clone(), rtype);
                    }
                });

            ui.checkbox(&mut tab.changes_only, "Modified only");

            let has_active_filter =
                !tab.search_query.is_empty() || tab.type_filter != "All" || tab.changes_only;
            if has_active_filter && ui.button("Reset").clicked() {
                tab.search_query.clear();
                tab.type_filter = "All".to_owned();
                tab.changes_only = false;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("New Record").clicked() {
                    let initial_type =
                        (tab.type_filter != "All").then_some(tab.type_filter.as_str());
                    new_editor = Some(RecordEditorModal::new_empty(default_ttl, initial_type));
                }
            });
        });
    });

    new_editor
}

fn render_bulk_bar(ui: &mut egui::Ui, tab: &mut AccountTab, blocked: bool) {
    ui.add_enabled_ui(!blocked, |ui| {
        ui.horizontal(|ui| {
            ui.strong(format!("{} selected", tab.selected_keys.len()));
            ui.separator();

            ui.label("TTL");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut tab.bulk_ttl_input).desired_width(78.0),
            );
            let enter_pressed =
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            if ui.button("Set TTL").clicked() || enter_pressed {
                match tab.bulk_ttl_input.trim().parse::<u32>() {
                    Ok(ttl) => {
                        if let Some(zone) = &mut tab.zone {
                            match zone.set_ttl_bulk(&tab.selected_keys, ttl) {
                                Ok(_) => tab.error_banner = None,
                                Err(err) => tab.error_banner = Some(err),
                            }
                        }
                    }
                    Err(_) => {
                        tab.error_banner = Some("Invalid bulk TTL.".to_owned());
                    }
                }
            }

            ui.separator();
            if ui.button("Delete Selected").clicked()
                && let Some(zone) = &mut tab.zone
            {
                zone.delete_bulk_local(&tab.selected_keys);
            }
            if ui.button("Revert Selected").clicked()
                && let Some(zone) = &mut tab.zone
            {
                zone.revert_bulk(&tab.selected_keys);
            }

            if ui.button("Clear Selection").clicked() {
                tab.selected_keys.clear();
            }
        });
    });
}

impl eframe::App for DesecApp {
    fn logic(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_backend_events();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_account_tabs(ui);
        self.render_top_bar(ui);
        self.render_bottom_bar(ui);
        self.render_zone_view(ui);

        let ctx = ui.ctx().clone();
        self.render_modals(&ctx);
    }
}
