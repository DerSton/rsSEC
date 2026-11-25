use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, RichText};

use crate::backend::{BackendCommand, BackendEvent, BackendHandle};
use crate::model::{DomainSummary, RrsetKey, ZoneRow, ZoneState};
use crate::state::{AccountState, ConnectionState, DomainState};
use crate::token::{self, AccountSource, StoredAccount, StoredAccounts};
use crate::ui::accounts_modal::{
    AccountListItem, AccountsModal, AccountsModalAction, render_accounts_modal,
};
use crate::ui::editor_modal::{EditorOutcome, RecordEditorModal, render_editor_modal};
use crate::ui::modals::{ReviewModalAction, render_about_modal, render_review_modal};
use crate::ui::theme::{color_added, color_deleted, color_modified};
use crate::ui::zone_table::render_zone_table;

struct PendingAddAccount {
    id: String,
    token: String,
    custom_label: Option<String>,
    save_to_keyring: bool,
}

#[derive(Debug, Clone)]
enum ConfirmDiscard {
    RefreshDomain { account_id: String, domain: String },
    RemoveAccount(String),
    CloseApp,
}

pub struct DesecApp {
    backend: BackendHandle,
    accounts: Vec<AccountState>,
    active_account_id: Option<String>,
    pending_add: Option<PendingAddAccount>,

    accounts_modal: Option<AccountsModal>,
    editor_modal: Option<RecordEditorModal>,
    show_review_modal: bool,
    show_about_modal: bool,
    confirm_discard: Option<ConfirmDiscard>,
    allowed_to_close: bool,
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

        let mut accounts: Vec<AccountState> = stored
            .accounts
            .into_iter()
            .map(AccountState::from_stored)
            .collect();

        if let Some(env_token) = token::load_env_token() {
            let already_saved = accounts.iter().any(|acc| {
                token::load_account_secret(&acc.id)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(env_token.as_str())
            });
            if !already_saved {
                accounts.push(AccountState::from_env(env_token));
            }
        }

        let active_account_id = initial_active.or_else(|| accounts.first().map(|a| a.id.clone()));
        let accounts_modal = accounts.is_empty().then(AccountsModal::new);

        let mut app = Self {
            backend,
            accounts,
            active_account_id: active_account_id.clone(),
            pending_add: None,
            accounts_modal,
            editor_modal: None,
            show_review_modal: false,
            show_about_modal: false,
            confirm_discard: None,
            allowed_to_close: false,
        };

        // Connect only the last active account on startup; inactive tabs stay idle until clicked.
        if let Some(id) = active_account_id {
            app.connect_account(&id);
        }

        app
    }

    fn has_open_modal(&self) -> bool {
        self.accounts_modal.is_some()
            || self.editor_modal.is_some()
            || self.show_review_modal
            || self.show_about_modal
            || self.confirm_discard.is_some()
    }

    fn active_account(&self) -> Option<&AccountState> {
        let id = self.active_account_id.as_deref()?;
        self.accounts.iter().find(|a| a.id == id)
    }

    fn active_account_mut(&mut self) -> Option<&mut AccountState> {
        let id = self.active_account_id.as_deref()?;
        self.accounts.iter_mut().find(|a| a.id == id)
    }

    fn account_mut(&mut self, id: &str) -> Option<&mut AccountState> {
        self.accounts.iter_mut().find(|a| a.id == id)
    }

    fn is_active_view_blocked(&self) -> bool {
        self.has_open_modal() || self.active_account().is_some_and(AccountState::is_active_busy)
    }

    fn total_pending_changes(&self) -> (usize, usize) {
        let changes: usize = self.accounts.iter().map(AccountState::pending_changes).sum();
        let domains: usize = self
            .accounts
            .iter()
            .map(AccountState::dirty_domain_count)
            .sum();
        (changes, domains)
    }

    fn persist_keyring_index(&self) -> Result<(), String> {
        let accounts: Vec<StoredAccount> = self
            .accounts
            .iter()
            .filter(|a| a.source == AccountSource::Keyring)
            .map(|a| StoredAccount {
                id: a.id.clone(),
                label: a.label.clone(),
                email: a.email.clone(),
                custom_label: a.custom_label,
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

    fn activate_account(&mut self, id: &str) {
        if !self.accounts.iter().any(|a| a.id == id) {
            return;
        }
        self.active_account_id = Some(id.to_owned());
        let _ = self.persist_keyring_index();

        let needs_connect = self.accounts.iter().any(|a| {
            a.id == id && matches!(a.connection, ConnectionState::Idle | ConnectionState::Failed)
        });
        if needs_connect {
            self.connect_account(id);
        }
    }

    fn connect_account(&mut self, id: &str) {
        let Some(acc) = self.account_mut(id) else {
            return;
        };

        let secret = match acc.source {
            AccountSource::Keyring => match token::load_account_secret(id) {
                Ok(Some(secret)) => secret,
                Ok(None) => {
                    acc.connection = ConnectionState::Failed;
                    acc.error =
                        Some("Saved token missing from keyring. Re-add this account.".to_owned());
                    acc.status_message = "Missing keyring token".to_owned();
                    return;
                }
                Err(err) => {
                    acc.connection = ConnectionState::Failed;
                    acc.error = Some(err);
                    acc.status_message = "Keyring error".to_owned();
                    return;
                }
            },
            AccountSource::Session | AccountSource::Env => match &acc.ephemeral_token {
                Some(secret) => secret.clone(),
                None => {
                    acc.connection = ConnectionState::Failed;
                    acc.error = Some("Session token unavailable.".to_owned());
                    return;
                }
            },
        };

        acc.connection = ConnectionState::Connecting;
        acc.busy_label = Some("Connecting...".to_owned());
        acc.status_message = format!("Connecting ({})...", acc.source.label());
        acc.error = None;

        self.backend.send(BackendCommand::Connect {
            account_id: id.to_owned(),
            token: secret,
        });
    }

    fn find_existing_account_for_token(&self, candidate: &str) -> Option<String> {
        for acc in &self.accounts {
            if acc.ephemeral_token.as_deref() == Some(candidate) {
                return Some(acc.id.clone());
            }
            if acc.source == AccountSource::Keyring
                && token::load_account_secret(&acc.id)
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(candidate)
            {
                return Some(acc.id.clone());
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
            self.activate_account(&existing_id);
            if let Some(acc) = self.account_mut(&existing_id) {
                acc.status_message = "Already added — switched to existing account".to_owned();
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

    /// Switches to `domain` in RAM without losing edits/filters; fetches lazily if not yet loaded.
    fn select_domain(&mut self, account_id: &str, domain: String) {
        let should_fetch = {
            let Some(acc) = self.account_mut(account_id) else {
                return;
            };
            let Some(dom) = acc.domains.get(&domain) else {
                return;
            };
            let needs_fetch = dom.zone.is_none() && !dom.loading;
            acc.active_domain = Some(domain.clone());
            needs_fetch
        };

        if should_fetch {
            self.request_fetch_zone(account_id, &domain);
        }
    }

    fn request_fetch_zone(&mut self, account_id: &str, domain: &str) {
        let Some(acc) = self.account_mut(account_id) else {
            return;
        };
        let Some(dom) = acc.domains.get_mut(domain) else {
            return;
        };
        let minimum_ttl = dom.minimum_ttl;
        dom.loading = true;
        dom.busy_label = Some(format!("Loading {domain}..."));
        dom.status_message = format!("Fetching {domain}...");
        dom.error = None;

        self.backend.send(BackendCommand::FetchZone {
            account_id: account_id.to_owned(),
            domain: domain.to_owned(),
            minimum_ttl,
        });
    }

    fn request_refresh_active(&mut self, account_id: &str) {
        let active_dom = self
            .accounts
            .iter()
            .find(|a| a.id == account_id)
            .and_then(|a| a.active_domain().map(|d| (d.name.clone(), d.is_dirty())));

        match active_dom {
            Some((domain, true)) => {
                self.confirm_discard = Some(ConfirmDiscard::RefreshDomain {
                    account_id: account_id.to_owned(),
                    domain,
                });
            }
            Some((domain, false)) => {
                self.request_fetch_zone(account_id, &domain);
            }
            None => {
                if let Some(acc) = self.account_mut(account_id)
                    && acc.is_connected()
                {
                    acc.busy_label = Some("Loading domains...".to_owned());
                    acc.error = None;
                    self.backend.send(BackendCommand::FetchDomains {
                        account_id: account_id.to_owned(),
                    });
                }
            }
        }
    }

    fn request_remove_account(&mut self, account_id: String) {
        let dirty = self
            .accounts
            .iter()
            .any(|a| a.id == account_id && a.is_dirty());
        if dirty {
            self.confirm_discard = Some(ConfirmDiscard::RemoveAccount(account_id));
        } else {
            self.remove_account_now(&account_id);
        }
    }

    fn remove_account_now(&mut self, account_id: &str) {
        let Some(pos) = self.accounts.iter().position(|a| a.id == account_id) else {
            return;
        };
        let removed = self.accounts.remove(pos);

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
                .accounts
                .get(pos)
                .or_else(|| pos.checked_sub(1).and_then(|p| self.accounts.get(p)))
                .map(|a| a.id.clone());

            self.active_account_id = next_id.clone();
            self.editor_modal = None;
            self.show_review_modal = false;

            if let Some(next_id) = next_id {
                self.activate_account(&next_id);
            } else {
                self.accounts_modal = Some(AccountsModal::new());
            }
        }

        if let Some(err) = keyring_err {
            if let Some(modal) = &mut self.accounts_modal {
                modal.error = Some(err);
            } else if let Some(acc) = self.active_account_mut() {
                acc.error = Some(err);
            }
        }
    }

    fn rename_account(&mut self, account_id: &str, new_label: String) {
        let is_keyring = if let Some(acc) = self.account_mut(account_id) {
            acc.label = new_label;
            acc.custom_label = true;
            acc.source == AccountSource::Keyring
        } else {
            return;
        };

        if is_keyring && let Err(err) = self.persist_keyring_index() {
            if let Some(modal) = &mut self.accounts_modal {
                modal.error = Some(err);
            } else if let Some(acc) = self.active_account_mut() {
                acc.error = Some(err);
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
                    let fetch_domain = if let Some(acc) = self.account_mut(&account_id) {
                        acc.busy_label = None;
                        acc.error = None;
                        acc.sync_domains(domains);
                        acc.status_message = if acc.domains.is_empty() {
                            "No domains in account".to_owned()
                        } else {
                            format!("{} domains", acc.domains.len())
                        };
                        acc.active_domain()
                            .filter(|d| d.zone.is_none() && !d.loading)
                            .map(|d| d.name.clone())
                    } else {
                        None
                    };
                    if let Some(domain) = fetch_domain {
                        self.request_fetch_zone(&account_id, &domain);
                    }
                }

                BackendEvent::ZoneLoaded {
                    account_id,
                    domain,
                    minimum_ttl,
                    rrsets,
                } => {
                    let count = rrsets.len();
                    let is_active_view = self.is_active_domain(&account_id, &domain);
                    if let Some(acc) = self.account_mut(&account_id)
                        && let Some(dom) = acc.domains.get_mut(&domain)
                    {
                        dom.apply_loaded_zone(
                            minimum_ttl,
                            rrsets,
                            format!("{domain} ({count} RRsets)"),
                        );
                    }
                    if is_active_view {
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
                    let count = rrsets.len();
                    let is_active_view = self.is_active_domain(&account_id, &domain);
                    if let Some(acc) = self.account_mut(&account_id)
                        && let Some(dom) = acc.domains.get_mut(&domain)
                    {
                        dom.apply_loaded_zone(
                            minimum_ttl,
                            rrsets,
                            format!("Applied {applied_count} to {domain} ({count} RRsets)"),
                        );
                    }
                    if is_active_view {
                        self.show_review_modal = false;
                    }
                }

                BackendEvent::Error {
                    account_id,
                    domain,
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

                    if let Some(acc) = self.account_mut(&account_id) {
                        if let Some(domain_name) = domain
                            && let Some(dom) = acc.domains.get_mut(&domain_name)
                        {
                            dom.loading = false;
                            dom.busy_label = None;
                            dom.error = Some(format!("{context}: {message}"));
                            dom.status_message = format!("{context} failed");
                        } else {
                            acc.busy_label = None;
                            if acc.connection == ConnectionState::Connecting {
                                acc.connection = ConnectionState::Failed;
                            }
                            acc.error = Some(format!("{context}: {message}"));
                            acc.status_message = format!("{context} failed");
                        }
                    }
                }
            }
        }
    }

    fn is_active_domain(&self, account_id: &str, domain: &str) -> bool {
        self.active_account_id.as_deref() == Some(account_id)
            && self
                .active_account()
                .and_then(|a| a.active_domain.as_deref())
                == Some(domain)
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
            let fallback_idx = self.accounts.len() + 1;
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

            let status_message = if domains.is_empty() {
                "No domains in account".to_owned()
            } else {
                format!("Connected ({} domains)", domains.len())
            };

            let mut acc = AccountState {
                id: pending.id.clone(),
                label,
                email,
                custom_label,
                source,
                ephemeral_token,
                connection: ConnectionState::Connected,
                busy_label: None,
                status_message,
                error: keyring_warning,
                domains: BTreeMap::new(),
                active_domain: None,
            };
            acc.sync_domains(domains);
            let first_domain = acc.active_domain.clone();

            self.accounts.push(acc);
            self.active_account_id = Some(pending.id.clone());
            self.accounts_modal = None;

            if source == AccountSource::Keyring
                && let Err(err) = self.persist_keyring_index()
                && let Some(acc) = self.account_mut(&pending.id)
            {
                acc.error = Some(err);
            }

            if let Some(domain) = first_domain {
                self.request_fetch_zone(&pending.id, &domain);
            }
            return;
        }

        let Some(idx) = self.accounts.iter().position(|a| a.id == account_id) else {
            return;
        };

        let mut persist_needed = false;
        let fetch_domain = {
            let acc = &mut self.accounts[idx];
            acc.connection = ConnectionState::Connected;
            acc.busy_label = None;
            acc.error = None;
            acc.sync_domains(domains);

            if email.is_some() && acc.email != email {
                acc.email = email;
                persist_needed = acc.source == AccountSource::Keyring;
            }
            if !acc.custom_label {
                let summaries: Vec<DomainSummary> = acc
                    .domains
                    .values()
                    .map(|d| DomainSummary {
                        name: d.name.clone(),
                        minimum_ttl: d.minimum_ttl,
                    })
                    .collect();
                let detected = acc
                    .email
                    .clone()
                    .unwrap_or_else(|| token::derive_fallback_label(&summaries, idx + 1));
                if acc.label != detected {
                    acc.label = detected;
                    persist_needed = acc.source == AccountSource::Keyring;
                }
            }

            if acc.domains.is_empty() {
                acc.status_message = "No domains in account".to_owned();
                None
            } else {
                acc.status_message = format!("Connected ({} domains)", acc.domains.len());
                acc.active_domain()
                    .filter(|d| d.zone.is_none() && !d.loading)
                    .map(|d| d.name.clone())
            }
        };

        if persist_needed {
            let _ = self.persist_keyring_index();
        }
        if let Some(domain) = fetch_domain {
            self.request_fetch_zone(&account_id, &domain);
        }
    }

    fn render_account_tabs(&mut self, ui: &mut egui::Ui) {
        if self.accounts.is_empty() {
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
                            for acc in &self.accounts {
                                let is_active =
                                    self.active_account_id.as_deref() == Some(acc.id.as_str());
                                let pending = acc.pending_changes();
                                let dirty_domains = acc.dirty_domain_count();

                                let display = if pending > 0 {
                                    format!("{} [{}]", acc.label, pending)
                                } else {
                                    acc.label.clone()
                                };

                                let mut rich = RichText::new(display);
                                if is_active {
                                    rich = rich.strong();
                                }
                                if pending > 0 {
                                    rich = rich.color(color_modified(ui));
                                } else if acc.connection == ConnectionState::Failed {
                                    rich = rich.color(color_deleted(ui));
                                } else if acc.connection == ConnectionState::Idle {
                                    rich = rich.weak();
                                }

                                let resp = ui.selectable_label(is_active, rich);
                                if resp.clicked() && !is_active {
                                    switch_to = Some(acc.id.clone());
                                }
                                resp.on_hover_ui(|ui| {
                                    if let Some(email) = &acc.email
                                        && email != &acc.label
                                    {
                                        ui.label(email);
                                    }
                                    ui.label(format!(
                                        "{} · {}",
                                        acc.source.label(),
                                        acc.connection.tag()
                                    ));
                                    if pending > 0 {
                                        ui.label(format!(
                                            "{pending} pending change(s) in {dirty_domains} domain(s)"
                                        ));
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
            self.activate_account(&id);
        }
        if open_add {
            self.accounts_modal = Some(AccountsModal::new());
        }
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui) {
        let modal_open = self.has_open_modal();
        let active_id = self.active_account_id.clone();

        let (connected, account_busy, domain_items, active_domain, active_loading, summary, has_zone) =
            match self.active_account() {
                Some(acc) => {
                    let items: Vec<(String, usize)> = acc
                        .domains
                        .values()
                        .map(|d| (d.name.clone(), d.pending_changes()))
                        .collect();
                    let active_dom = acc.active_domain();
                    let summary = active_dom
                        .and_then(|d| d.zone.as_ref())
                        .map(ZoneState::summary)
                        .unwrap_or_default();
                    (
                        acc.is_connected(),
                        acc.is_account_busy(),
                        items,
                        acc.active_domain.clone(),
                        active_dom.is_some_and(|d| d.loading),
                        summary,
                        active_dom.is_some_and(|d| d.zone.is_some()),
                    )
                }
                None => (false, false, Vec::new(), None, false, Default::default(), false),
            };

        let can_switch_domain = connected && !modal_open && !account_busy;
        let can_act_on_zone = can_switch_domain && !active_loading;

        let mut switched_to: Option<String> = None;
        let mut refresh_clicked = false;
        let mut discard_clicked = false;

        egui::Panel::top("top_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Zone");

                let current_label = active_domain.as_deref().unwrap_or("None").to_owned();

                ui.add_enabled_ui(can_switch_domain, |ui| {
                    egui::ComboBox::from_id_salt("domain_selector")
                        .selected_text(&current_label)
                        .width(260.0)
                        .show_ui(ui, |ui| {
                            for (name, pending) in &domain_items {
                                let selected = active_domain.as_deref() == Some(name.as_str());
                                let label = if *pending > 0 {
                                    RichText::new(format!("{name} [{pending}]"))
                                        .color(color_modified(ui))
                                } else {
                                    RichText::new(name)
                                };
                                if ui.selectable_label(selected, label).clicked() && !selected {
                                    switched_to = Some(name.clone());
                                }
                            }
                        });
                });

                if ui
                    .add_enabled(can_act_on_zone, egui::Button::new("Fetch"))
                    .clicked()
                {
                    refresh_clicked = true;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(!modal_open, egui::Button::new("About"))
                        .clicked()
                    {
                        self.show_about_modal = true;
                    }
                    if ui
                        .add_enabled(!modal_open, egui::Button::new("Accounts"))
                        .clicked()
                    {
                        self.accounts_modal = Some(AccountsModal::new());
                    }

                    let dirty = !summary.is_empty();

                    ui.add_enabled_ui(dirty && can_act_on_zone, |ui| {
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
                self.select_domain(&account_id, domain);
            } else if refresh_clicked {
                self.request_refresh_active(&account_id);
            } else if discard_clicked
                && let Some(acc) = self.active_account_mut()
                && let Some(dom) = acc.active_domain_mut()
                && let Some(zone) = &mut dom.zone
            {
                zone.discard_all();
            }
        }
    }

    fn render_bottom_bar(&mut self, ui: &mut egui::Ui) {
        let mut dismiss_error = false;
        let (error_banner, busy_label, status_message, min_ttl) = match self.active_account() {
            Some(acc) => {
                let dom = acc.active_domain();
                let error = dom
                    .and_then(|d| d.error.clone())
                    .or_else(|| acc.error.clone());
                let busy = acc
                    .busy_label
                    .clone()
                    .or_else(|| dom.and_then(|d| d.busy_label.clone()));
                let status = if acc.is_connected()
                    && let Some(dom) = dom
                {
                    dom.status_message.clone()
                } else {
                    acc.status_message.clone()
                };
                let min_ttl = dom.and_then(|d| d.zone.as_ref()).map(|z| z.minimum_ttl);
                (error, busy, status, min_ttl)
            }
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

        if dismiss_error && let Some(acc) = self.active_account_mut() {
            if let Some(dom) = acc.active_domain_mut()
                && dom.error.is_some()
            {
                dom.error = None;
            } else {
                acc.error = None;
            }
        }
    }

    fn render_zone_view(&mut self, ui: &mut egui::Ui) {
        let blocked = self.is_active_view_blocked();
        let mut open_editor: Option<RecordEditorModal> = None;
        let mut retry_account_id: Option<String> = None;
        let mut retry_domain: Option<(String, String)> = None;

        egui::CentralPanel::default().show(ui, |ui| {
            let Some(acc) = self.active_account_mut() else {
                ui.centered_and_justified(|ui| {
                    ui.label("No active account.");
                });
                return;
            };

            if !acc.is_connected() {
                ui.centered_and_justified(|ui| {
                    if acc.connection == ConnectionState::Failed {
                        ui.vertical_centered(|ui| {
                            ui.label("Failed to connect this account.");
                            ui.add_space(6.0);
                            if ui.button("Retry").clicked() {
                                retry_account_id = Some(acc.id.clone());
                            }
                        });
                    } else if acc.is_account_busy() {
                        ui.label("Connecting...");
                    } else {
                        ui.label("No active session.");
                    }
                });
                return;
            }

            let acc_id = acc.id.clone();
            let Some(dom) = acc.active_domain_mut() else {
                ui.centered_and_justified(|ui| {
                    ui.label("No zone selected.");
                });
                return;
            };

            let Some((available_types, default_ttl, all_rows)) = dom.zone.as_ref().map(|z| {
                (
                    z.available_record_types(),
                    z.minimum_ttl.max(3600),
                    z.rows(),
                )
            }) else {
                ui.centered_and_justified(|ui| {
                    if dom.loading {
                        ui.label("Loading...");
                    } else if dom.error.is_some() {
                        ui.vertical_centered(|ui| {
                            ui.label(format!("Failed to load {}.", dom.name));
                            ui.add_space(6.0);
                            if ui.button("Retry").clicked() {
                                retry_domain = Some((acc_id, dom.name.clone()));
                            }
                        });
                    } else {
                        ui.label("No zone loaded.");
                    }
                });
                return;
            };

            let valid_keys: BTreeSet<RrsetKey> = all_rows.iter().map(|r| r.key.clone()).collect();
            dom.selected_keys.retain(|k| valid_keys.contains(k));

            if let Some(new_modal) =
                render_filter_bar(ui, dom, &available_types, default_ttl, blocked)
            {
                open_editor = Some(new_modal);
            }

            if !dom.selected_keys.is_empty() {
                ui.separator();
                render_bulk_bar(ui, dom, blocked);
            }

            ui.separator();

            let query_lower = dom.search_query.trim().to_ascii_lowercase();
            let rows: Vec<ZoneRow> = all_rows
                .into_iter()
                .filter(|row| row.matches_filter(&query_lower, &dom.type_filter, dom.changes_only))
                .collect();

            if rows.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No records.");
                });
                return;
            }

            let actions = render_zone_table(ui, &rows, &mut dom.selected_keys, blocked);

            if let Some(row) = actions.edit_row {
                open_editor = Some(RecordEditorModal::from_row(&row));
            }
            if let Some(key) = actions.delete_key
                && let Some(zone) = &mut dom.zone
            {
                zone.delete_local(&key);
            }
            if let Some(key) = actions.revert_key
                && let Some(zone) = &mut dom.zone
            {
                zone.revert_key(&key);
            }
        });

        if let Some(modal) = open_editor {
            self.editor_modal = Some(modal);
        }
        if let Some(id) = retry_account_id {
            self.connect_account(&id);
        }
        if let Some((acc_id, domain)) = retry_domain {
            self.request_fetch_zone(&acc_id, &domain);
        }
    }

    fn render_modals(&mut self, ctx: &egui::Context) {
        if self.confirm_discard.is_none()
            && let Some(mut modal) = self.accounts_modal.take()
        {
            let items: Vec<AccountListItem> = self
                .accounts
                .iter()
                .map(|acc| AccountListItem {
                    id: acc.id.clone(),
                    label: acc.label.clone(),
                    email: acc.email.clone(),
                    source: acc.source,
                    active: self.active_account_id.as_deref() == Some(acc.id.as_str()),
                    status_tag: acc.connection.tag(),
                    failed: acc.connection == ConnectionState::Failed,
                    pending_changes: acc.pending_changes(),
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
                AccountsModalAction::SwitchAccount(id)
                | AccountsModalAction::ReconnectAccount(id) => {
                    self.activate_account(&id);
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
                    self.request_remove_account(id);
                }
                AccountsModalAction::Close => {}
            }
        }

        if self.confirm_discard.is_none()
            && let Some(mut modal) = self.editor_modal.take()
            && let Some(acc) = self.active_account_mut()
            && let Some(dom) = acc.active_domain_mut()
            && let Some(zone) = dom.zone.as_mut()
        {
            match render_editor_modal(ctx, &mut modal, zone) {
                EditorOutcome::KeepOpen => {
                    self.editor_modal = Some(modal);
                }
                EditorOutcome::Saved { old_key, new_key } => {
                    if let Some(old) = old_key
                        && old != new_key
                        && dom.selected_keys.remove(&old)
                    {
                        dom.selected_keys.insert(new_key);
                    }
                }
                EditorOutcome::Cancelled => {}
            }
        }

        if self.confirm_discard.is_none() && self.show_review_modal {
            let apply_request = if let Some(acc) = self.active_account()
                && let Some(dom) = acc.active_domain()
                && let Some(zone) = &dom.zone
            {
                match render_review_modal(ctx, zone, dom.loading) {
                    ReviewModalAction::None => None,
                    ReviewModalAction::Execute(ops) => Some(Ok((
                        acc.id.clone(),
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
                    if let Some(acc) = self.account_mut(&account_id)
                        && let Some(dom) = acc.domains.get_mut(&domain)
                    {
                        dom.loading = true;
                        dom.busy_label = Some(format!("Applying ({})...", ops.len()));
                        dom.error = None;
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

        if let Some(pending) = self.confirm_discard.clone() {
            let mut confirm = false;
            let mut cancel = ctx.input(|i| i.key_pressed(egui::Key::Escape));

            let (message, confirm_label) = match &pending {
                ConfirmDiscard::RefreshDomain { domain, .. } => (
                    format!("Unapplied changes in {domain} will be lost."),
                    "Discard",
                ),
                ConfirmDiscard::RemoveAccount(id) => {
                    let label = self
                        .accounts
                        .iter()
                        .find(|a| &a.id == id)
                        .map_or("this account", |a| a.label.as_str());
                    (
                        format!("Unapplied changes in {label} will be lost."),
                        "Discard",
                    )
                }
                ConfirmDiscard::CloseApp => {
                    let (changes, domains) = self.total_pending_changes();
                    (
                        format!(
                            "{changes} unapplied change(s) in {domains} domain(s) will be lost."
                        ),
                        "Discard & Quit",
                    )
                }
            };

            egui::Window::new("Discard Local Changes?")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .default_width(340.0)
                .show(ctx, |ui| {
                    ui.label(message);
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if ui.button(confirm_label).clicked() {
                            confirm = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });

            if confirm {
                self.confirm_discard = None;
                match pending {
                    ConfirmDiscard::RefreshDomain { account_id, domain } => {
                        self.request_fetch_zone(&account_id, &domain);
                    }
                    ConfirmDiscard::RemoveAccount(account_id) => {
                        self.remove_account_now(&account_id);
                    }
                    ConfirmDiscard::CloseApp => {
                        self.allowed_to_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            } else if cancel {
                self.confirm_discard = None;
            }
        }

        if self.confirm_discard.is_none() && self.show_about_modal && render_about_modal(ctx) {
            self.show_about_modal = false;
        }
    }
}

fn render_filter_bar(
    ui: &mut egui::Ui,
    dom: &mut DomainState,
    available_types: &[String],
    default_ttl: u32,
    blocked: bool,
) -> Option<RecordEditorModal> {
    let mut new_editor = None;

    ui.add_enabled_ui(!blocked, |ui| {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut dom.search_query)
                    .hint_text("Search")
                    .desired_width(240.0),
            );

            egui::ComboBox::from_id_salt("type_filter")
                .selected_text(&dom.type_filter)
                .width(115.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut dom.type_filter, "All".to_owned(), "All");
                    for rtype in available_types {
                        ui.selectable_value(&mut dom.type_filter, rtype.clone(), rtype);
                    }
                });

            ui.checkbox(&mut dom.changes_only, "Modified only");

            let has_active_filter =
                !dom.search_query.is_empty() || dom.type_filter != "All" || dom.changes_only;
            if has_active_filter && ui.button("Reset").clicked() {
                dom.search_query.clear();
                dom.type_filter = "All".to_owned();
                dom.changes_only = false;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("New Record").clicked() {
                    let initial_type =
                        (dom.type_filter != "All").then_some(dom.type_filter.as_str());
                    new_editor = Some(RecordEditorModal::new_empty(default_ttl, initial_type));
                }
            });
        });
    });

    new_editor
}

fn render_bulk_bar(ui: &mut egui::Ui, dom: &mut DomainState, blocked: bool) {
    ui.add_enabled_ui(!blocked, |ui| {
        ui.horizontal(|ui| {
            ui.strong(format!("{} selected", dom.selected_keys.len()));
            ui.separator();

            ui.label("TTL");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut dom.bulk_ttl_input).desired_width(78.0),
            );
            let enter_pressed =
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            if ui.button("Set TTL").clicked() || enter_pressed {
                match dom.bulk_ttl_input.trim().parse::<u32>() {
                    Ok(ttl) => {
                        if let Some(zone) = &mut dom.zone {
                            match zone.set_ttl_bulk(&dom.selected_keys, ttl) {
                                Ok(_) => dom.error = None,
                                Err(err) => dom.error = Some(err),
                            }
                        }
                    }
                    Err(_) => {
                        dom.error = Some("Invalid bulk TTL.".to_owned());
                    }
                }
            }

            ui.separator();
            if ui.button("Delete Selected").clicked()
                && let Some(zone) = &mut dom.zone
            {
                zone.delete_bulk_local(&dom.selected_keys);
            }
            if ui.button("Revert Selected").clicked()
                && let Some(zone) = &mut dom.zone
            {
                zone.revert_bulk(&dom.selected_keys);
            }

            if ui.button("Clear Selection").clicked() {
                dom.selected_keys.clear();
            }
        });
    });
}

impl eframe::App for DesecApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_backend_events();

        if ctx.input(|i| i.viewport().close_requested())
            && !self.allowed_to_close
            && self.total_pending_changes().0 > 0
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.confirm_discard = Some(ConfirmDiscard::CloseApp);
        }
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
