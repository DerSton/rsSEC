use eframe::egui::{self, RichText};

use crate::token::{AccountSource, scrub_secret};
use crate::ui::theme::{color_deleted, color_modified};

#[derive(Debug, Clone)]
pub struct AccountListItem {
    pub id: String,
    pub label: String,
    pub email: Option<String>,
    pub source: AccountSource,
    pub active: bool,
    pub status_tag: &'static str,
    pub failed: bool,
    pub pending_changes: usize,
}

#[derive(Debug, Clone)]
pub struct AccountsModal {
    pub token_input: String,
    pub label_input: String,
    pub save_to_keyring: bool,
    pub connecting: bool,
    pub error: Option<String>,
    editing: Option<(String, String)>,
}

impl AccountsModal {
    pub fn new() -> Self {
        Self {
            token_input: String::new(),
            label_input: String::new(),
            save_to_keyring: true,
            connecting: false,
            error: None,
            editing: None,
        }
    }
}

impl Drop for AccountsModal {
    fn drop(&mut self) {
        scrub_secret(&mut self.token_input);
    }
}

pub enum AccountsModalAction {
    None,
    AddAccount {
        token: String,
        custom_label: Option<String>,
        save_to_keyring: bool,
    },
    SwitchAccount(String),
    ReconnectAccount(String),
    RenameAccount {
        account_id: String,
        new_label: String,
    },
    RemoveAccount(String),
    Close,
}

pub fn render_accounts_modal(
    ctx: &egui::Context,
    modal: &mut AccountsModal,
    accounts: &[AccountListItem],
    blocked: bool,
) -> AccountsModalAction {
    let busy = modal.connecting || blocked;
    let can_close = !accounts.is_empty() && !busy;
    if can_close && modal.editing.is_none() && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return AccountsModalAction::Close;
    }

    let mut action = AccountsModalAction::None;
    let title = if accounts.is_empty() {
        "Connect Account"
    } else {
        "Accounts"
    };

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.set_min_width(420.0);

            ui.add_enabled_ui(!busy, |ui| {
                let token_resp = ui.add(
                    egui::TextEdit::singleline(&mut modal.token_input)
                        .password(true)
                        .hint_text("Paste deSEC API token")
                        .desired_width(f32::INFINITY),
                );
                let label_resp = ui.add(
                    egui::TextEdit::singleline(&mut modal.label_input)
                        .hint_text("Label (optional, auto-detected)")
                        .desired_width(f32::INFINITY),
                );

                let enter_pressed = (token_resp.lost_focus() || label_resp.lost_focus())
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut modal.save_to_keyring, "Save to keyring");

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if can_close && ui.button("Close").clicked() {
                            action = AccountsModalAction::Close;
                        }

                        let can_submit = !modal.token_input.trim().is_empty();
                        let submit_label = if accounts.is_empty() {
                            "Connect"
                        } else {
                            "Add"
                        };
                        if ui
                            .add_enabled(can_submit, egui::Button::new(submit_label))
                            .clicked()
                            || (enter_pressed && can_submit)
                        {
                            let token = modal.token_input.trim().to_owned();
                            let custom_label = {
                                let trimmed = modal.label_input.trim();
                                (!trimmed.is_empty()).then(|| trimmed.to_owned())
                            };
                            action = AccountsModalAction::AddAccount {
                                token,
                                custom_label,
                                save_to_keyring: modal.save_to_keyring,
                            };
                        }
                    });
                });
            });

            if modal.connecting {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting...");
                });
            } else if let Some(err) = &modal.error {
                ui.add_space(4.0);
                ui.label(RichText::new(err).color(color_deleted(ui)));
            }

            if !accounts.is_empty() {
                ui.add_space(6.0);
                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        ui.add_enabled_ui(!blocked, |ui| {
                            for item in accounts {
                                render_account_row(ui, modal, item, &mut action);
                                ui.add_space(2.0);
                            }
                        });
                    });
            }
        });

    action
}

fn render_account_row(
    ui: &mut egui::Ui,
    modal: &mut AccountsModal,
    item: &AccountListItem,
    action: &mut AccountsModalAction,
) {
    let is_editing = modal
        .editing
        .as_ref()
        .is_some_and(|(id, _)| id == &item.id);

    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(ui.available_width());

        if is_editing {
            let mut commit = false;
            let mut cancel = ui.input(|i| i.key_pressed(egui::Key::Escape));

            ui.horizontal(|ui| {
                if let Some((_, draft)) = &mut modal.editing {
                    let resp = ui.add(
                        egui::TextEdit::singleline(draft)
                            .desired_width((ui.available_width() - 120.0).max(120.0)),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        commit = true;
                    }
                }
                if ui.button("Save").clicked() {
                    commit = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });

            if commit && let Some((id, draft)) = modal.editing.take() {
                let trimmed = draft.trim().to_owned();
                if !trimmed.is_empty() {
                    *action = AccountsModalAction::RenameAccount {
                        account_id: id,
                        new_label: trimmed,
                    };
                }
            } else if cancel {
                modal.editing = None;
            }
            return;
        }

        ui.horizontal(|ui| {
            let label_text = if item.active {
                RichText::new(&item.label).strong()
            } else {
                RichText::new(&item.label)
            };

            if ui.selectable_label(item.active, label_text).clicked() && !item.active {
                *action = AccountsModalAction::SwitchAccount(item.id.clone());
            }

            if item.pending_changes > 0 {
                ui.label(
                    RichText::new(format!("[{}]", item.pending_changes))
                        .color(color_modified(ui))
                        .strong(),
                );
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_enabled_ui(!modal.connecting, |ui| {
                    if ui.button("Remove").clicked() {
                        *action = AccountsModalAction::RemoveAccount(item.id.clone());
                    }
                    if ui.button("Rename").clicked() {
                        modal.editing = Some((item.id.clone(), item.label.clone()));
                    }
                    if item.failed && ui.button("Retry").clicked() {
                        *action = AccountsModalAction::ReconnectAccount(item.id.clone());
                    }
                });
            });
        });

        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} · {}", item.source.label(), item.status_tag))
                    .small()
                    .weak(),
            );
            if let Some(email) = &item.email
                && email != &item.label
            {
                ui.label(RichText::new(format!("· {email}")).small().weak());
            }
        });
    });
}
