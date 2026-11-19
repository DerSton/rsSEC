use std::collections::BTreeSet;

use eframe::egui::{self, RichText};

use crate::model::{DiffOp, ZoneState};
use crate::token::{self, TokenSource};
use crate::ui::theme::{color_added, color_deleted, color_modified};

pub enum TokenModalAction {
    None,
    Connect(String),
    ClearedKeyring,
    Closed,
}

pub fn render_token_modal(
    ctx: &egui::Context,
    token_input: &mut String,
    save_to_keyring: &mut bool,
    token_source: &mut Option<TokenSource>,
    connected: bool,
    busy: bool,
    error_banner: &mut Option<String>,
) -> TokenModalAction {
    if connected && !busy && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return TokenModalAction::Closed;
    }

    let mut action = TokenModalAction::None;

    egui::Window::new("API Token")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(360.0)
        .show(ctx, |ui| {
            let response = ui.add(
                egui::TextEdit::singleline(token_input)
                    .password(true)
                    .hint_text("deSEC token")
                    .desired_width(f32::INFINITY),
            );
            let enter_pressed =
                response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            ui.checkbox(save_to_keyring, "Save to keyring");
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                let can_connect = !token_input.trim().is_empty() && !busy;
                if ui
                    .add_enabled(can_connect, egui::Button::new("Connect"))
                    .clicked()
                    || (enter_pressed && can_connect)
                {
                    let token_val = token_input.trim().to_owned();
                    if *save_to_keyring {
                        match token::save_token(&token_val) {
                            Ok(()) => *token_source = Some(TokenSource::Keyring),
                            Err(err) => *error_banner = Some(err),
                        }
                    }
                    action = TokenModalAction::Connect(token_val);
                }

                if ui.button("Clear Keyring").clicked() {
                    match token::delete_token() {
                        Ok(()) => {
                            if *token_source == Some(TokenSource::Keyring) {
                                *token_source = None;
                            }
                            action = TokenModalAction::ClearedKeyring;
                        }
                        Err(err) => *error_banner = Some(err),
                    }
                }

                if connected && ui.button("Close").clicked() {
                    action = TokenModalAction::Closed;
                }
            });
        });

    action
}

pub enum ReviewModalAction {
    None,
    Execute(Vec<DiffOp>),
    Cancel,
}

pub fn render_review_modal(ctx: &egui::Context, zone: &ZoneState, busy: bool) -> ReviewModalAction {
    if !busy && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return ReviewModalAction::Cancel;
    }

    let ops = zone.diff();
    if ops.is_empty() {
        return ReviewModalAction::Cancel;
    }

    let mut action = ReviewModalAction::None;

    egui::Window::new(format!("Apply Changes ({})", ops.len()))
        .collapsible(false)
        .resizable(true)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(600.0)
        .default_height(380.0)
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .show(ui, |ui| {
                    for op in &ops {
                        ui.group(|ui| {
                            let header_color = match op {
                                DiffOp::Create { .. } => color_added(ui),
                                DiffOp::Update { .. } => color_modified(ui),
                                DiffOp::Delete { .. } => color_deleted(ui),
                            };
                            ui.label(
                                RichText::new(format!(
                                    "{}  {}  {}",
                                    op.kind_label(),
                                    op.key().display_subname(),
                                    op.key().rtype
                                ))
                                .color(header_color)
                                .strong(),
                            );

                            match op {
                                DiffOp::Create { data, .. } => {
                                    ui.label(
                                        RichText::new(format!("TTL {}", data.ttl))
                                            .color(color_added(ui)),
                                    );
                                    for r in &data.records {
                                        ui.label(
                                            RichText::new(format!("+ {r}"))
                                                .monospace()
                                                .color(color_added(ui)),
                                        );
                                    }
                                }
                                DiffOp::Update { old, new, .. } => {
                                    if old.ttl != new.ttl {
                                        ui.label(
                                            RichText::new(format!(
                                                "TTL {} -> {}",
                                                old.ttl, new.ttl
                                            ))
                                            .color(color_modified(ui)),
                                        );
                                    } else {
                                        ui.label(format!("TTL {}", new.ttl));
                                    }

                                    let old_set: BTreeSet<&str> =
                                        old.records.iter().map(String::as_str).collect();
                                    let new_set: BTreeSet<&str> =
                                        new.records.iter().map(String::as_str).collect();

                                    for r in &old.records {
                                        if !new_set.contains(r.as_str()) {
                                            ui.label(
                                                RichText::new(format!("- {r}"))
                                                    .monospace()
                                                    .color(color_deleted(ui))
                                                    .strikethrough(),
                                            );
                                        }
                                    }
                                    for r in &new.records {
                                        if old_set.contains(r.as_str()) {
                                            ui.monospace(format!("  {r}"));
                                        } else {
                                            ui.label(
                                                RichText::new(format!("+ {r}"))
                                                    .monospace()
                                                    .color(color_added(ui)),
                                            );
                                        }
                                    }
                                }
                                DiffOp::Delete { old, .. } => {
                                    ui.label(
                                        RichText::new(format!("TTL {}", old.ttl))
                                            .color(color_deleted(ui)),
                                    );
                                    for r in &old.records {
                                        ui.label(
                                            RichText::new(format!("- {r}"))
                                                .monospace()
                                                .color(color_deleted(ui))
                                                .strikethrough(),
                                        );
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
                        action = ReviewModalAction::Execute(ops.clone());
                    }
                    if ui.button("Cancel").clicked() {
                        action = ReviewModalAction::Cancel;
                    }
                });
            });
        });

    action
}

/// Returns `true` when the About modal should be closed.
pub fn render_about_modal(ctx: &egui::Context) -> bool {
    let mut close = ctx.input(|i| i.key_pressed(egui::Key::Escape));

    egui::Window::new("About")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(360.0)
        .show(ctx, |ui| {
            ui.heading("rsSEC");
            let version = option_env!("APP_VERSION").unwrap_or("dev");
            ui.monospace(format!("{} {version}", env!("CARGO_PKG_NAME")));

            ui.add_space(6.0);
            ui.label(env!("CARGO_PKG_DESCRIPTION"));
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.label("License:");
                ui.monospace(env!("CARGO_PKG_LICENSE"));
            });
            ui.horizontal(|ui| {
                ui.label("Repository:");
                ui.hyperlink(env!("CARGO_PKG_REPOSITORY"));
            });

            ui.separator();
            if ui.button("Close").clicked() {
                close = true;
            }
        });

    close
}
