use std::collections::BTreeMap;

use eframe::egui::{self, RichText};

use crate::model::{DiffSummary, RrsetData, RrsetKey, ZoneState};
use crate::ui::theme::{color_added, color_deleted, color_modified};
use crate::zonefile::{ImportMode, ParsedZonefile, format_zonefile, parse_zonefile};

#[derive(Debug, Clone)]
pub struct ImportZoneModal {
    pub source_name: Option<String>,
    pub raw_text: String,
    pub mode: ImportMode,
    pub clamp_ttl: bool,
    pub dialog_open: bool,
    cache_dirty: bool,
    cached_preview: Option<Result<(ParsedZonefile, DiffSummary), String>>,
}

impl ImportZoneModal {
    pub fn new() -> Self {
        Self {
            source_name: None,
            raw_text: String::new(),
            mode: ImportMode::MergeUpdate,
            clamp_ttl: true,
            dialog_open: false,
            cache_dirty: false,
            cached_preview: None,
        }
    }

    pub fn set_file_content(&mut self, filename: String, content: String) {
        self.source_name = Some(filename);
        self.raw_text = content;
        self.dialog_open = false;
        self.cache_dirty = true;
    }

    fn ensure_preview(&mut self, zone: &ZoneState) {
        if !self.cache_dirty {
            return;
        }
        self.cache_dirty = false;

        if self.raw_text.trim().is_empty() {
            self.cached_preview = None;
            return;
        }

        let res = parse_zonefile(
            &self.raw_text,
            &zone.domain,
            zone.minimum_ttl,
            self.clamp_ttl,
        )
        .map(|parsed| {
            let diff = zone.preview_import(&parsed.rrsets, self.mode);
            (parsed, diff)
        });
        self.cached_preview = Some(res);
    }
}

pub enum ImportModalAction {
    None,
    PickFile,
    Confirm {
        rrsets: BTreeMap<RrsetKey, RrsetData>,
        mode: ImportMode,
    },
    Cancel,
}

pub fn render_import_modal(
    ctx: &egui::Context,
    modal: &mut ImportZoneModal,
    zone: &ZoneState,
) -> ImportModalAction {
    if !modal.dialog_open && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return ImportModalAction::Cancel;
    }

    modal.ensure_preview(zone);

    let mut action = ImportModalAction::None;

    egui::Window::new(format!("Import Zonefile — {}", zone.domain))
        .collapsible(false)
        .resizable(true)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(680.0)
        .min_width(540.0)
        .show(ctx, |ui| {
            ui.set_min_width(ui.available_width());

            ui.add_enabled_ui(!modal.dialog_open, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Choose File...").clicked() {
                        modal.dialog_open = true;
                        action = ImportModalAction::PickFile;
                    }
                    if !modal.raw_text.is_empty() && ui.button("Clear").clicked() {
                        modal.raw_text.clear();
                        modal.source_name = None;
                        modal.cache_dirty = true;
                    }
                    if let Some(name) = &modal.source_name {
                        ui.label(RichText::new(name).monospace().weak());
                    } else {
                        ui.label(
                            RichText::new("Select a BIND zonefile or paste records below.").weak(),
                        );
                    }
                });

                ui.add_space(4.0);

                egui::ScrollArea::vertical()
                    .id_salt("import_zonefile_editor_scroll")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        let resp = ui.add(
                            egui::TextEdit::multiline(&mut modal.raw_text)
                                .code_editor()
                                .desired_rows(11)
                                .desired_width(f32::INFINITY)
                                .hint_text("$TTL 3600\n@   IN A     192.0.2.1\nwww IN CNAME @"),
                        );
                        if resp.changed() {
                            modal.cache_dirty = true;
                        }
                    });

                ui.add_space(6.0);
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    for candidate in [
                        ImportMode::MergeUpdate,
                        ImportMode::MergeAppend,
                        ImportMode::Replace,
                    ] {
                        if ui
                            .radio_value(&mut modal.mode, candidate, candidate.label())
                            .changed()
                        {
                            modal.cache_dirty = true;
                        }
                    }
                });

                ui.label(RichText::new(modal.mode.description()).small().weak());

                ui.add_space(4.0);
                if ui
                    .checkbox(
                        &mut modal.clamp_ttl,
                        format!("Clamp TTLs below domain minimum ({}s)", zone.minimum_ttl),
                    )
                    .changed()
                {
                    modal.cache_dirty = true;
                }
            });

            modal.ensure_preview(zone);

            if let Some(preview) = &modal.cached_preview {
                ui.add_space(6.0);
                ui.separator();
                render_import_preview(ui, preview, modal.mode);
            }

            ui.add_space(6.0);
            ui.separator();

            let can_import = !modal.dialog_open
                && matches!(
                    &modal.cached_preview,
                    Some(Ok((parsed, _)))
                        if !parsed.rrsets.is_empty() || modal.mode == ImportMode::Replace
                );

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_import, egui::Button::new("Stage Import"))
                    .clicked()
                    && let Some(Ok((parsed, _))) = &modal.cached_preview
                {
                    action = ImportModalAction::Confirm {
                        rrsets: parsed.rrsets.clone(),
                        mode: modal.mode,
                    };
                }
                if ui
                    .add_enabled(!modal.dialog_open, egui::Button::new("Cancel"))
                    .clicked()
                {
                    action = ImportModalAction::Cancel;
                }
                if modal.dialog_open {
                    ui.spinner();
                    ui.label("Waiting for file dialog...");
                }
            });
        });

    action
}

fn render_import_preview(
    ui: &mut egui::Ui,
    preview: &Result<(ParsedZonefile, DiffSummary), String>,
    mode: ImportMode,
) {
    match preview {
        Err(err) => {
            ui.label(RichText::new(err).color(color_deleted(ui)));
        }
        Ok((parsed, diff)) => {
            ui.horizontal_wrapped(|ui| {
                ui.strong(format!(
                    "Parsed {} RRsets ({} records)",
                    parsed.rrsets.len(),
                    parsed.record_count
                ));
                ui.separator();

                if diff.is_empty() {
                    ui.label(RichText::new("No changes to local zone").weak());
                } else {
                    ui.label("Local impact:");
                    if diff.added > 0 {
                        ui.label(
                            RichText::new(format!("+{} added", diff.added))
                                .color(color_added(ui))
                                .strong(),
                        );
                    }
                    if diff.modified > 0 {
                        ui.label(
                            RichText::new(format!("~{} modified", diff.modified))
                                .color(color_modified(ui))
                                .strong(),
                        );
                    }
                    if diff.deleted > 0 {
                        ui.label(
                            RichText::new(format!("-{} deleted", diff.deleted))
                                .color(color_deleted(ui))
                                .strong(),
                        );
                    }
                }
            });

            if mode == ImportMode::Replace && diff.deleted > 0 {
                ui.label(
                    RichText::new(format!(
                        "Replace mode will mark {} existing RRset(s) for deletion (staged locally until Apply).",
                        diff.deleted
                    ))
                    .color(color_deleted(ui))
                    .small(),
                );
            }

            if !parsed.warnings.is_empty() {
                ui.add_space(4.0);
                for warning in &parsed.warnings {
                    ui.label(
                        RichText::new(format!("Note: {warning}"))
                            .color(color_modified(ui))
                            .small(),
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportSource {
    Local,
    Server,
}

#[derive(Debug, Clone)]
pub struct ExportZoneModal {
    pub domain: String,
    pub source: ExportSource,
    pub local_content: String,
    pub has_local_changes: bool,
    pub server_content: Option<String>,
    pub loading_server: bool,
    pub server_error: Option<String>,
    pub dialog_open: bool,
    pub copied_notice: bool,
}

impl ExportZoneModal {
    pub fn from_zone(zone: &ZoneState) -> Self {
        let default_ttl = zone.minimum_ttl.max(3600);
        let local_content = format_zonefile(&zone.domain, default_ttl, &zone.local);
        Self {
            domain: zone.domain.clone(),
            source: ExportSource::Local,
            local_content,
            has_local_changes: zone.is_dirty(),
            server_content: None,
            loading_server: false,
            server_error: None,
            dialog_open: false,
            copied_notice: false,
        }
    }

    pub fn active_content(&self) -> Option<&str> {
        match self.source {
            ExportSource::Local => Some(&self.local_content),
            ExportSource::Server => self.server_content.as_deref(),
        }
    }
}

pub enum ExportModalAction {
    None,
    FetchServerZonefile,
    SaveFile {
        default_name: String,
        content: String,
    },
    Close,
}

pub fn render_export_modal(ctx: &egui::Context, modal: &mut ExportZoneModal) -> ExportModalAction {
    if !modal.dialog_open && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        return ExportModalAction::Close;
    }

    let mut action = ExportModalAction::None;

    egui::Window::new(format!("Export Zonefile — {}", modal.domain))
        .collapsible(false)
        .resizable(true)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(680.0)
        .min_width(540.0)
        .show(ctx, |ui| {
            ui.set_min_width(ui.available_width());

            ui.add_enabled_ui(!modal.dialog_open, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Source:");
                    if ui
                        .radio_value(&mut modal.source, ExportSource::Local, "Local Zone")
                        .changed()
                    {
                        modal.copied_notice = false;
                    }
                    if ui
                        .radio_value(&mut modal.source, ExportSource::Server, "deSEC Server")
                        .changed()
                    {
                        modal.copied_notice = false;
                        if modal.server_content.is_none() && !modal.loading_server {
                            modal.loading_server = true;
                            modal.server_error = None;
                            action = ExportModalAction::FetchServerZonefile;
                        }
                    }

                    if modal.source == ExportSource::Server
                        && !modal.loading_server
                        && ui.button("Refresh").clicked()
                    {
                        modal.loading_server = true;
                        modal.server_error = None;
                        modal.copied_notice = false;
                        action = ExportModalAction::FetchServerZonefile;
                    }
                });
            });

            match modal.source {
                ExportSource::Local => {
                    if modal.has_local_changes {
                        ui.label(
                            RichText::new(
                                "Reflects your current local working copy (includes unapplied changes).",
                            )
                            .color(color_modified(ui))
                            .small(),
                        );
                    } else {
                        ui.label(
                            RichText::new(
                                "Generated locally from the synced RRsets (no API request).",
                            )
                            .small()
                            .weak(),
                        );
                    }
                }
                ExportSource::Server => {
                    ui.label(
                        RichText::new(
                            "Official zonefile from deSEC (authoritative remote state, includes SOA & apex NS).",
                        )
                        .small()
                        .weak(),
                    );
                }
            }

            ui.add_space(6.0);

            if modal.source == ExportSource::Server && modal.loading_server {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Fetching zonefile from deSEC...");
                });
            } else if modal.source == ExportSource::Server
                && let Some(err) = &modal.server_error
            {
                ui.label(RichText::new(err).color(color_deleted(ui)));
            } else if let Some(content) = modal.active_content() {
                egui::ScrollArea::vertical()
                    .id_salt("export_zonefile_preview_scroll")
                    .max_height(300.0)
                    .show(ui, |ui| {
                        let mut preview = content;
                        ui.add(
                            egui::TextEdit::multiline(&mut preview)
                                .code_editor()
                                .desired_rows(15)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }

            ui.add_space(6.0);
            ui.separator();

            let has_content = modal.active_content().is_some();

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        has_content && !modal.dialog_open && !modal.loading_server,
                        egui::Button::new("Save to File..."),
                    )
                    .clicked()
                    && let Some(content) = modal.active_content().map(str::to_owned)
                {
                    modal.dialog_open = true;
                    action = ExportModalAction::SaveFile {
                        default_name: format!("{}.zone", modal.domain),
                        content,
                    };
                }

                if ui
                    .add_enabled(
                        has_content && !modal.dialog_open && !modal.loading_server,
                        egui::Button::new("Copy to Clipboard"),
                    )
                    .clicked()
                    && let Some(content) = modal.active_content()
                {
                    ctx.copy_text(content.to_owned());
                    modal.copied_notice = true;
                }

                if ui
                    .add_enabled(!modal.dialog_open, egui::Button::new("Close"))
                    .clicked()
                {
                    action = ExportModalAction::Close;
                }

                if modal.dialog_open {
                    ui.spinner();
                    ui.label("Waiting for save dialog...");
                } else if modal.copied_notice {
                    ui.label(RichText::new("Copied!").color(color_added(ui)));
                }
            });
        });

    action
}
