use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use desec::api::rrsets::{BulkPatch, Rrset};
use desec::{Client, Error as DesecError, RecordType, Subname};
use eframe::egui;

use crate::model::{DiffOp, DomainSummary, RrsetData, RrsetKey};

#[derive(Debug)]
pub enum BackendCommand {
    Connect {
        token: String,
    },
    FetchDomains,
    FetchZone {
        domain: String,
        minimum_ttl: u32,
    },
    ApplyChanges {
        domain: String,
        minimum_ttl: u32,
        ops: Vec<DiffOp>,
    },
}

#[derive(Debug)]
pub enum BackendEvent {
    Connected {
        domains: Vec<DomainSummary>,
    },
    DomainsLoaded {
        domains: Vec<DomainSummary>,
    },
    ZoneLoaded {
        domain: String,
        minimum_ttl: u32,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
    },
    ChangesApplied {
        domain: String,
        minimum_ttl: u32,
        applied_count: usize,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
    },
    Error {
        context: String,
        message: String,
    },
}

pub struct BackendHandle {
    cmd_tx: Sender<BackendCommand>,
    event_rx: Receiver<BackendEvent>,
}

impl BackendHandle {
    pub fn spawn(ctx: egui::Context) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<BackendCommand>();
        let (event_tx, event_rx) = mpsc::channel::<BackendEvent>();

        thread::Builder::new()
            .name("desec-backend".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("failed to create tokio runtime");

                runtime.block_on(worker_loop(cmd_rx, event_tx, ctx));
            })
            .expect("failed to spawn backend thread");

        Self { cmd_tx, event_rx }
    }

    pub fn send(&self, cmd: BackendCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    pub fn try_recv(&self) -> Option<BackendEvent> {
        self.event_rx.try_recv().ok()
    }
}

async fn worker_loop(
    cmd_rx: Receiver<BackendCommand>,
    event_tx: Sender<BackendEvent>,
    ctx: egui::Context,
) {
    let mut client: Option<Client> = None;

    while let Ok(cmd) = cmd_rx.recv() {
        let event = match cmd {
            BackendCommand::Connect { token } => match Client::new(token.trim()) {
                Ok(new_client) => match fetch_domains(&new_client).await {
                    Ok(domains) => {
                        client = Some(new_client);
                        BackendEvent::Connected { domains }
                    }
                    Err(err) => BackendEvent::Error {
                        context: "Connect".to_owned(),
                        message: format_desec_error(&err, None),
                    },
                },
                Err(err) => BackendEvent::Error {
                    context: "Connect".to_owned(),
                    message: err.to_string(),
                },
            },

            BackendCommand::FetchDomains => match &client {
                Some(c) => match fetch_domains(c).await {
                    Ok(domains) => BackendEvent::DomainsLoaded { domains },
                    Err(err) => BackendEvent::Error {
                        context: "Fetch domains".to_owned(),
                        message: format_desec_error(&err, None),
                    },
                },
                None => BackendEvent::Error {
                    context: "Fetch domains".to_owned(),
                    message: "Not connected. Configure an API token first.".to_owned(),
                },
            },

            BackendCommand::FetchZone {
                domain,
                minimum_ttl,
            } => match &client {
                Some(c) => match fetch_rrsets(c, &domain).await {
                    Ok(rrsets) => BackendEvent::ZoneLoaded {
                        domain,
                        minimum_ttl,
                        rrsets,
                    },
                    Err(err) => BackendEvent::Error {
                        context: format!("Fetch {domain}"),
                        message: format_desec_error(&err, None),
                    },
                },
                None => BackendEvent::Error {
                    context: format!("Fetch {domain}"),
                    message: "Not connected. Configure an API token first.".to_owned(),
                },
            },

            BackendCommand::ApplyChanges {
                domain,
                minimum_ttl,
                ops,
            } => match &client {
                Some(c) => apply_changes(c, domain, minimum_ttl, ops).await,
                None => BackendEvent::Error {
                    context: format!("Apply {domain}"),
                    message: "Not connected. Configure an API token first.".to_owned(),
                },
            },
        };

        let _ = event_tx.send(event);
        ctx.request_repaint();
    }
}

async fn fetch_domains(client: &Client) -> Result<Vec<DomainSummary>, DesecError> {
    let mut domains: Vec<DomainSummary> = client
        .domains()
        .list()
        .all()
        .await?
        .into_iter()
        .map(|d| DomainSummary {
            name: d.name,
            minimum_ttl: d.minimum_ttl,
        })
        .collect();
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(domains)
}

async fn fetch_rrsets(
    client: &Client,
    domain: &str,
) -> Result<BTreeMap<RrsetKey, RrsetData>, DesecError> {
    let raw = client.rrsets(domain).list().all().await?;
    Ok(convert_rrsets(raw))
}

fn convert_rrsets(raw: Vec<Rrset>) -> BTreeMap<RrsetKey, RrsetData> {
    let mut map = BTreeMap::new();
    for item in raw {
        let key = RrsetKey::new(item.subname.as_payload(), item.record_type.as_str());
        let data = RrsetData::new(item.ttl, item.records);
        map.insert(key, data);
    }
    map
}

async fn apply_changes(
    client: &Client,
    domain: String,
    minimum_ttl: u32,
    ops: Vec<DiffOp>,
) -> BackendEvent {
    let mut patches = Vec::with_capacity(ops.len());

    for op in &ops {
        let key = op.key();
        let subname = match Subname::new(&key.subname) {
            Ok(s) => s,
            Err(err) => {
                return BackendEvent::Error {
                    context: format!("Apply {domain}"),
                    message: format!("{} {}: {}", key.display_subname(), key.rtype, err),
                };
            }
        };
        let rtype = match RecordType::from_str(&key.rtype) {
            Ok(t) => t,
            Err(err) => {
                return BackendEvent::Error {
                    context: format!("Apply {domain}"),
                    message: format!("{} {}: {}", key.display_subname(), key.rtype, err),
                };
            }
        };

        let patch = match op {
            DiffOp::Create { data, .. } => BulkPatch::new(subname, rtype)
                .ttl(data.ttl)
                .records(data.records.clone()),
            DiffOp::Update { new, .. } => BulkPatch::new(subname, rtype)
                .ttl(new.ttl)
                .records(new.records.clone()),
            DiffOp::Delete { .. } => BulkPatch::delete(subname, rtype),
        };
        patches.push(patch);
    }

    if let Err(err) = client.rrsets(&domain).patch_bulk(&patches).await {
        return BackendEvent::Error {
            context: format!("Apply {domain}"),
            message: format_desec_error(&err, Some(&ops)),
        };
    }

    let applied_count = ops.len();
    match fetch_rrsets(client, &domain).await {
        Ok(rrsets) => BackendEvent::ChangesApplied {
            domain,
            minimum_ttl,
            applied_count,
            rrsets,
        },
        Err(err) => BackendEvent::Error {
            context: format!("Refresh {domain}"),
            message: format!(
                "Changes were applied to deSEC, but refreshing failed: {}",
                format_desec_error(&err, None)
            ),
        },
    }
}

fn format_desec_error(err: &DesecError, ops: Option<&[DiffOp]>) -> String {
    if err.is_unauthorized() {
        return "Authentication failed (HTTP 401). Check your deSEC API token.".to_owned();
    }
    if err.is_forbidden() {
        return "Permission denied (HTTP 403). Your token may lack permission for this domain."
            .to_owned();
    }

    if let (Some(api_err), Some(ops)) = (err.api_error(), ops)
        && let Some(items) = api_err.bulk_items()
    {
        let mut lines = Vec::new();
        for (idx, item) in items.iter().enumerate() {
            let msgs = item.messages();
            if !msgs.is_empty() {
                let target = ops
                    .get(idx)
                    .map(|op| {
                        format!(
                            "{} {} {}",
                            op.kind_label(),
                            op.key().display_subname(),
                            op.key().rtype
                        )
                    })
                    .unwrap_or_else(|| format!("Item #{idx}"));
                lines.push(format!("{target}: {}", msgs.join("; ")));
            }
        }
        if !lines.is_empty() {
            return lines.join("\n");
        }
    }

    if let Some(api_err) = err.api_error() {
        if let Some(detail) = api_err.detail()
            && !detail.is_empty()
        {
            return detail.to_owned();
        }
        let formatted = api_err.to_string();
        if !formatted.is_empty() {
            return formatted;
        }
    }

    err.to_string()
}
