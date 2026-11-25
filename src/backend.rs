use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use desec::api::rrsets::{BulkPatch, Rrset};
use desec::{Client, Error as DesecError, RecordType, Subname};
use eframe::egui;
use tokio::sync::RwLock;

use crate::model::{DiffOp, DomainSummary, RrsetData, RrsetKey};

type ClientsMap = Arc<RwLock<HashMap<String, Client>>>;

#[derive(Debug)]
pub enum BackendCommand {
    Connect {
        account_id: String,
        token: String,
    },
    Disconnect {
        account_id: String,
    },
    FetchDomains {
        account_id: String,
    },
    FetchZone {
        account_id: String,
        domain: String,
        minimum_ttl: u32,
    },
    ApplyChanges {
        account_id: String,
        domain: String,
        minimum_ttl: u32,
        ops: Vec<DiffOp>,
    },
}

#[derive(Debug)]
pub enum BackendEvent {
    Connected {
        account_id: String,
        email: Option<String>,
        domains: Vec<DomainSummary>,
    },
    DomainsLoaded {
        account_id: String,
        domains: Vec<DomainSummary>,
    },
    ZoneLoaded {
        account_id: String,
        domain: String,
        minimum_ttl: u32,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
    },
    ChangesApplied {
        account_id: String,
        domain: String,
        minimum_ttl: u32,
        applied_count: usize,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
    },
    Error {
        account_id: String,
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
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (event_tx, event_rx) = mpsc::channel();

        thread::Builder::new()
            .name("rssec-backend".to_owned())
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
    let clients: ClientsMap = Arc::new(RwLock::new(HashMap::new()));

    while let Ok(cmd) = cmd_rx.recv() {
        if let BackendCommand::Disconnect { account_id } = cmd {
            clients.write().await.remove(&account_id);
            continue;
        }

        let clients = Arc::clone(&clients);
        let event_tx = event_tx.clone();
        let ctx = ctx.clone();

        tokio::spawn(async move {
            let event = match cmd {
                BackendCommand::Connect { account_id, token } => {
                    handle_connect(&clients, account_id, &token).await
                }
                BackendCommand::FetchDomains { account_id } => {
                    handle_fetch_domains(&clients, account_id).await
                }
                BackendCommand::FetchZone {
                    account_id,
                    domain,
                    minimum_ttl,
                } => handle_fetch_zone(&clients, account_id, domain, minimum_ttl).await,
                BackendCommand::ApplyChanges {
                    account_id,
                    domain,
                    minimum_ttl,
                    ops,
                } => handle_apply_changes(&clients, account_id, domain, minimum_ttl, ops).await,
                BackendCommand::Disconnect { .. } => unreachable!(),
            };

            let _ = event_tx.send(event);
            ctx.request_repaint();
        });
    }
}

async fn get_client(clients: &ClientsMap, account_id: &str) -> Option<Client> {
    clients.read().await.get(account_id).cloned()
}

async fn handle_connect(clients: &ClientsMap, account_id: String, token: &str) -> BackendEvent {
    let new_client = match Client::new(token.trim()) {
        Ok(c) => c,
        Err(err) => {
            return BackendEvent::Error {
                account_id,
                context: "Connect".to_owned(),
                message: err.to_string(),
            };
        }
    };

    match fetch_domains(&new_client).await {
        Ok(domains) => {
            // `GET /auth/account/` requires `perm_manage_tokens`; scoped DNS tokens return 403,
            // so treat account metadata lookup as best-effort and fall back cleanly.
            let email = new_client.account().get().await.ok().map(|acc| acc.email);
            clients.write().await.insert(account_id.clone(), new_client);
            BackendEvent::Connected {
                account_id,
                email,
                domains,
            }
        }
        Err(err) => BackendEvent::Error {
            account_id,
            context: "Connect".to_owned(),
            message: format_desec_error(&err, None),
        },
    }
}

async fn handle_fetch_domains(clients: &ClientsMap, account_id: String) -> BackendEvent {
    let Some(client) = get_client(clients, &account_id).await else {
        return not_connected_error(account_id, "Fetch domains");
    };

    match fetch_domains(&client).await {
        Ok(domains) => BackendEvent::DomainsLoaded {
            account_id,
            domains,
        },
        Err(err) => BackendEvent::Error {
            account_id,
            context: "Fetch domains".to_owned(),
            message: format_desec_error(&err, None),
        },
    }
}

async fn handle_fetch_zone(
    clients: &ClientsMap,
    account_id: String,
    domain: String,
    minimum_ttl: u32,
) -> BackendEvent {
    let Some(client) = get_client(clients, &account_id).await else {
        return not_connected_error(account_id, &format!("Fetch {domain}"));
    };

    match fetch_rrsets(&client, &domain).await {
        Ok(rrsets) => BackendEvent::ZoneLoaded {
            account_id,
            domain,
            minimum_ttl,
            rrsets,
        },
        Err(err) => BackendEvent::Error {
            account_id,
            context: format!("Fetch {domain}"),
            message: format_desec_error(&err, None),
        },
    }
}

async fn handle_apply_changes(
    clients: &ClientsMap,
    account_id: String,
    domain: String,
    minimum_ttl: u32,
    ops: Vec<DiffOp>,
) -> BackendEvent {
    let Some(client) = get_client(clients, &account_id).await else {
        return not_connected_error(account_id, &format!("Apply {domain}"));
    };

    let mut patches = Vec::with_capacity(ops.len());
    for op in &ops {
        match build_bulk_patch(op) {
            Ok(patch) => patches.push(patch),
            Err(message) => {
                return BackendEvent::Error {
                    account_id,
                    context: format!("Apply {domain}"),
                    message,
                };
            }
        }
    }

    if let Err(err) = client.rrsets(&domain).patch_bulk(&patches).await {
        return BackendEvent::Error {
            account_id,
            context: format!("Apply {domain}"),
            message: format_desec_error(&err, Some(&ops)),
        };
    }

    let applied_count = ops.len();
    match fetch_rrsets(&client, &domain).await {
        Ok(rrsets) => BackendEvent::ChangesApplied {
            account_id,
            domain,
            minimum_ttl,
            applied_count,
            rrsets,
        },
        Err(err) => BackendEvent::Error {
            account_id,
            context: format!("Refresh {domain}"),
            message: format!(
                "Changes were applied to deSEC, but refreshing failed: {}",
                format_desec_error(&err, None)
            ),
        },
    }
}

fn build_bulk_patch(op: &DiffOp) -> Result<BulkPatch, String> {
    let key = op.key();
    let subname = Subname::new(&key.subname)
        .map_err(|err| format!("{} {}: {err}", key.display_subname(), key.rtype))?;
    let rtype = RecordType::from_str(&key.rtype)
        .map_err(|err| format!("{} {}: {err}", key.display_subname(), key.rtype))?;

    let patch = match op {
        DiffOp::Create { data, .. } => BulkPatch::new(subname, rtype)
            .ttl(data.ttl)
            .records(data.records.clone()),
        DiffOp::Update { new, .. } => BulkPatch::new(subname, rtype)
            .ttl(new.ttl)
            .records(new.records.clone()),
        DiffOp::Delete { .. } => BulkPatch::delete(subname, rtype),
    };
    Ok(patch)
}

fn not_connected_error(account_id: String, context: &str) -> BackendEvent {
    BackendEvent::Error {
        account_id,
        context: context.to_owned(),
        message: "Not connected. Configure an API token first.".to_owned(),
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
    let raw: Vec<Rrset> = client.rrsets(domain).list().all().await?;
    let mut map = BTreeMap::new();
    for item in raw {
        let key = RrsetKey::new(item.subname.as_payload(), item.record_type.as_str());
        let data = RrsetData::new(item.ttl, item.records);
        map.insert(key, data);
    }
    Ok(map)
}

fn format_desec_error(err: &DesecError, ops: Option<&[DiffOp]>) -> String {
    if err.is_unauthorized() {
        return "Authentication failed (HTTP 401). Check your deSEC API token.".to_owned();
    }
    if err.is_forbidden() {
        return "Permission denied (HTTP 403). Your token may lack permission for this domain."
            .to_owned();
    }
    if let Some(status) = err.status()
        && status.is_server_error()
    {
        let reason = status.canonical_reason().unwrap_or("Server Error");
        return format!(
            "deSEC server temporarily unavailable (HTTP {} {reason}). Please try again shortly.",
            status.as_u16()
        );
    }

    // For failed bulk writes, deSEC returns a positional error array matching `ops` by index.
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
            return sanitize_error_text(detail);
        }
        let formatted = api_err.to_string();
        if !formatted.is_empty() {
            return sanitize_error_text(&formatted);
        }
    }

    sanitize_error_text(&err.to_string())
}

// Strips raw HTML error pages (e.g. from nginx/proxies) down to a single summary line.
fn sanitize_error_text(raw: &str) -> String {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower.contains("<html") || lower.contains("<head>") {
        if let Some(start) = lower.find("<title>")
            && let Some(end) = lower[start + 7..].find("</title>")
        {
            let title = trimmed[start + 7..start + 7 + end].trim();
            if !title.is_empty() {
                return format!("Server error ({title}). Please try again.");
            }
        }
        return "Server returned an HTML error page. Please try again.".to_owned();
    }

    trimmed.to_owned()
}
