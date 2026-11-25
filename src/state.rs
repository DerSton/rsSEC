use std::collections::{BTreeMap, BTreeSet};

use crate::model::{DomainSummary, RrsetData, RrsetKey, ZoneState};
use crate::token::{AccountSource, StoredAccount, scrub_secret};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Failed,
}

impl ConnectionState {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Connecting => "Connecting...",
            Self::Connected => "Connected",
            Self::Failed => "Error",
        }
    }
}

/// Ephemeral in-RAM state for a single DNS domain (never persisted to disk).
#[derive(Debug, Clone)]
pub struct DomainState {
    pub name: String,
    pub minimum_ttl: u32,
    pub loading: bool,
    pub busy_label: Option<String>,
    pub status_message: String,
    pub error: Option<String>,
    pub zone: Option<ZoneState>,

    pub search_query: String,
    pub type_filter: String,
    pub changes_only: bool,
    pub selected_keys: BTreeSet<RrsetKey>,
    pub bulk_ttl_input: String,
}

impl DomainState {
    pub fn new(summary: DomainSummary) -> Self {
        let bulk_ttl_input = summary.minimum_ttl.max(3600).to_string();
        Self {
            name: summary.name,
            minimum_ttl: summary.minimum_ttl,
            loading: false,
            busy_label: None,
            status_message: "Not loaded".to_owned(),
            error: None,
            zone: None,
            search_query: String::new(),
            type_filter: "All".to_owned(),
            changes_only: false,
            selected_keys: BTreeSet::new(),
            bulk_ttl_input,
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.zone.as_ref().is_some_and(ZoneState::is_dirty)
    }

    pub fn pending_changes(&self) -> usize {
        self.zone.as_ref().map_or(0, |z| z.summary().total())
    }

    /// Replaces the authoritative zone snapshot while keeping search/filter inputs intact.
    pub fn apply_loaded_zone(
        &mut self,
        minimum_ttl: u32,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
        status_message: String,
    ) {
        self.minimum_ttl = minimum_ttl;
        self.zone = Some(ZoneState::from_remote(
            self.name.clone(),
            minimum_ttl,
            rrsets,
        ));
        self.selected_keys.clear();
        self.loading = false;
        self.busy_label = None;
        self.error = None;
        self.status_message = status_message;
    }

    /// Marks the current local state as committed to remote when a bulk write succeeded
    /// but the follow-up zone refresh failed.
    pub fn mark_local_as_synced(
        &mut self,
        minimum_ttl: u32,
        status_message: String,
        warning: Option<String>,
    ) {
        self.minimum_ttl = minimum_ttl;
        if let Some(zone) = &mut self.zone {
            zone.minimum_ttl = minimum_ttl;
            zone.remote = zone.local.clone();
        }
        self.selected_keys.clear();
        self.loading = false;
        self.busy_label = None;
        self.error = warning;
        self.status_message = status_message;
    }
}

/// Ephemeral in-RAM session state for one deSEC account/token tab.
#[derive(Debug, Clone)]
pub struct AccountState {
    pub id: String,
    pub label: String,
    pub email: Option<String>,
    pub custom_label: bool,
    pub source: AccountSource,
    /// Kept in memory for `Session`/`Env` accounts; `Keyring` accounts load lazily from keyring.
    pub ephemeral_token: Option<String>,

    pub connection: ConnectionState,
    pub busy_label: Option<String>,
    pub status_message: String,
    pub error: Option<String>,

    pub domains: BTreeMap<String, DomainState>,
    pub active_domain: Option<String>,
}

impl Drop for AccountState {
    fn drop(&mut self) {
        if let Some(token) = &mut self.ephemeral_token {
            scrub_secret(token);
        }
    }
}

impl AccountState {
    pub fn from_stored(stored: StoredAccount) -> Self {
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
            error: None,
            domains: BTreeMap::new(),
            active_domain: None,
        }
    }

    pub fn from_env(token: String) -> Self {
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
            error: None,
            domains: BTreeMap::new(),
            active_domain: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection == ConnectionState::Connected
    }

    pub fn is_account_busy(&self) -> bool {
        self.busy_label.is_some()
    }

    pub fn is_active_busy(&self) -> bool {
        self.is_account_busy() || self.active_domain().is_some_and(|d| d.loading)
    }

    pub fn active_domain(&self) -> Option<&DomainState> {
        let name = self.active_domain.as_deref()?;
        self.domains.get(name)
    }

    pub fn active_domain_mut(&mut self) -> Option<&mut DomainState> {
        let name = self.active_domain.as_deref()?;
        self.domains.get_mut(name)
    }

    pub fn is_dirty(&self) -> bool {
        self.domains.values().any(DomainState::is_dirty)
    }

    pub fn dirty_domain_count(&self) -> usize {
        self.domains.values().filter(|d| d.is_dirty()).count()
    }

    pub fn pending_changes(&self) -> usize {
        self.domains.values().map(DomainState::pending_changes).sum()
    }

    /// Merges fresh deSEC domain summaries into `self.domains` without discarding
    /// existing per-domain RAM state (filters, search, selection, staged edits).
    pub fn sync_domains(&mut self, summaries: Vec<DomainSummary>) {
        let valid: BTreeSet<String> = summaries.iter().map(|s| s.name.clone()).collect();
        self.domains.retain(|name, _| valid.contains(name));

        for summary in summaries {
            match self.domains.get_mut(&summary.name) {
                Some(existing) => {
                    existing.minimum_ttl = summary.minimum_ttl;
                    if let Some(zone) = &mut existing.zone {
                        zone.minimum_ttl = summary.minimum_ttl;
                    }
                }
                None => {
                    self.domains
                        .insert(summary.name.clone(), DomainState::new(summary));
                }
            }
        }

        let active_still_valid = self
            .active_domain
            .as_deref()
            .is_some_and(|name| self.domains.contains_key(name));
        if !active_still_valid {
            self.active_domain = self.domains.keys().next().cloned();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_account() -> AccountState {
        AccountState::from_stored(StoredAccount {
            id: "acc-1".to_owned(),
            label: "alice@example.com".to_owned(),
            email: Some("alice@example.com".to_owned()),
            custom_label: false,
        })
    }

    #[test]
    fn sync_domains_preserves_ram_state_and_aggregates_pending_changes() {
        let mut acc = sample_account();
        acc.sync_domains(vec![
            DomainSummary {
                name: "a.example".to_owned(),
                minimum_ttl: 3600,
            },
            DomainSummary {
                name: "b.example".to_owned(),
                minimum_ttl: 3600,
            },
        ]);
        assert_eq!(acc.active_domain.as_deref(), Some("a.example"));

        // Populate loaded zones and per-domain RAM filters/edits on both domains.
        let mut rrsets_a = BTreeMap::new();
        rrsets_a.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned()]),
        );
        let dom_a = acc.domains.get_mut("a.example").unwrap();
        dom_a.search_query = "mail".to_owned();
        dom_a.type_filter = "TXT".to_owned();
        dom_a.changes_only = true;
        dom_a.apply_loaded_zone(3600, rrsets_a, "loaded".to_owned());
        dom_a
            .zone
            .as_mut()
            .unwrap()
            .upsert_local(
                None,
                RrsetKey::new("www", "A"),
                RrsetData::new(3600, vec!["192.0.2.2".to_owned()]),
            )
            .unwrap();

        let dom_b = acc.domains.get_mut("b.example").unwrap();
        dom_b.apply_loaded_zone(3600, BTreeMap::new(), "loaded".to_owned());
        dom_b
            .zone
            .as_mut()
            .unwrap()
            .upsert_local(
                None,
                RrsetKey::new("", "TXT"),
                RrsetData::new(3600, vec!["\"hello\"".to_owned()]),
            )
            .unwrap();

        assert!(acc.is_dirty());
        assert_eq!(acc.dirty_domain_count(), 2);
        assert_eq!(acc.pending_changes(), 2);

        // Refreshing domain list updates TTL, adds c.example, removes b.example,
        // and keeps a.example's filters + staged edits intact.
        acc.sync_domains(vec![
            DomainSummary {
                name: "a.example".to_owned(),
                minimum_ttl: 7200,
            },
            DomainSummary {
                name: "c.example".to_owned(),
                minimum_ttl: 3600,
            },
        ]);

        assert!(acc.domains.contains_key("a.example"));
        assert!(!acc.domains.contains_key("b.example"));
        assert!(acc.domains.contains_key("c.example"));

        let dom_a = acc.domains.get("a.example").unwrap();
        assert_eq!(dom_a.minimum_ttl, 7200);
        assert_eq!(dom_a.search_query, "mail");
        assert_eq!(dom_a.type_filter, "TXT");
        assert!(dom_a.changes_only);
        assert_eq!(dom_a.pending_changes(), 1);
        assert_eq!(acc.pending_changes(), 1);
    }
}
