use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// All DNS record types supported by deSEC for manual management.
/// Any additional/unknown record type returned by the API is also preserved.
pub const RECORD_TYPES: &[&str] = &[
    "A",
    "AAAA",
    "AFSDB",
    "APL",
    "CAA",
    "CDNSKEY",
    "CDS",
    "CERT",
    "CNAME",
    "DHCID",
    "DLV",
    "DNAME",
    "DNSKEY",
    "DS",
    "EUI48",
    "EUI64",
    "HINFO",
    "HTTPS",
    "KX",
    "L32",
    "L64",
    "LOC",
    "LP",
    "MX",
    "NAPTR",
    "NID",
    "NS",
    "OPENPGPKEY",
    "PTR",
    "RP",
    "SMIMEA",
    "SPF",
    "SRV",
    "SSHFP",
    "SVCB",
    "TLSA",
    "TXT",
    "URI",
];

/// Returns a concise BIND presentation format example for a DNS record type.
pub fn record_type_hint(rtype: &str) -> &'static str {
    match rtype {
        "A" => "IPv4 address, e.g. 192.0.2.1",
        "AAAA" => "IPv6 address, e.g. 2001:db8::1",
        "CNAME" => "Target hostname with trailing dot, e.g. target.example.com.",
        "MX" => "Priority and mail server with trailing dot, e.g. 10 mail.example.com.",
        "TXT" => "Quoted text string, e.g. \"v=spf1 -all\"",
        "NS" => "Nameserver hostname with trailing dot, e.g. ns1.example.com.",
        "SRV" => "Priority weight port target., e.g. 10 5 5060 sip.example.com.",
        "CAA" => "Flags tag \"value\", e.g. 0 issue \"letsencrypt.org\"",
        "PTR" => "Target hostname with trailing dot, e.g. host.example.com.",
        "TLSA" => "Usage selector matching-type hex-data, e.g. 3 1 1 0123abcd...",
        "SSHFP" => "Algorithm fp-type hex-fingerprint, e.g. 4 2 0123abcd...",
        "DS" => "Key-tag algorithm digest-type hex-digest, e.g. 12345 13 2 0123abcd...",
        "HTTPS" | "SVCB" => "Priority target params, e.g. 1 . alpn=\"h2,h3\"",
        "NAPTR" => "Order pref \"flags\" \"service\" \"regexp\" replacement.",
        "URI" => "Priority weight \"target\", e.g. 10 1 \"https://example.com/\"",
        "LOC" => "Latitude longitude altitude, e.g. 52 22 23.0 N 13 24 30.0 E 34.0m",
        "DNAME" => "Target domain with trailing dot, e.g. other.example.com.",
        "SPF" => "Quoted SPF text, e.g. \"v=spf1 -all\"",
        "HINFO" => "Quoted CPU and OS, e.g. \"INTEL\" \"LINUX\"",
        "RP" => "Mailbox and TXT domain with trailing dots, e.g. admin.example.com. .",
        _ => "BIND presentation format (hostnames require a trailing dot)",
    }
}

/// Summary of a domain returned by deSEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSummary {
    pub name: String,
    pub minimum_ttl: u32,
}

/// Canonical identity of an RRset within a zone: `(subname, type)`.
/// `subname` is stored in API payload format (`""` for the zone apex).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RrsetKey {
    pub subname: String,
    pub rtype: String,
}

impl RrsetKey {
    pub fn new(subname: impl Into<String>, rtype: impl Into<String>) -> Self {
        let raw_sub = subname.into();
        let trimmed_sub = raw_sub.trim();
        let normalized_sub = if trimmed_sub.is_empty() || trimmed_sub == "@" {
            String::new()
        } else {
            trimmed_sub.to_ascii_lowercase()
        };
        let normalized_type = rtype.into().trim().to_ascii_uppercase();
        Self {
            subname: normalized_sub,
            rtype: normalized_type,
        }
    }

    /// Human-readable subname (`@` at the zone apex).
    pub fn display_subname(&self) -> &str {
        if self.subname.is_empty() {
            "@"
        } else {
            &self.subname
        }
    }
}

impl Ord for RrsetKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Place apex (`""`) first, then sort alphabetically by subname and record type.
        match (self.subname.is_empty(), other.subname.is_empty()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self
                .subname
                .cmp(&other.subname)
                .then_with(|| self.rtype.cmp(&other.rtype)),
        }
    }
}

impl PartialOrd for RrsetKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Mutable payload of an RRset (TTL + record values).
#[derive(Debug, Clone, Eq)]
pub struct RrsetData {
    pub ttl: u32,
    pub records: Vec<String>,
}

impl RrsetData {
    pub fn new(ttl: u32, records: Vec<String>) -> Self {
        Self { ttl, records }
    }

    fn normalized_records(&self) -> Vec<&str> {
        let mut sorted: Vec<&str> = self.records.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted
    }
}

impl PartialEq for RrsetData {
    fn eq(&self, other: &Self) -> bool {
        self.ttl == other.ttl && self.normalized_records() == other.normalized_records()
    }
}

/// Sync state of a single row relative to the last fetched deSEC state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowStatus {
    Synced,
    Added,
    Modified,
    Deleted,
}

impl RowStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Synced => "Synced",
            Self::Added => "Added",
            Self::Modified => "Modified",
            Self::Deleted => "Deleted",
        }
    }

    pub fn is_changed(self) -> bool {
        !matches!(self, Self::Synced)
    }
}

/// A single row displayed in the zone editor table.
#[derive(Debug, Clone)]
pub struct ZoneRow {
    pub key: RrsetKey,
    pub status: RowStatus,
    /// Current values to display (local state, or remote state if deleted).
    pub display_data: RrsetData,
}

/// One atomic operation to apply to deSEC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffOp {
    Create {
        key: RrsetKey,
        data: RrsetData,
    },
    Update {
        key: RrsetKey,
        old: RrsetData,
        new: RrsetData,
    },
    Delete {
        key: RrsetKey,
        old: RrsetData,
    },
}

impl DiffOp {
    pub fn key(&self) -> &RrsetKey {
        match self {
            Self::Create { key, .. } | Self::Update { key, .. } | Self::Delete { key, .. } => key,
        }
    }

    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::Create { .. } => "ADD",
            Self::Update { .. } => "MODIFY",
            Self::Delete { .. } => "DELETE",
        }
    }
}

/// Aggregate count of pending local changes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiffSummary {
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
}

impl DiffSummary {
    pub fn total(self) -> usize {
        self.added + self.modified + self.deleted
    }

    pub fn is_empty(self) -> bool {
        self.total() == 0
    }
}

/// Holds both the authoritative deSEC (remote) state and the user's local working state.
#[derive(Debug, Clone)]
pub struct ZoneState {
    pub domain: String,
    pub minimum_ttl: u32,
    pub remote: BTreeMap<RrsetKey, RrsetData>,
    pub local: BTreeMap<RrsetKey, RrsetData>,
}

impl ZoneState {
    pub fn from_remote(
        domain: String,
        minimum_ttl: u32,
        rrsets: BTreeMap<RrsetKey, RrsetData>,
    ) -> Self {
        Self {
            domain,
            minimum_ttl,
            local: rrsets.clone(),
            remote: rrsets,
        }
    }

    /// Returns all rows (union of remote and local keys) with their sync status.
    pub fn rows(&self) -> Vec<ZoneRow> {
        let mut all_keys = BTreeSet::new();
        all_keys.extend(self.remote.keys().cloned());
        all_keys.extend(self.local.keys().cloned());

        all_keys
            .into_iter()
            .filter_map(|key| match (self.remote.get(&key), self.local.get(&key)) {
                (Some(rem), Some(loc)) => {
                    let status = if rem == loc {
                        RowStatus::Synced
                    } else {
                        RowStatus::Modified
                    };
                    Some(ZoneRow {
                        key,
                        status,
                        display_data: loc.clone(),
                    })
                }
                (None, Some(loc)) => Some(ZoneRow {
                    key,
                    status: RowStatus::Added,
                    display_data: loc.clone(),
                }),
                (Some(rem), None) => Some(ZoneRow {
                    key,
                    status: RowStatus::Deleted,
                    display_data: rem.clone(),
                }),
                (None, None) => None,
            })
            .collect()
    }

    /// Computes the minimal ordered list of operations needed to bring deSEC to match `local`.
    pub fn diff(&self) -> Vec<DiffOp> {
        let mut ops = Vec::new();
        let mut all_keys = BTreeSet::new();
        all_keys.extend(self.remote.keys().cloned());
        all_keys.extend(self.local.keys().cloned());

        for key in all_keys {
            match (self.remote.get(&key), self.local.get(&key)) {
                (None, Some(new)) => ops.push(DiffOp::Create {
                    key,
                    data: new.clone(),
                }),
                (Some(old), Some(new)) if old != new => ops.push(DiffOp::Update {
                    key,
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => ops.push(DiffOp::Delete {
                    key,
                    old: old.clone(),
                }),
                _ => {}
            }
        }
        ops
    }

    pub fn summary(&self) -> DiffSummary {
        let mut s = DiffSummary::default();
        for op in self.diff() {
            match op {
                DiffOp::Create { .. } => s.added += 1,
                DiffOp::Update { .. } => s.modified += 1,
                DiffOp::Delete { .. } => s.deleted += 1,
            }
        }
        s
    }

    pub fn is_dirty(&self) -> bool {
        !self.summary().is_empty()
    }

    /// Inserts or updates an RRset in `local`.
    /// If `original_key` is `Some(old)` and `old != new_key`, moves the RRset to `new_key`
    /// unless `new_key` already exists in `local`.
    pub fn upsert_local(
        &mut self,
        original_key: Option<&RrsetKey>,
        new_key: RrsetKey,
        data: RrsetData,
    ) -> Result<(), String> {
        if new_key.rtype.is_empty() {
            return Err("Record type cannot be empty.".to_owned());
        }
        if data.records.is_empty() {
            return Err("At least one record value is required.".to_owned());
        }
        if data.ttl < self.minimum_ttl {
            return Err(format!(
                "TTL must be at least {} seconds (domain minimum).",
                self.minimum_ttl
            ));
        }

        let is_rename = original_key.is_some_and(|old| old != &new_key);
        let is_new = original_key.is_none();

        if (is_new || is_rename) && self.local.contains_key(&new_key) {
            return Err(format!(
                "An RRset for {} {} already exists locally.",
                new_key.display_subname(),
                new_key.rtype
            ));
        }

        if let Some(old) = original_key
            && old != &new_key
        {
            self.local.remove(old);
        }

        self.local.insert(new_key, data);
        Ok(())
    }

    /// Removes an RRset from `local` (marking it as Deleted if it exists on deSEC).
    pub fn delete_local(&mut self, key: &RrsetKey) {
        self.local.remove(key);
    }

    /// Reverts a single RRset back to its deSEC remote state.
    pub fn revert_key(&mut self, key: &RrsetKey) {
        if let Some(rem) = self.remote.get(key) {
            self.local.insert(key.clone(), rem.clone());
        } else {
            self.local.remove(key);
        }
    }

    /// Discards all local changes, restoring `local` to match `remote`.
    pub fn discard_all(&mut self) {
        self.local = self.remote.clone();
    }

    /// Returns all record types present in this zone plus all standard deSEC types, sorted.
    pub fn available_record_types(&self) -> Vec<String> {
        let mut set: BTreeSet<String> = RECORD_TYPES.iter().map(|s| (*s).to_owned()).collect();
        for key in self.remote.keys().chain(self.local.keys()) {
            set.insert(key.rtype.clone());
        }
        set.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zone() -> ZoneState {
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("www", "AAAA"),
            RrsetData::new(3600, vec!["2001:db8::1".to_owned()]),
        );
        ZoneState::from_remote("example.com".to_owned(), 3600, remote)
    }

    #[test]
    fn key_normalizes_apex_and_orders_apex_first() {
        let apex_empty = RrsetKey::new("", "A");
        let apex_at = RrsetKey::new("@", "a");
        let sub = RrsetKey::new("aaa", "A");
        assert_eq!(apex_empty, apex_at);
        assert_eq!(apex_empty.display_subname(), "@");
        assert!(apex_empty < sub);
    }

    #[test]
    fn clean_zone_has_no_diff() {
        let zone = sample_zone();
        assert!(!zone.is_dirty());
        assert!(zone.diff().is_empty());
        assert!(zone.rows().iter().all(|r| r.status == RowStatus::Synced));
    }

    #[test]
    fn add_modify_delete_and_revert_diff_lifecycle() {
        let mut zone = sample_zone();

        // Add TXT record
        zone.upsert_local(
            None,
            RrsetKey::new("_dmarc", "TXT"),
            RrsetData::new(3600, vec!["\"v=DMARC1; p=none\"".to_owned()]),
        )
        .unwrap();

        // Modify apex A record
        let apex_a = RrsetKey::new("", "A");
        zone.upsert_local(
            Some(&apex_a),
            apex_a.clone(),
            RrsetData::new(7200, vec!["192.0.2.2".to_owned()]),
        )
        .unwrap();

        // Delete www AAAA record
        let www_aaaa = RrsetKey::new("www", "AAAA");
        zone.delete_local(&www_aaaa);

        let summary = zone.summary();
        assert_eq!(summary.added, 1);
        assert_eq!(summary.modified, 1);
        assert_eq!(summary.deleted, 1);
        assert_eq!(summary.total(), 3);

        // Deleted row still appears in table as Deleted
        let deleted_row = zone.rows().into_iter().find(|r| r.key == www_aaaa).unwrap();
        assert_eq!(deleted_row.status, RowStatus::Deleted);

        // Revert single deleted row
        zone.revert_key(&www_aaaa);
        assert_eq!(zone.summary().deleted, 0);

        // Discard everything
        zone.discard_all();
        assert!(!zone.is_dirty());
    }

    #[test]
    fn reordering_records_is_not_a_diff() {
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("", "TXT"),
            RrsetData::new(3600, vec!["\"b\"".to_owned(), "\"a\"".to_owned()]),
        );
        let mut zone = ZoneState::from_remote("example.com".to_owned(), 3600, remote);
        let key = RrsetKey::new("", "TXT");
        zone.upsert_local(
            Some(&key),
            key.clone(),
            RrsetData::new(3600, vec!["\"a\"".to_owned(), "\"b\"".to_owned()]),
        )
        .unwrap();
        assert!(!zone.is_dirty());
    }

    #[test]
    fn rename_key_produces_delete_and_create_and_prevents_collision() {
        let mut zone = sample_zone();
        let old = RrsetKey::new("www", "AAAA");
        let renamed = RrsetKey::new("blog", "AAAA");
        zone.upsert_local(
            Some(&old),
            renamed.clone(),
            RrsetData::new(3600, vec!["2001:db8::1".to_owned()]),
        )
        .unwrap();

        let ops = zone.diff();
        assert_eq!(ops.len(), 2);
        assert!(matches!(ops[0], DiffOp::Create { ref key, .. } if key == &renamed));
        assert!(matches!(ops[1], DiffOp::Delete { ref key, .. } if key == &old));

        // Collision with existing apex A should fail
        let collision = zone.upsert_local(
            Some(&renamed),
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.9".to_owned()]),
        );
        assert!(collision.is_err());
    }

    #[test]
    fn enforces_minimum_ttl() {
        let mut zone = sample_zone();
        let err = zone.upsert_local(
            None,
            RrsetKey::new("test", "A"),
            RrsetData::new(60, vec!["192.0.2.1".to_owned()]),
        );
        assert!(err.is_err());
    }
}
