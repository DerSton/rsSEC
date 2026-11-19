use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSummary {
    pub name: String,
    pub minimum_ttl: u32,
}

/// Unique identity of an RRset within a zone: `(subname, type)`.
/// `subname` uses the deSEC API payload format (`""` for the zone apex).
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
        // Place the zone apex (`""`) first, then sort alphabetically by subname and type.
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

#[derive(Debug, Clone, Eq)]
pub struct RrsetData {
    pub ttl: u32,
    pub records: Vec<String>,
}

impl RrsetData {
    pub fn new(ttl: u32, records: Vec<String>) -> Self {
        Self { ttl, records }
    }

    fn sorted_records(&self) -> Vec<&str> {
        let mut sorted: Vec<&str> = self.records.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        sorted
    }
}

impl PartialEq for RrsetData {
    fn eq(&self, other: &Self) -> bool {
        self.ttl == other.ttl && self.sorted_records() == other.sorted_records()
    }
}

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
        self != Self::Synced
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueDiffKind {
    Unchanged,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordValueDiff {
    pub kind: ValueDiffKind,
    pub value: String,
}

/// A single RRset card in the zone view, holding both cloud (`remote`) and working (`local`) snapshots.
#[derive(Debug, Clone)]
pub struct ZoneRow {
    pub key: RrsetKey,
    pub status: RowStatus,
    pub remote: Option<RrsetData>,
    pub local: Option<RrsetData>,
}

impl ZoneRow {
    /// Returns the data used to pre-populate the editor when clicking `Edit`.
    /// For a row marked `Deleted`, editing starts from its cloud data and restores it on save.
    pub fn editable_data(&self) -> &RrsetData {
        self.local
            .as_ref()
            .or(self.remote.as_ref())
            .expect("ZoneRow always has local or remote data")
    }

    /// Compares individual record values between cloud (`remote`) and working (`local`) state.
    pub fn record_diffs(&self) -> Vec<RecordValueDiff> {
        match (&self.remote, &self.local) {
            (None, Some(loc)) => loc
                .records
                .iter()
                .map(|v| RecordValueDiff {
                    kind: ValueDiffKind::Added,
                    value: v.clone(),
                })
                .collect(),

            (Some(rem), None) => rem
                .records
                .iter()
                .map(|v| RecordValueDiff {
                    kind: ValueDiffKind::Removed,
                    value: v.clone(),
                })
                .collect(),

            (Some(rem), Some(loc)) => {
                let rem_set: BTreeSet<&str> = rem.records.iter().map(String::as_str).collect();
                let loc_set: BTreeSet<&str> = loc.records.iter().map(String::as_str).collect();
                let mut diffs = Vec::new();

                for r in &rem.records {
                    if !loc_set.contains(r.as_str()) {
                        diffs.push(RecordValueDiff {
                            kind: ValueDiffKind::Removed,
                            value: r.clone(),
                        });
                    }
                }
                for l in &loc.records {
                    let kind = if rem_set.contains(l.as_str()) {
                        ValueDiffKind::Unchanged
                    } else {
                        ValueDiffKind::Added
                    };
                    diffs.push(RecordValueDiff {
                        kind,
                        value: l.clone(),
                    });
                }
                diffs
            }

            (None, None) => Vec::new(),
        }
    }

    pub fn matches_filter(&self, query_lower: &str, type_filter: &str, changes_only: bool) -> bool {
        if changes_only && !self.status.is_changed() {
            return false;
        }
        if type_filter != "All" && self.key.rtype != type_filter {
            return false;
        }
        if query_lower.is_empty() {
            return true;
        }

        let sub_match = self
            .key
            .display_subname()
            .to_ascii_lowercase()
            .contains(query_lower);
        let type_match = self.key.rtype.to_ascii_lowercase().contains(query_lower);
        let val_match = self
            .record_diffs()
            .iter()
            .any(|d| d.value.to_ascii_lowercase().contains(query_lower));

        sub_match || type_match || val_match
    }
}

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

/// Holds both the authoritative deSEC (`remote`) state and the user's `local` working state.
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

    fn all_keys(&self) -> BTreeSet<RrsetKey> {
        let mut keys = BTreeSet::new();
        keys.extend(self.remote.keys().cloned());
        keys.extend(self.local.keys().cloned());
        keys
    }

    pub fn rows(&self) -> Vec<ZoneRow> {
        self.all_keys()
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
                        remote: Some(rem.clone()),
                        local: Some(loc.clone()),
                    })
                }
                (None, Some(loc)) => Some(ZoneRow {
                    key,
                    status: RowStatus::Added,
                    remote: None,
                    local: Some(loc.clone()),
                }),
                (Some(rem), None) => Some(ZoneRow {
                    key,
                    status: RowStatus::Deleted,
                    remote: Some(rem.clone()),
                    local: None,
                }),
                (None, None) => None,
            })
            .collect()
    }

    pub fn diff(&self) -> Vec<DiffOp> {
        let mut ops = Vec::new();
        for key in self.all_keys() {
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
        let mut summary = DiffSummary::default();
        for op in self.diff() {
            match op {
                DiffOp::Create { .. } => summary.added += 1,
                DiffOp::Update { .. } => summary.modified += 1,
                DiffOp::Delete { .. } => summary.deleted += 1,
            }
        }
        summary
    }

    pub fn is_dirty(&self) -> bool {
        !self.summary().is_empty()
    }

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

    pub fn delete_local(&mut self, key: &RrsetKey) {
        self.local.remove(key);
    }

    pub fn delete_bulk_local<'a>(&mut self, keys: impl IntoIterator<Item = &'a RrsetKey>) {
        for key in keys {
            self.local.remove(key);
        }
    }

    pub fn set_ttl_bulk<'a>(
        &mut self,
        keys: impl IntoIterator<Item = &'a RrsetKey>,
        ttl: u32,
    ) -> Result<usize, String> {
        if ttl < self.minimum_ttl {
            return Err(format!(
                "TTL must be at least {}s (domain minimum).",
                self.minimum_ttl
            ));
        }

        let mut updated = 0;
        for key in keys {
            if let Some(loc) = self.local.get_mut(key) {
                loc.ttl = ttl;
                updated += 1;
            } else if let Some(rem) = self.remote.get(key) {
                let mut restored = rem.clone();
                restored.ttl = ttl;
                self.local.insert(key.clone(), restored);
                updated += 1;
            }
        }
        Ok(updated)
    }

    pub fn revert_key(&mut self, key: &RrsetKey) {
        if let Some(rem) = self.remote.get(key) {
            self.local.insert(key.clone(), rem.clone());
        } else {
            self.local.remove(key);
        }
    }

    pub fn revert_bulk<'a>(&mut self, keys: impl IntoIterator<Item = &'a RrsetKey>) {
        for key in keys {
            self.revert_key(key);
        }
    }

    pub fn discard_all(&mut self) {
        self.local = self.remote.clone();
    }

    pub fn available_record_types(&self) -> Vec<String> {
        let mut types: BTreeSet<String> = RECORD_TYPES.iter().map(|s| (*s).to_owned()).collect();
        for key in self.remote.keys().chain(self.local.keys()) {
            types.insert(key.rtype.clone());
        }
        types.into_iter().collect()
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
    fn editing_back_to_cloud_values_restores_synced_state() {
        let mut zone = sample_zone();
        let apex_a = RrsetKey::new("", "A");

        zone.upsert_local(
            Some(&apex_a),
            apex_a.clone(),
            RrsetData::new(7200, vec!["192.0.2.99".to_owned()]),
        )
        .unwrap();
        assert!(zone.is_dirty());
        let row = zone.rows().into_iter().find(|r| r.key == apex_a).unwrap();
        assert_eq!(row.status, RowStatus::Modified);
        assert_eq!(
            row.record_diffs(),
            vec![
                RecordValueDiff {
                    kind: ValueDiffKind::Removed,
                    value: "192.0.2.1".to_owned(),
                },
                RecordValueDiff {
                    kind: ValueDiffKind::Added,
                    value: "192.0.2.99".to_owned(),
                },
            ]
        );

        zone.upsert_local(
            Some(&apex_a),
            apex_a.clone(),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned()]),
        )
        .unwrap();
        assert!(!zone.is_dirty());
        let row = zone.rows().into_iter().find(|r| r.key == apex_a).unwrap();
        assert_eq!(row.status, RowStatus::Synced);
        assert_eq!(
            row.record_diffs(),
            vec![RecordValueDiff {
                kind: ValueDiffKind::Unchanged,
                value: "192.0.2.1".to_owned(),
            }]
        );
    }

    #[test]
    fn add_modify_delete_and_revert_diff_lifecycle() {
        let mut zone = sample_zone();

        zone.upsert_local(
            None,
            RrsetKey::new("_dmarc", "TXT"),
            RrsetData::new(3600, vec!["\"v=DMARC1; p=none\"".to_owned()]),
        )
        .unwrap();

        let apex_a = RrsetKey::new("", "A");
        zone.upsert_local(
            Some(&apex_a),
            apex_a.clone(),
            RrsetData::new(7200, vec!["192.0.2.2".to_owned()]),
        )
        .unwrap();

        let www_aaaa = RrsetKey::new("www", "AAAA");
        zone.delete_local(&www_aaaa);

        let summary = zone.summary();
        assert_eq!(summary.added, 1);
        assert_eq!(summary.modified, 1);
        assert_eq!(summary.deleted, 1);
        assert_eq!(summary.total(), 3);

        let deleted_row = zone.rows().into_iter().find(|r| r.key == www_aaaa).unwrap();
        assert_eq!(deleted_row.status, RowStatus::Deleted);

        zone.revert_key(&www_aaaa);
        assert_eq!(zone.summary().deleted, 0);

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

    #[test]
    fn bulk_ttl_and_bulk_delete_and_revert() {
        let mut zone = sample_zone();
        let keys = vec![RrsetKey::new("", "A"), RrsetKey::new("www", "AAAA")];

        zone.set_ttl_bulk(&keys, 7200).unwrap();
        assert_eq!(zone.summary().modified, 2);

        zone.set_ttl_bulk(&keys, 3600).unwrap();
        assert!(!zone.is_dirty());

        zone.delete_bulk_local(&keys);
        assert_eq!(zone.summary().deleted, 2);

        zone.revert_bulk(&keys);
        assert!(!zone.is_dirty());
    }
}
