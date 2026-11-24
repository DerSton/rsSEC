use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::rdata::{canonical_record, records_equivalent};
use crate::zonefile::{ImportMode, is_desec_managed_key, is_singleton_rtype};

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

    /// Returns the DNS-canonical set of records for `rtype` (RRsets are unordered per RFC 2181 §5).
    pub fn canonical_records(&self, rtype: &str) -> BTreeSet<String> {
        self.records
            .iter()
            .map(|r| canonical_record(rtype, r))
            .collect()
    }

    /// Returns `true` if `self` and `other` have the same TTL and DNS-equivalent record sets.
    pub fn is_equivalent(&self, rtype: &str, other: &Self) -> bool {
        self.ttl == other.ttl && self.canonical_records(rtype) == other.canonical_records(rtype)
    }

    /// Returns `true` if `self.records` already contains a record DNS-equivalent to `candidate`.
    pub fn contains_equivalent(&self, rtype: &str, candidate: &str) -> bool {
        self.records
            .iter()
            .any(|existing| records_equivalent(rtype, existing, candidate))
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
        diff_records(&self.key.rtype, self.remote.as_ref(), self.local.as_ref())
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
                    let status = if rem.is_equivalent(&key.rtype, loc) {
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
                (Some(old), Some(new)) if !old.is_equivalent(&key.rtype, new) => {
                    ops.push(DiffOp::Update {
                        key,
                        old: old.clone(),
                        new: new.clone(),
                    })
                }
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

    /// Computes what `self.local` would look like after applying `imported` under `mode`.
    pub fn compute_imported_local(
        &self,
        imported: &BTreeMap<RrsetKey, RrsetData>,
        mode: ImportMode,
    ) -> BTreeMap<RrsetKey, RrsetData> {
        match mode {
            ImportMode::MergeUpdate => {
                let mut next = self.local.clone();
                for (key, data) in imported {
                    next.insert(key.clone(), data.clone());
                }
                next
            }
            ImportMode::MergeAppend => {
                let mut next = self.local.clone();
                for (key, data) in imported {
                    if is_singleton_rtype(&key.rtype) || !next.contains_key(key) {
                        next.insert(key.clone(), data.clone());
                    } else if let Some(existing) = next.get_mut(key) {
                        for record in &data.records {
                            if !existing.contains_equivalent(&key.rtype, record) {
                                existing.records.push(record.clone());
                            }
                        }
                    }
                }
                next
            }
            ImportMode::Replace => {
                let mut next = BTreeMap::new();
                // Preserve deSEC-managed keys (such as apex NS) so Apply never fails with HTTP 400.
                for (key, data) in &self.remote {
                    if is_desec_managed_key(key) {
                        next.insert(key.clone(), data.clone());
                    }
                }
                for (key, data) in &self.local {
                    if is_desec_managed_key(key) {
                        next.insert(key.clone(), data.clone());
                    }
                }
                for (key, data) in imported {
                    if !is_desec_managed_key(key) {
                        next.insert(key.clone(), data.clone());
                    }
                }
                next
            }
        }
    }

    /// Previews how many RRsets will be added, modified, or deleted relative to current `self.local`.
    pub fn preview_import(
        &self,
        imported: &BTreeMap<RrsetKey, RrsetData>,
        mode: ImportMode,
    ) -> DiffSummary {
        let next = self.compute_imported_local(imported, mode);
        diff_summary_between(&self.local, &next)
    }

    /// Applies parsed zonefile RRsets into `self.local` (staged locally until Apply).
    pub fn apply_import_local(
        &mut self,
        imported: &BTreeMap<RrsetKey, RrsetData>,
        mode: ImportMode,
    ) -> Result<DiffSummary, String> {
        for (key, data) in imported {
            if key.rtype.is_empty() {
                return Err("Imported record type cannot be empty.".to_owned());
            }
            if data.records.is_empty() {
                return Err(format!(
                    "{} {}: imported RRset has no record values.",
                    key.display_subname(),
                    key.rtype
                ));
            }
            if data.ttl < self.minimum_ttl {
                return Err(format!(
                    "{} {}: TTL {}s is below domain minimum ({}s).",
                    key.display_subname(),
                    key.rtype,
                    data.ttl,
                    self.minimum_ttl
                ));
            }
        }

        let next = self.compute_imported_local(imported, mode);
        let summary = diff_summary_between(&self.local, &next);
        self.local = next;
        Ok(summary)
    }

    pub fn available_record_types(&self) -> Vec<String> {
        let mut types: BTreeSet<String> = RECORD_TYPES.iter().map(|s| (*s).to_owned()).collect();
        for key in self.remote.keys().chain(self.local.keys()) {
            types.insert(key.rtype.clone());
        }
        types.into_iter().collect()
    }
}

/// Order-insensitive, DNS-canonical diff between remote and local records of an RRset.
pub fn diff_records(
    rtype: &str,
    remote: Option<&RrsetData>,
    local: Option<&RrsetData>,
) -> Vec<RecordValueDiff> {
    match (remote, local) {
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
            let rem_set = rem.canonical_records(rtype);
            let loc_set = loc.canonical_records(rtype);
            let mut diffs = Vec::new();

            for r in &rem.records {
                if !loc_set.contains(&canonical_record(rtype, r)) {
                    diffs.push(RecordValueDiff {
                        kind: ValueDiffKind::Removed,
                        value: r.clone(),
                    });
                }
            }
            for l in &loc.records {
                let kind = if rem_set.contains(&canonical_record(rtype, l)) {
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

pub fn diff_summary_between(
    base: &BTreeMap<RrsetKey, RrsetData>,
    target: &BTreeMap<RrsetKey, RrsetData>,
) -> DiffSummary {
    let mut keys = BTreeSet::new();
    keys.extend(base.keys());
    keys.extend(target.keys());

    let mut summary = DiffSummary::default();
    for key in keys {
        match (base.get(key), target.get(key)) {
            (None, Some(_)) => summary.added += 1,
            (Some(old), Some(new)) if !old.is_equivalent(&key.rtype, new) => summary.modified += 1,
            (Some(_), None) => summary.deleted += 1,
            _ => {}
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_zone() -> ZoneState {
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("", "NS"),
            RrsetData::new(3600, vec!["ns1.desec.io.".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("www", "CNAME"),
            RrsetData::new(3600, vec!["example.com.".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("old", "A"),
            RrsetData::new(3600, vec!["192.0.2.99".to_owned()]),
        );
        ZoneState::from_remote("example.com".to_owned(), 3600, remote)
    }

    fn sample_import() -> BTreeMap<RrsetKey, RrsetData> {
        let mut imp = BTreeMap::new();
        imp.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(7200, vec!["192.0.2.2".to_owned()]),
        );
        imp.insert(
            RrsetKey::new("www", "CNAME"),
            RrsetData::new(3600, vec!["cdn.example.com.".to_owned()]),
        );
        imp.insert(
            RrsetKey::new("new", "AAAA"),
            RrsetData::new(3600, vec!["2001:db8::1".to_owned()]),
        );
        imp
    }

    #[test]
    fn merge_update_overwrites_matching_and_keeps_untouched() {
        let mut zone = sample_zone();
        let summary = zone
            .apply_import_local(&sample_import(), ImportMode::MergeUpdate)
            .unwrap();
        assert_eq!(
            summary,
            DiffSummary {
                added: 1,
                modified: 2,
                deleted: 0
            }
        );
        assert_eq!(
            zone.local.get(&RrsetKey::new("", "A")).unwrap().records,
            vec!["192.0.2.2"]
        );
        assert_eq!(zone.local.get(&RrsetKey::new("", "A")).unwrap().ttl, 7200);
        assert!(zone.local.contains_key(&RrsetKey::new("old", "A")));
    }

    #[test]
    fn merge_append_unions_values_and_overwrites_cname() {
        let mut zone = sample_zone();
        let summary = zone
            .apply_import_local(&sample_import(), ImportMode::MergeAppend)
            .unwrap();
        assert_eq!(
            summary,
            DiffSummary {
                added: 1,
                modified: 2,
                deleted: 0
            }
        );
        assert_eq!(
            zone.local.get(&RrsetKey::new("", "A")).unwrap().records,
            vec!["192.0.2.1", "192.0.2.2"]
        );
        assert_eq!(zone.local.get(&RrsetKey::new("", "A")).unwrap().ttl, 3600);
        assert_eq!(
            zone.local
                .get(&RrsetKey::new("www", "CNAME"))
                .unwrap()
                .records,
            vec!["cdn.example.com."]
        );
        assert!(zone.local.contains_key(&RrsetKey::new("old", "A")));
    }

    #[test]
    fn replace_deletes_unmentioned_but_preserves_apex_ns() {
        let mut zone = sample_zone();
        let summary = zone
            .apply_import_local(&sample_import(), ImportMode::Replace)
            .unwrap();
        assert_eq!(
            summary,
            DiffSummary {
                added: 1,
                modified: 2,
                deleted: 1
            }
        );
        assert!(!zone.local.contains_key(&RrsetKey::new("old", "A")));
        assert!(zone.local.contains_key(&RrsetKey::new("", "NS")));
        assert!(zone.local.contains_key(&RrsetKey::new("new", "AAAA")));
    }

    #[test]
    fn reordered_records_and_equivalent_presentation_produce_no_diff() {
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned(), "192.0.2.2".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("", "MX"),
            RrsetData::new(
                3600,
                vec![
                    "10 mail1.example.com.".to_owned(),
                    "20 mail2.example.com.".to_owned(),
                ],
            ),
        );
        remote.insert(
            RrsetKey::new("", "TXT"),
            RrsetData::new(
                3600,
                vec![
                    "\"v=spf1 -all\"".to_owned(),
                    "\"v=DKIM1\\; k=rsa\"".to_owned(),
                ],
            ),
        );
        remote.insert(
            RrsetKey::new("_443._tcp", "TLSA"),
            RrsetData::new(3600, vec!["3 1 1 deadbeef".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("", "HTTPS"),
            RrsetData::new(
                3600,
                vec!["1 . alpn=\"h2,h3\" ipv4hint=\"192.0.2.1\" mandatory=alpn,ipv4hint".to_owned()],
            ),
        );
        remote.insert(
            RrsetKey::new("", "AAAA"),
            RrsetData::new(3600, vec!["2001:db8::1".to_owned()]),
        );
        remote.insert(
            RrsetKey::new("", "CAA"),
            RrsetData::new(3600, vec!["0 issue \"letsencrypt.org\"".to_owned()]),
        );

        let mut zone = ZoneState::from_remote("example.com".to_owned(), 3600, remote);

        // Same content with reversed record order and different presentation formats.
        let mut imported = BTreeMap::new();
        imported.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.2".to_owned(), "192.0.2.1".to_owned()]),
        );
        imported.insert(
            RrsetKey::new("", "MX"),
            RrsetData::new(
                3600,
                vec![
                    "20 Mail2.Example.COM.".to_owned(),
                    "10 MAIL1.EXAMPLE.COM.".to_owned(),
                ],
            ),
        );
        imported.insert(
            RrsetKey::new("", "TXT"),
            RrsetData::new(
                3600,
                vec![
                    "\"v=DKIM1; k=rsa\"".to_owned(),
                    "\"v=spf1 -all\"".to_owned(),
                ],
            ),
        );
        imported.insert(
            RrsetKey::new("_443._tcp", "TLSA"),
            RrsetData::new(3600, vec!["3 1 1 DEADBEEF".to_owned()]),
        );
        imported.insert(
            RrsetKey::new("", "HTTPS"),
            RrsetData::new(
                3600,
                vec!["1 . mandatory=ipv4hint,alpn ipv4hint=192.0.2.1 alpn=h2,h3".to_owned()],
            ),
        );
        imported.insert(
            RrsetKey::new("", "AAAA"),
            RrsetData::new(3600, vec!["2001:0DB8:0000:0000:0000:0000:0000:0001".to_owned()]),
        );
        imported.insert(
            RrsetKey::new("", "CAA"),
            RrsetData::new(3600, vec!["0 ISSUE \"letsencrypt.org\"".to_owned()]),
        );

        let preview = zone.preview_import(&imported, ImportMode::Replace);
        assert!(preview.is_empty(), "expected no diff, got {preview:?}");

        let applied = zone
            .apply_import_local(&imported, ImportMode::Replace)
            .unwrap();
        assert!(applied.is_empty());
        assert!(zone.diff().is_empty());
        assert!(zone.rows().iter().all(|r| r.status == RowStatus::Synced));
        for row in zone.rows() {
            assert!(
                row.record_diffs()
                    .iter()
                    .all(|d| d.kind == ValueDiffKind::Unchanged),
                "unexpected record diff on {} {}: {:?}",
                row.key.display_subname(),
                row.key.rtype,
                row.record_diffs()
            );
        }
    }

    #[test]
    fn dns_significant_ordering_still_produces_diff() {
        // 1. Multi-chunk TXT order is DNS-significant.
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("_dkim", "TXT"),
            RrsetData::new(3600, vec!["\"part1\" \"part2\"".to_owned()]),
        );
        // 2. HTTPS ALPN protocol list order is preference-ordered (RFC 9460 §7.1.1).
        remote.insert(
            RrsetKey::new("", "HTTPS"),
            RrsetData::new(3600, vec!["1 . alpn=h2,h3".to_owned()]),
        );
        // 3. APL prefix order is DNS-significant (RFC 3123 §4).
        remote.insert(
            RrsetKey::new("acl", "APL"),
            RrsetData::new(3600, vec!["1:192.0.2.0/24 !1:192.0.2.1/32".to_owned()]),
        );

        let mut zone = ZoneState::from_remote("example.com".to_owned(), 3600, remote);

        let mut imported = BTreeMap::new();
        imported.insert(
            RrsetKey::new("_dkim", "TXT"),
            RrsetData::new(3600, vec!["\"part2\" \"part1\"".to_owned()]),
        );
        imported.insert(
            RrsetKey::new("", "HTTPS"),
            RrsetData::new(3600, vec!["1 . alpn=h3,h2".to_owned()]),
        );
        imported.insert(
            RrsetKey::new("acl", "APL"),
            RrsetData::new(3600, vec!["!1:192.0.2.1/32 1:192.0.2.0/24".to_owned()]),
        );

        let summary = zone
            .apply_import_local(&imported, ImportMode::MergeUpdate)
            .unwrap();
        assert_eq!(
            summary,
            DiffSummary {
                added: 0,
                modified: 3,
                deleted: 0,
            }
        );
        assert_eq!(zone.diff().len(), 3);
    }

    #[test]
    fn merge_append_skips_canonically_equivalent_duplicates() {
        let mut remote = BTreeMap::new();
        remote.insert(
            RrsetKey::new("_443._tcp", "TLSA"),
            RrsetData::new(3600, vec!["3 1 1 deadbeef".to_owned()]),
        );
        let mut zone = ZoneState::from_remote("example.com".to_owned(), 3600, remote);

        let mut imported = BTreeMap::new();
        imported.insert(
            RrsetKey::new("_443._tcp", "TLSA"),
            RrsetData::new(3600, vec!["3 1 1 DEADBEEF".to_owned()]),
        );

        let summary = zone
            .apply_import_local(&imported, ImportMode::MergeAppend)
            .unwrap();
        assert!(summary.is_empty());
        assert_eq!(
            zone.local
                .get(&RrsetKey::new("_443._tcp", "TLSA"))
                .unwrap()
                .records
                .len(),
            1
        );
    }
}
