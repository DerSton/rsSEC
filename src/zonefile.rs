use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::str::FromStr;

use domain::base::iana::Class;
use domain::base::name::Name;
use domain::base::zonefile_fmt::{DisplayKind, ZonefileFmt};
use domain::zonefile::inplace::{Entry, Zonefile};

use crate::model::{RrsetData, RrsetKey};
use crate::rdata::tokenize_rdata;

/// Controls how imported RRsets are merged into the local working zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    /// Keep untouched local RRsets; overwrite matching `(subname, type)` RRsets.
    #[default]
    MergeUpdate,
    /// Keep untouched local RRsets; union record values into matching RRsets
    /// (except singleton types like CNAME/DNAME which are overwritten).
    MergeAppend,
    /// Replace all non-protected local RRsets with the imported zonefile.
    Replace,
}

impl ImportMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::MergeUpdate => "Merge (Update)",
            Self::MergeAppend => "Merge (Append)",
            Self::Replace => "Replace",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::MergeUpdate => {
                "Keep existing RRsets not in the file; overwrite matching (subname, type) RRsets."
            }
            Self::MergeAppend => {
                "Keep existing RRsets; append new values into matching RRsets (CNAME/DNAME overwrite)."
            }
            Self::Replace => {
                "Replace the entire zone with imported records; unmentioned RRsets are marked for deletion (apex NS is preserved)."
            }
        }
    }
}

/// Result of parsing a BIND zonefile into deSEC-compatible RRsets.
#[derive(Debug, Clone)]
pub struct ParsedZonefile {
    pub rrsets: BTreeMap<RrsetKey, RrsetData>,
    pub warnings: Vec<String>,
    pub record_count: usize,
}

/// Returns `true` for RRsets that deSEC manages automatically and rejects in bulk RRset writes.
pub fn is_desec_managed_key(key: &RrsetKey) -> bool {
    if matches!(
        key.rtype.as_str(),
        "SOA" | "RRSIG" | "NSEC" | "NSEC3" | "NSEC3PARAM"
    ) {
        return true;
    }

    key.subname.is_empty() && matches!(key.rtype.as_str(), "NS" | "DNSKEY" | "CDS" | "CDNSKEY")
}

/// Returns `true` for record types that can only hold a single value in an RRset.
pub fn is_singleton_rtype(rtype: &str) -> bool {
    matches!(rtype, "CNAME" | "DNAME")
}

/// Parses a BIND presentation-format zonefile for `domain` into grouped `RrsetKey -> RrsetData`.
pub fn parse_zonefile(
    input: &str,
    domain: &str,
    minimum_ttl: u32,
    clamp_ttl: bool,
) -> Result<ParsedZonefile, String> {
    let domain_clean = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain_clean.is_empty() {
        return Err("Invalid target domain.".to_owned());
    }

    let origin_fqdn = format!("{domain_clean}.");
    let origin = Name::from_str(&origin_fqdn)
        .map_err(|err| format!("Invalid domain origin '{domain_clean}': {err}"))?;

    // Ensure the buffer ends with a newline so the final record is always terminated cleanly.
    let mut normalized_input = String::with_capacity(input.len() + 1);
    normalized_input.push_str(input);
    if !normalized_input.ends_with('\n') {
        normalized_input.push('\n');
    }

    let mut zonefile = Zonefile::from(normalized_input.as_str()).allow_invalid();
    zonefile.set_origin(origin);
    zonefile.set_default_class(Class::IN);

    let domain_suffix = format!(".{domain_clean}");

    let mut rrsets: BTreeMap<RrsetKey, RrsetData> = BTreeMap::new();
    let mut skipped_managed: BTreeMap<String, usize> = BTreeMap::new();
    let mut skipped_non_in: usize = 0;
    let mut skipped_out_of_zone: usize = 0;
    let mut conflicting_ttl_keys: BTreeSet<RrsetKey> = BTreeSet::new();
    let mut record_count: usize = 0;

    while let Some(entry) = zonefile
        .next_entry()
        .map_err(|err| format!("Zonefile parse error: {err}"))?
    {
        match entry {
            Entry::Include { path, .. } => {
                return Err(format!(
                    "$INCLUDE directive ('{path}') is not supported for security reasons."
                ));
            }
            Entry::Record(record) => {
                if record.class() != Class::IN {
                    skipped_non_in += 1;
                    continue;
                }

                let owner_raw = record.owner().to_string();
                let owner_clean = owner_raw.trim_end_matches('.').to_ascii_lowercase();

                let subname = if owner_clean == domain_clean {
                    String::new()
                } else if let Some(prefix) = owner_clean.strip_suffix(&domain_suffix) {
                    prefix.to_owned()
                } else {
                    skipped_out_of_zone += 1;
                    continue;
                };

                let rtype = record.rtype().to_string().to_ascii_uppercase();
                let key = RrsetKey::new(subname, rtype);

                if is_desec_managed_key(&key) {
                    let label = if key.subname.is_empty() && key.rtype == "NS" {
                        "@ NS".to_owned()
                    } else {
                        key.rtype.clone()
                    };
                    *skipped_managed.entry(label).or_insert(0) += 1;
                    continue;
                }

                let raw_rdata = record
                    .data()
                    .display_zonefile(DisplayKind::Simple)
                    .to_string();
                let rdata = normalize_imported_rdata(&key.rtype, raw_rdata);
                let ttl = record.ttl().as_secs();

                match rrsets.get_mut(&key) {
                    Some(existing) => {
                        if existing.ttl != ttl {
                            existing.ttl = existing.ttl.min(ttl);
                            conflicting_ttl_keys.insert(key.clone());
                        }
                        if !existing.contains_equivalent(&key.rtype, &rdata) {
                            existing.records.push(rdata);
                            record_count += 1;
                        }
                    }
                    None => {
                        rrsets.insert(key, RrsetData::new(ttl, vec![rdata]));
                        record_count += 1;
                    }
                }
            }
        }
    }

    let mut clamped_ttl_count: usize = 0;
    for (key, data) in &mut rrsets {
        if data.ttl < minimum_ttl {
            if clamp_ttl {
                data.ttl = minimum_ttl;
                clamped_ttl_count += 1;
            } else {
                return Err(format!(
                    "{} {}: TTL {}s is below domain minimum ({minimum_ttl}s). Enable TTL clamping or update the zonefile.",
                    key.display_subname(),
                    key.rtype,
                    data.ttl
                ));
            }
        }
    }

    let mut warnings = Vec::new();
    if !skipped_managed.is_empty() {
        let details: Vec<String> = skipped_managed
            .into_iter()
            .map(|(label, count)| format!("{count}× {label}"))
            .collect();
        warnings.push(format!(
            "Skipped deSEC-managed record(s): {}",
            details.join(", ")
        ));
    }
    if skipped_out_of_zone > 0 {
        warnings.push(format!(
            "Skipped {skipped_out_of_zone} out-of-zone record(s) (expected domain {domain_clean})."
        ));
    }
    if skipped_non_in > 0 {
        warnings.push(format!("Skipped {skipped_non_in} non-IN class record(s)."));
    }
    if !conflicting_ttl_keys.is_empty() {
        warnings.push(format!(
            "{} RRset(s) had mixed TTLs; kept the lowest TTL per RRset.",
            conflicting_ttl_keys.len()
        ));
    }
    if clamped_ttl_count > 0 {
        warnings.push(format!(
            "Raised TTL to domain minimum ({minimum_ttl}s) on {clamped_ttl_count} RRset(s)."
        ));
    }

    Ok(ParsedZonefile {
        rrsets,
        warnings,
        record_count,
    })
}

/// Normalizes `domain`'s `DisplayKind::Simple` output into clean deSEC-compatible presentation
/// format (expands `@.<origin>.`, lowercases hex/CAA tags, and fixes `domain`'s `nodefaultalpn`).
fn normalize_imported_rdata(rtype: &str, rdata: String) -> String {
    let rdata = normalize_at_origin_rdata(rtype, rdata);
    match rtype {
        "TLSA" | "SMIMEA" | "DS" | "CDS" | "DLV" => {
            let mut tokens: Vec<String> = rdata.split_whitespace().map(str::to_owned).collect();
            if tokens.len() >= 4 {
                let hex_lower = tokens[3..].concat().to_ascii_lowercase();
                tokens.truncate(3);
                tokens.push(hex_lower);
                return tokens.join(" ");
            }
            rdata
        }
        "SSHFP" => {
            let mut tokens: Vec<String> = rdata.split_whitespace().map(str::to_owned).collect();
            if tokens.len() >= 3 {
                let hex_lower = tokens[2..].concat().to_ascii_lowercase();
                tokens.truncate(2);
                tokens.push(hex_lower);
                return tokens.join(" ");
            }
            rdata
        }
        "CAA" => {
            let mut tokens = tokenize_rdata(&rdata);
            if tokens.len() >= 3 {
                tokens[1] = tokens[1].to_ascii_lowercase();
                return tokens.join(" ");
            }
            rdata
        }
        "HTTPS" | "SVCB" => {
            let mut tokens = tokenize_rdata(&rdata);
            let mut changed = false;
            for tok in tokens.iter_mut().skip(2) {
                if tok == "nodefaultalpn" {
                    *tok = "no-default-alpn".to_owned();
                    changed = true;
                }
            }
            if changed { tokens.join(" ") } else { rdata }
        }
        _ => rdata,
    }
}

/// `domain::zonefile::inplace` expands `@` to `$ORIGIN` for owner names, but treats a bare `@`
/// in RDATA domain-name fields as a literal label (`@.<origin>.`). This normalizes `@.<origin>.`
/// back to `<origin>.` strictly at domain-name token positions of known RR types.
fn normalize_at_origin_rdata(rtype: &str, rdata: String) -> String {
    if rtype == "NAPTR" {
        if let Some((prefix, last)) = rdata.rsplit_once(' ')
            && let Some(stripped) = last.strip_prefix("@.")
            && !stripped.is_empty()
        {
            return format!("{prefix} {stripped}");
        }
        return rdata;
    }

    let target_indices: &[usize] = match rtype {
        "CNAME" | "DNAME" | "NS" | "PTR" => &[0],
        "MX" | "KX" | "AFSDB" | "LP" | "SVCB" | "HTTPS" => &[1],
        "RP" => &[0, 1],
        "SRV" => &[3],
        _ => return rdata,
    };

    if !rdata.contains("@.") {
        return rdata;
    }

    let mut tokens: Vec<String> = rdata.split_whitespace().map(str::to_owned).collect();
    let mut changed = false;
    for &idx in target_indices {
        if let Some(tok) = tokens.get_mut(idx)
            && let Some(stripped) = tok.strip_prefix("@.")
            && !stripped.is_empty()
        {
            *tok = stripped.to_owned();
            changed = true;
        }
    }

    if changed { tokens.join(" ") } else { rdata }
}

/// Formats `rrsets` into a clean, RFC-1035-compliant BIND zonefile string.
pub fn format_zonefile(
    domain: &str,
    default_ttl: u32,
    rrsets: &BTreeMap<RrsetKey, RrsetData>,
) -> String {
    let domain_clean = domain.trim().trim_end_matches('.');
    let mut out = String::new();

    let _ = writeln!(out, "; Zonefile for {domain_clean} exported by rsSEC");
    let _ = writeln!(out, "$ORIGIN {domain_clean}.");
    let _ = writeln!(out, "$TTL {default_ttl}");

    if rrsets.is_empty() {
        return out;
    }

    let _ = writeln!(out);

    let owner_width = rrsets
        .keys()
        .map(|k| k.display_subname().len())
        .max()
        .unwrap_or(8)
        .clamp(8, 32);
    let type_width = rrsets
        .keys()
        .map(|k| k.rtype.len())
        .max()
        .unwrap_or(5)
        .clamp(5, 10);

    for (key, data) in rrsets {
        let owner = key.display_subname();
        for value in &data.records {
            let _ = writeln!(
                out,
                "{owner:<owner_width$} {:>6} IN {:<type_width$} {value}",
                data.ttl, key.rtype
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_bind_zonefile_and_skips_managed_records() {
        let input = r#"
; Example zonefile
$ORIGIN example.com.
$TTL 3600

@       3600 IN SOA   get.desec.io. hostmaster.desec.io. (
                        2026112001 ; serial
                        86400      ; refresh
                        7200       ; retry
                        3600000    ; expire
                        172800 )   ; minimum
@       3600 IN NS    ns1.desec.io.
@       3600 IN NS    ns2.desec.org.
@            IN A     192.0.2.1
             IN A     192.0.2.2
www     IN 7200 CNAME @
mail    3600    A     192.0.2.10
@       3600 IN MX    10 mail
_txt    3600 IN TXT   "v=DKIM1; k=rsa; p=abc123"
sub     3600 IN NS    ns1.external.net.
"#;

        let parsed = parse_zonefile(input, "example.com", 3600, true).unwrap();
        assert_eq!(parsed.rrsets.len(), 6);
        assert_eq!(parsed.record_count, 7);

        let apex_a = parsed.rrsets.get(&RrsetKey::new("", "A")).unwrap();
        assert_eq!(apex_a.ttl, 3600);
        assert_eq!(apex_a.records, vec!["192.0.2.1", "192.0.2.2"]);

        let www = parsed.rrsets.get(&RrsetKey::new("www", "CNAME")).unwrap();
        assert_eq!(www.ttl, 7200);
        assert_eq!(www.records, vec!["example.com."]);

        let mx = parsed.rrsets.get(&RrsetKey::new("", "MX")).unwrap();
        assert_eq!(mx.records, vec!["10 mail.example.com."]);

        let txt = parsed.rrsets.get(&RrsetKey::new("_txt", "TXT")).unwrap();
        assert_eq!(txt.records, vec!["\"v=DKIM1; k=rsa; p=abc123\""]);

        // Subdomain NS delegation must be kept while apex NS and SOA are skipped.
        let sub_ns = parsed.rrsets.get(&RrsetKey::new("sub", "NS")).unwrap();
        assert_eq!(sub_ns.records, vec!["ns1.external.net."]);
        assert!(!parsed.rrsets.contains_key(&RrsetKey::new("", "NS")));
        assert!(!parsed.rrsets.contains_key(&RrsetKey::new("", "SOA")));

        assert!(
            parsed
                .warnings
                .iter()
                .any(|w| w.contains("SOA") && w.contains("@ NS"))
        );
    }

    #[test]
    fn skips_out_of_zone_records_with_warning() {
        let input = r#"
example.com. 3600 IN A 192.0.2.1
other.org.   3600 IN A 198.51.100.1
"#;
        let parsed = parse_zonefile(input, "example.com", 3600, true).unwrap();
        assert_eq!(parsed.rrsets.len(), 1);
        assert!(parsed.warnings.iter().any(|w| w.contains("out-of-zone")));
    }

    #[test]
    fn clamps_or_rejects_low_ttls() {
        let input = "www 300 IN A 192.0.2.1\n";

        let clamped = parse_zonefile(input, "example.com", 3600, true).unwrap();
        assert_eq!(
            clamped.rrsets.get(&RrsetKey::new("www", "A")).unwrap().ttl,
            3600
        );
        assert!(clamped.warnings.iter().any(|w| w.contains("Raised TTL")));

        let err = parse_zonefile(input, "example.com", 3600, false).unwrap_err();
        assert!(err.contains("below domain minimum"));
    }

    #[test]
    fn rejects_include_directive() {
        let input = "$INCLUDE /etc/passwd\n";
        let err = parse_zonefile(input, "example.com", 3600, true).unwrap_err();
        assert!(err.contains("$INCLUDE"));
    }

    #[test]
    fn export_roundtrips_complex_record_types() {
        let mut rrsets = BTreeMap::new();
        rrsets.insert(
            RrsetKey::new("", "A"),
            RrsetData::new(3600, vec!["192.0.2.1".to_owned(), "192.0.2.2".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("", "AAAA"),
            RrsetData::new(3600, vec!["2001:db8::1".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("", "MX"),
            RrsetData::new(3600, vec!["10 mail.example.com.".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("", "CAA"),
            RrsetData::new(3600, vec!["0 issue \"letsencrypt.org\"".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("_sip._tcp", "SRV"),
            RrsetData::new(3600, vec!["10 5 5060 sip.example.com.".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("www", "CNAME"),
            RrsetData::new(7200, vec!["example.com.".to_owned()]),
        );
        rrsets.insert(
            RrsetKey::new("", "TXT"),
            RrsetData::new(
                3600,
                vec!["\"v=spf1 include:_spf.example.com -all\"".to_owned()],
            ),
        );
        rrsets.insert(
            RrsetKey::new("", "HTTPS"),
            RrsetData::new(3600, vec!["1 . alpn=h2,h3".to_owned()]),
        );

        let exported = format_zonefile("example.com", 3600, &rrsets);
        let parsed = parse_zonefile(&exported, "example.com", 3600, true).unwrap();

        assert_eq!(parsed.rrsets, rrsets);
        assert!(
            parsed.warnings.is_empty(),
            "warnings: {:?}",
            parsed.warnings
        );
    }

    #[test]
    fn expands_at_origin_in_rdata_and_nested_origin() {
        let input = r#"
$TTL 3600
@          IN MX  10 @
_sip._tcp  IN SRV 10 5 5060 @
$ORIGIN sub.example.com.
www        IN CNAME @
note       IN TXT "@.sub.example.com."
"#;
        let parsed = parse_zonefile(input, "example.com", 3600, true).unwrap();
        assert_eq!(
            parsed.rrsets.get(&RrsetKey::new("", "MX")).unwrap().records,
            vec!["10 example.com."]
        );
        assert_eq!(
            parsed
                .rrsets
                .get(&RrsetKey::new("_sip._tcp", "SRV"))
                .unwrap()
                .records,
            vec!["10 5 5060 example.com."]
        );
        assert_eq!(
            parsed
                .rrsets
                .get(&RrsetKey::new("www.sub", "CNAME"))
                .unwrap()
                .records,
            vec!["sub.example.com."]
        );
        // TXT values must never be altered by RDATA @-origin normalization.
        assert_eq!(
            parsed
                .rrsets
                .get(&RrsetKey::new("note.sub", "TXT"))
                .unwrap()
                .records,
            vec!["\"@.sub.example.com.\""]
        );
    }

    #[test]
    fn normalizes_imported_hex_caa_and_no_default_alpn() {
        let input = r#"
$ORIGIN example.com.
$TTL 3600
_443._tcp IN TLSA  3 1 1 DEADBEEF
@         IN SSHFP 4 2 AABBCCDD
@         IN CAA   0 ISSUE "letsencrypt.org"
@         IN HTTPS 1 . alpn="h3" no-default-alpn
"#;
        let parsed = parse_zonefile(input, "example.com", 3600, true).unwrap();
        assert_eq!(
            parsed
                .rrsets
                .get(&RrsetKey::new("_443._tcp", "TLSA"))
                .unwrap()
                .records,
            vec!["3 1 1 deadbeef"]
        );
        assert_eq!(
            parsed.rrsets.get(&RrsetKey::new("", "SSHFP")).unwrap().records,
            vec!["4 2 aabbccdd"]
        );
        assert_eq!(
            parsed.rrsets.get(&RrsetKey::new("", "CAA")).unwrap().records,
            vec!["0 issue \"letsencrypt.org\""]
        );
        assert_eq!(
            parsed.rrsets.get(&RrsetKey::new("", "HTTPS")).unwrap().records,
            vec!["1 . alpn=h3 no-default-alpn"]
        );
    }
}
