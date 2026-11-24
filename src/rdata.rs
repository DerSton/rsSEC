use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ipnet::{Ipv4Net, Ipv6Net};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Ipv4,
    Ipv6,
    Fqdn,
    FqdnOrDot,
    U8,
    U16,
    Hex,
    Base64,
    QuotedText,
    CaaTag,
    AplPrefixes,
    Eui48,
    Eui64,
    Hex64,
    LocLatDeg,
    LocLonDeg,
    LocMin,
    LocSec,
    LocDirNS,
    LocDirEW,
    LocAlt,
    LocSize,
    SvcbParams,
    Raw,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub label: &'static str,
    pub hint: &'static str,
    pub width: f32,
    pub kind: FieldKind,
    pub optional: bool,
}

impl FieldSpec {
    pub const fn req(label: &'static str, hint: &'static str, width: f32, kind: FieldKind) -> Self {
        Self {
            label,
            hint,
            width,
            kind,
            optional: false,
        }
    }

    pub const fn opt(label: &'static str, hint: &'static str, width: f32, kind: FieldKind) -> Self {
        Self {
            label,
            hint,
            width,
            kind,
            optional: true,
        }
    }
}

/// Returns the structured input field specifications for any DNS record type.
pub fn schema_for_type(rtype: &str) -> &'static [FieldSpec] {
    const A: &[FieldSpec] = &[FieldSpec::req("IPv4", "192.0.2.1", 260.0, FieldKind::Ipv4)];
    const AAAA: &[FieldSpec] = &[FieldSpec::req(
        "IPv6",
        "2001:db8::1",
        280.0,
        FieldKind::Ipv6,
    )];
    const TARGET: &[FieldSpec] = &[FieldSpec::req(
        "Target",
        "host.example.com.",
        320.0,
        FieldKind::Fqdn,
    )];
    const PRIO_TARGET: &[FieldSpec] = &[
        FieldSpec::req("Prio", "10", 60.0, FieldKind::U16),
        FieldSpec::req("Target", "mail.example.com.", 280.0, FieldKind::Fqdn),
    ];
    const SRV: &[FieldSpec] = &[
        FieldSpec::req("Prio", "10", 52.0, FieldKind::U16),
        FieldSpec::req("Weight", "5", 52.0, FieldKind::U16),
        FieldSpec::req("Port", "5060", 60.0, FieldKind::U16),
        FieldSpec::req("Target", "sip.example.com.", 220.0, FieldKind::FqdnOrDot),
    ];
    const TXT: &[FieldSpec] = &[FieldSpec::req(
        "Text",
        "v=spf1 -all",
        360.0,
        FieldKind::QuotedText,
    )];
    const CAA: &[FieldSpec] = &[
        FieldSpec::req("Flags", "0", 52.0, FieldKind::U8),
        FieldSpec::req("Tag", "issue", 90.0, FieldKind::CaaTag),
        FieldSpec::req("Value", "letsencrypt.org", 230.0, FieldKind::QuotedText),
    ];
    const SVCB: &[FieldSpec] = &[
        FieldSpec::req("Prio", "1", 52.0, FieldKind::U16),
        FieldSpec::req("Target", ".", 130.0, FieldKind::FqdnOrDot),
        FieldSpec::opt("Params", "alpn=\"h2,h3\"", 210.0, FieldKind::SvcbParams),
    ];
    const URI: &[FieldSpec] = &[
        FieldSpec::req("Prio", "10", 52.0, FieldKind::U16),
        FieldSpec::req("Weight", "1", 52.0, FieldKind::U16),
        FieldSpec::req(
            "Target",
            "https://example.com/",
            260.0,
            FieldKind::QuotedText,
        ),
    ];
    const TLSA: &[FieldSpec] = &[
        FieldSpec::req("Usage", "3", 48.0, FieldKind::U8),
        FieldSpec::req("Sel", "1", 48.0, FieldKind::U8),
        FieldSpec::req("Match", "1", 48.0, FieldKind::U8),
        FieldSpec::req("Data (Hex)", "0123abcd...", 230.0, FieldKind::Hex),
    ];
    const SSHFP: &[FieldSpec] = &[
        FieldSpec::req("Alg", "4", 48.0, FieldKind::U8),
        FieldSpec::req("Type", "2", 48.0, FieldKind::U8),
        FieldSpec::req("Fingerprint (Hex)", "0123abcd...", 280.0, FieldKind::Hex),
    ];
    const DS: &[FieldSpec] = &[
        FieldSpec::req("KeyTag", "12345", 64.0, FieldKind::U16),
        FieldSpec::req("Alg", "13", 48.0, FieldKind::U8),
        FieldSpec::req("Type", "2", 48.0, FieldKind::U8),
        FieldSpec::req("Digest (Hex)", "0123abcd...", 220.0, FieldKind::Hex),
    ];
    const DNSKEY: &[FieldSpec] = &[
        FieldSpec::req("Flags", "257", 56.0, FieldKind::U16),
        FieldSpec::req("Proto", "3", 48.0, FieldKind::U8),
        FieldSpec::req("Alg", "13", 48.0, FieldKind::U8),
        FieldSpec::req("Key (Base64)", "AwEAAc...", 225.0, FieldKind::Base64),
    ];
    const CERT: &[FieldSpec] = &[
        FieldSpec::req("Type", "1", 52.0, FieldKind::U16),
        FieldSpec::req("KeyTag", "12345", 64.0, FieldKind::U16),
        FieldSpec::req("Alg", "13", 48.0, FieldKind::U8),
        FieldSpec::req("Cert (Base64)", "AwEAAc...", 210.0, FieldKind::Base64),
    ];
    const B64_SINGLE: &[FieldSpec] = &[FieldSpec::req(
        "Data (Base64)",
        "mQINBF...",
        360.0,
        FieldKind::Base64,
    )];
    const NAPTR: &[FieldSpec] = &[
        FieldSpec::req("Order", "100", 50.0, FieldKind::U16),
        FieldSpec::req("Pref", "10", 50.0, FieldKind::U16),
        FieldSpec::req("Flags", "S", 50.0, FieldKind::QuotedText),
        FieldSpec::req("Service", "SIP+D2U", 85.0, FieldKind::QuotedText),
        FieldSpec::req(
            "Regexp",
            "!^.*$!sip:info@example.com!",
            125.0,
            FieldKind::QuotedText,
        ),
        FieldSpec::req("Replace", ".", 100.0, FieldKind::FqdnOrDot),
    ];
    const HINFO: &[FieldSpec] = &[
        FieldSpec::req("CPU", "X86-64", 180.0, FieldKind::QuotedText),
        FieldSpec::req("OS", "LINUX", 180.0, FieldKind::QuotedText),
    ];
    const RP: &[FieldSpec] = &[
        FieldSpec::req("Mailbox", "admin.example.com.", 190.0, FieldKind::FqdnOrDot),
        FieldSpec::req("Txt", ".", 190.0, FieldKind::FqdnOrDot),
    ];
    const EUI48: &[FieldSpec] = &[FieldSpec::req(
        "MAC (EUI-48)",
        "00-00-5e-00-53-2a",
        260.0,
        FieldKind::Eui48,
    )];
    const EUI64: &[FieldSpec] = &[FieldSpec::req(
        "MAC (EUI-64)",
        "00-00-5e-ef-10-00-00-2a",
        280.0,
        FieldKind::Eui64,
    )];
    const L32: &[FieldSpec] = &[
        FieldSpec::req("Pref", "10", 60.0, FieldKind::U16),
        FieldSpec::req("Locator32", "192.0.2.1", 260.0, FieldKind::Ipv4),
    ];
    const L64: &[FieldSpec] = &[
        FieldSpec::req("Pref", "10", 60.0, FieldKind::U16),
        FieldSpec::req(
            "ID (64-bit)",
            "2001:0db8:0000:0001",
            260.0,
            FieldKind::Hex64,
        ),
    ];
    const APL: &[FieldSpec] = &[FieldSpec::opt(
        "Prefixes",
        "1:192.0.2.0/24 !1:192.0.2.1/32",
        360.0,
        FieldKind::AplPrefixes,
    )];
    const LOC: &[FieldSpec] = &[
        FieldSpec::req("Lat°", "52", 42.0, FieldKind::LocLatDeg),
        FieldSpec::req("Lat'", "22", 42.0, FieldKind::LocMin),
        FieldSpec::req("Lat\"", "23.0", 52.0, FieldKind::LocSec),
        FieldSpec::req("N/S", "N", 36.0, FieldKind::LocDirNS),
        FieldSpec::req("Lon°", "13", 42.0, FieldKind::LocLonDeg),
        FieldSpec::req("Lon'", "24", 42.0, FieldKind::LocMin),
        FieldSpec::req("Lon\"", "30.0", 52.0, FieldKind::LocSec),
        FieldSpec::req("E/W", "E", 36.0, FieldKind::LocDirEW),
        FieldSpec::req("Alt(m)", "34.0m", 64.0, FieldKind::LocAlt),
        FieldSpec::opt("Size", "1m 10000m 10m", 110.0, FieldKind::LocSize),
    ];
    const RAW: &[FieldSpec] = &[FieldSpec::req("Value", "RDATA", 360.0, FieldKind::Raw)];

    match rtype {
        "A" => A,
        "AAAA" => AAAA,
        "CNAME" | "DNAME" | "NS" | "PTR" => TARGET,
        "MX" | "KX" | "AFSDB" | "LP" => PRIO_TARGET,
        "SRV" => SRV,
        "TXT" | "SPF" => TXT,
        "CAA" => CAA,
        "HTTPS" | "SVCB" => SVCB,
        "URI" => URI,
        "TLSA" | "SMIMEA" => TLSA,
        "SSHFP" => SSHFP,
        "DS" | "CDS" | "DLV" => DS,
        "DNSKEY" | "CDNSKEY" => DNSKEY,
        "CERT" => CERT,
        "OPENPGPKEY" | "DHCID" => B64_SINGLE,
        "NAPTR" => NAPTR,
        "HINFO" => HINFO,
        "RP" => RP,
        "EUI48" => EUI48,
        "EUI64" => EUI64,
        "L32" => L32,
        "L64" | "NID" => L64,
        "APL" => APL,
        "LOC" => LOC,
        _ => RAW,
    }
}

/// Default field values when creating a blank record of a given type.
pub fn default_fields_for_type(rtype: &str) -> Vec<String> {
    let schema = schema_for_type(rtype);
    match rtype {
        "CAA" => vec!["0".into(), "issue".into(), String::new()],
        "DNSKEY" | "CDNSKEY" => vec!["257".into(), "3".into(), "13".into(), String::new()],
        "TLSA" | "SMIMEA" => vec!["3".into(), "1".into(), "1".into(), String::new()],
        "SSHFP" => vec!["4".into(), "2".into(), String::new()],
        "DS" | "CDS" | "DLV" => vec![String::new(), "13".into(), "2".into(), String::new()],
        "HTTPS" | "SVCB" => vec!["1".into(), ".".into(), String::new()],
        "MX" | "KX" | "AFSDB" | "LP" | "L32" | "L64" | "NID" => {
            vec!["10".into(), String::new()]
        }
        "SRV" => vec!["10".into(), "5".into(), String::new(), String::new()],
        "URI" => vec!["10".into(), "1".into(), String::new()],
        "NAPTR" => vec![
            "100".into(),
            "10".into(),
            String::new(),
            String::new(),
            String::new(),
            ".".into(),
        ],
        "RP" => vec![String::new(), ".".into()],
        "LOC" => vec![
            "52".into(),
            "0".into(),
            "0.0".into(),
            "N".into(),
            "13".into(),
            "0".into(),
            "0.0".into(),
            "E".into(),
            "0.0m".into(),
            String::new(),
        ],
        _ => vec![String::new(); schema.len()],
    }
}

/// Splits an existing BIND presentation RDATA string into the fields for `rtype`.
pub fn parse_record_to_fields(rtype: &str, raw: &str) -> Vec<String> {
    let schema = schema_for_type(rtype);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return default_fields_for_type(rtype);
    }

    if schema.len() == 1 {
        let val = match schema[0].kind {
            FieldKind::QuotedText => unquote_txt(trimmed),
            _ => trimmed.to_owned(),
        };
        return vec![val];
    }

    let tokens = tokenize_rdata(trimmed);
    let mut out = Vec::with_capacity(schema.len());

    for (idx, spec) in schema.iter().enumerate() {
        let is_last = idx + 1 == schema.len();
        let val = if is_last {
            if idx < tokens.len() {
                let joined = tokens[idx..].join(" ");
                if spec.kind == FieldKind::QuotedText {
                    unquote_txt(&joined)
                } else {
                    joined
                }
            } else {
                String::new()
            }
        } else if let Some(tok) = tokens.get(idx) {
            if spec.kind == FieldKind::QuotedText {
                unquote_txt(tok)
            } else {
                tok.clone()
            }
        } else {
            String::new()
        };
        out.push(val);
    }

    out
}

/// Validates structured field inputs for `rtype` and formats them into canonical BIND RDATA.
pub fn validate_and_format(rtype: &str, fields: &[String]) -> Result<String, String> {
    let schema = schema_for_type(rtype);
    if fields.len() != schema.len() {
        return Err("Internal field count mismatch.".to_owned());
    }

    // For APL, an empty prefix list is explicitly allowed by RFC 3123.
    let mut parts = Vec::with_capacity(schema.len());

    for (spec, raw_val) in schema.iter().zip(fields.iter()) {
        let val = raw_val.trim();
        if val.is_empty() {
            if spec.optional {
                continue;
            }
            return Err(format!("{} is required.", spec.label));
        }

        let formatted = validate_field(spec, val)?;
        if !formatted.is_empty() {
            parts.push(formatted);
        }
    }

    Ok(parts.join(" "))
}

fn validate_field(spec: &FieldSpec, val: &str) -> Result<String, String> {
    let label = spec.label;
    match spec.kind {
        FieldKind::Ipv4 => {
            let ip =
                Ipv4Addr::from_str(val).map_err(|_| format!("{label}: invalid IPv4 address."))?;
            Ok(ip.to_string())
        }
        FieldKind::Ipv6 => {
            let ip =
                Ipv6Addr::from_str(val).map_err(|_| format!("{label}: invalid IPv6 address."))?;
            Ok(ip.to_string())
        }
        FieldKind::Fqdn => validate_fqdn(label, val, false),
        FieldKind::FqdnOrDot => validate_fqdn(label, val, true),
        FieldKind::U8 => {
            let n: u8 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..255."))?;
            Ok(n.to_string())
        }
        FieldKind::U16 => {
            let n: u16 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..65535."))?;
            Ok(n.to_string())
        }
        FieldKind::Hex => {
            let cleaned: String = val.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if cleaned.is_empty() {
                return Err(format!("{label}: hex data required."));
            }
            hex::decode(&cleaned).map_err(|_| {
                format!("{label}: invalid hex string (even number of 0-9a-f digits required).")
            })?;
            Ok(cleaned.to_ascii_lowercase())
        }
        FieldKind::Base64 => {
            let cleaned: String = val.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if cleaned.is_empty() {
                return Err(format!("{label}: Base64 data required."));
            }
            BASE64_STANDARD
                .decode(&cleaned)
                .map_err(|_| format!("{label}: invalid Base64 string."))?;
            Ok(cleaned)
        }
        FieldKind::QuotedText => Ok(quote_txt(val)),
        FieldKind::CaaTag => {
            if !val.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(format!(
                    "{label}: must be alphanumeric (e.g. issue, issuewild, iodef)."
                ));
            }
            Ok(val.to_ascii_lowercase())
        }
        FieldKind::Eui48 => validate_eui(label, val, 6),
        FieldKind::Eui64 => validate_eui(label, val, 8),
        FieldKind::Hex64 => {
            let groups: Vec<&str> = val.split(':').collect();
            if groups.len() != 4
                || !groups.iter().all(|g| {
                    !g.is_empty() && g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit())
                })
            {
                return Err(format!(
                    "{label}: expected 4 hex groups separated by ':' (e.g. 2001:0db8:0000:0001)."
                ));
            }
            Ok(groups.join(":"))
        }
        FieldKind::AplPrefixes => {
            let mut out = Vec::new();
            for item in val.split_whitespace() {
                let rest = item.strip_prefix('!').unwrap_or(item);
                let Some((afi, net)) = rest.split_once(':') else {
                    return Err(format!(
                        "{label}: invalid item '{item}' (expected [!]1:IPv4/prefix or [!]2:IPv6/prefix)."
                    ));
                };
                match afi {
                    "1" => {
                        Ipv4Net::from_str(net)
                            .map_err(|_| format!("{label}: invalid IPv4 CIDR '{net}'."))?;
                    }
                    "2" => {
                        Ipv6Net::from_str(net)
                            .map_err(|_| format!("{label}: invalid IPv6 CIDR '{net}'."))?;
                    }
                    _ => {
                        return Err(format!(
                            "{label}: address family must be 1 (IPv4) or 2 (IPv6)."
                        ));
                    }
                }
                out.push(item.to_owned());
            }
            Ok(out.join(" "))
        }
        FieldKind::LocLatDeg => {
            let d: u8 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..90."))?;
            if d > 90 {
                return Err(format!("{label}: latitude degrees must be 0..90."));
            }
            Ok(d.to_string())
        }
        FieldKind::LocLonDeg => {
            let d: u8 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..180."))?;
            if d > 180 {
                return Err(format!("{label}: longitude degrees must be 0..180."));
            }
            Ok(d.to_string())
        }
        FieldKind::LocMin => {
            let m: u8 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..59."))?;
            if m > 59 {
                return Err(format!("{label}: minutes must be 0..59."));
            }
            Ok(m.to_string())
        }
        FieldKind::LocSec => {
            let s: f64 = val
                .parse()
                .map_err(|_| format!("{label}: must be 0..59.999."))?;
            if !(0.0..60.0).contains(&s) {
                return Err(format!("{label}: seconds must be 0..59.999."));
            }
            Ok(val.to_owned())
        }
        FieldKind::LocDirNS => {
            let u = val.to_ascii_uppercase();
            if u != "N" && u != "S" {
                return Err(format!("{label}: must be N or S."));
            }
            Ok(u)
        }
        FieldKind::LocDirEW => {
            let u = val.to_ascii_uppercase();
            if u != "E" && u != "W" {
                return Err(format!("{label}: must be E or W."));
            }
            Ok(u)
        }
        FieldKind::LocAlt => {
            let num_part = val.strip_suffix('m').unwrap_or(val);
            let alt: f64 = num_part
                .parse()
                .map_err(|_| format!("{label}: invalid altitude in meters (e.g. 34.0m)."))?;
            if !(-100_000.0..=42_849_672.95).contains(&alt) {
                return Err(format!("{label}: altitude out of RFC 1876 range."));
            }
            Ok(format!("{num_part}m"))
        }
        FieldKind::LocSize => {
            for tok in val.split_whitespace() {
                let num = tok.strip_suffix('m').unwrap_or(tok);
                let v: f64 = num
                    .parse()
                    .map_err(|_| format!("{label}: invalid meter measurement '{tok}'."))?;
                if v < 0.0 {
                    return Err(format!("{label}: measurement cannot be negative."));
                }
            }
            Ok(val.split_whitespace().collect::<Vec<_>>().join(" "))
        }
        FieldKind::SvcbParams => {
            for tok in tokenize_rdata(val) {
                if let Some((k, _)) = tok.split_once('=') {
                    if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                        return Err(format!("{label}: invalid param key '{k}'."));
                    }
                } else if !tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(format!("{label}: invalid param '{tok}'."));
                }
            }
            Ok(val.to_owned())
        }
        FieldKind::Raw => Ok(val.to_owned()),
    }
}

fn validate_fqdn(label: &str, val: &str, allow_root_dot: bool) -> Result<String, String> {
    if val == "." {
        if allow_root_dot {
            return Ok(".".to_owned());
        }
        return Err(format!(
            "{label}: root '.' is not allowed for this record type."
        ));
    }

    // Automatically append the trailing dot required by deSEC / BIND if the user omitted it.
    let with_dot = if val.ends_with('.') {
        val.to_owned()
    } else {
        format!("{val}.")
    };

    let without_trailing = with_dot.strip_suffix('.').unwrap_or(&with_dot);
    if without_trailing.is_empty() || with_dot.len() > 254 {
        return Err(format!("{label}: invalid domain name length."));
    }

    for part in without_trailing.split('.') {
        if part.is_empty() || part.len() > 63 {
            return Err(format!("{label}: empty or overlong label in '{val}'."));
        }
        if part.starts_with('-') || part.ends_with('-') {
            return Err(format!(
                "{label}: label '{part}' cannot start or end with '-'."
            ));
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "{label}: invalid character in '{part}' (use ASCII/punycode labels)."
            ));
        }
    }

    Ok(with_dot)
}

fn validate_eui(label: &str, val: &str, expected_octets: usize) -> Result<String, String> {
    let normalized = val.replace(':', "-");
    let parts: Vec<&str> = normalized.split('-').collect();
    if parts.len() != expected_octets
        || !parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(format!(
            "{label}: expected {expected_octets} hex byte pairs separated by '-' (e.g. 00-00-5e-...)."
        ));
    }
    Ok(parts
        .into_iter()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-"))
}

/// Formats a text value as a quoted BIND character-string (or leaves valid multi-segment quotes intact).
fn quote_txt(input: &str) -> String {
    let trimmed = input.trim();
    // If the user already entered properly quoted string(s), keep them.
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return trimmed.to_owned();
    }
    let escaped = trimmed.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Strips outer quotes and unescapes a single BIND quoted string for comfortable editing.
fn unquote_txt(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        let inner = &trimmed[1..trimmed.len() - 1];
        // Only strip outer quotes if there are no unescaped middle quotes (multi-segment TXT).
        let mut chars = inner.chars().peekable();
        let mut has_unescaped_quote = false;
        while let Some(c) = chars.next() {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '"' {
                has_unescaped_quote = true;
                break;
            }
        }
        if !has_unescaped_quote {
            return inner.replace("\\\"", "\"").replace("\\\\", "\\");
        }
    }
    trimmed.to_owned()
}

/// Splits a BIND RDATA line into whitespace-delimited tokens while keeping quoted segments together.
pub(crate) fn tokenize_rdata(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' && in_quotes {
            current.push(c);
            if let Some(next) = chars.next() {
                current.push(next);
            }
        } else if c == '"' {
            in_quotes = !in_quotes;
            current.push(c);
        } else if c.is_ascii_whitespace() && !in_quotes {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Returns a DNS-canonical representation of an RDATA string for equivalence diffing.
///
/// Purely cosmetic presentation differences (e.g. hex/hostname/IPv6 casing, whitespace in
/// hex/Base64, RFC 9460 SvcParam ordering and quoting, redundant BIND escapes inside quotes)
/// normalize to the same string, while DNS-significant ordering (such as multi-chunk `TXT`/`SPF`
/// strings, `ALPN` preference order, and `APL` prefix order) is strictly preserved.
pub fn canonical_record(rtype: &str, raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    match rtype.trim().to_ascii_uppercase().as_str() {
        "A" => Ipv4Addr::from_str(trimmed)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| trimmed.to_owned()),
        "AAAA" => Ipv6Addr::from_str(trimmed)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| trimmed.to_owned()),
        "CNAME" | "DNAME" | "NS" | "PTR" => canonicalize_fqdn(trimmed),
        "MX" | "KX" | "AFSDB" | "LP" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 2 {
                format!(
                    "{} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_fqdn(&tokens[1])
                )
            } else {
                tokens.join(" ")
            }
        }
        "SRV" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 4 {
                format!(
                    "{} {} {} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_u16(&tokens[1]),
                    canonicalize_u16(&tokens[2]),
                    canonicalize_fqdn(&tokens[3])
                )
            } else {
                tokens.join(" ")
            }
        }
        "RP" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 2 {
                format!(
                    "{} {}",
                    canonicalize_fqdn(&tokens[0]),
                    canonicalize_fqdn(&tokens[1])
                )
            } else {
                tokens.join(" ")
            }
        }
        "TXT" | "SPF" => {
            let tokens = tokenize_rdata(trimmed);
            tokens
                .iter()
                .map(|t| canonicalize_single_charstr(t))
                .collect::<Vec<_>>()
                .join(" ")
        }
        "CAA" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 3 {
                let value = tokens[2..].join(" ");
                format!(
                    "{} {} {}",
                    canonicalize_u8(&tokens[0]),
                    tokens[1].to_ascii_lowercase(),
                    canonicalize_single_charstr(&value)
                )
            } else {
                tokens.join(" ")
            }
        }
        "HTTPS" | "SVCB" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 2 {
                let prio = canonicalize_u16(&tokens[0]);
                let target = canonicalize_fqdn(&tokens[1]);
                if tokens.len() == 2 {
                    format!("{prio} {target}")
                } else {
                    format!("{prio} {target} {}", canonicalize_svcb_params(&tokens[2..]))
                }
            } else {
                tokens.join(" ")
            }
        }
        "URI" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 3 {
                format!(
                    "{} {} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_u16(&tokens[1]),
                    canonicalize_single_charstr(&tokens[2])
                )
            } else {
                tokens.join(" ")
            }
        }
        "TLSA" | "SMIMEA" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 4 {
                format!(
                    "{} {} {} {}",
                    canonicalize_u8(&tokens[0]),
                    canonicalize_u8(&tokens[1]),
                    canonicalize_u8(&tokens[2]),
                    canonicalize_hex(&tokens[3..])
                )
            } else {
                tokens.join(" ")
            }
        }
        "SSHFP" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 3 {
                format!(
                    "{} {} {}",
                    canonicalize_u8(&tokens[0]),
                    canonicalize_u8(&tokens[1]),
                    canonicalize_hex(&tokens[2..])
                )
            } else {
                tokens.join(" ")
            }
        }
        "DS" | "CDS" | "DLV" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 4 {
                format!(
                    "{} {} {} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_u8(&tokens[1]),
                    canonicalize_u8(&tokens[2]),
                    canonicalize_hex(&tokens[3..])
                )
            } else {
                tokens.join(" ")
            }
        }
        "DNSKEY" | "CDNSKEY" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 4 {
                format!(
                    "{} {} {} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_u8(&tokens[1]),
                    canonicalize_u8(&tokens[2]),
                    canonicalize_base64(&tokens[3..])
                )
            } else {
                tokens.join(" ")
            }
        }
        "CERT" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() >= 4 {
                format!(
                    "{} {} {} {}",
                    tokens[0].to_ascii_uppercase(),
                    canonicalize_u16(&tokens[1]),
                    canonicalize_u8(&tokens[2]),
                    canonicalize_base64(&tokens[3..])
                )
            } else {
                tokens.join(" ")
            }
        }
        "OPENPGPKEY" | "DHCID" => canonicalize_base64(&tokenize_rdata(trimmed)),
        "NAPTR" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 6 {
                format!(
                    "{} {} {} {} {} {}",
                    canonicalize_u16(&tokens[0]),
                    canonicalize_u16(&tokens[1]),
                    canonicalize_single_charstr(&tokens[2]),
                    canonicalize_single_charstr(&tokens[3]),
                    canonicalize_single_charstr(&tokens[4]),
                    canonicalize_fqdn(&tokens[5])
                )
            } else {
                tokens.join(" ")
            }
        }
        "HINFO" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 2 {
                format!(
                    "{} {}",
                    canonicalize_single_charstr(&tokens[0]),
                    canonicalize_single_charstr(&tokens[1])
                )
            } else {
                tokens.join(" ")
            }
        }
        "EUI48" | "EUI64" => trimmed.replace(':', "-").to_ascii_lowercase(),
        "L32" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 2 {
                let ip = Ipv4Addr::from_str(&tokens[1])
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|_| tokens[1].clone());
                format!("{} {ip}", canonicalize_u16(&tokens[0]))
            } else {
                tokens.join(" ")
            }
        }
        "L64" | "NID" => {
            let tokens = tokenize_rdata(trimmed);
            if tokens.len() == 2 {
                format!(
                    "{} {}",
                    canonicalize_u16(&tokens[0]),
                    tokens[1].to_ascii_lowercase()
                )
            } else {
                tokens.join(" ")
            }
        }
        "APL" => canonicalize_apl(&tokenize_rdata(trimmed)),
        "LOC" => canonicalize_loc(&tokenize_rdata(trimmed)),
        _ => tokenize_rdata(trimmed).join(" "),
    }
}

/// Returns `true` if two RDATA presentation strings for `rtype` represent the same DNS record.
pub fn records_equivalent(rtype: &str, a: &str, b: &str) -> bool {
    a == b || canonical_record(rtype, a) == canonical_record(rtype, b)
}

/// Returns `true` if two editor field inputs of `kind` represent the same DNS field value.
pub fn field_values_equivalent(kind: FieldKind, a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a == b {
        return true;
    }
    match kind {
        FieldKind::Ipv4 => Ipv4Addr::from_str(a).ok() == Ipv4Addr::from_str(b).ok() && Ipv4Addr::from_str(a).is_ok(),
        FieldKind::Ipv6 => Ipv6Addr::from_str(a).ok() == Ipv6Addr::from_str(b).ok() && Ipv6Addr::from_str(a).is_ok(),
        FieldKind::Fqdn | FieldKind::FqdnOrDot => canonicalize_fqdn(a) == canonicalize_fqdn(b),
        FieldKind::U8 => a.parse::<u8>().ok().is_some_and(|n| b.parse::<u8>().ok() == Some(n)),
        FieldKind::U16 => a.parse::<u16>().ok().is_some_and(|n| b.parse::<u16>().ok() == Some(n)),
        FieldKind::Hex => {
            let ca: String = a.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let cb: String = b.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            ca.eq_ignore_ascii_case(&cb)
        }
        FieldKind::Base64 => {
            let ca: String = a.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            let cb: String = b.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            ca == cb
        }
        FieldKind::QuotedText => {
            let qa = quote_txt(a);
            let qb = quote_txt(b);
            canonical_record("TXT", &qa) == canonical_record("TXT", &qb)
        }
        FieldKind::CaaTag | FieldKind::Hex64 | FieldKind::LocDirNS | FieldKind::LocDirEW => {
            a.eq_ignore_ascii_case(b)
        }
        FieldKind::Eui48 | FieldKind::Eui64 => {
            a.replace(':', "-").eq_ignore_ascii_case(&b.replace(':', "-"))
        }
        FieldKind::AplPrefixes => {
            canonicalize_apl(&tokenize_rdata(a)) == canonicalize_apl(&tokenize_rdata(b))
        }
        FieldKind::SvcbParams => {
            canonicalize_svcb_params(&tokenize_rdata(a))
                == canonicalize_svcb_params(&tokenize_rdata(b))
        }
        FieldKind::LocLatDeg | FieldKind::LocLonDeg | FieldKind::LocMin => {
            a.parse::<u8>().ok().is_some_and(|n| b.parse::<u8>().ok() == Some(n))
        }
        FieldKind::LocSec => a.parse::<f64>().ok().is_some_and(|va| {
            b.parse::<f64>()
                .ok()
                .is_some_and(|vb| (va - vb).abs() < 1e-4)
        }),
        FieldKind::LocAlt => parse_loc_meters(a).is_some_and(|va| {
            parse_loc_meters(b).is_some_and(|vb| (va - vb).abs() < 1e-3)
        }),
        FieldKind::LocSize => {
            let fa: Option<Vec<f64>> = a.split_whitespace().map(parse_loc_meters).collect();
            let fb: Option<Vec<f64>> = b.split_whitespace().map(parse_loc_meters).collect();
            match (fa, fb) {
                (Some(va), Some(vb)) if va.len() == vb.len() => va
                    .iter()
                    .zip(vb.iter())
                    .all(|(x, y)| (x - y).abs() < 1e-3),
                _ => false,
            }
        }
        FieldKind::Raw => false,
    }
}

fn canonicalize_fqdn(tok: &str) -> String {
    tok.trim().to_ascii_lowercase()
}

fn canonicalize_u8(tok: &str) -> String {
    tok.parse::<u8>()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| tok.to_owned())
}

fn canonicalize_u16(tok: &str) -> String {
    tok.parse::<u16>()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| tok.to_owned())
}

fn canonicalize_hex(tokens: &[String]) -> String {
    tokens
        .iter()
        .flat_map(|t| t.chars())
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn canonicalize_base64(tokens: &[String]) -> String {
    tokens
        .iter()
        .flat_map(|t| t.chars())
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

fn canonicalize_single_charstr(token: &str) -> String {
    encode_canonical_charstr(&decode_bind_charstr(token))
}

fn decode_bind_charstr(token: &str) -> Vec<u8> {
    let inner = token
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(token);
    let mut out = Vec::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            let mut look = chars.clone();
            let d1 = look.next().and_then(|ch| ch.to_digit(10));
            let d2 = look.next().and_then(|ch| ch.to_digit(10));
            let d3 = look.next().and_then(|ch| ch.to_digit(10));
            if let (Some(a), Some(b), Some(d)) = (d1, d2, d3)
                && let Ok(byte) = u8::try_from(a * 100 + b * 10 + d)
            {
                let _ = chars.next();
                let _ = chars.next();
                let _ = chars.next();
                out.push(byte);
            } else if let Some(next) = chars.next() {
                let mut buf = [0u8; 4];
                out.extend_from_slice(next.encode_utf8(&mut buf).as_bytes());
            } else {
                out.push(b'\\');
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    out
}

fn encode_canonical_charstr(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
    out.push('"');
    out
}

fn canonicalize_svcb_key(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "key0" | "mandatory" => "mandatory".to_owned(),
        "key1" | "alpn" => "alpn".to_owned(),
        "key2" | "no-default-alpn" | "nodefaultalpn" => "no-default-alpn".to_owned(),
        "key3" | "port" => "port".to_owned(),
        "key4" | "ipv4hint" => "ipv4hint".to_owned(),
        "key5" | "ech" => "ech".to_owned(),
        "key6" | "ipv6hint" => "ipv6hint".to_owned(),
        "key7" | "dohpath" => "dohpath".to_owned(),
        "key8" | "ohttp" => "ohttp".to_owned(),
        other => other.to_owned(),
    }
}

fn canonicalize_svcb_params(tokens: &[String]) -> String {
    let mut normalized: Vec<(String, String)> = tokens
        .iter()
        .map(|tok| {
            let Some((raw_k, raw_v)) = tok.split_once('=') else {
                let k = canonicalize_svcb_key(tok);
                return (k.clone(), k);
            };
            let key = canonicalize_svcb_key(raw_k);
            let decoded = decode_bind_charstr(raw_v);
            let val_str = String::from_utf8_lossy(&decoded);

            let canon_val = match key.as_str() {
                "mandatory" => {
                    let mut keys: Vec<String> = val_str
                        .split(',')
                        .map(|item| canonicalize_svcb_key(item.trim()))
                        .collect();
                    keys.sort_unstable();
                    keys.join(",")
                }
                "port" => canonicalize_u16(val_str.trim()),
                "ipv4hint" => val_str
                    .split(',')
                    .map(|item| {
                        let t = item.trim();
                        Ipv4Addr::from_str(t)
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|_| t.to_owned())
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                "ipv6hint" => val_str
                    .split(',')
                    .map(|item| {
                        let t = item.trim();
                        Ipv6Addr::from_str(t)
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|_| t.to_owned())
                    })
                    .collect::<Vec<_>>()
                    .join(","),
                "ech" => val_str
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect(),
                // Preserve ALPN list order (RFC 9460 §7.1.1 preference order) and opaque values.
                _ => encode_canonical_charstr(&decoded),
            };

            (key.clone(), format!("{key}={canon_val}"))
        })
        .collect();

    // RFC 9460 §2.2: SvcParams are unordered in presentation format (wire format sorts by key).
    normalized.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    normalized
        .into_iter()
        .map(|(_, formatted)| formatted)
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonicalize_apl(tokens: &[String]) -> String {
    // RFC 3123 §4: Prefix order inside an APL record is DNS-significant; preserve order.
    tokens
        .iter()
        .map(|item| {
            let (neg, rest) = match item.strip_prefix('!') {
                Some(r) => ("!", r),
                None => ("", item.as_str()),
            };
            let Some((afi, net)) = rest.split_once(':') else {
                return item.clone();
            };
            let normalized_net = match afi {
                "1" => Ipv4Net::from_str(net)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| net.to_owned()),
                "2" => Ipv6Net::from_str(net)
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| net.to_owned()),
                _ => net.to_owned(),
            };
            format!("{neg}{afi}:{normalized_net}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_loc_meters(tok: &str) -> Option<f64> {
    tok.strip_suffix('m')
        .or_else(|| tok.strip_suffix('M'))
        .unwrap_or(tok)
        .parse::<f64>()
        .ok()
}

fn canonicalize_loc(tokens: &[String]) -> String {
    let parse_coord =
        |idx: &mut usize, dirs: [&'static str; 2]| -> Option<(u8, u8, f64, &'static str)> {
        let deg: u8 = tokens.get(*idx)?.parse().ok()?;
        *idx += 1;
        let next = tokens.get(*idx)?;
        if next.eq_ignore_ascii_case(dirs[0]) {
            *idx += 1;
            return Some((deg, 0, 0.0, dirs[0]));
        }
        if next.eq_ignore_ascii_case(dirs[1]) {
            *idx += 1;
            return Some((deg, 0, 0.0, dirs[1]));
        }
        let min: u8 = next.parse().ok()?;
        *idx += 1;
        let next = tokens.get(*idx)?;
        if next.eq_ignore_ascii_case(dirs[0]) {
            *idx += 1;
            return Some((deg, min, 0.0, dirs[0]));
        }
        if next.eq_ignore_ascii_case(dirs[1]) {
            *idx += 1;
            return Some((deg, min, 0.0, dirs[1]));
        }
        let sec: f64 = next.parse().ok()?;
        *idx += 1;
        let dir_tok = tokens.get(*idx)?;
        let dir = if dir_tok.eq_ignore_ascii_case(dirs[0]) {
            dirs[0]
        } else if dir_tok.eq_ignore_ascii_case(dirs[1]) {
            dirs[1]
        } else {
            return None;
        };
        *idx += 1;
        Some((deg, min, sec, dir))
    };

    let mut idx = 0;
    let Some((lat_d, lat_m, lat_s, ns)) = parse_coord(&mut idx, ["N", "S"]) else {
        return tokens.join(" ");
    };
    let Some((lon_d, lon_m, lon_s, ew)) = parse_coord(&mut idx, ["E", "W"]) else {
        return tokens.join(" ");
    };
    let Some(alt) = tokens.get(idx).and_then(|t| parse_loc_meters(t)) else {
        return tokens.join(" ");
    };
    idx += 1;
    let size = tokens
        .get(idx)
        .and_then(|t| parse_loc_meters(t))
        .unwrap_or(1.0);
    let hp = tokens
        .get(idx + 1)
        .and_then(|t| parse_loc_meters(t))
        .unwrap_or(10_000.0);
    let vp = tokens
        .get(idx + 2)
        .and_then(|t| parse_loc_meters(t))
        .unwrap_or(10.0);

    format!(
        "{lat_d} {lat_m} {lat_s:.3} {ns} {lon_d} {lon_m} {lon_s:.3} {ew} {alt:.2}m {size:.2}m {hp:.2}m {vp:.2}m"
    )
}
