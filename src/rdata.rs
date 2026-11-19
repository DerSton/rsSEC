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
fn tokenize_rdata(input: &str) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RECORD_TYPES;

    #[test]
    fn every_supported_record_type_has_schema_and_defaults() {
        for &rt in RECORD_TYPES {
            let schema = schema_for_type(rt);
            let defaults = default_fields_for_type(rt);
            assert!(!schema.is_empty(), "empty schema for {rt}");
            assert_eq!(
                schema.len(),
                defaults.len(),
                "default length mismatch for {rt}"
            );
        }
    }

    #[test]
    fn validates_and_formats_common_and_advanced_types() {
        // A
        assert_eq!(
            validate_and_format("A", &["192.0.2.10".into()]).unwrap(),
            "192.0.2.10"
        );
        assert!(validate_and_format("A", &["999.1.1.1".into()]).is_err());

        // AAAA
        assert_eq!(
            validate_and_format("AAAA", &["2001:db8::1".into()]).unwrap(),
            "2001:db8::1"
        );

        // CNAME auto-appends trailing dot
        assert_eq!(
            validate_and_format("CNAME", &["target.example.com".into()]).unwrap(),
            "target.example.com."
        );

        // MX
        assert_eq!(
            validate_and_format("MX", &["10".into(), "mail.example.com".into()]).unwrap(),
            "10 mail.example.com."
        );

        // SRV
        assert_eq!(
            validate_and_format(
                "SRV",
                &[
                    "10".into(),
                    "5".into(),
                    "5060".into(),
                    "sip.example.com.".into()
                ]
            )
            .unwrap(),
            "10 5 5060 sip.example.com."
        );

        // TXT auto-quotes
        assert_eq!(
            validate_and_format("TXT", &["v=spf1 -all".into()]).unwrap(),
            "\"v=spf1 -all\""
        );

        // CAA
        assert_eq!(
            validate_and_format(
                "CAA",
                &["0".into(), "issue".into(), "letsencrypt.org".into()]
            )
            .unwrap(),
            "0 issue \"letsencrypt.org\""
        );

        // TLSA validates hex
        assert_eq!(
            validate_and_format(
                "TLSA",
                &["3".into(), "1".into(), "1".into(), "0123ABCD".into()]
            )
            .unwrap(),
            "3 1 1 0123abcd"
        );
        assert!(
            validate_and_format(
                "TLSA",
                &["3".into(), "1".into(), "1".into(), "not-hex".into()]
            )
            .is_err()
        );

        // DNSKEY validates Base64
        assert_eq!(
            validate_and_format(
                "DNSKEY",
                &["257".into(), "3".into(), "13".into(), "AQIDBA==".into()]
            )
            .unwrap(),
            "257 3 13 AQIDBA=="
        );

        // EUI48 normalizes colons to hyphens
        assert_eq!(
            validate_and_format("EUI48", &["00:00:5e:00:53:2a".into()]).unwrap(),
            "00-00-5e-00-53-2a"
        );

        // APL validates CIDR prefixes
        assert_eq!(
            validate_and_format("APL", &["1:192.0.2.0/24 !2:2001:db8::/32".into()]).unwrap(),
            "1:192.0.2.0/24 !2:2001:db8::/32"
        );
    }

    #[test]
    fn round_trips_existing_records_into_fields() {
        let caa_fields = parse_record_to_fields("CAA", "0 issue \"letsencrypt.org\"");
        assert_eq!(caa_fields, vec!["0", "issue", "letsencrypt.org"]);
        assert_eq!(
            validate_and_format("CAA", &caa_fields).unwrap(),
            "0 issue \"letsencrypt.org\""
        );

        let https_fields = parse_record_to_fields("HTTPS", "1 . alpn=\"h2,h3\" ipv4hint=192.0.2.1");
        assert_eq!(
            https_fields,
            vec!["1", ".", "alpn=\"h2,h3\" ipv4hint=192.0.2.1"]
        );
        assert_eq!(
            validate_and_format("HTTPS", &https_fields).unwrap(),
            "1 . alpn=\"h2,h3\" ipv4hint=192.0.2.1"
        );
    }
}
