use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::model::DomainSummary;

const SERVICE_NAME: &str = "rssec";
const ACCOUNTS_INDEX_KEY: &str = "accounts";
const LEGACY_TOKEN_KEY: &str = "api-token";
const ENV_VAR_NAME: &str = "DESEC_TOKEN";

static ID_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSource {
    Keyring,
    Session,
    Env,
}

impl AccountSource {
    pub fn label(self) -> &'static str {
        match self {
            Self::Keyring => "Keyring",
            Self::Session => "Session",
            Self::Env => "ENV",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAccount {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub email: Option<String>,
    /// True when the user explicitly set or renamed the label (prevents auto-overwrite).
    #[serde(default)]
    pub custom_label: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAccounts {
    #[serde(default)]
    pub active_id: Option<String>,
    #[serde(default)]
    pub accounts: Vec<StoredAccount>,
}

impl StoredAccounts {
    /// Returns the stored active ID if it still exists, otherwise falls back to the first account.
    pub fn resolved_active_id(&self) -> Option<&str> {
        if let Some(active) = self.active_id.as_deref()
            && self.accounts.iter().any(|a| a.id == active)
        {
            return Some(active);
        }
        self.accounts.first().map(|a| a.id.as_str())
    }
}

fn token_entry_key(id: &str) -> String {
    format!("token:{id}")
}

/// Overwrites a string's buffer in-place before clearing it.
pub fn scrub_secret(secret: &mut String) {
    // SAFETY: Overwriting valid UTF-8 bytes with ASCII zero bytes (0x00) preserves valid UTF-8.
    unsafe {
        secret.as_bytes_mut().fill(0);
    }
    secret.clear();
}

/// Generates a unique local account identifier for keyring secret storage.
pub fn generate_account_id(existing_ids: &[&str]) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    loop {
        let seq = ID_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = format!("acc-{millis:x}-{seq}");
        if !existing_ids.contains(&candidate.as_str()) {
            return candidate;
        }
    }
}

/// Builds a readable fallback label when `GET /auth/account/` is unavailable (e.g. scoped tokens).
pub fn derive_fallback_label(domains: &[DomainSummary], fallback_index: usize) -> String {
    match domains {
        [] => format!("Account {fallback_index}"),
        [only] => only.name.clone(),
        [first, rest @ ..] => format!("{} (+{})", first.name, rest.len()),
    }
}

/// Loads the `DESEC_TOKEN` environment variable if set and non-empty.
pub fn load_env_token() -> Option<String> {
    std::env::var(ENV_VAR_NAME)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// Loads saved account metadata from the OS keyring, transparently migrating the legacy
/// single-token entry (`api-token`) on first run.
pub fn load_accounts() -> Result<StoredAccounts, String> {
    let entry = Entry::new(SERVICE_NAME, ACCOUNTS_INDEX_KEY)
        .map_err(|e| format!("Keyring unavailable: {e}"))?;
    match entry.get_password() {
        Ok(raw) => serde_json::from_str::<StoredAccounts>(&raw)
            .map_err(|e| format!("Failed to parse keyring accounts metadata: {e}")),
        Err(keyring::Error::NoEntry) => {
            if let Some(migrated) = migrate_legacy_token() {
                return Ok(migrated);
            }
            Ok(StoredAccounts::default())
        }
        Err(e) => Err(format!("Failed to read accounts from keyring: {e}")),
    }
}

fn migrate_legacy_token() -> Option<StoredAccounts> {
    let legacy = Entry::new(SERVICE_NAME, LEGACY_TOKEN_KEY).ok()?;
    let secret = legacy.get_password().ok()?;
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return None;
    }

    let account = StoredAccount {
        id: "default".to_owned(),
        label: "Default".to_owned(),
        email: None,
        custom_label: false,
    };
    let store = StoredAccounts {
        active_id: Some(account.id.clone()),
        accounts: vec![account],
    };

    if save_account_secret("default", trimmed).is_ok() && save_accounts(&store).is_ok() {
        let _ = legacy.delete_credential();
    }

    Some(store)
}

/// Persists account metadata (without secrets) to the OS keyring.
pub fn save_accounts(store: &StoredAccounts) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, ACCOUNTS_INDEX_KEY)
        .map_err(|e| format!("Keyring unavailable: {e}"))?;
    if store.accounts.is_empty() {
        return match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("Failed to clear keyring accounts: {e}")),
        };
    }

    let json = serde_json::to_string(store)
        .map_err(|e| format!("Failed to serialize accounts metadata: {e}"))?;
    entry
        .set_password(&json)
        .map_err(|e| format!("Failed to save accounts to keyring: {e}"))
}

/// Loads a single account's API token secret from the OS keyring.
pub fn load_account_secret(id: &str) -> Result<Option<String>, String> {
    let entry = Entry::new(SERVICE_NAME, &token_entry_key(id))
        .map_err(|e| format!("Keyring unavailable: {e}"))?;
    match entry.get_password() {
        Ok(secret) => {
            let trimmed = secret.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to read token from keyring: {e}")),
    }
}

/// Saves a single account's API token secret to the OS keyring.
pub fn save_account_secret(id: &str, token: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, &token_entry_key(id))
        .map_err(|e| format!("Keyring unavailable: {e}"))?;
    entry
        .set_password(token.trim())
        .map_err(|e| format!("Failed to save token to keyring: {e}"))
}

/// Deletes a single account's API token secret from the OS keyring.
pub fn delete_account_secret(id: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE_NAME, &token_entry_key(id))
        .map_err(|e| format!("Keyring unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete saved token: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_accounts_roundtrip_and_active_resolution() {
        let store = StoredAccounts {
            active_id: Some("acc-2".to_owned()),
            accounts: vec![
                StoredAccount {
                    id: "acc-1".to_owned(),
                    label: "alice@example.com".to_owned(),
                    email: Some("alice@example.com".to_owned()),
                    custom_label: false,
                },
                StoredAccount {
                    id: "acc-2".to_owned(),
                    label: "Work".to_owned(),
                    email: None,
                    custom_label: true,
                },
            ],
        };

        let json = serde_json::to_string(&store).unwrap();
        let parsed: StoredAccounts = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, store);
        assert_eq!(parsed.resolved_active_id(), Some("acc-2"));

        let missing_active = StoredAccounts {
            active_id: Some("gone".to_owned()),
            accounts: store.accounts,
        };
        assert_eq!(missing_active.resolved_active_id(), Some("acc-1"));
    }

    #[test]
    fn fallback_label_formats_zero_one_and_many_domains() {
        assert_eq!(derive_fallback_label(&[], 2), "Account 2");
        assert_eq!(
            derive_fallback_label(
                &[DomainSummary {
                    name: "example.com".to_owned(),
                    minimum_ttl: 3600,
                }],
                1
            ),
            "example.com"
        );
        assert_eq!(
            derive_fallback_label(
                &[
                    DomainSummary {
                        name: "a.example".to_owned(),
                        minimum_ttl: 3600,
                    },
                    DomainSummary {
                        name: "b.example".to_owned(),
                        minimum_ttl: 3600,
                    },
                    DomainSummary {
                        name: "c.example".to_owned(),
                        minimum_ttl: 3600,
                    },
                ],
                1
            ),
            "a.example (+2)"
        );
    }

    #[test]
    fn scrub_secret_zeroes_and_clears_buffer() {
        let mut secret = "super-secret-token".to_owned();
        let ptr = secret.as_ptr();
        let cap = secret.capacity();
        scrub_secret(&mut secret);
        assert!(secret.is_empty());
        let raw = unsafe { std::slice::from_raw_parts(ptr, cap.min(18)) };
        assert!(raw.iter().all(|&b| b == 0));
    }
}
