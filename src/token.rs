use keyring::Entry;

const SERVICE_NAME: &str = "rssec";
const ACCOUNT_NAME: &str = "api-token";
const ENV_VAR_NAME: &str = "DESEC_TOKEN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    Keyring,
    Env,
}

#[derive(Debug, Clone)]
pub struct LoadedToken {
    pub token: String,
    pub source: TokenSource,
}

/// Loads the deSEC API token from the OS keyring first, falling back to `DESEC_TOKEN`.
pub fn load_token() -> Option<LoadedToken> {
    if let Ok(entry) = Entry::new(SERVICE_NAME, ACCOUNT_NAME)
        && let Ok(secret) = entry.get_password()
    {
        let trimmed = secret.trim();
        if !trimmed.is_empty() {
            return Some(LoadedToken {
                token: trimmed.to_owned(),
                source: TokenSource::Keyring,
            });
        }
    }

    if let Ok(env_val) = std::env::var(ENV_VAR_NAME) {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return Some(LoadedToken {
                token: trimmed.to_owned(),
                source: TokenSource::Env,
            });
        }
    }

    None
}

/// Saves the deSEC API token to the OS keyring.
pub fn save_token(token: &str) -> Result<(), String> {
    let entry =
        Entry::new(SERVICE_NAME, ACCOUNT_NAME).map_err(|e| format!("Keyring unavailable: {e}"))?;
    entry
        .set_password(token.trim())
        .map_err(|e| format!("Failed to save token to keyring: {e}"))
}

/// Deletes any saved deSEC API token from the OS keyring.
pub fn delete_token() -> Result<(), String> {
    let entry =
        Entry::new(SERVICE_NAME, ACCOUNT_NAME).map_err(|e| format!("Keyring unavailable: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Failed to delete saved token: {e}")),
    }
}
