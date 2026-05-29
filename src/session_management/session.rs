use crate::domain::VaultResult;
use crate::error::KeviError;
use crate::filesystem::secure::{atomic_write_secure, ensure_parent_secure};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct SessionEnvelope<T> {
    expires_at_unix: u64,
    data: T,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn save<T: Serialize>(path: &Path, data: &T, ttl: Duration) -> VaultResult<()> {
    let envelope = SessionEnvelope {
        expires_at_unix: now_unix().saturating_add(ttl.as_secs()),
        data,
    };
    let ron = ron::to_string(&envelope).map_err(|e| KeviError::common(e.to_string()))?;
    ensure_parent_secure(path).map_err(|e| KeviError::io(e.to_string()))?;
    atomic_write_secure(path, ron.as_bytes()).map_err(|e| KeviError::io(e.to_string()))?;
    Ok(())
}

pub fn load<T: DeserializeOwned>(path: &Path) -> VaultResult<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        fs::read(path).map_err(|e| KeviError::io(format!("Failed to read session file: {e}")))?;
    let content = String::from_utf8_lossy(&bytes);

    let envelope: SessionEnvelope<T> = match ron::from_str(&content) {
        Ok(v) => v,
        Err(_) => {
            // Corrupt or invalid format; clear it
            let _ = fs::remove_file(path);
            return Ok(None);
        }
    };

    if now_unix() >= envelope.expires_at_unix {
        let _ = fs::remove_file(path);
        return Ok(None);
    }

    Ok(Some(envelope.data))
}

pub fn clear(path: &Path) -> VaultResult<()> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    Ok(())
}
