use crate::filesystem::secure::{atomic_write_secure, ensure_parent_secure};
use anyhow::{Context, Result};
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

pub fn save<T: Serialize>(path: &Path, data: &T, ttl: Duration) -> Result<()> {
    let envelope = SessionEnvelope {
        expires_at_unix: now_unix().saturating_add(ttl.as_secs()),
        data,
    };
    let ron = ron::to_string(&envelope).context("failed to serialize session")?;
    ensure_parent_secure(path)?;
    atomic_write_secure(path, ron.as_bytes())
}

pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).context("Failed to read session file")?;
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

pub fn clear(path: &Path) -> Result<()> {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    Ok(())
}
