use crate::core::fs_secure::{atomic_write_secure, ensure_parent_secure};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct SessionData {
    expires_at_unix: u64,
    password: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn session_file_for(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("session")
}

pub fn write_session(session_path: &Path, password: &str, ttl: Duration) -> Result<()> {
    let data = SessionData {
        expires_at_unix: now_unix().saturating_add(ttl.as_secs()),
        password: password.to_string(),
    };
    let ron = ron::to_string(&data).context("failed to serialize session")?;
    ensure_parent_secure(session_path)?;
    atomic_write_secure(session_path, ron.as_bytes())
}

pub fn read_session(session_path: &Path) -> Result<Option<String>> {
    if !session_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(session_path).context("failed to read session file")?;
    let data: SessionData = match ron::from_str(&String::from_utf8_lossy(&bytes)) {
        Ok(v) => v,
        Err(_) => {
            // Corrupt session file; remove it
            let _ = fs::remove_file(session_path);
            return Ok(None);
        }
    };
    if now_unix() >= data.expires_at_unix {
        // Expired; delete
        let _ = fs::remove_file(session_path);
        return Ok(None);
    }
    Ok(Some(data.password))
}

pub fn clear_session(session_path: &Path) -> Result<()> {
    if session_path.exists() {
        let _ = fs::remove_file(session_path);
    }
    Ok(())
}
