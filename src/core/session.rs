use crate::core::fs_secure::{atomic_write_secure, ensure_parent_secure};
use anyhow::{Context, Result};
use ron::de::SpannedError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, io};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
struct SessionData {
    expires_at_unix: u64,
    password: String,
}

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Session file not found at: {0}")]
    NotFound(String),
    #[error("Failed to read session file (Permission/IO)")]
    IoFailure(#[from] io::Error),
    #[error("Session data is corrupt and could not be parsed")]
    ParseError(#[from] SpannedError),
    #[error("Unknown session error")]
    Unknown,
}

pub trait SessionConstructor: Sized + DeserializeOwned + Debug {
    fn new(session_path: &Path) -> Result<Self, SessionError> {
        if !session_path.exists() {
            return Err(SessionError::NotFound(session_path.display().to_string()));
        }

        let bytes = fs::read(session_path).map_err(SessionError::IoFailure)?;
        match ron::from_str(&String::from_utf8_lossy(&bytes)) {
            Ok(v) => Ok(v),
            Err(e) => {
                // Corrupt session file; remove it
                let _ = fs::remove_file(session_path);
                Err(SessionError::ParseError(e))
            }
        }
    }
}

impl SessionConstructor for SessionData {}

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
    let data = match SessionData::new(session_path) {
        Ok(v) => v,
        Err(_) => return Ok(None),
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
