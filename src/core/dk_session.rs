use crate::core::fs_secure::{atomic_write_secure, ensure_parent_secure};
use crate::core::session::SessionConstructor;
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct DerivedKeySessionFile {
    expires_at_unix: u64,
    header_fingerprint_hex: String,
    // base64-encoded derived key bytes (32 bytes)
    key_b64: String,
}

impl SessionConstructor for DerivedKeySessionFile {}

pub struct DerivedKeySession {
    pub expires_at_unix: u64,
    pub header_fingerprint_hex: String,
    pub key: SecretBox<Vec<u8>>,
}

impl core::fmt::Debug for DerivedKeySession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKeySession")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("header_fingerprint_hex", &self.header_fingerprint_hex)
            .field("key", &"<REDACTED>")
            .finish()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn dk_session_file_for(vault_path: &Path) -> PathBuf {
    vault_path.with_extension("dksession")
}

pub fn write_dk_session(
    session_path: &Path,
    header_fingerprint_hex: &str,
    key: &SecretBox<Vec<u8>>,
    ttl: Duration,
) -> Result<()> {
    let data = DerivedKeySessionFile {
        expires_at_unix: now_unix().saturating_add(ttl.as_secs()),
        header_fingerprint_hex: header_fingerprint_hex.to_string(),
        key_b64: general_purpose::STANDARD.encode(key.expose_secret()),
    };
    let ron = ron::to_string(&data).context("failed to serialize derived-key session")?;
    ensure_parent_secure(session_path)?;
    atomic_write_secure(session_path, ron.as_bytes())
}

pub fn read_dk_session(session_path: &Path) -> Result<Option<DerivedKeySession>> {
    let data = match DerivedKeySessionFile::new(session_path) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    if now_unix() >= data.expires_at_unix {
        let _ = fs::remove_file(session_path);
        return Ok(None);
    }
    let key_bytes = match general_purpose::STANDARD.decode(&data.key_b64) {
        Ok(v) => v,
        Err(_) => {
            let _ = fs::remove_file(session_path);
            return Ok(None);
        }
    };
    Ok(Some(DerivedKeySession {
        expires_at_unix: data.expires_at_unix,
        header_fingerprint_hex: data.header_fingerprint_hex,
        key: SecretBox::new(Box::new(key_bytes)),
    }))
}

pub fn clear_dk_session(session_path: &Path) -> Result<()> {
    if session_path.exists() {
        let _ = fs::remove_file(session_path);
    }
    Ok(())
}
