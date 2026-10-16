use crate::domain::VaultResult;
#[cfg(all(unix, not(target_os = "macos")))]
use crate::error::KeviError;
use serde::de::DeserializeOwned;
#[cfg(all(unix, not(target_os = "macos")))]
use serde::Deserialize;
use serde::Serialize;
#[cfg(all(unix, not(target_os = "macos")))]
use std::fs;
use std::path::Path;
use std::time::Duration;
#[cfg(all(unix, not(target_os = "macos")))]
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
#[cfg(all(unix, not(target_os = "macos")))]
struct SessionEnvelope<T> {
    expires_at_unix: u64,
    data: T,
}

#[cfg(all(unix, not(target_os = "macos")))]
fn now_unix() -> VaultResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| crate::error::CacheError::Clock.into())
}

/// Persist a generic expiring session envelope on supported Unix platforms.
///
/// Fractional-second TTLs are rejected with `CacheError::InvalidTtl` rather
/// than silently shortened. A zero TTL is a no-op on every platform. Returns
/// `CacheError::Unavailable` for nonzero whole-second TTLs on macOS and
/// non-Unix platforms, where safe generic file persistence cannot be
/// established.
pub fn save<T: Serialize>(path: &Path, data: &T, ttl: Duration) -> VaultResult<()> {
    if ttl.is_zero() {
        return Ok(());
    }
    if ttl.subsec_nanos() != 0 {
        return Err(crate::error::CacheError::InvalidTtl.into());
    }
    #[cfg(any(not(unix), target_os = "macos"))]
    {
        let _ = (path, data, ttl);
        Err(crate::error::CacheError::Unavailable.into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let envelope = SessionEnvelope {
            expires_at_unix: now_unix()?
                .checked_add(ttl.as_secs())
                .ok_or(crate::error::CacheError::Clock)?,
            data,
        };
        let ron = ron::to_string(&envelope).map_err(|e| KeviError::common(e.to_string()))?;
        crate::session_management::cache_file::write(path, ron.as_bytes())?;
        Ok(())
    }
}

/// Load a generic expiring session envelope on supported Unix platforms.
///
/// Returns `CacheError::Unavailable` on macOS and non-Unix platforms without
/// inspecting the path, including when it does not exist.
pub fn load<T: DeserializeOwned>(path: &Path) -> VaultResult<Option<T>> {
    #[cfg(any(not(unix), target_os = "macos"))]
    {
        let _ = path;
        Err(crate::error::CacheError::Unavailable.into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path)
            .map_err(|e| KeviError::io(format!("Failed to read session file: {e}")))?;
        let content = String::from_utf8_lossy(&bytes);

        let envelope: SessionEnvelope<T> = match ron::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                return Ok(None);
            }
        };

        if now_unix()? >= envelope.expires_at_unix {
            return Ok(None);
        }

        Ok(Some(envelope.data))
    }
}

/// Remove a file only when it is a recognized cache payload and its directory
/// passes the guarded cleanup checks. Generic or ambiguous serialized data is
/// preserved and reported as a cleanup conflict; a missing path is a no-op.
pub fn clear(path: &Path) -> VaultResult<()> {
    crate::session_management::cleanup_file::clear_recognizable_session_file(path)
}
