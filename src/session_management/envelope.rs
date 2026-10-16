use crate::domain::VaultResult;
use crate::error::CacheError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_PAYLOAD_BYTES: usize = 4096;

pub trait Clock: Send + Sync {
    fn now(&self) -> VaultResult<u64>;
}

pub struct WallClock;

impl Clock for WallClock {
    fn now(&self) -> VaultResult<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| CacheError::Clock.into())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedKeyStored {
    pub schema: u32,
    pub identity: String,
    pub header_fingerprint_hex: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub key_b64: String,
}

impl fmt::Debug for DerivedKeyStored {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DerivedKeyStored([REDACTED])")
    }
}

impl Drop for DerivedKeyStored {
    fn drop(&mut self) {
        self.key_b64.zeroize();
    }
}

impl DerivedKeyStored {
    pub fn issue(
        identity: String,
        fingerprint: String,
        key: &SecretBox<Vec<u8>>,
        ttl: Duration,
        clock: &dyn Clock,
    ) -> VaultResult<Self> {
        if key.expose_secret().len() != 32 || ttl.is_zero() {
            return Err(CacheError::Malformed.into());
        }
        let issued = clock.now()?;
        let expires = issued.checked_add(ttl.as_secs()).ok_or(CacheError::Clock)?;
        if expires <= issued {
            return Err(CacheError::Clock.into());
        }
        UNIX_EPOCH
            .checked_add(Duration::from_secs(expires))
            .ok_or(CacheError::Clock)?;
        let mut encoded_key = Zeroizing::new(STANDARD.encode(key.expose_secret()));
        let stored = Self {
            schema: 1,
            identity,
            header_fingerprint_hex: fingerprint,
            issued_at_unix: issued,
            expires_at_unix: expires,
            key_b64: std::mem::take(&mut *encoded_key),
        };
        stored.encode()?;
        Ok(stored)
    }

    pub fn key(
        &self,
        identity: &str,
        fingerprint: &str,
        clock: &dyn Clock,
    ) -> VaultResult<SecretBox<Vec<u8>>> {
        let now = clock.now()?;
        if self.schema != 1
            || self.identity != identity
            || self.header_fingerprint_hex != fingerprint
            || self.issued_at_unix > now
            || self.expires_at_unix <= self.issued_at_unix
            || now >= self.expires_at_unix
            || UNIX_EPOCH
                .checked_add(Duration::from_secs(self.expires_at_unix))
                .is_none()
            || self.key_b64.len() != 44
        {
            return Err(CacheError::Malformed.into());
        }
        let mut key = Zeroizing::new(
            STANDARD
                .decode(&self.key_b64)
                .map_err(|_| CacheError::Malformed)?,
        );
        if key.len() != 32 {
            return Err(CacheError::Malformed.into());
        }
        Ok(SecretBox::new(Box::new(std::mem::take(&mut *key))))
    }

    pub fn encode(&self) -> VaultResult<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_json::to_vec(self).map_err(|_| CacheError::Malformed)?);
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CacheError::Malformed.into());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(CacheError::Malformed.into());
        }
        let stored: Self = serde_json::from_slice(bytes).map_err(|_| CacheError::Malformed)?;
        if stored.schema != 1 {
            return Err(CacheError::Malformed.into());
        }
        Ok(stored)
    }
}
