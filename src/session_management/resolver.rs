use crate::cryptography::primitives::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, KeviHeader, KEY_LEN,
};
use crate::session_management::session::{load, save};
use crate::vault::ports::{DerivedKey, HeaderParams, KeyResolver};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct DerivedKeyStored {
    pub header_fingerprint_hex: String,
    pub key_b64: String,
}

pub fn dk_session_file_for(vault_path: &std::path::Path) -> PathBuf {
    vault_path.with_extension("dksession")
}

pub fn save_derived_key_session(
    path: &std::path::Path,
    fingerprint: &str,
    key: &SecretBox<Vec<u8>>,
    ttl: Duration,
) -> Result<()> {
    let stored = DerivedKeyStored {
        header_fingerprint_hex: fingerprint.to_string(),
        key_b64: general_purpose::STANDARD.encode(key.expose_secret()),
    };
    save(path, &stored, ttl)
}

pub trait PasswordResolver {
    fn resolve_password(&self) -> String {
        let pw = if let Ok(pw) = env::var("KEVI_PASSWORD") {
            pw
        } else {
            inquire::Password::new("Master password")
                .without_confirmation()
                .prompt()
                .unwrap()
        };
        pw
    }
}

pub struct CachedKeyResolver {
    dk_session_path: PathBuf,
}

impl PasswordResolver for CachedKeyResolver {}

impl CachedKeyResolver {
    pub fn new(vault_path: PathBuf) -> Self {
        let dk = vault_path.with_extension("dksession");
        Self {
            dk_session_path: dk,
        }
    }
}

impl KeyResolver for CachedKeyResolver {
    fn resolve_for_header(&self, hdr: &KeviHeader) -> Result<DerivedKey> {
        let fp = header_fingerprint_excluding_nonce(hdr);
        if let Some(sess) = load::<DerivedKeyStored>(&self.dk_session_path)? {
            if sess.header_fingerprint_hex == fp {
                if let Ok(vec) = general_purpose::STANDARD.decode(&sess.key_b64) {
                    let mut arr = [0u8; KEY_LEN];
                    if vec.len() >= KEY_LEN {
                        arr.copy_from_slice(&vec[..KEY_LEN]);
                        return Ok(DerivedKey {
                            key: SecretBox::new(Box::new(arr.to_vec())),
                        });
                    }
                }
            }
        }
        // Cache miss: derive from passphrase
        let pw = self.resolve_password();
        let key_arr = derive_key_argon2id(&pw, &hdr.salt, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));
        // Default TTL: 900s unless KEVI_UNLOCK_TTL provided
        let ttl_secs = env::var("KEVI_UNLOCK_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);

        let stored = DerivedKeyStored {
            header_fingerprint_hex: fp,
            key_b64: general_purpose::STANDARD.encode(key_vec.expose_secret()),
        };
        save(
            &self.dk_session_path,
            &stored,
            Duration::from_secs(ttl_secs),
        )?;

        Ok(DerivedKey { key: key_vec })
    }

    fn resolve_for_new_vault(&self, params: HeaderParams, salt: [u8; 16]) -> Result<DerivedKey> {
        let pw = self.resolve_password();
        let key_arr =
            derive_key_argon2id(&pw, &salt, params.m_cost_kib, params.t_cost, params.p_lanes)?;
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));

        // Also cache it
        let hdr = KeviHeader {
            version: crate::cryptography::primitives::HEADER_VERSION,
            kdf_id: crate::cryptography::primitives::KDF_ARGON2ID,
            aead_id: crate::cryptography::primitives::AEAD_AES256GCM,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_lanes: params.p_lanes,
            salt,
            nonce: [0u8; crate::cryptography::primitives::NONCE_LEN],
        };
        let fp = header_fingerprint_excluding_nonce(&hdr);
        let ttl_secs = env::var("KEVI_UNLOCK_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);

        let stored = DerivedKeyStored {
            header_fingerprint_hex: fp,
            key_b64: general_purpose::STANDARD.encode(key_vec.expose_secret()),
        };
        save(
            &self.dk_session_path,
            &stored,
            Duration::from_secs(ttl_secs),
        )?;

        Ok(DerivedKey { key: key_vec })
    }
}

pub struct BypassKeyResolver;

impl PasswordResolver for BypassKeyResolver {}

impl Default for BypassKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassKeyResolver {
    pub fn new() -> Self {
        Self
    }
}

impl KeyResolver for BypassKeyResolver {
    fn resolve_for_header(&self, hdr: &KeviHeader) -> Result<DerivedKey> {
        let pw = self.resolve_password();
        let key_arr = derive_key_argon2id(&pw, &hdr.salt, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(key_arr.to_vec())),
        })
    }

    fn resolve_for_new_vault(&self, params: HeaderParams, salt: [u8; 16]) -> Result<DerivedKey> {
        let pw = if let Ok(pw) = env::var("KEVI_PASSWORD") {
            pw
        } else {
            inquire::Password::new("Master password")
                .without_confirmation()
                .prompt()?
        };
        let key_arr =
            derive_key_argon2id(&pw, &salt, params.m_cost_kib, params.t_cost, params.p_lanes)?;
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(key_arr.to_vec())),
        })
    }
}
