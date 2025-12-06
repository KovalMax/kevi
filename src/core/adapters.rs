use crate::core::crypto::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, KeviHeader, KEY_LEN,
};
use crate::core::dk_session::{dk_session_file_for, read_dk_session, write_dk_session};
use crate::core::entry::VaultEntry;
use crate::core::ports::{ByteStore, DerivedKey, KeyResolver, VaultCodec};
use anyhow::{anyhow, Context, Result};
use ron::ser::PrettyConfig;
use secrecy::{ExposeSecret, SecretBox};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

// ===== Codec (RON) adapter =====
pub struct RonCodec;

impl VaultCodec for RonCodec {
    fn encode(&self, entries: &[VaultEntry]) -> Result<Vec<u8>> {
        let pretty = PrettyConfig::new()
            .depth_limit(3)
            .separate_tuple_members(true)
            .enumerate_arrays(true);
        let s = ron::ser::to_string_pretty(entries, pretty)?;
        Ok(s.into_bytes())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<VaultEntry>> {
        let s = String::from_utf8(data.to_vec())
            .map_err(|_| anyhow!("vault content not valid UTF-8 RON"))?;
        let vault: Vec<VaultEntry> = ron::from_str(&s).context("Failed to parse vault content")?;
        Ok(vault)
    }
}

// ===== File ByteStore adapter =====
pub struct FileByteStore {
    path: PathBuf,
    backups: usize,
}

impl FileByteStore {
    /// Construct with backups count resolved from environment (KEVI_BACKUPS) or default 2.
    pub fn new(path: PathBuf) -> Self {
        Self { path, backups: 2 }
    }

    /// Preferred: construct with explicit backups count to avoid env coupling.
    pub fn new_with_backups(path: PathBuf, backups: usize) -> Self {
        Self { path, backups }
    }
}

impl ByteStore for FileByteStore {
    fn read(&self) -> Result<Vec<u8>> {
        let path = &self.path;
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(path).context("Failed to open vault file")?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn write(&self, bytes: &[u8]) -> Result<()> {
        crate::core::fs_secure::write_with_backups_n(&self.path, bytes, self.backups)
    }
}

// ===== Derived-key resolver bound to header params/salt =====
pub struct CachedKeyResolver {
    dk_session_path: PathBuf,
    // For deriving when a cache is missed
    // Uses env var KEVI_PASSWORD or interactive prompt
}

impl PasswordResolver for CachedKeyResolver {}

impl CachedKeyResolver {
    pub fn new(vault_path: PathBuf) -> Self {
        let dk = dk_session_file_for(&vault_path);
        Self {
            dk_session_path: dk,
        }
    }
}

impl KeyResolver for CachedKeyResolver {
    fn resolve_for_header(&self, hdr: &KeviHeader) -> Result<DerivedKey> {
        let fp = header_fingerprint_excluding_nonce(hdr);
        if let Some(sess) = read_dk_session(&self.dk_session_path)? {
            if sess.header_fingerprint_hex == fp {
                let vec = sess.key.expose_secret().clone();
                let mut arr = [0u8; KEY_LEN];
                arr.copy_from_slice(&vec[..KEY_LEN]);
                return Ok(DerivedKey {
                    key: SecretBox::new(Box::new(arr.to_vec())),
                });
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
        write_dk_session(
            &self.dk_session_path,
            &fp,
            &key_vec,
            std::time::Duration::from_secs(ttl_secs),
        )?;
        Ok(DerivedKey { key: key_vec })
    }

    fn resolve_for_new_vault(
        &self,
        params: crate::core::ports::HeaderParams,
        salt: [u8; 16],
    ) -> Result<DerivedKey> {
        // For new vaults, prompt/env to get passphrase and derive key with provided params+salt,
        // compute a pseudo-header to fingerprint (nonce excluded)
        let pw = self.resolve_password();
        let key_arr =
            derive_key_argon2id(&pw, &salt, params.m_cost_kib, params.t_cost, params.p_lanes)?;
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));
        let hdr = KeviHeader {
            version: crate::core::crypto::HEADER_VERSION,
            kdf_id: crate::core::crypto::KDF_ARGON2ID,
            aead_id: crate::core::crypto::AEAD_AES256GCM,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_lanes: params.p_lanes,
            salt,
            nonce: [0u8; crate::core::crypto::NONCE_LEN],
        };
        let fp = header_fingerprint_excluding_nonce(&hdr);
        let ttl_secs = env::var("KEVI_UNLOCK_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);
        write_dk_session(
            &self.dk_session_path,
            &fp,
            &key_vec,
            std::time::Duration::from_secs(ttl_secs),
        )?;
        Ok(DerivedKey { key: key_vec })
    }
}

/// A resolver that always derives from a passphrase and never reads/writes the dk-session cache.
pub struct BypassKeyResolver;

impl PasswordResolver for BypassKeyResolver {}

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

    fn resolve_for_new_vault(
        &self,
        params: crate::core::ports::HeaderParams,
        salt: [u8; 16],
    ) -> Result<DerivedKey> {
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
