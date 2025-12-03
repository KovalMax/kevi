use crate::core::crypto::{decrypt_vault_with_key, default_params, encrypt_vault_with_key, parse_kevi_header, KEY_LEN, SALT_LEN};
use crate::core::entry::VaultEntry;
use crate::core::memlock::{lock_slice, unlock_slice};
use crate::core::ports::{ByteStore, HeaderParams, KeyResolver, VaultCodec};
use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::ExposeSecret;
use std::sync::Arc;
use zeroize::Zeroize;

pub struct VaultService {
    store: Arc<dyn ByteStore>,
    codec: Arc<dyn VaultCodec>,
    key_resolver: Arc<dyn KeyResolver>,
}

impl VaultService {
    pub fn new(
        store: Arc<dyn ByteStore>,
        codec: Arc<dyn VaultCodec>,
        key_resolver: Arc<dyn KeyResolver>,
    ) -> Self {
        Self {
            store,
            codec,
            key_resolver,
        }
    }

    pub fn load(&self) -> Result<Vec<VaultEntry>> {
        let bytes = self.store.read()?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        if !bytes.starts_with(b"KEVI") {
            anyhow::bail!("unsupported vault format: missing KEVI header (plaintext is not allowed)");
        }
        let (hdr, _off) = parse_kevi_header(&bytes).map_err(|e| anyhow::anyhow!("invalid header: {e}"))?;
        let dk = self.key_resolver.resolve_for_header(&hdr)?;
        // Convert key vec to array for ring API
        let key_vec = dk.key.expose_secret().clone();
        let mut key_arr = [0u8; KEY_LEN];
        key_arr.copy_from_slice(&key_vec[..KEY_LEN]);
        // Best‑effort lock while in use
        let _ = lock_slice(&mut key_arr);
        let pt = decrypt_vault_with_key(&bytes, &key_arr).context("Failed to decrypt vault (wrong key?)")?;
        // Always unlock + zeroize
        let _ = unlock_slice(&mut key_arr);
        key_arr.zeroize();
        self.codec.decode(&pt)
    }

    pub fn save(&self, entries: &[VaultEntry]) -> Result<()> {
        let plain = self.codec.encode(entries)?;
        let bytes = self.store.read()?;
        if !bytes.is_empty() {
            // Reuse existing header params and salt, generate new nonce
            let (hdr, _off) = parse_kevi_header(&bytes).map_err(|e| anyhow::anyhow!("invalid header: {e}"))?;
            let dk = self.key_resolver.resolve_for_header(&hdr)?;
            let key_vec = dk.key.expose_secret().clone();
            let mut key_arr = [0u8; KEY_LEN];
            key_arr.copy_from_slice(&key_vec[..KEY_LEN]);
            let _ = lock_slice(&mut key_arr);
            let ct = encrypt_vault_with_key(&plain, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes, hdr.salt, &key_arr)?;
            let _ = unlock_slice(&mut key_arr);
            key_arr.zeroize();
            self.store.write(&ct)
        } else {
            // New vault: generate params + salt, derive/cached key, encrypt and write
            let (m_cost_kib, t_cost, p_lanes) = default_params();
            let mut salt = [0u8; SALT_LEN];
            SystemRandom::new().fill(&mut salt).map_err(|_| anyhow::anyhow!("failed to generate salt"))?;
            let params = HeaderParams { m_cost_kib, t_cost, p_lanes };
            let dk = self.key_resolver.resolve_for_new_vault(params, salt)?;
            let key_vec = dk.key.expose_secret().clone();
            let mut key_arr = [0u8; KEY_LEN];
            key_arr.copy_from_slice(&key_vec[..KEY_LEN]);
            let _ = lock_slice(&mut key_arr);
            let ct = encrypt_vault_with_key(&plain, m_cost_kib, t_cost, p_lanes, salt, &key_arr)?;
            let _ = unlock_slice(&mut key_arr);
            key_arr.zeroize();
            self.store.write(&ct)
        }
    }

    pub fn add_entry(&self, entry: VaultEntry) -> Result<()> {
        let mut entries = self.load()?;
        entries.push(entry);
        self.save(&entries)
    }

    pub fn remove_entry(&self, label: &str) -> Result<bool> {
        let mut entries = self.load()?;
        let before = entries.len();
        entries.retain(|e| e.label != label);
        let removed = entries.len() != before;
        if removed {
            self.save(&entries)?;
        }
        Ok(removed)
    }
}
