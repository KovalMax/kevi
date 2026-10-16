//! Vault service encapsulating load/save operations, header reuse, and encryption parameters.
//! Serves as the core API for handlers/CLI/TUI while hiding persistence and crypto details.

use crate::cryptography::memlock::{lock_slice, unlock_slice};
use crate::cryptography::primitives::{
    decrypt_vault_with_key, default_params, encrypt_vault_with_key, parse_kevi_header, KEY_LEN,
    SALT_LEN,
};
use crate::domain::VaultResult;
use crate::error::VaultError;
use crate::vault::models::{VaultData, VaultEntry};
use crate::vault::ports::{ByteStore, HeaderParams, KeyResolver, VaultCodec};
use kevi_core::vault::service::{VaultDomainService, VaultRepository};
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::ExposeSecret;
use std::sync::Arc;
use zeroize::Zeroize;

pub struct VaultService<
    StoreType = Arc<dyn ByteStore>,
    CodecType = Arc<dyn VaultCodec>,
    ResolverType = Arc<dyn KeyResolver>,
> where
    StoreType: ByteStore,
    CodecType: VaultCodec,
    ResolverType: KeyResolver,
{
    store: StoreType,
    codec: CodecType,
    key_resolver: ResolverType,
}

impl<StoreType, CodecType, ResolverType> VaultService<StoreType, CodecType, ResolverType>
where
    StoreType: ByteStore,
    CodecType: VaultCodec,
    ResolverType: KeyResolver,
{
    fn domain_service(
        &self,
    ) -> VaultDomainService<LoadedVaultRepository<'_, StoreType, CodecType, ResolverType>> {
        VaultDomainService::new(LoadedVaultRepository { service: self })
    }

    pub fn new(store: StoreType, codec: CodecType, key_resolver: ResolverType) -> Self {
        Self {
            store,
            codec,
            key_resolver,
        }
    }

    pub fn load(&self) -> VaultResult<VaultData> {
        let bytes = self.store.read()?;
        if bytes.is_empty() {
            return Ok(VaultData::default());
        }
        if !bytes.starts_with(b"KEVI") {
            return Err(VaultError::Message(
                "unsupported vault format: missing KEVI header (plaintext is not allowed)"
                    .to_string(),
            )
            .into());
        }
        let (hdr, _off) = parse_kevi_header(&bytes).map_err(VaultError::from)?;
        let acquired = self.key_resolver.acquire_for_header(&hdr)?;
        let dk = &acquired.derived;
        // Convert key vec to array for ring API
        let mut key_arr: [u8; KEY_LEN] = dk
            .key
            .expose_secret()
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Message("invalid derived key length".into()))?;
        // Best‑effort lock while in use
        let _ = lock_slice(&mut key_arr);
        let pt = decrypt_vault_with_key(&bytes, &key_arr)
            .map_err(|_| VaultError::Message("Failed to decrypt vault (wrong key?)".to_string()));
        // Always unlock + zeroize
        let _ = unlock_slice(&mut key_arr);
        key_arr.zeroize();
        let data = self.codec.decode(&pt?)?;
        self.key_resolver.publish(&hdr, &acquired);
        Ok(data)
    }

    pub fn save(&self, data: &VaultData) -> VaultResult<()> {
        let plain = self.codec.encode(data)?;
        let bytes = self.store.read()?;
        if !bytes.is_empty() {
            // Reuse existing header params and salt, generate new nonce
            let (hdr, _off) = parse_kevi_header(&bytes).map_err(VaultError::from)?;
            let acquired = self.key_resolver.acquire_for_header(&hdr)?;
            let dk = &acquired.derived;
            let mut key_arr: [u8; KEY_LEN] = dk
                .key
                .expose_secret()
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Message("invalid derived key length".into()))?;
            let _ = lock_slice(&mut key_arr);
            let ct = (|| {
                let original = decrypt_vault_with_key(&bytes, &key_arr).map_err(|_| {
                    VaultError::Message("Failed to authenticate original vault".into())
                })?;
                self.codec.decode(&original)?;
                encrypt_vault_with_key(
                    &plain,
                    hdr.m_cost_kib,
                    hdr.t_cost,
                    hdr.p_lanes,
                    hdr.salt,
                    &key_arr,
                )
            })();
            let _ = unlock_slice(&mut key_arr);
            key_arr.zeroize();
            self.store.write(&ct?)?;
            self.key_resolver.publish(&hdr, &acquired);
            Ok(())
        } else {
            // New vault: generate params + salt, derive/cached key, encrypt and write
            let (m_cost_kib, t_cost, p_lanes) = default_params();
            let mut salt = [0u8; SALT_LEN];
            SystemRandom::new()
                .fill(&mut salt)
                .map_err(|_| VaultError::Message("failed to generate salt".to_string()))?;
            let params = HeaderParams {
                m_cost_kib,
                t_cost,
                p_lanes,
            };
            let acquired = self.key_resolver.acquire_for_new_vault(params, salt)?;
            let dk = &acquired.derived;
            let mut key_arr: [u8; KEY_LEN] = dk
                .key
                .expose_secret()
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::Message("invalid derived key length".into()))?;
            let _ = lock_slice(&mut key_arr);
            let ct = encrypt_vault_with_key(&plain, m_cost_kib, t_cost, p_lanes, salt, &key_arr);
            let _ = unlock_slice(&mut key_arr);
            key_arr.zeroize();
            self.store.write(&ct?)?;
            let header = crate::session_management::lifecycle::header_for(params, salt);
            self.key_resolver.publish(&header, &acquired);
            Ok(())
        }
    }

    pub fn add_entry(&self, entry: VaultEntry) -> VaultResult<()> {
        self.domain_service().add_entry(entry)
    }

    pub fn remove_entry(&self, label: &str) -> VaultResult<bool> {
        self.domain_service().remove_entry(label)
    }
}

struct LoadedVaultRepository<'service, StoreType, CodecType, ResolverType>
where
    StoreType: ByteStore,
    CodecType: VaultCodec,
    ResolverType: KeyResolver,
{
    service: &'service VaultService<StoreType, CodecType, ResolverType>,
}

impl<'service, StoreType, CodecType, ResolverType> VaultRepository
    for LoadedVaultRepository<'service, StoreType, CodecType, ResolverType>
where
    StoreType: ByteStore,
    CodecType: VaultCodec,
    ResolverType: KeyResolver,
{
    type Error = crate::error::KeviError;

    fn load(&self) -> VaultResult<VaultData> {
        self.service.load()
    }

    fn save(&self, data: &VaultData) -> VaultResult<()> {
        self.service.save(data)
    }
}
