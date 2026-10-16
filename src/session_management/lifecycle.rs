use crate::cryptography::primitives::{
    decrypt_vault_with_key, parse_kevi_header, KeviHeader, AEAD_AES256GCM, HEADER_VERSION,
    KDF_ARGON2ID,
};
use crate::domain::VaultResult;
use crate::error::KeviError;
use crate::session_management::resolver::CachedKeyResolver;
use crate::vault::codec::RonCodec;
use crate::vault::ports::{HeaderParams, KeyResolver, VaultCodec};
use secrecy::ExposeSecret;
use std::path::Path;
use std::time::Duration;

pub fn header_for(params: HeaderParams, salt: [u8; 16]) -> KeviHeader {
    KeviHeader {
        version: HEADER_VERSION,
        kdf_id: KDF_ARGON2ID,
        aead_id: AEAD_AES256GCM,
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p_lanes: params.p_lanes,
        salt,
        nonce: [0; 12],
    }
}

pub fn unlock_bytes(resolver: &CachedKeyResolver, bytes: &[u8]) -> VaultResult<()> {
    let (header, _) = parse_kevi_header(bytes)?;
    // Explicit unlock must derive afresh, regardless of a currently valid session.
    let key = resolver.resolve_for_new_vault(
        HeaderParams {
            m_cost_kib: header.m_cost_kib,
            t_cost: header.t_cost,
            p_lanes: header.p_lanes,
        },
        header.salt,
    )?;
    let key_array: &[u8; 32] = key
        .key
        .expose_secret()
        .as_slice()
        .try_into()
        .map_err(|_| KeviError::vault("invalid derived key length"))?;
    let plain = decrypt_vault_with_key(bytes, key_array)
        .map_err(|_| KeviError::vault("Failed to decrypt vault (wrong key?)"))?;
    RonCodec.decode(&plain)?;
    resolver.persist(&header, &key)
}

pub fn unlock(path: &Path, ttl: Duration) -> VaultResult<()> {
    let bytes = std::fs::read(path).map_err(|_| KeviError::io("failed to read vault"))?;
    unlock_bytes(&CachedKeyResolver::new(path.into()).with_ttl(ttl), &bytes)
}
