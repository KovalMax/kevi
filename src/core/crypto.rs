use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const KEY_LEN: usize = 32; // 256-bit key
pub const NONCE_LEN: usize = 12; // 96-bit GCM nonce
pub const SALT_LEN: usize = 16; // Argon2 salt

// Header layout (little-endian):
// magic: 4 bytes = b"KEVI"
// version: u16 = 1
// kdf_id: u8 (2 = Argon2id; other values unsupported)
// aead_id: u8 (1 = AES-256-GCM, 2 reserved for CHACHA20-POLY1305)
// m_cost_kib: u32
// t_cost: u32
// p_lanes: u32
// salt: [u8; SALT_LEN]
// nonce: [u8; NONCE_LEN]
pub const HEADER_MAGIC: &[u8; 4] = b"KEVI";
pub const HEADER_VERSION: u16 = 1;
pub const KDF_ARGON2ID: u8 = 2;
pub const AEAD_AES256GCM: u8 = 1;

pub fn default_params() -> (u32, u32, u32) {
    // Sensible 2025 defaults for CLI: 64 MiB, 3 iterations, 1 lane
    (64 * 1024, 3, 1)
}

pub fn derive_key_argon2id(
    password: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p: u32,
) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(m_cost_kib, t_cost, p, Some(KEY_LEN))
        .map_err(|e| anyhow!("invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;
    Ok(key)
}

fn build_header(
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    m_cost_kib: u32,
    t_cost: u32,
    p: u32,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(4 + 2 + 1 + 1 + 4 * 3 + SALT_LEN + NONCE_LEN);
    h.extend_from_slice(HEADER_MAGIC);
    h.extend_from_slice(&HEADER_VERSION.to_le_bytes());
    h.push(KDF_ARGON2ID);
    h.push(AEAD_AES256GCM);
    h.extend_from_slice(&m_cost_kib.to_le_bytes());
    h.extend_from_slice(&t_cost.to_le_bytes());
    h.extend_from_slice(&p.to_le_bytes());
    h.extend_from_slice(salt);
    h.extend_from_slice(nonce);
    h
}

#[derive(Debug, Clone)]
pub struct KeviHeader {
    pub version: u16,
    pub kdf_id: u8,
    pub aead_id: u8,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Error, Clone)]
pub enum HeaderError {
    #[error("ciphertext too short for header")]
    TooShort,
    #[error("invalid magic (expected KEVI)")]
    InvalidMagic,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported kdf id: {0}")]
    UnsupportedKdf(u8),
    #[error("unsupported aead id: {0}")]
    UnsupportedAead(u8),
}

pub fn parse_kevi_header(data: &[u8]) -> std::result::Result<(KeviHeader, usize), HeaderError> {
    let min_len = 4 + 2 + 1 + 1 + 4 * 3 + SALT_LEN + NONCE_LEN;
    if data.len() < min_len {
        return Err(HeaderError::TooShort);
    }
    if &data[0..4] != HEADER_MAGIC {
        return Err(HeaderError::InvalidMagic);
    }
    let version = u16::from_le_bytes([data[4], data[5]]);
    if version != HEADER_VERSION {
        return Err(HeaderError::UnsupportedVersion(version));
    }
    let kdf_id = data[6];
    if kdf_id != KDF_ARGON2ID {
        return Err(HeaderError::UnsupportedKdf(kdf_id));
    }
    let aead_id = data[7];
    if aead_id != AEAD_AES256GCM {
        return Err(HeaderError::UnsupportedAead(aead_id));
    }
    let m_cost_off = 8;
    let t_cost_off = 12;
    let p_off = 16;
    let salt_off = 20;
    let nonce_off = salt_off + SALT_LEN;
    let m_cost_kib = u32::from_le_bytes(data[m_cost_off..m_cost_off + 4].try_into().unwrap());
    let t_cost = u32::from_le_bytes(data[t_cost_off..t_cost_off + 4].try_into().unwrap());
    let p_lanes = u32::from_le_bytes(data[p_off..p_off + 4].try_into().unwrap());
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[salt_off..salt_off + SALT_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[nonce_off..nonce_off + NONCE_LEN]);
    let header = KeviHeader {
        version,
        kdf_id,
        aead_id,
        m_cost_kib,
        t_cost,
        p_lanes,
        salt,
        nonce,
    };
    Ok((header, nonce_off + NONCE_LEN))
}

/// Compute a fingerprint of header fields excluding the nonce. This allows
/// binding a derived-key cache to a specific vault configuration.
pub fn header_fingerprint_excluding_nonce(hdr: &KeviHeader) -> String {
    let mut hasher = Sha256::new();
    hasher.update(HEADER_MAGIC);
    hasher.update(&hdr.version.to_le_bytes());
    hasher.update(&[hdr.kdf_id]);
    hasher.update(&[hdr.aead_id]);
    hasher.update(&hdr.m_cost_kib.to_le_bytes());
    hasher.update(&hdr.t_cost.to_le_bytes());
    hasher.update(&hdr.p_lanes.to_le_bytes());
    hasher.update(&hdr.salt);
    let digest = hasher.finalize();
    hex::encode(digest)
}

pub fn encrypt_vault(data: &[u8], password: &str) -> Result<Vec<u8>> {
    // Derive key using defaults, then delegate to key-based path to avoid AEAD duplication
    let (m_cost_kib, t_cost, p_lanes) = default_params();
    let rng = SystemRandom::new();
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| anyhow!("failed to generate salt"))?;
    let key = derive_key_argon2id(password, &salt, m_cost_kib, t_cost, p_lanes)?;
    encrypt_vault_with_key(data, m_cost_kib, t_cost, p_lanes, salt, &key)
}

pub fn decrypt_vault(data: &[u8], password: &str) -> Result<Vec<u8>> {
    // Parse header then delegate to key-based decrypt
    let (hdr, _ct_offset) = parse_kevi_header(data).map_err(|e| anyhow!("invalid header: {e}"))?;
    let key = derive_key_argon2id(password, &hdr.salt, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
    decrypt_vault_with_key(data, &key)
}

/// Encrypt with a provided derived key and explicit params/salt. Generates a new random nonce.
pub fn encrypt_vault_with_key(
    data: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    p_lanes: u32,
    salt: [u8; SALT_LEN],
    derived_key: &[u8; KEY_LEN],
) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("failed to generate nonce"))?;

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, derived_key)
        .map_err(|_| anyhow!("failed to create sealing key"))?;
    let sealing_key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let header = build_header(&salt, &nonce_bytes, m_cost_kib, t_cost, p_lanes);
    let mut in_out = data.to_vec();
    in_out.reserve(aead::AES_256_GCM.tag_len());
    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::from(&header), &mut in_out)
        .map_err(|_| anyhow!("encryption failed"))?;
    let mut out = header;
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// Decrypt with a provided derived key. Uses header as AAD and verifies.
pub fn decrypt_vault_with_key(data: &[u8], derived_key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let (_hdr, ct_offset) = parse_kevi_header(data).map_err(|e| anyhow!("invalid header: {e}"))?;
    let ciphertext = &data[ct_offset..];
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, derived_key)
        .map_err(|_| anyhow!("failed to create opening key"))?;
    let opening_key = aead::LessSafeKey::new(unbound);
    // Extract nonce from header again for convenience
    let nonce = aead::Nonce::try_assume_unique_for_key(&data[ct_offset - NONCE_LEN..ct_offset])
        .map_err(|_| anyhow!("invalid nonce"))?;
    let aad = aead::Aad::from(&data[..ct_offset]);
    let mut in_out = ciphertext.to_vec();
    let pt = opening_key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|_| anyhow!("decryption failed"))?;
    Ok(pt.to_vec())
}
