use anyhow::Result;
use secrecy::SecretBox;

use super::crypto::KeviHeader;
use super::entry::VaultEntry;

// Randomness provider for deterministic testing.
pub trait Rng: Send + Sync {
    fn fill(&self, bytes: &mut [u8]) -> Result<()>;
}

pub trait VaultCodec: Send + Sync {
    fn encode(&self, entries: &[VaultEntry]) -> Result<Vec<u8>>;
    fn decode(&self, data: &[u8]) -> Result<Vec<VaultEntry>>;
}

pub trait ByteStore: Send + Sync {
    fn read(&self) -> Result<Vec<u8>>;
    fn write(&self, bytes: &[u8]) -> Result<()>;
}

// Password generator policy and trait
#[derive(Debug, Clone)]
pub struct GenPolicy {
    pub length: u16,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
    // Passphrase options
    pub passphrase: bool,
    pub words: u16,
    pub sep: String,
}

impl Default for GenPolicy {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
            passphrase: false,
            words: 6,
            sep: ":".to_string(),
        }
    }
}

pub trait PasswordGenerator: Send + Sync {
    fn generate(&self, policy: &GenPolicy) -> Result<String>;
}

// ===== Derived-key cache resolver (PR13) =====

pub struct DerivedKey {
    pub key: SecretBox<Vec<u8>>, // 32 bytes expected
}

impl core::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("key", &"<REDACTED>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_lanes: u32,
}

pub trait KeyResolver: Send + Sync {
    // Resolve a derived key for an existing header (bound to its params/salt)
    fn resolve_for_header(&self, hdr: &KeviHeader) -> Result<DerivedKey>;
    // Resolve for new vault parameters (default params + fresh salt)
    fn resolve_for_new_vault(&self, params: HeaderParams, salt: [u8; 16]) -> Result<DerivedKey>;
}
