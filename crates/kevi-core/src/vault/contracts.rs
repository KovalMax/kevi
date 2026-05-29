use secrecy::SecretBox;
use std::result::Result;
use crate::vault::models::VaultData;

#[derive(Debug, Clone)]
pub struct GenPolicy {
    pub length: u16,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
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

pub trait Rng: Send + Sync {
    type Error;

    fn fill(&self, bytes: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait PasswordGenerator: Send + Sync {
    type Error;

    fn generate(&self, policy: &GenPolicy) -> Result<String, Self::Error>;
}

pub trait VaultCodec: Send + Sync {
    type Error;

    fn encode(&self, data: &VaultData) -> Result<Vec<u8>, Self::Error>;
    fn decode(&self, data: &[u8]) -> Result<VaultData, Self::Error>;
}

pub trait ByteStore: Send + Sync {
    type Error;

    fn read(&self) -> Result<Vec<u8>, Self::Error>;
    fn write(&self, bytes: &[u8]) -> Result<(), Self::Error>;
}

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
