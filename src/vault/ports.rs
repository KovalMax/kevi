use std::sync::Arc;

use crate::cryptography::primitives::KeviHeader;
use crate::domain::VaultResult;
use crate::vault::models::VaultData;
pub use kevi_core::vault::contracts::{
    ByteStore as CoreByteStore, DerivedKey, GenPolicy, HeaderParams,
    PasswordGenerator as CorePasswordGenerator, Rng as CoreRng, VaultCodec as CoreVaultCodec,
};

pub trait VaultCodec: Send + Sync {
    fn encode(&self, data: &VaultData) -> VaultResult<Vec<u8>>;
    fn decode(&self, data: &[u8]) -> VaultResult<VaultData>;
}

impl<T: VaultCodec + ?Sized> VaultCodec for Arc<T> {
    fn encode(&self, data: &VaultData) -> VaultResult<Vec<u8>> {
        (**self).encode(data)
    }

    fn decode(&self, data: &[u8]) -> VaultResult<VaultData> {
        (**self).decode(data)
    }
}

pub trait ByteStore: Send + Sync {
    fn read(&self) -> VaultResult<Vec<u8>>;
    fn write(&self, bytes: &[u8]) -> VaultResult<()>;
}

impl<T: ByteStore + ?Sized> ByteStore for Arc<T> {
    fn read(&self) -> VaultResult<Vec<u8>> {
        (**self).read()
    }

    fn write(&self, bytes: &[u8]) -> VaultResult<()> {
        (**self).write(bytes)
    }
}

pub trait PasswordGenerator: Send + Sync {
    fn generate(&self, policy: &GenPolicy) -> VaultResult<String>;
}

impl<T> PasswordGenerator for T
where
    T: CorePasswordGenerator<Error = crate::error::KeviError> + Send + Sync,
{
    fn generate(&self, policy: &GenPolicy) -> VaultResult<String> {
        CorePasswordGenerator::generate(self, policy)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    Fresh,
    Cached,
}

pub struct AcquiredKey {
    pub derived: DerivedKey,
    pub origin: KeyOrigin,
}

pub trait KeyResolver: Send + Sync {
    fn acquire_for_header(&self, header: &KeviHeader) -> VaultResult<AcquiredKey> {
        Ok(AcquiredKey {
            derived: self.resolve_for_header(header)?,
            origin: KeyOrigin::Fresh,
        })
    }
    fn acquire_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<AcquiredKey> {
        Ok(AcquiredKey {
            derived: self.resolve_for_new_vault(params, salt)?,
            origin: KeyOrigin::Fresh,
        })
    }
    fn publish(&self, _header: &KeviHeader, _acquired: &AcquiredKey) {}
    // Resolve a derived key for an existing header (bound to its params/salt)
    fn resolve_for_header(&self, hdr: &KeviHeader) -> VaultResult<DerivedKey>;
    // Resolve for new vault parameters (default params + fresh salt)
    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey>;
}

impl<T: KeyResolver + ?Sized> KeyResolver for Arc<T> {
    fn acquire_for_header(&self, header: &KeviHeader) -> VaultResult<AcquiredKey> {
        (**self).acquire_for_header(header)
    }
    fn acquire_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<AcquiredKey> {
        (**self).acquire_for_new_vault(params, salt)
    }
    fn publish(&self, header: &KeviHeader, acquired: &AcquiredKey) {
        (**self).publish(header, acquired);
    }
    fn resolve_for_header(&self, hdr: &KeviHeader) -> VaultResult<DerivedKey> {
        (**self).resolve_for_header(hdr)
    }

    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        (**self).resolve_for_new_vault(params, salt)
    }
}
