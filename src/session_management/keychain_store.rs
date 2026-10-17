#[cfg(target_os = "macos")]
use crate::domain::VaultResult;
#[cfg(target_os = "macos")]
use crate::error::CacheError;
#[cfg(target_os = "macos")]
use crate::session_management::resolver::{DerivedKeySessionStore, DerivedKeyStored};

#[cfg(target_os = "macos")]
pub struct MacOsKeychainSessionStore {
    account: String,
}

#[cfg(target_os = "macos")]
impl MacOsKeychainSessionStore {
    pub fn for_account(account: &str) -> Self {
        Self {
            account: account.into(),
        }
    }
}

#[cfg(target_os = "macos")]
fn classify(error: security_framework::base::Error) -> CacheError {
    match error.code() {
        -25300 => CacheError::Missing, // errSecItemNotFound
        -25292 | -25293 | -25308 | -25315 | -128 => CacheError::Denied,
        _ => CacheError::Unavailable,
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "keychain_store_test.rs"]
mod tests;

#[cfg(target_os = "macos")]
impl DerivedKeySessionStore for MacOsKeychainSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        match security_framework::passwords::get_generic_password("kevi.dk", &self.account) {
            Ok(bytes) => DerivedKeyStored::decode(&bytes).map(Some),
            Err(error) => match classify(error) {
                CacheError::Missing => Ok(None),
                kind => Err(kind.into()),
            },
        }
    }
    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: std::time::Duration) -> VaultResult<()> {
        security_framework::passwords::set_generic_password(
            "kevi.dk",
            &self.account,
            &stored.encode()?,
        )
        .map_err(|error| classify(error).into())
    }
    fn clear_cached(&self) -> VaultResult<()> {
        match security_framework::passwords::delete_generic_password("kevi.dk", &self.account) {
            Ok(()) => Ok(()),
            Err(error) => match classify(error) {
                CacheError::Missing => Ok(()),
                CacheError::Denied => Err(CacheError::Denied.into()),
                _ => Err(CacheError::Delete.into()),
            },
        }
    }
}
