#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::{
    domain::VaultResult,
    error::CacheError,
    session_management::resolver::{DerivedKeySessionStore, DerivedKeyStored},
};

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct LinuxWindowsKeyringSessionStore {
    account: String,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn classify(error: keyring_core::Error) -> CacheError {
    match error {
        keyring_core::Error::NoEntry => CacheError::Missing,
        keyring_core::Error::NoStorageAccess(_) => CacheError::Denied,
        keyring_core::Error::BadEncoding(_)
        | keyring_core::Error::BadDataFormat(_, _)
        | keyring_core::Error::BadStoreFormat(_) => CacheError::Malformed,
        _ => CacheError::Unavailable,
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl LinuxWindowsKeyringSessionStore {
    pub fn for_account(account: &str) -> Self {
        Self {
            account: account.into(),
        }
    }
    fn entry(&self) -> VaultResult<keyring_core::Entry> {
        static INITIALIZED: std::sync::OnceLock<Result<(), CacheError>> =
            std::sync::OnceLock::new();
        let result = INITIALIZED.get_or_init(|| {
            #[cfg(target_os = "linux")]
            let result = keyring::use_named_store("secret-service");
            #[cfg(target_os = "windows")]
            let result = keyring::use_named_store("windows");
            result.map_err(classify)
        });
        (*result)?;
        keyring_core::Entry::new("kevi.dk", &self.account).map_err(|error| classify(error).into())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl DerivedKeySessionStore for LinuxWindowsKeyringSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        match self.entry()?.get_password() {
            Ok(value) => DerivedKeyStored::decode(value.as_bytes()).map(Some),
            Err(error) => match classify(error) {
                CacheError::Missing => Ok(None),
                kind => Err(kind.into()),
            },
        }
    }
    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: std::time::Duration) -> VaultResult<()> {
        let payload = stored.encode()?;
        let text = std::str::from_utf8(&payload).map_err(|_| CacheError::Malformed)?;
        self.entry()?
            .set_password(text)
            .map_err(|error| classify(error).into())
    }
    fn clear_cached(&self) -> VaultResult<()> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(()),
            Err(error) => match classify(error) {
                CacheError::Missing => Ok(()),
                CacheError::Denied => Err(CacheError::Denied.into()),
                _ => Err(CacheError::Delete.into()),
            },
        }
    }
}
