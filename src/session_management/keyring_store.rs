#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::session_management::resolver::{DerivedKeySessionStore, DerivedKeyStored};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use keyring::Entry;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub struct LinuxWindowsKeyringSessionStore {
    service: String,
    account: String,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl LinuxWindowsKeyringSessionStore {
    pub fn new(vault_path: &Path) -> Result<Self> {
        let mut hasher = Sha256::new();
        hasher.update(vault_path.to_string_lossy().as_bytes());
        let account = hex::encode(hasher.finalize());

        Ok(Self {
            service: "kevi.dk".to_string(),
            account,
        })
    }

    fn entry(&self) -> Result<Entry> {
        Ok(Entry::new(self.service.as_str(), self.account.as_str())?)
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl DerivedKeySessionStore for LinuxWindowsKeyringSessionStore {
    fn load_cached(&self) -> Result<Option<DerivedKeyStored>> {
        let entry = self.entry()?;
        match entry.get_password() {
            Ok(value) => Ok(serde_json::from_str::<DerivedKeyStored>(&value).ok()),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Ok(None),
        }
    }

    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: Duration) -> Result<()> {
        let entry = self.entry()?;
        let payload = serde_json::to_string(stored)?;
        entry.set_password(payload.as_str())?;
        Ok(())
    }

    fn clear_cached(&self) -> Result<()> {
        let entry = self.entry()?;
        let _ = entry.delete_credential();
        Ok(())
    }
}
