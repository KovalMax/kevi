#[cfg(target_os = "macos")]
use crate::session_management::resolver::{DerivedKeySessionStore, DerivedKeyStored};
#[cfg(target_os = "macos")]
use crate::{domain::VaultResult, error::KeviError};
#[cfg(target_os = "macos")]
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
trait KeychainClient: Send + Sync {
    fn get_password_bytes(&self, service: &str, account: &str) -> VaultResult<Option<Vec<u8>>>;
    fn set_password_bytes(&self, service: &str, account: &str, value: &[u8]) -> VaultResult<()>;
}

#[cfg(target_os = "macos")]
struct SecurityFrameworkClient;

#[cfg(target_os = "macos")]
impl KeychainClient for SecurityFrameworkClient {
    fn get_password_bytes(&self, service: &str, account: &str) -> VaultResult<Option<Vec<u8>>> {
        match get_generic_password(service, account) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None),
        }
    }

    fn set_password_bytes(&self, service: &str, account: &str, value: &[u8]) -> VaultResult<()> {
        let _ = delete_generic_password(service, account);
        set_generic_password(service, account, value)
            .map_err(|error| KeviError::vault(error.to_string()))?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub struct MacOsKeychainSessionStore {
    service: String,
    account: String,
    client: Box<dyn KeychainClient>,
}

#[cfg(target_os = "macos")]
impl MacOsKeychainSessionStore {
    pub fn new(vault_path: &Path) -> VaultResult<Self> {
        Ok(Self::new_with_client(
            vault_path,
            Box::new(SecurityFrameworkClient),
        ))
    }
}

#[cfg(target_os = "macos")]
impl MacOsKeychainSessionStore {
    #[cfg(test)]
    fn new_with_client(vault_path: &Path, client: Box<dyn KeychainClient>) -> Self {
        let path_string = vault_path.to_string_lossy();
        let mut hasher = Sha256::new();
        hasher.update(path_string.as_bytes());
        let account = hex::encode(hasher.finalize());

        Self {
            service: "kevi.dk".to_string(),
            account,
            client,
        }
    }

    #[cfg(not(test))]
    fn new_with_client(vault_path: &Path, client: Box<dyn KeychainClient>) -> Self {
        let path_string = vault_path.to_string_lossy();
        let mut hasher = Sha256::new();
        hasher.update(path_string.as_bytes());
        let account = hex::encode(hasher.finalize());

        Self {
            service: "kevi.dk".to_string(),
            account,
            client,
        }
    }
}

#[cfg(target_os = "macos")]
impl DerivedKeySessionStore for MacOsKeychainSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        let Some(bytes) = self
            .client
            .get_password_bytes(&self.service, &self.account)?
        else {
            return Ok(None);
        };

        let stored = serde_json::from_slice::<DerivedKeyStored>(&bytes).ok();
        Ok(stored)
    }

    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: Duration) -> VaultResult<()> {
        let payload =
            serde_json::to_vec(stored).map_err(|error| KeviError::vault(error.to_string()))?;
        self.client
            .set_password_bytes(&self.service, &self.account, &payload)?;
        Ok(())
    }

    fn clear_cached(&self) -> VaultResult<()> {
        let _ = delete_generic_password(self.service.as_str(), self.account.as_str());
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{KeychainClient, MacOsKeychainSessionStore};
    use crate::domain::VaultResult;
    use crate::session_management::resolver::{DerivedKeySessionStore, DerivedKeyStored};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeKeychainClient {
        values: Mutex<HashMap<(String, String), Vec<u8>>>,
    }

    impl KeychainClient for FakeKeychainClient {
        fn get_password_bytes(&self, service: &str, account: &str) -> VaultResult<Option<Vec<u8>>> {
            Ok(self
                .values
                .lock()
                .expect("lock")
                .get(&(service.to_string(), account.to_string()))
                .cloned())
        }

        fn set_password_bytes(
            &self,
            service: &str,
            account: &str,
            value: &[u8],
        ) -> VaultResult<()> {
            self.values
                .lock()
                .expect("lock")
                .insert((service.to_string(), account.to_string()), value.to_vec());
            Ok(())
        }
    }

    #[test]
    fn load_returns_none_when_keychain_entry_missing() {
        let store = MacOsKeychainSessionStore::new_with_client(
            Path::new("/tmp/missing.ron"),
            Box::new(FakeKeychainClient::default()),
        );
        assert!(store.load_cached().expect("load").is_none());
    }

    #[test]
    fn save_then_load_round_trips_payload() {
        let store = MacOsKeychainSessionStore::new_with_client(
            Path::new("/tmp/roundtrip.ron"),
            Box::new(FakeKeychainClient::default()),
        );
        let payload = DerivedKeyStored {
            header_fingerprint_hex: "fingerprint".to_string(),
            key_b64: "Zm9vYmFy".to_string(),
        };

        store
            .save_cached(&payload, Duration::from_secs(30))
            .expect("save");

        let loaded = store.load_cached().expect("load").expect("stored payload");
        assert_eq!(
            loaded.header_fingerprint_hex,
            payload.header_fingerprint_hex
        );
        assert_eq!(loaded.key_b64, payload.key_b64);
    }

    #[test]
    fn load_returns_none_when_payload_is_not_valid_json() {
        let client = FakeKeychainClient::default();
        client
            .set_password_bytes("kevi.dk", "broken", b"not-json")
            .expect("seed broken payload");
        let store = MacOsKeychainSessionStore {
            service: "kevi.dk".to_string(),
            account: "broken".to_string(),
            client: Box::new(client),
        };

        assert!(store.load_cached().expect("load").is_none());
    }
}
