use kevi::cryptography::primitives::{default_params, derive_key_argon2id, KeviHeader, SALT_LEN};
use kevi::vault::models::VaultData;
use kevi::vault::ports::{ByteStore, DerivedKey, HeaderParams, KeyResolver, VaultCodec};
use kevi::vault::service::VaultService;
use secrecy::{ExposeSecret, SecretBox};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct MemoryStore {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            bytes: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ByteStore for MemoryStore {
    fn read(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.bytes.lock().expect("lock").clone())
    }

    fn write(&self, bytes: &[u8]) -> anyhow::Result<()> {
        *self.bytes.lock().expect("lock") = bytes.to_vec();
        Ok(())
    }
}

#[derive(Clone)]
struct TestCodec;

impl VaultCodec for TestCodec {
    fn encode(&self, data: &VaultData) -> anyhow::Result<Vec<u8>> {
        Ok(ron::to_string(data)?.into_bytes())
    }

    fn decode(&self, data: &[u8]) -> anyhow::Result<VaultData> {
        if data.is_empty() {
            return Ok(VaultData::default());
        }
        Ok(ron::from_str(std::str::from_utf8(data)?)?)
    }
}

struct FixedResolver {
    key: SecretBox<Vec<u8>>,
}

impl FixedResolver {
    fn from_password(password: &str) -> Self {
        let (m_cost_kib, t_cost, p_lanes) = default_params();
        let salt = [1u8; SALT_LEN];
        let key = derive_key_argon2id(password, &salt, m_cost_kib, t_cost, p_lanes)
            .expect("derive key")
            .to_vec();
        Self {
            key: SecretBox::new(Box::new(key)),
        }
    }
}

impl KeyResolver for FixedResolver {
    fn resolve_for_header(&self, _hdr: &KeviHeader) -> anyhow::Result<DerivedKey> {
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(self.key.expose_secret().clone())),
        })
    }

    fn resolve_for_new_vault(
        &self,
        _params: HeaderParams,
        _salt: [u8; 16],
    ) -> anyhow::Result<DerivedKey> {
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(self.key.expose_secret().clone())),
        })
    }
}

#[test]
fn save_new_vault_then_load_round_trips_default_data() {
    let store: Arc<dyn ByteStore> = Arc::new(MemoryStore::new());
    let codec: Arc<dyn VaultCodec> = Arc::new(TestCodec);
    let resolver: Arc<dyn KeyResolver> = Arc::new(FixedResolver::from_password("pw"));
    let service = VaultService::new(store, codec, resolver);

    let data = VaultData::default();
    service.save(&data).expect("save new vault");
    let loaded = service.load().expect("load saved vault");

    assert!(loaded.entries.is_empty());
    assert!(loaded.otps.is_empty());
}
