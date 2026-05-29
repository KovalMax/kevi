use kevi::api::Config;
use kevi::api::{
    default_params, derive_key_argon2id, ByteStore, DerivedKey, HeaderParams, KeviError,
    KeviHeader, KeyResolver, OtpAddOptions, OtpAlgorithm, OtpGetOptions, OtpHandlers,
    OtpListOptions, OtpRemoveOptions, VaultCodec, VaultData, VaultPath, VaultResult,
    VaultService, SALT_LEN,
};
use rand::{rng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ===== Test infrastructure: in-memory store / codec / resolver =====

#[derive(Clone)]
struct MemoryStore {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl MemoryStore {
    fn new() -> Self {
        Self {
            buf: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ByteStore for MemoryStore {
    fn read(&self) -> VaultResult<Vec<u8>> {
        Ok(self.buf.lock().unwrap().clone())
    }

    fn write(&self, bytes: &[u8]) -> VaultResult<()> {
        *self.buf.lock().unwrap() = bytes.to_vec();
        Ok(())
    }
}

#[derive(Clone)]
struct RonCodec;

impl VaultCodec for RonCodec {
    fn encode(&self, data: &VaultData) -> VaultResult<Vec<u8>> {
        let s = ron::to_string(data).map_err(|e| KeviError::vault(e.to_string()))?;
        Ok(s.into_bytes())
    }

    fn decode(&self, data: &[u8]) -> VaultResult<VaultData> {
        if data.is_empty() {
            return Ok(VaultData::default());
        }
        let s = std::str::from_utf8(data).map_err(|e| KeviError::vault(e.to_string()))?;
        ron::from_str::<VaultData>(s).map_err(|e| KeviError::vault(e.to_string()))
    }
}

struct FixedKeyResolver {
    key: SecretBox<Vec<u8>>,
}

impl FixedKeyResolver {
    fn new_for_password(pw: &str) -> Self {
        let (m_cost_kib, t_cost, p_lanes) = default_params();
        let mut salt = [0u8; SALT_LEN];
        // non-crypto rng is fine in tests
        rng().fill_bytes(&mut salt);
        let key_arr = derive_key_argon2id(pw, &salt, m_cost_kib, t_cost, p_lanes).unwrap();
        let key_vec = key_arr.to_vec();
        Self {
            key: SecretBox::new(Box::new(key_vec)),
        }
    }
}

impl KeyResolver for FixedKeyResolver {
    fn resolve_for_header(&self, _hdr: &KeviHeader) -> VaultResult<DerivedKey> {
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(self.key.expose_secret().clone())),
        })
    }

    fn resolve_for_new_vault(
        &self,
        _params: HeaderParams,
        _salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(self.key.expose_secret().clone())),
        })
    }
}

fn test_config() -> Config {
    Config {
        vault_path: VaultPath::from(PathBuf::from("test-vault.ron")),
        clipboard_ttl: Some(3),
        backups: Some(0),
        generator_length: None,
        generator_words: None,
        generator_sep: None,
        avoid_ambiguous: None,
        default_profile: None,
        profiles: std::collections::HashMap::new(),
    }
}

// Simple harness that shares one VaultService between handlers and assertions.
struct Harness {
    service: Arc<VaultService>,
    handlers: OtpHandlers<'static>,
}

fn make_harness() -> Harness {
    let cfg = test_config();
    let store: Arc<dyn ByteStore> = Arc::new(MemoryStore::new());
    let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
    let resolver: Arc<dyn KeyResolver> =
        Arc::new(FixedKeyResolver::new_for_password("test-password"));
    let service = Arc::new(VaultService::new(store, codec, resolver));

    // Leak cfg to get &'static for tests; fine in test-only code.
    let cfg_static: &'static Config = Box::leak(Box::new(cfg.clone()));
    let handlers = OtpHandlers::create(cfg_static, service.clone());

    Harness { service, handlers }
}

// ===== Tests =====

#[tokio::test]
async fn otp_add_get_and_list_round_trip() {
    let h = make_harness();

    // add an OTP entry
    let add_opts = OtpAddOptions {
        name: "example1".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: Some("Example".into()),
        username: Some("demo@example.com".into()),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };
    h.handlers.handle_add(&add_opts).await.expect("add ok");

    // get code, echo, no-copy
    let get_opts = OtpGetOptions {
        name: "example1".into(),
        no_copy: false,
        echo: false,
        at: None,
        once: false,
        json: false,
    };
    h.handlers.handle_get(get_opts).await.expect("get ok");

    // list entries (text mode)
    let list_opts = OtpListOptions {
        query: None,
        json: false,
    };
    h.handlers.handle_list(list_opts).await.expect("list ok");

    // Test duplicate fails
    let err = h.handlers.handle_add(&add_opts).await.unwrap_err();
    assert!(err.to_string().contains("already exists"));

    // verify there is exactly one OTP entry
    let data = h.service.load().expect("load");
    assert_eq!(data.otps.len(), 1);
    assert_eq!(data.otps[0].name, "example1");
}

#[tokio::test]
async fn otp_add_duplicate_without_override_fails() {
    let h = make_harness();

    let base = OtpAddOptions {
        name: "dup".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: None,
        username: None,
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };

    h.handlers.handle_add(&base).await.expect("first add ok");
    let err = h.handlers.handle_add(&base).await.unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn otp_add_rejects_invalid_params() {
    let h = make_harness();

    // bad digits
    let opts = OtpAddOptions {
        name: "bad-digits".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: None,
        username: None,
        digits: 5,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };
    let err = h.handlers.handle_add(&opts).await.unwrap_err();
    assert!(err.to_string().to_lowercase().contains("digits"));
}

#[tokio::test]
async fn otp_add_duplicate_with_override_succeeds() {
    let h = make_harness();

    let base = OtpAddOptions {
        name: "dup-override".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: Some("Issuer1".into()),
        username: Some("user1@example.com".into()),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: Some("v1".into()),
        on_duplicate_override: false,
    };

    h.handlers.handle_add(&base).await.expect("first add ok");

    let override_opts = OtpAddOptions {
        on_duplicate_override: true,
        issuer: Some("Issuer2".into()),
        username: Some("user2@example.com".into()),
        notes: Some("v2".into()),
        ..base.clone()
    };

    h.handlers
        .handle_add(&override_opts)
        .await
        .expect("override ok");

    // Verify replaced entry via the same service
    let data = h.service.load().expect("load");
    let entry = data
        .otps
        .iter()
        .find(|e| e.name == "dup-override")
        .expect("entry should exist");
    assert_eq!(entry.issuer.as_deref(), Some("Issuer2"));
    assert_eq!(entry.username, "user2@example.com");
    assert_eq!(entry.notes.as_deref(), Some("v2"));
}

#[tokio::test]
async fn otp_get_rejects_no_echo_and_no_copy() {
    let h = make_harness();

    let opts = OtpGetOptions {
        name: "whatever".into(),
        no_copy: true,
        echo: false,
        at: None,
        once: false,
        json: false,
    };

    let err = h.handlers.handle_get(opts).await.unwrap_err();
    assert!(err.to_string().contains("nothing to do"));
}

#[tokio::test]
async fn otp_get_json_output_executes() {
    let h = make_harness();

    // Seed one OTP
    let add_opts = OtpAddOptions {
        name: "json-entry".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: Some("JsonIssuer".into()),
        username: Some("json@example.com".into()),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };
    h.handlers.handle_add(&add_opts).await.expect("add ok");

    let opts = OtpGetOptions {
        name: "json-entry".into(),
        no_copy: true,
        echo: false,
        at: Some(59),
        once: false,
        json: true,
    };

    // Just assert it runs successfully with a JSON format
    h.handlers.handle_get(opts).await.expect("get ok");
}

#[tokio::test]
async fn otp_get_non_existing_entry_is_ok_and_does_not_panic() {
    let h = make_harness();

    let opts = OtpGetOptions {
        name: "does-not-exist".into(),
        no_copy: true,
        echo: true,
        at: Some(59),
        once: false,
        json: false,
    };

    // Should not error; handler prints a message and returns Ok.
    h.handlers.handle_get(opts).await.expect("get ok");
}

#[tokio::test]
async fn otp_get_once_path_executes() {
    let h = make_harness();

    let add_opts = OtpAddOptions {
        name: "once-entry".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: None,
        username: None,
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };
    h.handlers.handle_add(&add_opts).await.expect("add ok");

    let opts = OtpGetOptions {
        name: "once-entry".into(),
        no_copy: true,
        echo: true,
        at: Some(59),
        once: true,
        json: false,
    };

    h.handlers.handle_get(opts).await.expect("get ok");
}

#[tokio::test]
async fn otp_list_json_and_filter_executes() {
    let h = make_harness();

    // Seed multiple OTPs
    let mk = |name: &str| OtpAddOptions {
        name: name.into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: None,
        username: None,
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };

    h.handlers.handle_add(&mk("github")).await.unwrap();
    h.handlers.handle_add(&mk("gitlab")).await.unwrap();

    // JSON output, with filter
    let opts = OtpListOptions {
        query: Some("hub".into()),
        json: true,
    };

    h.handlers.handle_list(opts).await.expect("list ok");
}

#[tokio::test]
async fn otp_list_empty_executes() {
    let h = make_harness();

    let opts = OtpListOptions {
        query: None,
        json: false,
    };

    h.handlers.handle_list(opts).await.expect("list ok");
}

#[tokio::test]
async fn otp_remove_not_existing_executes() {
    let h = make_harness();

    let opts = OtpRemoveOptions {
        name: "missing".into(),
        yes: true,
    };

    h.handlers.handle_remove(opts).await.expect("remove ok");
}

#[tokio::test]
async fn otp_remove_existing_with_yes_flag_removes_entry() {
    let h = make_harness();

    let add_opts = OtpAddOptions {
        name: "to-remove".into(),
        secret: Some("JBSWY3DPEHPK3PXP".into()),
        from_uri: None,
        issuer: None,
        username: None,
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    };
    h.handlers.handle_add(&add_opts).await.expect("add ok");

    let opts = OtpRemoveOptions {
        name: "to-remove".into(),
        yes: true,
    };

    h.handlers.handle_remove(opts).await.expect("remove ok");

    let data = h.service.load().expect("load");
    assert!(data.otps.iter().all(|e| e.name != "to-remove"));
}
