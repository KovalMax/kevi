use base64::Engine as _;
use kevi::api::{
    clear, dk_session_file_for, header_fingerprint_excluding_nonce, load, save,
    save_derived_key_session, session_store_for_vault, BypassKeyResolver, CachedKeyResolver,
    DerivedKeySessionStore, DerivedKeyStored, HeaderParams, KeviHeader, KeyResolver, VaultResult,
    AEAD_AES256GCM, HEADER_VERSION, KDF_ARGON2ID,
};
use secrecy::{ExposeSecret, SecretBox};
use serial_test::serial;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::tempdir;

#[derive(Default)]
struct MemoryDerivedKeySessionStore {
    value: Mutex<Option<DerivedKeyStored>>,
    save_calls: Mutex<usize>,
}

#[derive(Default)]
struct FailingDerivedKeySessionStore;

impl DerivedKeySessionStore for MemoryDerivedKeySessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        Ok(self.value.lock().expect("lock").clone())
    }

    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: Duration) -> VaultResult<()> {
        *self.value.lock().expect("lock") = Some(DerivedKeyStored {
            header_fingerprint_hex: stored.header_fingerprint_hex.clone(),
            key_b64: stored.key_b64.clone(),
        });
        *self.save_calls.lock().expect("lock") += 1;
        Ok(())
    }

    fn clear_cached(&self) -> VaultResult<()> {
        *self.value.lock().expect("lock") = None;
        Ok(())
    }
}

impl DerivedKeySessionStore for FailingDerivedKeySessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        Err(kevi::api::KeviError::vault("load failed"))
    }

    fn save_cached(&self, _stored: &DerivedKeyStored, _ttl: Duration) -> VaultResult<()> {
        Err(kevi::api::KeviError::vault("save failed"))
    }

    fn clear_cached(&self) -> VaultResult<()> {
        Ok(())
    }
}

fn sample_header() -> KeviHeader {
    KeviHeader {
        version: HEADER_VERSION,
        kdf_id: KDF_ARGON2ID,
        aead_id: AEAD_AES256GCM,
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_lanes: 1,
        salt: [7u8; 16],
        nonce: [9u8; 12],
    }
}

#[test]
fn dk_session_file_uses_dksession_extension() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let session_path = dk_session_file_for(&vault_path);
    assert!(
        session_path.to_string_lossy().ends_with("vault.dksession"),
        "expected .dksession extension"
    );
}

#[test]
fn save_derived_key_session_round_trips_with_ttl() {
    let td = tempdir().expect("tempdir");
    let session_path = td.path().join("session.dksession");
    let key = SecretBox::new(Box::new(vec![42u8; 32]));

    save_derived_key_session(&session_path, "fingerprint", &key, Duration::from_secs(60))
        .expect("save session");

    let loaded: Option<DerivedKeyStored> = load(&session_path).expect("load session");
    let envelope = loaded.expect("existing session envelope");
    assert_eq!(envelope.header_fingerprint_hex, "fingerprint");
    assert!(!envelope.key_b64.is_empty());
}

#[test]
#[serial]
fn cached_resolver_caches_key_and_reuses_it_without_password_env() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let hdr = sample_header();

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let first = resolver
        .resolve_for_header(&hdr)
        .expect("derive and cache key");
    std::env::remove_var("KEVI_PASSWORD");

    let second = resolver
        .resolve_for_header(&hdr)
        .expect("load key from cache");

    assert_eq!(first.key.expose_secret(), second.key.expose_secret());
}

#[test]
#[serial]
fn bypass_resolver_derives_without_session_side_effects() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let session_path = dk_session_file_for(&vault_path);
    let resolver = BypassKeyResolver::new();

    let params = HeaderParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_lanes: 1,
    };
    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let key = resolver
        .resolve_for_new_vault(params, [11u8; 16])
        .expect("derive key");
    std::env::remove_var("KEVI_PASSWORD");

    assert_eq!(key.key.expose_secret().len(), 32);
    assert!(!session_path.exists(), "bypass resolver must not cache key");
    clear(&session_path).expect("clear no-op");
}

#[test]
#[serial]
fn cached_resolver_rederives_when_cached_fingerprint_mismatches() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let session_path = dk_session_file_for(&vault_path);

    let stored = DerivedKeyStored {
        header_fingerprint_hex: "different-fingerprint".to_string(),
        key_b64: base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
    };
    save(&session_path, &stored, Duration::from_secs(120)).expect("save mismatched session");

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let derived = resolver
        .resolve_for_header(&sample_header())
        .expect("should rederive on mismatch");
    std::env::remove_var("KEVI_PASSWORD");

    assert_eq!(derived.key.expose_secret().len(), 32);
}

#[test]
#[serial]
fn cached_resolver_rederives_when_cached_key_is_invalid_base64() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let session_path = dk_session_file_for(&vault_path);

    let stored = DerivedKeyStored {
        header_fingerprint_hex: header_fingerprint_excluding_nonce(&sample_header()),
        key_b64: "%%%not-base64%%%".to_string(),
    };
    save(&session_path, &stored, Duration::from_secs(120)).expect("save invalid base64 session");

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let derived = resolver
        .resolve_for_header(&sample_header())
        .expect("should rederive on invalid cache encoding");
    std::env::remove_var("KEVI_PASSWORD");

    assert_eq!(derived.key.expose_secret().len(), 32);
}

#[test]
#[serial]
fn cached_resolver_new_vault_caches_and_reuses_key() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let params = HeaderParams {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_lanes: 1,
    };
    let salt = [23u8; 16];

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let first = resolver
        .resolve_for_new_vault(params, salt)
        .expect("derive new vault key");
    std::env::remove_var("KEVI_PASSWORD");

    let hdr = KeviHeader {
        version: HEADER_VERSION,
        kdf_id: KDF_ARGON2ID,
        aead_id: AEAD_AES256GCM,
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p_lanes: params.p_lanes,
        salt,
        nonce: [0u8; 12],
    };
    let second = resolver
        .resolve_for_header(&hdr)
        .expect("reuse cached new-vault key");

    assert_eq!(first.key.expose_secret(), second.key.expose_secret());
}

#[test]
#[serial]
fn cached_resolver_ignores_truncated_cached_key_and_rederives() {
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let session_path = dk_session_file_for(&vault_path);
    let header = sample_header();

    let stored = DerivedKeyStored {
        header_fingerprint_hex: header_fingerprint_excluding_nonce(&header),
        key_b64: base64::engine::general_purpose::STANDARD.encode([5u8; 8]),
    };
    save(&session_path, &stored, Duration::from_secs(120)).expect("save truncated key session");

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let derived = resolver
        .resolve_for_header(&header)
        .expect("rederive when cached key is truncated");
    std::env::remove_var("KEVI_PASSWORD");

    assert_eq!(derived.key.expose_secret().len(), 32);
}

#[test]
#[serial]
fn cached_resolver_with_injected_store_saves_then_reads_from_store() {
    let store = Arc::new(MemoryDerivedKeySessionStore::default());
    let resolver = CachedKeyResolver::new_with_store(store.clone());
    let header = sample_header();

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let first = resolver
        .resolve_for_header(&header)
        .expect("derive and store key");
    std::env::remove_var("KEVI_PASSWORD");

    let second = resolver
        .resolve_for_header(&header)
        .expect("load from injected store");

    assert_eq!(first.key.expose_secret(), second.key.expose_secret());
    assert_eq!(*store.save_calls.lock().expect("lock"), 1);
}

#[test]
#[serial]
fn fallback_is_disabled_when_secure_store_is_unavailable() {
    std::env::remove_var("KEVI_INSECURE_CACHE_FALLBACK");
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");

    let (_store, warning) = session_store_for_vault(&vault_path);

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    assert!(warning.is_none());

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    assert!(warning.is_some());
}

#[test]
#[serial]
fn insecure_fallback_can_be_enabled_explicitly() {
    std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", "1");
    let td = tempdir().expect("tempdir");
    let vault_path = td.path().join("vault.ron");

    let (store, warning) = session_store_for_vault(&vault_path);
    let payload = DerivedKeyStored {
        header_fingerprint_hex: "fp".to_string(),
        key_b64: "Zm9vYmFy".to_string(),
    };

    store
        .save_cached(&payload, Duration::from_secs(60))
        .expect("explicit fallback should be writable");

    assert!(warning.is_none());
    std::env::remove_var("KEVI_INSECURE_CACHE_FALLBACK");
}

#[test]
#[serial]
fn injected_failing_store_emits_warning_once_on_load_and_save_errors() {
    let store = Arc::new(FailingDerivedKeySessionStore);
    let warnings = Arc::new(Mutex::new(Vec::<String>::new()));
    let warnings_for_sink = warnings.clone();
    let resolver = CachedKeyResolver::new_with_store_and_warning(
        store,
        Some("secure cache unavailable".to_string()),
        Arc::new(move |message| {
            warnings_for_sink
                .lock()
                .expect("lock")
                .push(message.to_string())
        }),
    );

    std::env::set_var("KEVI_PASSWORD", "master-pw");
    let _first = resolver
        .resolve_for_header(&sample_header())
        .expect("derive key when store load/save fail");
    let _second = resolver
        .resolve_for_header(&sample_header())
        .expect("derive key again when store load/save fail");
    std::env::remove_var("KEVI_PASSWORD");

    let recorded = warnings.lock().expect("lock").clone();
    assert_eq!(recorded, vec!["secure cache unavailable".to_string()]);
}
