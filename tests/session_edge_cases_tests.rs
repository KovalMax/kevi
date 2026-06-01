use kevi::api::{
    default_params, dk_session_file_for, header_fingerprint_excluding_nonce, load,
    save_derived_key_session, CachedKeyResolver, DerivedKeyStored, KeviHeader, KeyResolver,
    AEAD_AES256GCM, HEADER_VERSION, KDF_ARGON2ID, NONCE_LEN,
};
use secrecy::{ExposeSecret, SecretBox};
use serde::Serialize;
use serial_test::serial;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

#[derive(Serialize)]
struct SessionEnvelopeForTest<T> {
    expires_at_unix: u64,
    data: T,
}

#[derive(Serialize)]
struct StoredSessionForTest {
    header_fingerprint_hex: String,
    key_b64: String,
}

fn build_header() -> KeviHeader {
    let (m_cost_kib, t_cost, p_lanes) = default_params();
    KeviHeader {
        version: HEADER_VERSION,
        kdf_id: KDF_ARGON2ID,
        aead_id: AEAD_AES256GCM,
        m_cost_kib,
        t_cost,
        p_lanes,
        salt: [7u8; 16],
        nonce: [0u8; NONCE_LEN],
    }
}

#[test]
fn load_returns_none_for_missing_session_file() {
    let dir = tempdir().expect("tempdir");
    let missing = dir.path().join("missing.dksession");
    let loaded: Option<DerivedKeyStored> = load(&missing).expect("load should succeed");
    assert!(loaded.is_none());
}

#[test]
fn load_returns_none_and_deletes_corrupt_session_file() {
    let dir = tempdir().expect("tempdir");
    let session_path = dir.path().join("corrupt.dksession");
    std::fs::write(&session_path, "not valid ron").expect("write corrupt session");

    let loaded: Option<DerivedKeyStored> = load(&session_path).expect("load should succeed");
    assert!(loaded.is_none());
    assert!(!session_path.exists(), "corrupt session should be removed");
}

#[test]
#[serial]
fn cached_key_resolver_derives_when_cached_fingerprint_mismatches() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.ron");
    let dk_path = dk_session_file_for(&vault_path);
    env::set_var("KEVI_INSECURE_CACHE_FALLBACK", "1");
    let resolver = CachedKeyResolver::new(vault_path.clone());
    let header = build_header();
    let fingerprint = header_fingerprint_excluding_nonce(&header);

    let key = SecretBox::new(Box::new(vec![0x11; 32]));
    save_derived_key_session(
        &dk_path,
        "different-fingerprint",
        &key,
        Duration::from_secs(60),
    )
    .expect("seed cached key");

    env::set_var("KEVI_PASSWORD", "session-edge-pw");
    let derived = resolver
        .resolve_for_header(&header)
        .expect("resolver should derive on mismatch");
    env::remove_var("KEVI_PASSWORD");
    env::remove_var("KEVI_INSECURE_CACHE_FALLBACK");

    assert_eq!(derived.key.expose_secret().len(), 32);
    let stored: DerivedKeyStored = load(&dk_path)
        .expect("load rewritten session")
        .expect("session should exist");
    assert_eq!(stored.header_fingerprint_hex, fingerprint);
}

#[test]
#[serial]
fn cached_key_resolver_derives_when_cached_base64_is_invalid() {
    let dir = tempdir().expect("tempdir");
    let vault_path = dir.path().join("vault.ron");
    let dk_path = dk_session_file_for(&vault_path);
    env::set_var("KEVI_INSECURE_CACHE_FALLBACK", "1");
    let resolver = CachedKeyResolver::new(vault_path);
    let header = build_header();
    let fingerprint = header_fingerprint_excluding_nonce(&header);

    let envelope = SessionEnvelopeForTest {
        expires_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unix time")
            .as_secs()
            + 120,
        data: StoredSessionForTest {
            header_fingerprint_hex: fingerprint.clone(),
            key_b64: "not-base64".to_string(),
        },
    };
    let ron = ron::to_string(&envelope).expect("serialize envelope");
    std::fs::write(&dk_path, ron).expect("write invalid b64 session");

    env::set_var("KEVI_PASSWORD", "session-edge-pw");
    let derived = resolver
        .resolve_for_header(&header)
        .expect("resolver should derive on invalid base64");
    env::remove_var("KEVI_PASSWORD");
    env::remove_var("KEVI_INSECURE_CACHE_FALLBACK");

    assert_eq!(derived.key.expose_secret().len(), 32);
    let stored: DerivedKeyStored = load(&dk_path)
        .expect("load rewritten session")
        .expect("session should exist");
    assert_eq!(stored.header_fingerprint_hex, fingerprint);
    assert_ne!(stored.key_b64, "not-base64");
}
