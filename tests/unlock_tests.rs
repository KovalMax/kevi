use kevi::config::config::Config;
use kevi::core::adapters::{CachedKeyResolver, FileByteStore, RonCodec};
use kevi::core::dk_session::{dk_session_file_for, read_dk_session};
use kevi::core::entry::VaultEntry;
use kevi::core::service::VaultService;
use kevi::core::vault::Vault;
use secrecy::SecretString;
use std::env;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn service_uses_cached_derived_key_session() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    // Provide a password to derive and cache a derived key upon first save
    env::set_var("KEVI_PASSWORD", "pw");

    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = VaultService::new(store, codec, resolver);

    // Save an entry (will derive and cache derived key)
    let entry = VaultEntry {
        label: "cached".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("pw!".into()),
        notes: None,
    };
    service.save(&[entry]).expect("save using cache");

    // Clear env to ensure resolver uses cached derived key
    env::remove_var("KEVI_PASSWORD");
    // Load it back (should not prompt, should use dk session)
    let loaded = service.load().expect("load using cache");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].label, "cached");
}

#[tokio::test]
async fn vault_handle_unlock_and_lock_manage_session() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    // Initialize an encrypted vault file (empty) so header exists
    {
        use kevi::core::store::save_vault_file;
        let entries: Vec<kevi::core::entry::VaultEntry> = Vec::new();
        // Ensure password available
        std::env::set_var("KEVI_PASSWORD", "pw");
        save_vault_file(&entries, &path, "pw").expect("init empty vault");
    }
    let config = Config::create(Some(path.clone()));
    let vault = Vault::create(&config);

    // Provide password via env to avoid prompt
    env::set_var("KEVI_PASSWORD", "pw");
    vault.handle_unlock(Some(30)).await.expect("unlock ok");
    let dk_path = dk_session_file_for(&path);
    assert!(dk_path.exists(), "dk session file should exist after unlock");
    assert!(read_dk_session(&dk_path).unwrap().is_some());

    // Clear env then lock; a session file should be removed
    env::remove_var("KEVI_PASSWORD");
    vault.handle_lock().await.expect("lock ok");
    assert!(!dk_path.exists(), "dk session file should be removed after lock");
}
