use kevi::core::adapters::{CachedKeyResolver, FileByteStore, RonCodec};
use kevi::core::entry::VaultEntry;
use kevi::core::service::VaultService;
use kevi::core::store::load_vault_file;
use secrecy::SecretString;
use std::fs;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn store_rejects_plaintext_vault_files() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");

    // Write a plaintext RON file (no KEVI header)
    let entries = vec![VaultEntry {
        label: "plain".into(),
        username: None,
        password: SecretString::new("pw".into()),
        notes: None,
    }];
    let ron = ron::to_string(&entries).unwrap();
    fs::write(&path, ron).unwrap();

    // Attempt to load should error due to missing KEVI header
    let res = load_vault_file(&path, "irrelevant");
    assert!(res.is_err());
    let err = format!("{}", res.unwrap_err());
    assert!(err.contains("missing KEVI header"));
}

#[test]
fn service_rejects_plaintext_vault_files() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");

    // Write a plaintext RON file (no KEVI header)
    let entries = vec![VaultEntry {
        label: "plain".into(),
        username: None,
        password: SecretString::new("pw".into()),
        notes: None,
    }];
    let ron = ron::to_string(&entries).unwrap();
    fs::write(&path, ron).unwrap();

    // Compose service
    std::env::set_var("KEVI_PASSWORD", "pw");
    let store = Arc::new(FileByteStore::new(path));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(td.path().join("vault.ron")));
    let svc = VaultService::new(store, codec, resolver);

    let res = svc.load();
    assert!(res.is_err());
    let err = format!("{}", res.unwrap_err());
    assert!(err.contains("missing KEVI header"));
}
