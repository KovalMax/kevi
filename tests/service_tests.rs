use kevi::filesystem::store::FileByteStore;
use kevi::session_management::resolver::CachedKeyResolver;
use kevi::vault::codec::RonCodec;
use kevi::vault::models::VaultEntry;
use kevi::vault::service::VaultService;
use secrecy::SecretString;
use std::env;
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn service_add_and_load_round_trip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");

    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path.clone()));
    let service = VaultService::new(store, codec, resolver);

    // Initially empty
    let initial = service.load().expect("load ok");
    assert!(initial.entries.is_empty());

    // Add entry
    let entry = VaultEntry {
        label: "svc_label".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("pw".into()),
        notes: None,
    };
    service.add_entry(entry).expect("add ok");

    // Load and verify
    let loaded = service.load().expect("reload ok");
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].label, "svc_label");

    // File should be encrypted with a KEVI header
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"KEVI"));
}

#[test]
fn service_remove_entry() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    env::set_var("KEVI_PASSWORD", "svcpass");

    let store = Arc::new(FileByteStore::new(path));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(dir.path().join("vault.ron")));
    let service = VaultService::new(store, codec, resolver);

    // Add two entries
    service
        .add_entry(VaultEntry {
            label: "a".into(),
            username: None,
            password: SecretString::new("1".into()),
            notes: None,
        })
        .unwrap();
    service
        .add_entry(VaultEntry {
            label: "b".into(),
            username: None,
            password: SecretString::new("2".into()),
            notes: None,
        })
        .unwrap();

    // Remove one
    let removed = service.remove_entry("a").unwrap();
    assert!(removed);
    let after = service.load().unwrap();
    assert_eq!(after.entries.len(), 1);
    assert_eq!(after.entries[0].label, "b");
}

#[test]
fn service_rejects_plaintext_with_clear_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    std::fs::write(&path, "(entries:[],otps:[])").unwrap();
    env::set_var("KEVI_PASSWORD", "svcpass");

    let store = Arc::new(FileByteStore::new(path.clone()));
    let codec = Arc::new(RonCodec);
    let resolver = Arc::new(CachedKeyResolver::new(path));
    let service = VaultService::new(store, codec, resolver);

    let err = service.load().expect_err("plaintext vault must fail");
    let msg = err.to_string();
    assert!(msg.contains("missing KEVI header"));
}
