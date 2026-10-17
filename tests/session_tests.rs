use kevi::api::*;
use secrecy::SecretBox;
use std::time::Duration;
use tempfile::tempdir;
struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> VaultResult<u64> {
        Ok(self.0)
    }
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn file_session_roundtrip_is_restrictive_and_expired_reads_do_not_delete() {
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::var_os("HOME").expect("CI provides a protected home directory");
    let dir = tempfile::tempdir_in(home).expect("create fixture below protected home");
    let path = dk_session_file_for(dir.path().join("vault.ron")).unwrap();
    let store = FileDerivedKeySessionStore::new(path.clone());
    assert!(store.load_cached().unwrap().is_none());
    let stored = DerivedKeyStored::issue(
        "identity".into(),
        "ab".repeat(32),
        &SecretBox::new(Box::new(vec![42; 32])),
        Duration::from_secs(30),
        &Fixed(100),
    )
    .unwrap();
    store.save_cached(&stored, Duration::from_secs(30)).unwrap();
    let before = std::fs::read(&path).unwrap();
    save(&path, &"dummy", Duration::ZERO).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let loaded = store.load_cached().unwrap().unwrap();
    assert_eq!(stored.encode().unwrap(), loaded.encode().unwrap());
    assert!(loaded.key("identity", "fingerprint", &Fixed(130)).is_err());
    assert!(path.exists());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    store.clear_cached().unwrap();
    store.clear_cached().unwrap();
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn generic_session_api_roundtrips_on_supported_unix() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-session");
    save(&path, &"dummy session", Duration::from_secs(60)).unwrap();
    assert_eq!(
        load::<String>(&path).unwrap().as_deref(),
        Some("dummy session")
    );
}

#[test]
fn generic_session_save_rejects_fractional_ttl_before_platform_availability() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-session");
    let existing_bytes = b"pre-existing session bytes";
    std::fs::write(&path, existing_bytes).unwrap();

    for ttl in [Duration::from_millis(500), Duration::from_millis(2500)] {
        assert!(matches!(
            save(&path, &"dummy session", ttl),
            Err(KeviError::Cache(CacheError::InvalidTtl))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), existing_bytes);
    }
}

#[test]
fn generic_session_save_zero_ttl_is_a_noop_on_every_platform() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("generic-session");

    save(&path, &"dummy session", Duration::ZERO).unwrap();
    assert!(!path.exists());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn malformed_and_oversized_file_payloads_are_reported_without_deletion() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dummy-session");
    let store = FileDerivedKeySessionStore::new(path.clone());
    for bytes in [
        b"not-json".to_vec(),
        vec![b'x'; 4097],
        b"(expires_at_unix:999,data:())".to_vec(),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            store.load_cached(),
            Err(KeviError::Cache(CacheError::Malformed))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
#[cfg(any(not(unix), target_os = "macos"))]
fn file_mode_fails_closed_without_a_platform_access_control_guarantee() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dummy-session");
    let store = FileDerivedKeySessionStore::new(path.clone());
    let stored = DerivedKeyStored::issue(
        "i".into(),
        "f".into(),
        &SecretBox::new(Box::new(vec![1; 32])),
        Duration::from_secs(30),
        &Fixed(100),
    )
    .unwrap();
    assert!(matches!(
        store.load_cached(),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert!(matches!(
        store.save_cached(&stored, Duration::from_secs(30)),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert!(!path.exists());
}

#[test]
#[cfg(target_os = "macos")]
fn macos_file_mode_does_not_read_write_or_delete_session_files() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("dummy-session");
    let store = FileDerivedKeySessionStore::new(path.clone());
    std::fs::write(&path, b"preserve-me").unwrap();

    assert!(matches!(
        store.load_cached(),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert!(matches!(
        store.clear_cached(),
        Err(KeviError::Cache(CacheError::CleanupConflict))
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"preserve-me");
}

#[test]
#[cfg(any(not(unix), target_os = "macos"))]
fn generic_session_api_fails_closed_without_reading_or_writing() {
    let dir = tempdir().unwrap();
    let existing = dir.path().join("generic-session");
    let bytes = b"(expires_at_unix: 9999999999, data: \"dummy payload\")";
    std::fs::write(&existing, bytes).unwrap();
    let missing = dir.path().join("missing-session");

    assert!(matches!(
        save(&missing, &"dummy", Duration::from_secs(60)),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert!(!missing.exists());
    assert!(save(&missing, &"dummy", Duration::ZERO).is_ok());
    assert!(matches!(
        load::<String>(&existing),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert!(matches!(
        load::<String>(&missing),
        Err(KeviError::Cache(CacheError::Unavailable))
    ));
    assert_eq!(std::fs::read(&existing).unwrap(), bytes);
    assert!(!missing.exists());

    assert!(matches!(
        clear(&existing),
        Err(KeviError::Cache(CacheError::CleanupConflict))
    ));
    assert_eq!(std::fs::read(&existing).unwrap(), bytes);
    assert!(clear(&missing).is_ok());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn failed_replace_cleans_temporary_and_never_follows_destination_symlink() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("session");
    let stored = DerivedKeyStored::issue(
        "i".into(),
        "f".into(),
        &SecretBox::new(Box::new(vec![1; 32])),
        Duration::from_secs(30),
        &Fixed(100),
    )
    .unwrap();
    std::fs::create_dir(&path).unwrap();
    let store = FileDerivedKeySessionStore::new(path.clone());
    assert!(store.save_cached(&stored, Duration::from_secs(30)).is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    std::fs::remove_dir(&path).unwrap();
    let sentinel = dir.path().join("sentinel");
    std::fs::write(&sentinel, b"untouched").unwrap();
    std::os::unix::fs::symlink(&sentinel, &path).unwrap();
    store.save_cached(&stored, Duration::from_secs(30)).unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
    assert!(!std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
}
