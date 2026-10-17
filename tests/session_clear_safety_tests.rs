use kevi::api::*;
#[cfg(all(unix, not(target_os = "macos")))]
use secrecy::SecretBox;
#[cfg(all(unix, not(target_os = "macos")))]
use std::time::Duration;
use tempfile::tempdir;

#[cfg(all(unix, not(target_os = "macos")))]
struct FixedClock;

#[cfg(all(unix, not(target_os = "macos")))]
impl Clock for FixedClock {
    fn now(&self) -> VaultResult<u64> {
        Ok(100)
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn stored_session() -> DerivedKeyStored {
    DerivedKeyStored::issue(
        "identity".into(),
        "ab".repeat(32),
        &SecretBox::new(Box::new(vec![7; 32])),
        Duration::from_secs(60),
        &FixedClock,
    )
    .unwrap()
}

#[test]
fn public_clear_leaves_unrelated_and_vault_files_untouched() {
    let directory = tempdir().unwrap();
    for (name, contents) in [
        ("ordinary", b"ordinary file".as_slice()),
        (
            "generic-ron",
            b"(expires_at_unix: 200, data: \"not a session cache\")".as_slice(),
        ),
        ("vault", b"KEVI encrypted vault"),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, contents).unwrap();

        assert!(clear(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), contents);
    }
}

#[test]
fn public_clear_preserves_bare_key_shaped_ron() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unrelated.ron");
    let bytes = format!(
        "(header_fingerprint_hex: \"{}\", key_b64: \"{}\")",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    std::fs::write(&path, &bytes).unwrap();

    assert!(clear(&path).is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes.as_bytes());
}

#[test]
fn public_clear_missing_path_is_a_noop() {
    let directory = tempdir().unwrap();
    assert!(clear(&directory.path().join("missing.dksession")).is_ok());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn public_clear_removes_recognizable_cache_session_in_protected_directory() {
    let home = std::env::var_os("HOME").expect("CI provides a protected home directory");
    let directory = tempfile::tempdir_in(home).expect("create fixture below protected home");
    let path = directory.path().join("cache.dksession");
    FileDerivedKeySessionStore::new(path.clone())
        .save_cached(&stored_session(), Duration::from_secs(60))
        .unwrap();

    clear(&path).unwrap();
    assert!(!path.exists());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn public_clear_preserves_generic_ron_session_written_by_public_save() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("generic-session.ron");
    save(&path, &"dummy session payload", Duration::from_secs(60)).unwrap();
    let bytes = std::fs::read(&path).unwrap();

    assert!(matches!(
        clear(&path),
        Err(KeviError::Cache(CacheError::CleanupConflict))
    ));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn public_clear_preserves_recognizable_session_when_parent_is_unsafe() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let path = directory.path().join("session.ron");
    save(&path, &"dummy session payload", Duration::from_secs(60)).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

    assert!(clear(&path).is_err());
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
#[cfg(any(target_os = "macos", windows, not(unix)))]
fn public_clear_fails_closed_for_existing_session_on_unverified_platform() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("session.ron");
    let bytes = b"(expires_at_unix:160,data:\"dummy session payload\")";
    std::fs::write(&path, bytes).unwrap();

    assert!(matches!(
        clear(&path),
        Err(KeviError::Cache(CacheError::CleanupConflict))
    ));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
