use kevi::api::*;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;

fn session_bytes() -> Vec<u8> {
    DerivedKeyStored {
        schema: 1,
        identity: "test-identity".into(),
        header_fingerprint_hex: "ab".repeat(32),
        issued_at_unix: 100,
        expires_at_unix: 200,
        key_b64: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
    }
    .encode()
    .unwrap()
    .to_vec()
}

#[derive(Default)]
struct Cleanup {
    native: Mutex<Vec<String>>,
    files: Mutex<Vec<PathBuf>>,
    failure: Option<CacheError>,
}
impl CacheCleanup for Cleanup {
    fn native(&self, account: &str) -> VaultResult<()> {
        self.native.lock().unwrap().push(account.into());
        match self.failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
    fn file(&self, path: &Path) -> VaultResult<()> {
        self.files.lock().unwrap().push(path.into());
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CacheError::Delete.into()),
        }
    }
}

#[test]
fn new_namespace_does_not_collide_by_extension_and_resolves_missing_ancestors() {
    let dir = tempdir().unwrap();
    let first = dir.path().join("vault.ron");
    let second = dir.path().join("vault.bin");
    assert_ne!(
        dk_session_file_for(first).unwrap(),
        dk_session_file_for(second).unwrap()
    );
    let missing = dir.path().join("new/deeper/vault.ron");
    assert_eq!(
        canonical_vault_path(&missing).unwrap(),
        dir.path()
            .canonicalize()
            .unwrap()
            .join("new/deeper/vault.ron")
    );
}

#[test]
#[cfg(unix)]
fn symlinks_and_non_utf8_paths_have_lossless_consistent_identity() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    std::fs::write(&vault, b"dummy").unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&vault, &alias).unwrap();
    assert_eq!(
        path_identity(&vault).unwrap(),
        path_identity(&alias).unwrap()
    );
    assert_eq!(
        dk_session_file_for(&vault).unwrap(),
        dk_session_file_for(&alias).unwrap()
    );
    let first = dir.path().join(std::ffi::OsString::from_vec(vec![0xfe]));
    let second = dir.path().join(std::ffi::OsString::from_vec(vec![0xff]));
    assert_ne!(
        path_identity(&first).unwrap(),
        path_identity(&second).unwrap()
    );
    let directory_alias = dir.path().join("directory-alias");
    std::os::unix::fs::symlink(dir.path(), &directory_alias).unwrap();
    assert_eq!(
        path_identity(directory_alias.join("missing/vault").as_path()).unwrap(),
        path_identity(dir.path().join("missing/vault").as_path()).unwrap()
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn cleanup_attempts_all_targets_after_native_errors_and_missing_only_succeeds() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    let legacy = vault.with_extension("dksession");
    for failure in [
        CacheError::Denied,
        CacheError::Unavailable,
        CacheError::Delete,
    ] {
        std::fs::write(&current, session_bytes()).unwrap();
        std::fs::write(&legacy, session_bytes()).unwrap();
        let cleanup = Cleanup {
            failure: Some(failure),
            ..Cleanup::default()
        };
        let error = clear_with(&vault, &cleanup).unwrap_err();
        assert!(error.to_string().contains("partial cache cleanup failure"));
        assert!(!current.exists());
        assert!(!legacy.exists());
        let native = cleanup.native.lock().unwrap();
        assert!(native.len() >= 2);
        assert_eq!(
            native.len(),
            native
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        assert!(cleanup.files.lock().unwrap().contains(&current));
    }
    clear_with(
        &vault,
        &Cleanup {
            failure: Some(CacheError::Missing),
            ..Cleanup::default()
        },
    )
    .unwrap();
}

#[test]
#[cfg(not(target_os = "macos"))]
fn file_failure_does_not_stop_other_deletions_or_native_cleanup() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    std::fs::create_dir(&current).unwrap();
    let legacy = vault.with_extension("dksession");
    std::fs::write(&legacy, session_bytes()).unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&vault, &cleanup).is_err());
    assert!(!legacy.exists());
    assert!(!cleanup.native.lock().unwrap().is_empty());
}

#[test]
#[cfg(unix)]
fn cleanup_preserves_selected_dksession_vault_and_symlink_alias_vault() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("actual.dksession");
    std::fs::write(&vault, b"KEVI encrypted vault fixture").unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&vault, &cleanup).is_err());
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        b"KEVI encrypted vault fixture"
    );

    let alias = dir.path().join("alias.ron");
    std::os::unix::fs::symlink(&vault, &alias).unwrap();
    let alias_cleanup = Cleanup::default();
    assert!(clear_with(&alias, &alias_cleanup).is_err());
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        b"KEVI encrypted vault fixture"
    );
}

#[test]
fn cleanup_preserves_another_encrypted_vault_at_the_legacy_cache_name() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    std::fs::write(&vault, b"selected vault").unwrap();
    let other_vault = vault.with_extension("dksession");
    std::fs::write(&other_vault, b"KEVI another encrypted vault").unwrap();
    let cleanup = Cleanup::default();

    assert!(clear_with(&vault, &cleanup).is_err());
    assert_eq!(
        std::fs::read(&other_vault).unwrap(),
        b"KEVI another encrypted vault"
    );
}

#[test]
#[cfg(not(target_os = "macos"))]
fn cleanup_removes_a_recognizable_legacy_session_file() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    std::fs::write(&legacy, session_bytes()).unwrap();

    clear_with(&vault, &Cleanup::default()).unwrap();
    assert!(!legacy.exists());
}

#[test]
fn cleanup_rejects_generic_ron_with_expiry_and_arbitrary_data() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let unrelated = b"(expires_at_unix: 200, data: \"not a cache\")";
    std::fs::write(&legacy, unrelated).unwrap();

    #[cfg(not(target_os = "macos"))]
    assert!(clear_with(&vault, &Cleanup::default()).is_err());
    assert_eq!(std::fs::read(&legacy).unwrap(), unrelated);
}

#[test]
fn bounded_lock_cleanup_preserves_bare_key_shaped_ron() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let unrelated = format!(
        "(header_fingerprint_hex: \"{}\", key_b64: \"{}\")",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    std::fs::write(&legacy, &unrelated).unwrap();

    #[cfg(not(target_os = "macos"))]
    assert!(clear_with(&vault, &Cleanup::default()).is_err());
    assert_eq!(std::fs::read(legacy).unwrap(), unrelated.as_bytes());
}

#[test]
fn cleanup_recognizes_exact_supported_ron_legacy_session() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let payload = format!(
        "(expires_at_unix: 200, data: (header_fingerprint_hex: \"{}\", key_b64: \"{}\"))",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    std::fs::write(&legacy, payload).unwrap();

    #[cfg(not(target_os = "macos"))]
    {
        clear_with(&vault, &Cleanup::default()).unwrap();
        assert!(!legacy.exists());
    }
}

#[test]
#[cfg(not(target_os = "macos"))]
fn cleanup_removes_current_file_cache_in_a_protected_directory() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    std::fs::write(&current, session_bytes()).unwrap();

    clear_with(&vault, &Cleanup::default()).unwrap();

    assert!(!current.exists());
}

#[test]
#[cfg(unix)]
fn cleanup_preserves_file_sessions_in_externally_mutable_directory_but_attempts_other_targets() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    std::fs::write(&vault, b"dummy vault").unwrap();
    let unsafe_dir = dir.path().join("externally-mutable");
    std::fs::create_dir(&unsafe_dir).unwrap();
    let alias = unsafe_dir.join("vault-alias.ron");
    std::os::unix::fs::symlink(&vault, &alias).unwrap();
    let current = dk_session_file_for(&vault).unwrap();
    let legacy = alias.with_extension("dksession");
    std::fs::write(&current, session_bytes()).unwrap();
    std::fs::write(&legacy, session_bytes()).unwrap();
    std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

    let cleanup = Cleanup::default();
    let error = clear_with(&alias, &cleanup).unwrap_err();

    assert!(error.to_string().contains("partial cache cleanup failure"));
    assert!(legacy.exists(), "unsafe legacy artifact must be preserved");
    #[cfg(not(target_os = "macos"))]
    assert!(
        !current.exists(),
        "other eligible targets are still attempted"
    );
    #[cfg(target_os = "macos")]
    assert!(current.exists(), "macOS ACL status is not verifiable");
    #[cfg(not(target_os = "macos"))]
    assert!(!cleanup.files.lock().unwrap().contains(&legacy));
    #[cfg(target_os = "macos")]
    assert!(!cleanup.files.lock().unwrap().contains(&legacy));
    assert!(!cleanup.native.lock().unwrap().is_empty());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn identity_resolution_failure_still_attempts_supplied_legacy_targets() {
    let dir = tempdir().unwrap();
    let loop_path = dir.path().join("loop");
    std::os::unix::fs::symlink(&loop_path, &loop_path).unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&loop_path, &cleanup).is_err());
    assert!(!cleanup.native.lock().unwrap().is_empty());
    assert!(cleanup
        .files
        .lock()
        .unwrap()
        .contains(&loop_path.with_extension("dksession")));
}

#[test]
#[cfg(target_os = "macos")]
fn macos_file_cleanup_fails_closed_for_current_and_legacy_names() {
    let dir = tempdir().unwrap();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    let legacy = vault.with_extension("dksession");
    std::fs::write(&current, session_bytes()).unwrap();
    std::fs::write(&legacy, session_bytes()).unwrap();
    let cleanup = Cleanup::default();

    let error = clear_with(&vault, &cleanup).unwrap_err();

    assert!(error.to_string().contains("partial cache cleanup failure"));
    assert!(current.exists());
    assert!(legacy.exists());
    assert!(cleanup.files.lock().unwrap().is_empty());
    assert!(!cleanup.native.lock().unwrap().is_empty());
}

#[test]
fn provider_diagnostics_are_sanitized_and_other_targets_continue() {
    struct Noisy {
        files: Mutex<usize>,
    }
    impl CacheCleanup for Noisy {
        fn native(&self, _: &str) -> VaultResult<()> {
            Err(KeviError::vault("sensitive-provider-diagnostic"))
        }
        fn file(&self, _: &Path) -> VaultResult<()> {
            *self.files.lock().unwrap() += 1;
            Ok(())
        }
    }
    let dir = tempdir().unwrap();
    let cleanup = Noisy {
        files: Mutex::new(0),
    };
    let error = clear_with(&dir.path().join("vault"), &cleanup).unwrap_err();
    assert!(!error.to_string().contains("sensitive-provider-diagnostic"));
    assert!(matches!(error, KeviError::CacheCleanup(_)));
    assert!(*cleanup.files.lock().unwrap() >= 2);
}
