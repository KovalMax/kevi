use kevi::api::*;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;

fn cleanup_test_dir() -> tempfile::TempDir {
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var_os("HOME").expect("CI provides a protected home directory");
        tempfile::tempdir_in(home).expect("create fixture below protected home")
    }
    #[cfg(not(target_os = "linux"))]
    {
        tempdir().unwrap()
    }
}

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
    let dir = cleanup_test_dir();
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
    let dir = cleanup_test_dir();
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
fn cleanup_attempts_current_targets_after_native_errors_and_missing_only_succeeds() {
    let dir = cleanup_test_dir();
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
        #[cfg(all(unix, not(target_os = "macos")))]
        assert!(!current.exists());
        #[cfg(any(target_os = "macos", windows))]
        assert!(current.exists(), "unsupported file cleanup fails closed");
        assert!(legacy.exists(), "legacy cache files are left untouched");
        let native = cleanup.native.lock().unwrap();
        assert_eq!(native.len(), 1, "only the current native account is used");
        assert_eq!(
            native.len(),
            native
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(
            *cleanup.files.lock().unwrap(),
            vec![current.clone()],
            "only the current file path is passed to cleanup"
        );
        #[cfg(any(target_os = "macos", windows))]
        assert!(cleanup.files.lock().unwrap().is_empty());
    }
    std::fs::remove_file(&current).unwrap();
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
fn file_failure_does_not_stop_other_deletions_or_native_cleanup() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    std::fs::create_dir(&current).unwrap();
    let legacy = vault.with_extension("dksession");
    std::fs::write(&legacy, session_bytes()).unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&vault, &cleanup).is_err());
    assert!(
        legacy.exists(),
        "legacy cache files are not cleanup targets"
    );
    assert_eq!(cleanup.native.lock().unwrap().len(), 1);
    assert!(cleanup.files.lock().unwrap().is_empty());
}

#[test]
#[cfg(unix)]
fn cleanup_ignores_dksession_named_vault_and_symlink_alias() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("actual.dksession");
    std::fs::write(&vault, b"KEVI encrypted vault fixture").unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&vault, &cleanup).is_ok());
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        b"KEVI encrypted vault fixture"
    );

    let alias = dir.path().join("alias.ron");
    std::os::unix::fs::symlink(&vault, &alias).unwrap();
    let alias_cleanup = Cleanup::default();
    assert!(clear_with(&alias, &alias_cleanup).is_ok());
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        b"KEVI encrypted vault fixture"
    );
}

#[test]
fn cleanup_ignores_unrelated_vault_with_historical_extension() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    std::fs::write(&vault, b"selected vault").unwrap();
    let other_vault = vault.with_extension("dksession");
    std::fs::write(&other_vault, b"KEVI another encrypted vault").unwrap();
    let cleanup = Cleanup::default();

    assert!(clear_with(&vault, &cleanup).is_ok());
    assert_eq!(cleanup.native.lock().unwrap().len(), 1);
    assert_eq!(cleanup.files.lock().unwrap().len(), 1);
    assert_eq!(
        std::fs::read(&other_vault).unwrap(),
        b"KEVI another encrypted vault"
    );
}

#[test]
fn cleanup_ignores_legacy_cache_file_on_every_platform() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    std::fs::write(&legacy, session_bytes()).unwrap();

    let cleanup = Cleanup::default();
    clear_with(&vault, &cleanup).unwrap();
    assert_eq!(std::fs::read(&legacy).unwrap(), session_bytes());
    assert_eq!(
        *cleanup.native.lock().unwrap(),
        vec![path_identity(&vault).unwrap()]
    );
    assert_eq!(
        *cleanup.files.lock().unwrap(),
        vec![dk_session_file_for(&vault).unwrap()]
    );
}

#[test]
fn cleanup_ignores_generic_ron_at_historical_path() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let unrelated = b"(expires_at_unix: 200, data: \"not a cache\")";
    std::fs::write(&legacy, unrelated).unwrap();

    clear_with(&vault, &Cleanup::default()).unwrap();
    assert_eq!(std::fs::read(&legacy).unwrap(), unrelated);
}

#[test]
fn cleanup_ignores_bare_key_shaped_ron_at_historical_path() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let unrelated = format!(
        "(header_fingerprint_hex: \"{}\", key_b64: \"{}\")",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    std::fs::write(&legacy, &unrelated).unwrap();

    clear_with(&vault, &Cleanup::default()).unwrap();
    assert_eq!(std::fs::read(legacy).unwrap(), unrelated.as_bytes());
}

#[test]
fn cleanup_ignores_exact_legacy_ron_session() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let payload = format!(
        "(expires_at_unix: 200, data: (header_fingerprint_hex: \"{}\", key_b64: \"{}\"))",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    std::fs::write(&legacy, &payload).unwrap();

    let cleanup = Cleanup::default();
    clear_with(&vault, &cleanup).unwrap();
    assert_eq!(std::fs::read(&legacy).unwrap(), payload.as_bytes());
    assert_eq!(
        *cleanup.native.lock().unwrap(),
        vec![path_identity(&vault).unwrap()]
    );
    assert_eq!(
        *cleanup.files.lock().unwrap(),
        vec![dk_session_file_for(&vault).unwrap()]
    );
}

#[test]
fn cleanup_removes_current_file_cache_in_a_protected_directory() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let current = dk_session_file_for(&vault).unwrap();
    std::fs::write(&current, session_bytes()).unwrap();

    let result = clear_with(&vault, &Cleanup::default());
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        result.unwrap();
        assert!(!current.exists());
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        assert!(result.is_err());
        assert!(
            current.exists(),
            "file cleanup fails closed on this platform"
        );
    }
}

#[test]
#[cfg(unix)]
fn cleanup_preserves_file_sessions_in_externally_mutable_directory_but_attempts_other_targets() {
    use std::os::unix::fs::PermissionsExt;

    let dir = cleanup_test_dir();
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
    assert!(legacy.exists(), "legacy artifacts are not cleanup targets");
    #[cfg(not(target_os = "macos"))]
    assert!(
        !current.exists(),
        "other eligible targets are still attempted"
    );
    #[cfg(target_os = "macos")]
    assert!(current.exists(), "macOS ACL status is not verifiable");
    assert!(!cleanup.files.lock().unwrap().contains(&legacy));
    assert_eq!(cleanup.native.lock().unwrap().len(), 1);
}

#[test]
#[cfg(windows)]
fn windows_cleanup_fails_closed_for_current_file_and_ignores_legacy_file() {
    let dir = cleanup_test_dir();
    let vault = dir.path().join("vault.ron");
    let legacy = vault.with_extension("dksession");
    let current = dk_session_file_for(&vault).unwrap();
    std::fs::write(&current, session_bytes()).unwrap();
    std::fs::write(&legacy, session_bytes()).unwrap();

    let cleanup = Cleanup::default();
    assert!(clear_with(&vault, &cleanup).is_err());
    assert_eq!(std::fs::read(&current).unwrap(), session_bytes());
    assert_eq!(std::fs::read(&legacy).unwrap(), session_bytes());
    assert!(cleanup.files.lock().unwrap().is_empty());
    assert_eq!(cleanup.native.lock().unwrap().len(), 1);
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn identity_resolution_failure_does_not_fall_back_to_legacy_targets() {
    let dir = tempdir().unwrap();
    let loop_path = dir.path().join("loop");
    std::os::unix::fs::symlink(&loop_path, &loop_path).unwrap();
    let cleanup = Cleanup::default();
    assert!(clear_with(&loop_path, &cleanup).is_err());
    assert!(cleanup.native.lock().unwrap().is_empty());
    assert!(cleanup.files.lock().unwrap().is_empty());
}

#[test]
#[cfg(target_os = "macos")]
fn macos_file_cleanup_fails_closed_for_current_and_ignores_legacy_name() {
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
    assert_eq!(cleanup.native.lock().unwrap().len(), 1);
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
    assert_eq!(*cleanup.files.lock().unwrap(), 1);
}
