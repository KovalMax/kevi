use super::cleanup_file::check_target;
use super::envelope::{Clock, DerivedKeyStored};
use crate::domain::VaultResult;
use secrecy::SecretBox;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> VaultResult<u64> {
        Ok(100)
    }
}

fn current_session_bytes() -> Vec<u8> {
    DerivedKeyStored::issue(
        "identity".into(),
        "ab".repeat(32),
        &SecretBox::new(Box::new(vec![7; 32])),
        Duration::from_secs(60),
        &FixedClock,
    )
    .unwrap()
    .encode()
    .unwrap()
    .to_vec()
}

#[test]
fn current_session_is_recognized_but_vault_alias_is_protected() {
    let directory = tempdir().unwrap();
    let candidate = directory.path().join("cache");
    fs::write(&candidate, current_session_bytes()).unwrap();

    assert!(check_target(&[], &candidate).is_ok());
    assert!(check_target(&[candidate.as_path()], &candidate).is_err());
    #[cfg(not(windows))]
    assert!(check_target(&[directory.path()], &candidate).is_ok());
}

#[test]
fn missing_targets_are_noops_and_non_files_are_rejected() {
    let directory = tempdir().unwrap();
    let missing = directory.path().join("missing");
    assert!(check_target(&[], &missing).is_ok());
    assert!(check_target(&[], directory.path()).is_err());

    #[cfg(unix)]
    {
        let target = directory.path().join("target");
        fs::write(&target, current_session_bytes()).unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(check_target(&[], &link).is_err());
    }
}

#[test]
fn oversized_and_vault_magic_files_are_rejected() {
    let directory = tempdir().unwrap();
    let candidate = directory.path().join("cache");

    fs::write(
        &candidate,
        vec![b' '; super::envelope::MAX_PAYLOAD_BYTES + 1],
    )
    .unwrap();
    assert!(check_target(&[], &candidate).is_err());

    fs::write(&candidate, b"KEVI-not-a-cache").unwrap();
    assert!(check_target(&[], &candidate).is_err());
}

#[test]
fn generic_ron_with_expiry_and_arbitrary_data_is_not_a_cache() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("ambiguous.ron");
    let bytes = b"(expires_at_unix: 200, data: \"unrelated file\")";
    fs::write(&path, bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn legacy_ron_session_is_not_recognized_as_a_current_cache() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("legacy.ron");
    let bytes = format!(
        "(expires_at_unix: 200, data: (header_fingerprint_hex: \"{}\", key_b64: \"{}\"))",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    fs::write(&path, &bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes.as_bytes());
}

#[test]
fn bare_key_shaped_ron_is_ambiguous_and_preserved() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("unrelated.ron");
    let bytes = format!(
        "(header_fingerprint_hex: \"{}\", key_b64: \"{}\")",
        "ab".repeat(32),
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    fs::write(&path, &bytes).unwrap();

    assert!(check_target(&[], &path).is_err());
    assert_eq!(fs::read(path).unwrap(), bytes.as_bytes());
}
