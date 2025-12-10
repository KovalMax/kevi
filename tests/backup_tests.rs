use kevi::cryptography::primitives::decrypt_vault;
use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::save_vault_file;
use secrecy::SecretString;
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{fs, slice};
use tempfile::tempdir;

fn bp(path: &Path, n: usize) -> PathBuf {
    PathBuf::from(format!("{}.{n}", path.display()))
}

#[test]
fn rotating_backups_keep_two_versions_and_prune() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    let pw = "pw";

    // Ensure we keep 2 backups
    std::env::set_var("KEVI_BACKUPS", "2");

    // First content
    let e1 = VaultEntry {
        label: "one".into(),
        username: Some(SecretString::new("u1".into())),
        password: SecretString::new("p1".into()),
        notes: None,
    };
    save_vault_file(slice::from_ref(&e1), &path, pw).expect("save 1");

    // Second content
    let e2 = VaultEntry {
        label: "two".into(),
        username: Some(SecretString::new("u2".into())),
        password: SecretString::new("p2".into()),
        notes: None,
    };
    save_vault_file(slice::from_ref(&e2), &path, pw).expect("save 2");

    // Third content
    let e3 = VaultEntry {
        label: "three".into(),
        username: Some(SecretString::new("u3".into())),
        password: SecretString::new("p3".into()),
        notes: None,
    };
    save_vault_file(slice::from_ref(&e3), &path, pw).expect("save 3");

    // Main file should be latest (e3)
    let main_bytes = fs::read(&path).unwrap();
    assert!(main_bytes.starts_with(b"KEVI"), "main must be encrypted");
    let main_plain = decrypt_vault(&main_bytes, pw).expect("decrypt main");
    let main_entries: Vec<VaultEntry> =
        ron::from_str(&String::from_utf8(main_plain).unwrap()).unwrap();
    assert_eq!(main_entries[0].label, "three");

    // .1 should be previous (e2), .2 should be first (e1)
    let b1 = bp(&path, 1);
    let b2 = bp(&path, 2);
    assert!(b1.exists(), ".1 must exist");
    assert!(b2.exists(), ".2 must exist");
    let b1_bytes = fs::read(&b1).unwrap();
    let b2_bytes = fs::read(&b2).unwrap();
    assert!(b1_bytes.starts_with(b"KEVI") && b2_bytes.starts_with(b"KEVI"));
    let b1_plain = decrypt_vault(&b1_bytes, pw).unwrap();
    let b2_plain = decrypt_vault(&b2_bytes, pw).unwrap();
    let b1_entries: Vec<VaultEntry> = ron::from_str(&String::from_utf8(b1_plain).unwrap()).unwrap();
    let b2_entries: Vec<VaultEntry> = ron::from_str(&String::from_utf8(b2_plain).unwrap()).unwrap();
    assert_eq!(b1_entries[0].label, "two");
    assert_eq!(b2_entries[0].label, "one");

    // .3 should not exist (pruned)
    let b3 = bp(&path, 3);
    assert!(!b3.exists(), ".3 should be pruned");

    // On Unix, backups must have 0600 perms
    #[cfg(target_family = "unix")]
    {
        let mode1 = fs::metadata(&b1).unwrap().permissions().mode() & 0o777;
        let mode2 = fs::metadata(&b2).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode1, 0o600);
        assert_eq!(mode2, 0o600);
    }
}
