use assert_cmd::prelude::*;
use predicates::prelude::*;
use secrecy::SecretString;
use std::process::Command;
use tempfile::tempdir;

use kevi::session_management::resolver::dk_session_file_for;
use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::save_vault_file;

#[test]
fn get_once_bypasses_session_cache_and_does_not_create_it() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed vault with one item
    let entry = VaultEntry {
        label: "k".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("s3cr3t".into()),
        notes: None,
    };
    save_vault_file(&[entry], &path, pw).expect("seed vault");

    // Ensure no derived-key session exists
    let dk_path = dk_session_file_for(&path);
    if dk_path.exists() {
        std::fs::remove_file(&dk_path).unwrap();
    }

    // Run `get --once --no-copy --echo` to print the password without creating a session
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("get")
        .arg("k")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--no-copy")
        .arg("--echo")
        .arg("--field")
        .arg("password")
        .arg("--once");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("s3cr3t"));

    // Session file should still not exist (no caching when --once)
    assert!(
        !dk_path.exists(),
        "dk-session should not be created by --once"
    );
}
