use assert_cmd::prelude::*;
use predicates::prelude::*;
use secrecy::SecretString;
use std::process::Command;
use tempfile::tempdir;

use kevi::core::entry::VaultEntry;
use kevi::core::store::save_vault_file;

#[test]
fn list_shows_labels_by_default_and_user_when_requested() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed vault
    let entries = vec![
        VaultEntry {
            label: "alpha".into(),
            username: Some(SecretString::new("alice".into())),
            password: SecretString::new("aaa".into()),
            notes: None,
        },
        VaultEntry {
            label: "beta".into(),
            username: None,
            password: SecretString::new("bbb".into()),
            notes: None,
        },
    ];
    save_vault_file(&entries, &path, pw).expect("seed vault");

    // By default: only labels
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("alpha").and(predicate::str::contains("beta")))
        .stdout(predicate::str::contains("alice").not());

    // With --show-users: include usernames next to labels
    let mut cmd2 = Command::cargo_bin("kevi").unwrap();
    cmd2.env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--show-users");
    cmd2.assert()
        .success()
        .stdout(predicate::str::contains("alpha\talice"))
        .stdout(predicate::str::contains("beta"));
}
