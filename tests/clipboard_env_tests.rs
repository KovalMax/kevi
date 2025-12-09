use assert_cmd::prelude::*;
use predicates::prelude::*;
use secrecy::SecretString;
use std::process::Command;
use tempfile::tempdir;

use kevi::core::entry::VaultEntry;
use kevi::core::store::save_vault_file;

#[test]
fn get_warns_in_ssh_like_environment() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed vault with one item
    let entry = VaultEntry {
        label: "srv".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("p".into()),
        notes: None,
    };
    save_vault_file(&[entry], &path, pw).expect("seed vault");

    // Simulate SSH session; do not use --no-copy to exercise clipboard path
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .env("SSH_CONNECTION", "1")
        .arg("get")
        .arg("srv")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());

    // We expect success and a warning on stderr about SSH/clipboard; stdout should be empty by default
    cmd.assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("Detected SSH session"));
}
