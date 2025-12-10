use assert_cmd::prelude::*;
use secrecy::ExposeSecret;
use std::process::Command;
use tempfile::tempdir;

use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::load_vault_file;

#[test]
fn cli_add_generate_char_mode_creates_expected_password() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Run CLI to add a generated password entry
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--length")
        .arg("24")
        .arg("--label")
        .arg("gen1")
        .arg("--user")
        .arg("u1")
        .arg("--notes")
        .arg("n1");
    cmd.assert().success();

    // Load vault and verify
    let entries: Vec<VaultEntry> = load_vault_file(&path, pw).expect("load vault");
    let e = entries
        .iter()
        .find(|e| e.label == "gen1")
        .expect("entry present");
    let secret = e.password.expose_secret().to_string();
    assert_eq!(secret.len(), 24);
    assert!(secret.chars().any(|c| c.is_ascii_lowercase()));
    assert!(secret.chars().any(|c| c.is_ascii_uppercase()));
    assert!(secret.chars().any(|c| c.is_ascii_digit()));
    assert!(secret.chars().any(|c| !c.is_ascii_alphanumeric())); // symbol
}

#[test]
fn cli_add_generate_passphrase_mode_produces_words() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Run CLI to add a passphrase-based entry
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--passphrase")
        .arg("--words")
        .arg("5")
        .arg("--sep")
        .arg(":")
        .arg("--label")
        .arg("phrase1")
        .arg("--user")
        .arg("u2")
        .arg("--notes")
        .arg("");
    cmd.assert().success();

    // Load vault and verify
    let entries: Vec<VaultEntry> = load_vault_file(&path, pw).expect("load vault");
    let e = entries
        .iter()
        .find(|e| e.label == "phrase1")
        .expect("entry present");
    let secret = e.password.expose_secret().to_string();
    let parts: Vec<&str> = secret.split(':').collect();
    assert_eq!(parts.len(), 5);
    assert!(parts.iter().all(|w| !w.is_empty()));
    assert!(secret.chars().all(|c| c.is_ascii_lowercase() || c == ':'));
}
