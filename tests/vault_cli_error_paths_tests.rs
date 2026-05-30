use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::SecretString;
use tempfile::tempdir;

use kevi::vault::models::{VaultData, VaultEntry};
use kevi::vault::persistence::save_vault_file;

fn seed_empty_vault(path: &std::path::Path) {
    save_vault_file(&VaultData::default(), path, "pw").expect("seed empty vault");
}

fn seed_vault_with_entry(path: &std::path::Path, label: &str) {
    let data = VaultData {
        entries: vec![VaultEntry {
            label: label.into(),
            username: Some(SecretString::new("user@example.com".into())),
            password: SecretString::new("secret".to_string().into()),
            notes: Some("note".to_string()),
        }],
        otps: vec![],
    };
    save_vault_file(&data, path, "pw").expect("seed vault with entry");
}

#[test]
fn list_on_empty_vault_prints_empty() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_empty_vault(&path);

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("(empty)"));
}

#[test]
fn get_on_missing_key_reports_not_found() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_empty_vault(&path);

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .arg("get")
        .arg("missing")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--echo")
        .arg("--no-copy");
    cmd.assert().success().stdout(predicate::str::contains(
        "No entry found with key 'missing'",
    ));
}

#[test]
fn show_on_missing_key_fails() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_empty_vault(&path);

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .arg("show")
        .arg("missing")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("entry 'missing' not found"));
}

#[test]
fn rm_on_missing_key_reports_not_found() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_empty_vault(&path);

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .arg("rm")
        .arg("missing")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--yes");
    cmd.assert().success().stdout(predicate::str::contains(
        "No entry found with key 'missing'",
    ));
}

#[test]
fn add_duplicate_label_returns_message_without_prompting() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_vault_with_entry(&path, "github");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--label")
        .arg("github");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("already exists"));
}
