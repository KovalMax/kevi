use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use kevi::core::entry::VaultEntry;
use kevi::core::store::save_vault_file;
use secrecy::SecretString;

fn default_vault_path_for(home: &std::path::Path) -> std::path::PathBuf {
    home.join(".kevi").join("vault.ron")
}

fn seed_vault(home: &std::path::Path) {
    let path = default_vault_path_for(home);
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    let pw = "pw";
    let entry = VaultEntry {
        label: "label1".into(),
        username: Some(SecretString::new("user123".into())),
        password: SecretString::new("p@ss".into()),
        notes: Some("noteZ".into()),
    };
    save_vault_file(&[entry], &path, pw).expect("seed vault");
}

#[test]
fn get_echo_password_and_no_copy_prints_secret() {
    let td = tempdir().unwrap();
    let home = td.path();
    seed_vault(home);

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("HOME", home)
        .env("KEVI_PASSWORD", "pw")
        .arg("get").arg("label1")
        .arg("--path").arg(default_vault_path_for(home).to_string_lossy().to_string())
        .arg("--no-copy")
        .arg("--echo");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("p@ss"));
}

#[test]
fn get_echo_user_and_no_copy_prints_username() {
    let td = tempdir().unwrap();
    let home = td.path();
    seed_vault(home);

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("HOME", home)
        .env("KEVI_PASSWORD", "pw")
        .arg("get").arg("label1")
        .arg("--path").arg(default_vault_path_for(home).to_string_lossy().to_string())
        .arg("--field").arg("user")
        .arg("--no-copy")
        .arg("--echo");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("user123"));
}

#[test]
fn get_echo_notes_and_no_copy_prints_notes() {
    let td = tempdir().unwrap();
    let home = td.path();
    seed_vault(home);

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("HOME", home)
        .env("KEVI_PASSWORD", "pw")
        .arg("get").arg("label1")
        .arg("--path").arg(default_vault_path_for(home).to_string_lossy().to_string())
        .arg("--field").arg("notes")
        .arg("--no-copy")
        .arg("--echo");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("noteZ"));
}

#[test]
fn get_no_copy_without_echo_prints_nothing() {
    let td = tempdir().unwrap();
    let home = td.path();
    seed_vault(home);

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("HOME", home)
        .env("KEVI_PASSWORD", "pw")
        .arg("get").arg("label1")
        .arg("--path").arg(default_vault_path_for(home).to_string_lossy().to_string())
        .arg("--no-copy");
    cmd.assert()
        .success()
        .stdout(predicate::str::is_empty());
}
