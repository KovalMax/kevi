use assert_cmd::prelude::*;
use secrecy::ExposeSecret;
use std::env;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::load_vault_file;

fn write_config(_dir: &std::path::Path, content: &str) {
    // Respect KEVI_CONFIG_DIR for isolation
    let base = env::var("KEVI_CONFIG_DIR").unwrap_or_else(|_| {
        dirs::config_dir()
            .expect("config_dir available")
            .to_string_lossy()
            .to_string()
    });
    let kevi_dir = std::path::PathBuf::from(base).join("kevi");
    let _ = fs::create_dir_all(&kevi_dir);
    let path = kevi_dir.join("config.toml");
    fs::write(path, content).expect("write config");
}

#[test]
fn generator_uses_config_length_when_not_overridden() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    // Isolate HOME and config dir
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    // Configure generator_length via env (highest precedence)
    env::set_var("KEVI_GEN_LENGTH", "33");

    let pw = "pw";
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .env("HOME", td.path())
        .env(
            "KEVI_CONFIG_DIR",
            td.path().join("cfg").to_string_lossy().to_string(),
        )
        .env("KEVI_GEN_LENGTH", "33")
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        // no --length here, should fall back to config value 33
        .arg("--label")
        .arg("cfg_len")
        .arg("--user")
        .arg("u1")
        .arg("--notes")
        .arg("");
    cmd.assert().success();

    let entries: Vec<VaultEntry> = load_vault_file(&path, pw).expect("load");
    let e = entries
        .iter()
        .find(|e| e.label == "cfg_len")
        .expect("present");
    assert_eq!(e.password.expose_secret().len(), 33);
}

#[test]
fn passphrase_uses_config_words_and_sep_when_not_overridden() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    // Isolate
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    // Configure passphrase defaults
    write_config(td.path(), "generator_words = 6\ngenerator_sep = \":\"\n");

    let pw = "pw";
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .env("HOME", td.path())
        .env(
            "KEVI_CONFIG_DIR",
            td.path().join("cfg").to_string_lossy().to_string(),
        )
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--passphrase")
        // no --words or --sep provided
        .arg("--label")
        .arg("cfg_phrase")
        .arg("--user")
        .arg("u2")
        .arg("--notes")
        .arg("");
    cmd.assert().success();

    let entries: Vec<VaultEntry> = load_vault_file(&path, pw).expect("load");
    let e = entries
        .iter()
        .find(|e| e.label == "cfg_phrase")
        .expect("present");
    let secret = e.password.expose_secret().to_string();
    // Count contiguous lowercase word chunks regardless of separator
    let mut count = 0;
    let mut in_word = false;
    for ch in secret.chars() {
        if ch.is_ascii_lowercase() {
            if !in_word {
                count += 1;
                in_word = true;
            }
        } else {
            in_word = false;
        }
    }
    assert_eq!(count, 6);
}
