use assert_cmd::prelude::*;
use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::save_vault_file;
use predicates::prelude::*;
use secrecy::SecretString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::tempdir;

fn run_header(path: &Path) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.arg("header")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());
    cmd.assert()
}

#[test]
fn header_on_valid_vault_prints_fields() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    let pw = "pw";
    // Save a simple encrypted vault (empty entries also fine)
    let entries: Vec<VaultEntry> = vec![VaultEntry {
        label: "lbl".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("p".into()),
        notes: None,
    }];
    save_vault_file(&entries, &path, pw).expect("save vault");

    run_header(&path)
        .success()
        .stdout(predicate::str::contains("KEVI header:"))
        .stdout(predicate::str::contains("kdf: Argon2id"))
        .stdout(predicate::str::contains("aead: AES-256-GCM"));
}

#[test]
fn header_bad_magic_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("not_a_vault");
    fs::write(&path, b"PLAINTEXT").unwrap();

    run_header(&path).failure().stderr(
        predicate::str::contains("Failed to parse header")
            .or(predicate::str::contains("invalid header")),
    );
}

#[test]
fn header_truncated_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("truncated");
    fs::write(&path, b"KEVI").unwrap();

    run_header(&path).failure().stderr(
        predicate::str::contains("Failed to parse header")
            .or(predicate::str::contains("too short")),
    );
}

fn write_header_with_ids(path: &PathBuf, kdf_id: u8, aead_id: u8) {
    // Build a minimal header with provided IDs and zero params/salt/nonce
    let version: u16 = 1;
    let m_cost_kib: u32 = 0;
    let t_cost: u32 = 0;
    let p: u32 = 0;
    let salt = [0u8; 16];
    let nonce = [0u8; 12];

    let mut v = Vec::new();
    v.extend_from_slice(b"KEVI");
    v.extend_from_slice(&version.to_le_bytes());
    v.push(kdf_id);
    v.push(aead_id);
    v.extend_from_slice(&m_cost_kib.to_le_bytes());
    v.extend_from_slice(&t_cost.to_le_bytes());
    v.extend_from_slice(&p.to_le_bytes());
    v.extend_from_slice(&salt);
    v.extend_from_slice(&nonce);

    let mut f = fs::File::create(path).unwrap();
    f.write_all(&v).unwrap();
}

#[test]
fn header_unknown_kdf_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unknown_kdf");
    write_header_with_ids(&path, 9, 1); // unknown KDF id
    run_header(&path)
        .failure()
        .stderr(predicate::str::contains("unsupported kdf"));
}

#[test]
fn header_unknown_aead_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unknown_aead");
    write_header_with_ids(&path, 2, 9); // unknown AEAD id
    run_header(&path)
        .failure()
        .stderr(predicate::str::contains("unsupported aead"));
}
