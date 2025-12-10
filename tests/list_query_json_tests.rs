use assert_cmd::prelude::*;
use secrecy::SecretString;
use std::process::Command;
use tempfile::tempdir;

use kevi::vault::models::VaultEntry;
use kevi::vault::persistence::save_vault_file;

#[test]
fn list_filters_with_query_and_emits_json() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed vault
    let entries = vec![
        VaultEntry {
            label: "alpha".into(),
            username: Some(SecretString::new("alice".into())),
            password: SecretString::new("a".into()),
            notes: None,
        },
        VaultEntry {
            label: "beta".into(),
            username: Some(SecretString::new("bob".into())),
            password: SecretString::new("b".into()),
            notes: None,
        },
        VaultEntry {
            label: "gamma".into(),
            username: None,
            password: SecretString::new("c".into()),
            notes: None,
        },
    ];
    save_vault_file(&entries, &path, pw).expect("seed vault");

    // Filter: only beta should appear
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--query")
        .arg("BeTa") // case-insensitive
        .arg("--show-users")
        .arg("--json");
    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    // Expect a JSON array with one object containing beta + username
    let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let obj = arr[0].as_object().expect("object");
    assert_eq!(obj.get("label").unwrap().as_str().unwrap(), "beta");
    assert_eq!(obj.get("username").unwrap().as_str().unwrap(), "bob");

    // JSON without show-users should not include username field
    let mut cmd2 = Command::cargo_bin("kevi").unwrap();
    cmd2.env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--query")
        .arg("a")
        .arg("--json");
    let assert2 = cmd2.assert().success();
    let out2 = String::from_utf8(assert2.get_output().stdout.clone()).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&out2).expect("valid json");
    let arr2 = v2.as_array().unwrap();
    assert!(arr2.iter().all(|o| o.get("username").is_none()));
}
