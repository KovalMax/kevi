use assert_cmd::prelude::*;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use std::process::Command;
use tempfile::tempdir;

use kevi::api::{load_vault_file, VaultData};

#[test]
fn cli_init_add_and_list_round_trip() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Initialize a new vault
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("init")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success();

    // Add an entry with a generated password of known length
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--length")
        .arg("16")
        .arg("--label")
        .arg("demo")
        .arg("--user")
        .arg("alice@example.com")
        .arg("--notes")
        .arg("note")
        .assert()
        .success();

    // List entries with users to confirm CLI output
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--show-users")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("demo").and(predicate::str::contains("alice@example.com")),
        );

    // Load the vault to verify contents and generated length
    let data: VaultData = load_vault_file(&path, pw).expect("load vault");
    assert_eq!(data.entries.len(), 1);
    assert_eq!(data.entries[0].label.as_str(), "demo");
    assert_eq!(data.entries[0].password.expose_secret().len(), 16);
}

#[test]
fn cli_otp_add_get_and_list_round_trip() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Initialize a new vault
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("init")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success();

    // Add an OTP entry
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("otp")
        .arg("add")
        .arg("github")
        .arg("--secret")
        .arg("JBSWY3DPEHPK3PXP")
        .arg("--issuer")
        .arg("GitHub")
        .arg("--username")
        .arg("octo@example.com")
        .arg("--digits")
        .arg("6")
        .arg("--period")
        .arg("30")
        .arg("--notes")
        .arg("otp-note")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success();

    // Fetch a code at a deterministic timestamp without touching clipboard
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("otp")
        .arg("get")
        .arg("github")
        .arg("--no-copy")
        .arg("--echo")
        .arg("--at")
        .arg("0")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^[0-9]{6}\s*$").unwrap());

    // List OTP entries and verify presence
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("otp")
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success()
        .stdout(predicate::str::contains("github"));

    // Inspect the vault contents for stored OTP entry
    let data: VaultData = load_vault_file(&path, pw).expect("load vault");
    assert_eq!(data.otps.len(), 1);
    let otp = &data.otps[0];
    assert_eq!(otp.name, "github");
    assert_eq!(otp.issuer.as_deref(), Some("GitHub"));
    assert_eq!(otp.username, "octo@example.com");
    assert_eq!(otp.digits, 6);
    assert_eq!(otp.period, 30);
    assert_eq!(otp.notes.as_deref(), Some("otp-note"));
}

#[test]
fn cli_add_and_rm_entry() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Initialize a new vault
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("init")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success();

    // Add an entry with a generated password
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--length")
        .arg("12")
        .arg("--label")
        .arg("temp")
        .arg("--user")
        .arg("user@example.com")
        .arg("--notes")
        .arg("")
        .assert()
        .success();

    // Remove the entry without prompting
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("rm")
        .arg("temp")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("removed"));

    // Removing again should report it is missing but still succeed
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("rm")
        .arg("temp")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--yes")
        .assert()
        .success()
        .stdout(predicate::str::contains("No entry found"));

    // Vault file should have no entries remaining
    let data: VaultData = load_vault_file(&path, pw).expect("load vault");
    assert!(data.entries.is_empty());
}

#[test]
fn cli_list_json_includes_users_when_requested() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Initialize a new vault
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("init")
        .arg(path.to_string_lossy().to_string())
        .assert()
        .success();

    // Add an entry with username to ensure JSON includes it when requested
    Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("add")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--generate")
        .arg("--length")
        .arg("10")
        .arg("--label")
        .arg("json_entry")
        .arg("--user")
        .arg("json@example.com")
        .arg("--notes")
        .arg("")
        .assert()
        .success();

    // List entries as JSON with users included
    let output = Command::cargo_bin("kevi")
        .unwrap()
        .env("KEVI_PASSWORD", pw)
        .arg("list")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--show-users")
        .arg("--json")
        .output()
        .expect("list command runs");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");
    let arr = json.as_array().expect("array output");
    assert_eq!(arr.len(), 1);
    let obj = arr[0].as_object().expect("object item");
    assert_eq!(obj.get("label").unwrap().as_str().unwrap(), "json_entry");
    assert_eq!(
        obj.get("username").unwrap().as_str().unwrap(),
        "json@example.com"
    );
}
