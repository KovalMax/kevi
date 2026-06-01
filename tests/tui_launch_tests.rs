use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn tui_command_fails_cleanly_for_missing_vault_file() {
    let td = tempdir().expect("tempdir");
    let missing = td.path().join("missing-vault.ron");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .timeout(Duration::from_secs(10))
        .arg("tui")
        .arg("--path")
        .arg(missing.to_string_lossy().to_string());

    cmd.assert().failure().stderr(
        predicate::str::contains("vault file does not exist").or(predicate::str::contains(
            "failed to load vault for TUI",
        )
        .or(predicate::str::contains("Device not configured"))
        .or(predicate::str::contains("terminal error"))
        .or(predicate::str::contains(
            "Failed to initialize input reader",
        ))),
    );
}

#[test]
fn tui_command_fails_cleanly_for_invalid_header() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    fs::write(&path, b"plaintext").expect("write plaintext");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .timeout(Duration::from_secs(10))
        .arg("tui")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load vault for TUI").or(
            predicate::str::contains("Failed to initialize input reader"),
        ));
}
