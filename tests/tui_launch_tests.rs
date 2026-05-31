use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn tui_command_fails_cleanly_for_missing_vault_file() {
    let td = tempdir().expect("tempdir");
    let missing = td.path().join("missing-vault.ron");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("tui")
        .arg("--path")
        .arg(missing.to_string_lossy().to_string());

    cmd.assert().failure().stderr(
        predicate::str::contains("failed to load vault for TUI")
            .or(predicate::str::contains("Device not configured"))
            .or(predicate::str::contains(
                "Failed to initialize input reader",
            )),
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
        .arg("tui")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load vault for TUI").or(
            predicate::str::contains("Failed to initialize input reader"),
        ));
}
