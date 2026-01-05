use assert_cmd::Command;
use kevi::vault::models::VaultData;
use kevi::vault::persistence::save_vault_file;
use predicates::str::contains;
use std::{env, fs};
use tempfile::tempdir;

#[test]
fn test_cli() {
    let td = tempdir().unwrap();
    let config_dir = td.path().join("config");
    let data_dir = td.path().join("data");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    // 1. List - initially empty
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("--help");

    cmd.assert()
        .success()
        .stdout(contains("Kevi — Secure CLI Vault"));
}

#[test]
fn test_otp() {
    let td = tempdir().unwrap();
    let config_dir = td.path().join("config");
    let data_dir = td.path().join("data");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();
    let path = data_dir.join("vault.ron");
    // Initialize an encrypted vault file (empty) so the header exists
    {
        let entries = VaultData {
            entries: Vec::new(),
            otps: Vec::new(),
        };
        // Ensure password available
        env::set_var("KEVI_PASSWORD", "pw");
        save_vault_file(&entries, &path, "pw").expect("init empty vault");
    }

    // 1. List - initially empty
    let mut cmd = Command::cargo_bin("kevi").unwrap();

    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("KEVI_DATA_DIR", data_dir.to_str().unwrap())
        .env("KEVI_PASSWORD", "pw")
        .args([
            "otp",
            "add",
            "test-otp",
            "--secret",
            "JBSWY3DPEHPK3PXP",
            "--issuer",
            "Example",
            "--username",
            "user1",
            "--digits",
            "6",
            "--period",
            "30",
        ])
        .assert()
        .success();

    let mut cmd2 = Command::cargo_bin("kevi").unwrap();

    cmd2.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .env("KEVI_DATA_DIR", data_dir.to_str().unwrap())
        .env("KEVI_PASSWORD", "pw")
        .args(["otp", "list", "--json"])
        .assert()
        .success()
        .stdout(contains("test-otp"));
}

#[test]
fn test_tui_runs() {
    #[cfg(all(test, target_family = "unix"))]
    {
        let td = tempdir().unwrap();
        let config_dir = td.path().join("config");
        let data_dir = td.path().join("data");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&data_dir).unwrap();

        let mut cmd = Command::cargo_bin("kevi").unwrap();
        cmd.env("KEVI_CONFIG_DIR", &config_dir)
            .env("KEVI_DATA_DIR", &data_dir)
            .env("KEVI_PASSWORD", "pw")
            .arg("init")
            .assert()
            .success();

        let mut tui_cmd = Command::cargo_bin("kevi").unwrap();
        tui_cmd
            .env("KEVI_CONFIG_DIR", &config_dir)
            .env("KEVI_DATA_DIR", &data_dir)
            .env("KEVI_PASSWORD", "pw")
            .arg("tui");

        // Run briefly and kill
        let _ = tui_cmd.output().expect("tui starts");
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
