use assert_cmd::Command;
use kevi::api::{save_vault_file, VaultData, VaultEntry};
use predicates::prelude::*;
use secrecy::SecretString;
use std::fs;
use tempfile::tempdir;

fn seed_vault(path: &std::path::Path, label: &str, secret: &str) {
    let data = VaultData {
        entries: vec![VaultEntry {
            label: label.into(),
            username: Some(SecretString::new("user@example.com".into())),
            password: SecretString::new(secret.to_string().into()),
            notes: Some("note".to_string()),
        }],
        otps: vec![],
    };
    save_vault_file(&data, path, "pw").expect("seed vault");
}

#[test]
fn profile_precedence_cli_path_over_profile_over_env() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config dir");

    let env_vault = td.path().join("env.ron");
    let profile_vault = td.path().join("profile.ron");
    let cli_vault = td.path().join("cli.ron");

    seed_vault(&env_vault, "env-key", "env-secret");
    seed_vault(&profile_vault, "profile-key", "profile-secret");
    seed_vault(&cli_vault, "cli-key", "cli-secret");

    let config_toml = format!(
        "default_profile = \"work\"\n[profiles.work]\nvault_path = \"{}\"\n",
        profile_vault.display()
    );
    fs::write(config_dir.join("kevi").join("config.toml"), config_toml).expect("write config");

    // Profile should win over env path.
    let mut profile_cmd = Command::cargo_bin("kevi").expect("binary");
    profile_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .env("KEVI_VAULT_PATH", env_vault.to_string_lossy().to_string())
        .env("KEVI_PASSWORD", "pw")
        .arg("--profile")
        .arg("work")
        .arg("get")
        .arg("profile-key")
        .arg("--field")
        .arg("password")
        .arg("--echo")
        .arg("--no-copy");
    profile_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("profile-secret"));

    // CLI path should win over both profile and env.
    let mut cli_path_cmd = Command::cargo_bin("kevi").expect("binary");
    cli_path_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .env("KEVI_VAULT_PATH", env_vault.to_string_lossy().to_string())
        .env("KEVI_PASSWORD", "pw")
        .arg("--profile")
        .arg("work")
        .arg("get")
        .arg("cli-key")
        .arg("--path")
        .arg(cli_vault.to_string_lossy().to_string())
        .arg("--field")
        .arg("password")
        .arg("--echo")
        .arg("--no-copy");
    cli_path_cmd
        .assert()
        .success()
        .stdout(predicate::str::contains("cli-secret"));
}

#[test]
fn otp_get_echo_and_copy_flags_behavior() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");

    let mut init_cmd = Command::cargo_bin("kevi").expect("binary");
    init_cmd
        .env("KEVI_PASSWORD", "pw")
        .arg("init")
        .arg(path.to_string_lossy().to_string());
    init_cmd.assert().success();

    let mut add_otp_cmd = Command::cargo_bin("kevi").expect("binary");
    add_otp_cmd
        .env("KEVI_PASSWORD", "pw")
        .arg("otp")
        .arg("add")
        .arg("github")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--secret")
        .arg("JBSWY3DPEHPK3PXP")
        .arg("--issuer")
        .arg("Example")
        .arg("--username")
        .arg("dev")
        .arg("--digits")
        .arg("6")
        .arg("--period")
        .arg("30");
    add_otp_cmd.assert().success();

    let mut invalid_flags_cmd = Command::cargo_bin("kevi").expect("binary");
    invalid_flags_cmd
        .env("KEVI_PASSWORD", "pw")
        .arg("otp")
        .arg("get")
        .arg("github")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--no-copy");
    invalid_flags_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing to do"));

    let mut echo_no_copy_cmd = Command::cargo_bin("kevi").expect("binary");
    echo_no_copy_cmd
        .env("KEVI_PASSWORD", "pw")
        .arg("otp")
        .arg("get")
        .arg("github")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--echo")
        .arg("--no-copy");
    echo_no_copy_cmd
        .assert()
        .success()
        .stdout(predicate::str::is_match("(?m)^\\d{6}$").expect("valid regex"));
}
