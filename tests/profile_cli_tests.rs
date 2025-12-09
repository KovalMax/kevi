use assert_cmd::Command;
use predicates::prelude::*;
use std::env;
use std::fs;
use tempfile::tempdir;

#[test]
fn profile_add_list_default_flow() {
    let td = tempdir().unwrap();
    let config_dir = td.path().join("config");
    let data_dir = td.path().join("data");
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&data_dir).unwrap();

    // 1. List - initially empty
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("profile")
        .arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("No profiles defined"));

    // 2. Add a profile
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("profile")
        .arg("add")
        .arg("work")
        .arg("--path")
        .arg("/tmp/work-vault.ron");
    cmd.assert().success().stdout(predicate::str::contains(
        "Profile \"work\" set to vault_path",
    ));

    // 3. List - should show work
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("profile")
        .arg("list");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("work -> /tmp/work-vault.ron"));

    // 4. Set default
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("profile")
        .arg("default")
        .arg("work");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Default profile set to \"work\""));

    // 5. Check default
    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_CONFIG_DIR", config_dir.to_str().unwrap())
        .arg("profile")
        .arg("default");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Default profile: work"));

    // 6. Verify config persistence by reading file
    let config_path = config_dir.join("kevi/config.toml");
    let content = fs::read_to_string(config_path).unwrap();
    assert!(content.contains("[profiles.work]"));
    assert!(content.contains("default_profile = \"work\""));
}
