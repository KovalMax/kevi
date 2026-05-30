use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

fn config_path(config_dir: &std::path::Path) -> std::path::PathBuf {
    config_dir.join("kevi").join("config.toml")
}

#[test]
fn profile_show_missing_fails_with_actionable_message() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("show")
        .arg("missing");
    cmd.assert().failure().stderr(predicate::str::contains(
        "profile \"missing\" is not defined",
    ));
}

#[test]
fn profile_add_duplicate_without_override_fails() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config");

    let mut first_add = Command::cargo_bin("kevi").expect("binary");
    first_add
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("add")
        .arg("work")
        .arg("--path")
        .arg("/tmp/work.ron");
    first_add.assert().success();

    let mut second_add = Command::cargo_bin("kevi").expect("binary");
    second_add
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("add")
        .arg("work")
        .arg("--path")
        .arg("/tmp/work2.ron");
    second_add
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn profile_remove_default_fails_until_default_cleared() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config");

    let mut add_cmd = Command::cargo_bin("kevi").expect("binary");
    add_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("add")
        .arg("work")
        .arg("--path")
        .arg("/tmp/work.ron");
    add_cmd.assert().success();

    let mut default_cmd = Command::cargo_bin("kevi").expect("binary");
    default_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("default")
        .arg("work");
    default_cmd.assert().success();

    let mut remove_default_cmd = Command::cargo_bin("kevi").expect("binary");
    remove_default_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("rm")
        .arg("work");
    remove_default_cmd
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot remove default profile"));

    let mut clear_default_cmd = Command::cargo_bin("kevi").expect("binary");
    clear_default_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("default")
        .arg("--clear");
    clear_default_cmd.assert().success();

    let mut remove_cmd = Command::cargo_bin("kevi").expect("binary");
    remove_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("rm")
        .arg("work");
    remove_cmd.assert().success();
}

#[test]
fn profile_default_unknown_fails() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config");

    let mut cmd = Command::cargo_bin("kevi").expect("binary");
    cmd.env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("default")
        .arg("unknown");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("is not defined"));
}

#[test]
fn profile_config_file_kept_consistent_after_clear() {
    let td = tempdir().expect("tempdir");
    let config_dir = td.path().join("config");
    fs::create_dir_all(config_dir.join("kevi")).expect("create config");

    let mut add_cmd = Command::cargo_bin("kevi").expect("binary");
    add_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("add")
        .arg("work")
        .arg("--path")
        .arg("/tmp/work.ron");
    add_cmd.assert().success();

    let mut default_cmd = Command::cargo_bin("kevi").expect("binary");
    default_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("default")
        .arg("work");
    default_cmd.assert().success();

    let mut clear_cmd = Command::cargo_bin("kevi").expect("binary");
    clear_cmd
        .env("KEVI_CONFIG_DIR", &config_dir)
        .arg("profile")
        .arg("default")
        .arg("--clear");
    clear_cmd.assert().success();

    let content = fs::read_to_string(config_path(&config_dir)).expect("read config");
    assert!(content.contains("[profiles.work]"));
    assert!(!content.contains("default_profile = \"work\""));
}
