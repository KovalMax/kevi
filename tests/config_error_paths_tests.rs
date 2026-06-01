use kevi::api::{load_file_config_with_path, save_file_config, Config, FileConfig};
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
#[serial]
fn create_fails_for_unknown_cli_profile() {
    let td = tempdir().expect("tempdir");
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg"));
    env::remove_var("KEVI_VAULT_PATH");

    let err = Config::create(None, Some("missing".to_string())).expect_err("must fail");
    assert!(err.to_string().contains("not defined"));
}

#[test]
#[serial]
fn load_file_config_defaults_on_invalid_toml() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(&cfg_path, "not = [valid toml").expect("write invalid toml");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);

    let (_path, cfg) = load_file_config_with_path();
    assert!(cfg.vault_path.is_none());
    assert!(cfg.profiles.is_none());
}

#[test]
#[serial]
fn load_file_config_defaults_on_invalid_utf8() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(&cfg_path, [0xff, 0xfe, 0xfd]).expect("write invalid utf8");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);

    let (_path, cfg) = load_file_config_with_path();
    assert!(cfg.vault_path.is_none());
    assert!(cfg.profiles.is_none());
}

#[tokio::test]
#[serial]
async fn save_file_config_creates_parent_and_persists() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("nested").join("kevi").join("config.toml");
    let cfg = FileConfig {
        vault_path: Some("/tmp/vault.ron".to_string()),
        backups: Some(3),
        ..FileConfig::default()
    };

    save_file_config(&PathBuf::from(&path), &cfg)
        .await
        .expect("save config");
    let content = fs::read_to_string(&path).expect("read config");
    assert!(content.contains("vault_path = \"/tmp/vault.ron\""));
    assert!(content.contains("backups = 3"));
}

#[test]
#[serial]
fn cli_profile_resolves_to_profile_vault_path() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(
        &cfg_path,
        "[profiles.work]\nvault_path = \"/tmp/work-vault.ron\"\n",
    )
    .expect("write config");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);

    let cfg = Config::create(None, Some("work".to_string())).expect("profile config");
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/work-vault.ron"));
}

#[test]
#[serial]
fn default_profile_missing_falls_back_to_file_vault_path() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(
        &cfg_path,
        "default_profile = \"missing\"\nvault_path = \"/tmp/fallback-vault.ron\"\n",
    )
    .expect("write config");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);
    env::remove_var("KEVI_VAULT_PATH");

    let cfg = Config::create(None, None).expect("fallback config");
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/fallback-vault.ron"));
}

#[test]
#[serial]
fn invalid_env_values_fall_back_to_config_values() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(&cfg_path, "clipboard_ttl = 25\nbackups = 4\n").expect("write config");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);
    env::set_var("KEVI_CLIP_TTL", "not-a-number");
    env::set_var("KEVI_BACKUPS", "bad-value");

    let cfg = Config::create(None, None).expect("config with fallback values");
    assert_eq!(cfg.clipboard_ttl, Some(25));
    assert_eq!(cfg.backups, Some(4));
}

#[test]
#[serial]
fn default_profile_resolves_to_profile_path_when_present() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    let cfg_path = cfg_dir.join("kevi").join("config.toml");
    fs::create_dir_all(cfg_path.parent().expect("parent")).expect("mkdir");
    fs::write(
        &cfg_path,
        "default_profile = \"work\"\n[profiles.work]\nvault_path = \"/tmp/work-default.ron\"\n",
    )
    .expect("write config");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);
    env::remove_var("KEVI_VAULT_PATH");

    let cfg = Config::create(None, None).expect("config with default profile");
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/work-default.ron"));
}

#[test]
#[serial]
fn generator_env_overrides_are_applied() {
    let td = tempdir().expect("tempdir");
    let cfg_dir = td.path().join("cfg");
    env::set_var("KEVI_CONFIG_DIR", &cfg_dir);
    env::set_var("KEVI_GEN_LENGTH", "24");
    env::set_var("KEVI_GEN_WORDS", "7");
    env::set_var("KEVI_GEN_SEP", "-");
    env::set_var("KEVI_AVOID_AMBIGUOUS", "true");

    let cfg = Config::create(None, None).expect("config with env generator overrides");
    assert_eq!(cfg.generator_length, Some(24));
    assert_eq!(cfg.generator_words, Some(7));
    assert_eq!(cfg.generator_sep.as_deref(), Some("-"));
    assert_eq!(cfg.avoid_ambiguous, Some(true));

    env::remove_var("KEVI_GEN_LENGTH");
    env::remove_var("KEVI_GEN_WORDS");
    env::remove_var("KEVI_GEN_SEP");
    env::remove_var("KEVI_AVOID_AMBIGUOUS");
}
