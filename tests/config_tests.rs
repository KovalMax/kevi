use kevi::config::app_config::{Config, ConfigError};
use kevi::domain::VaultPath;
use kevi::filesystem::store::FileByteStore;
use kevi::vault::ports::ByteStore;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn write_config_file(_dir: &Path, content: &str) {
    // Honor KEVI_CONFIG_DIR to avoid cross-test interference
    let base = env::var("KEVI_CONFIG_DIR").unwrap_or_else(|_| {
        dirs::config_dir()
            .expect("config_dir available")
            .to_string_lossy()
            .to_string()
    });
    let kevi_dir = PathBuf::from(base).join("kevi");
    let _ = fs::create_dir_all(&kevi_dir);
    let path = kevi_dir.join("config.toml");
    fs::write(path, content).expect("write config file");
}

#[test]
#[serial]
fn vault_path_precedence_cli_over_env_and_file() {
    let td = tempdir().unwrap();
    // Isolate env
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_VAULT_PATH");

    // Write a config with a vault_path
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");

    // Also set env var; CLI should still win
    env::set_var("KEVI_VAULT_PATH", "/tmp/env_vault.ron");
    let cli_path = PathBuf::from("/tmp/cli_vault.ron");
    let cfg = Config::create(Some(cli_path.clone()), None).unwrap();
    assert_eq!(cfg.vault_path, cli_path);
}

#[test]
#[serial]
fn vault_path_precedence_env_over_file() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    // file config
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");
    // env overrides
    env::set_var("KEVI_VAULT_PATH", "/tmp/env_vault.ron");
    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/env_vault.ron"));
}

#[test]
#[serial]
fn vault_path_precedence_file_over_default() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_VAULT_PATH");
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");
    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/cfg_vault.ron"));
}

#[test]
#[serial]
fn clipboard_ttl_and_backups_precedence() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_CLIP_TTL");
    env::remove_var("KEVI_BACKUPS");

    // From file when env not set
    write_config_file(td.path(), "clipboard_ttl = 33\nbackups = 4\n");
    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.clipboard_ttl, Some(33));
    assert_eq!(cfg.backups, Some(4));

    // Env overrides file
    env::set_var("KEVI_CLIP_TTL", "99");
    env::set_var("KEVI_BACKUPS", "7");
    let cfg2 = Config::create(None, None).unwrap();
    assert_eq!(cfg2.clipboard_ttl, Some(99));
    assert_eq!(cfg2.backups, Some(7));
}

#[test]
#[serial]
fn generator_defaults_precedence() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );

    env::remove_var("KEVI_GEN_LENGTH");
    env::remove_var("KEVI_GEN_WORDS");
    env::remove_var("KEVI_GEN_SEP");
    env::remove_var("KEVI_AVOID_AMBIGUOUS");

    // From file when env not set
    write_config_file(
        td.path(),
        r#"
generator_length = 18
generator_words = 7
generator_sep = "-"
avoid_ambiguous = true
"#,
    );

    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.generator_length, Some(18));
    assert_eq!(cfg.generator_words, Some(7));
    assert_eq!(cfg.generator_sep.as_deref(), Some("-"));
    assert_eq!(cfg.avoid_ambiguous, Some(true));

    // Env overrides file
    env::set_var("KEVI_GEN_LENGTH", "24");
    env::set_var("KEVI_GEN_WORDS", "9");
    env::set_var("KEVI_GEN_SEP", ".");
    env::set_var("KEVI_AVOID_AMBIGUOUS", "false");
    let cfg2 = Config::create(None, None).unwrap();
    assert_eq!(cfg2.generator_length, Some(24));
    assert_eq!(cfg2.generator_words, Some(9));
    assert_eq!(cfg2.generator_sep.as_deref(), Some("."));
    assert_eq!(cfg2.avoid_ambiguous, Some(false));

    // Defaults when neither env nor file provide values
    env::remove_var("KEVI_GEN_LENGTH");
    env::remove_var("KEVI_GEN_WORDS");
    env::remove_var("KEVI_GEN_SEP");
    env::remove_var("KEVI_AVOID_AMBIGUOUS");
    let _ = fs::remove_file(
        PathBuf::from(env::var("KEVI_CONFIG_DIR").unwrap())
            .join("kevi")
            .join("config.toml"),
    );

    let cfg3 = Config::create(None, None).unwrap();
    assert_eq!(cfg3.generator_length, None);
    assert_eq!(cfg3.generator_words, None);
    assert_eq!(cfg3.generator_sep, None);
    assert_eq!(cfg3.avoid_ambiguous, Some(false));
}

#[test]
#[serial]
fn default_vault_path_uses_platform_data_dir_under_home() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_VAULT_PATH");
    env::remove_var("KEVI_DATA_DIR");

    // Ensure no config file
    let _ = fs::remove_file(
        PathBuf::from(env::var("KEVI_CONFIG_DIR").unwrap())
            .join("kevi")
            .join("config.toml"),
    );

    // Force data_dir to be deterministic via override
    let data_root = td.path().join("data");
    env::set_var("KEVI_DATA_DIR", data_root.to_string_lossy().to_string());
    let cfg = Config::create(None, None).unwrap();
    let expected = data_root.join("kevi").join("vault.ron");
    assert_eq!(cfg.vault_path, expected);
}

#[test]
#[serial]
fn backups_rotation_uses_configured_count() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    // No env override
    env::remove_var("KEVI_BACKUPS");

    // Configure backups = 3
    let path = td.path().join("vault.ron");
    let backups = 3usize;
    let _cfg = Config {
        vault_path: VaultPath::from(path.clone()),
        clipboard_ttl: None,
        backups: Some(backups),
        generator_length: None,
        generator_words: None,
        generator_sep: None,
        avoid_ambiguous: None,
        default_profile: None,
        profiles: Default::default(),
    };

    // Use FileByteStore with explicit backups count (no env coupling)
    let store = FileByteStore::new_with_backups(path.clone(), backups);

    // Perform multiple writes to trigger rotation
    store.write(b"A").expect("write 1");
    // After first write no backups yet
    assert!(!Path::new(&format!("{}{}", path.display(), ".1")).exists());

    store.write(b"B").expect("write 2");
    assert!(Path::new(&format!("{}{}", path.display(), ".1")).exists());

    store.write(b"C").expect("write 3");
    store.write(b"D").expect("write 4");
    // We keep up to .1, .2, .3; .4 must not exist
    assert!(Path::new(&format!("{}{}", path.display(), ".1")).exists());
    assert!(Path::new(&format!("{}{}", path.display(), ".2")).exists());
    assert!(Path::new(&format!("{}{}", path.display(), ".3")).exists());
    assert!(!Path::new(&format!("{}{}", path.display(), ".4")).exists());
}

#[test]
#[serial]
fn vault_path_cli_profile_overrides_env_and_file() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );

    // Env and file defaults should be ignored when CLI profile is provided
    env::set_var("KEVI_VAULT_PATH", "/tmp/env_vault.ron");
    write_config_file(
        td.path(),
        r#"
vault_path = "/tmp/file_vault.ron"
default_profile = "home"

[profiles]
work = { vault_path = "/tmp/work_vault.ron" }
home = { vault_path = "/tmp/home_vault.ron" }
"#,
    );

    let cfg = Config::create(None, Some("work".to_string())).unwrap();
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/work_vault.ron"));
}

#[test]
#[serial]
fn vault_path_uses_default_profile_when_present() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_VAULT_PATH");

    write_config_file(
        td.path(),
        r#"
default_profile = "home"

[profiles]
home = { vault_path = "/tmp/home_vault.ron" }
work = { vault_path = "/tmp/work_vault.ron" }
"#,
    );

    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/home_vault.ron"));
}

#[test]
#[serial]
fn vault_path_ignores_missing_default_profile_and_falls_back_to_file() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );
    env::remove_var("KEVI_VAULT_PATH");

    write_config_file(
        td.path(),
        r#"
vault_path = "/tmp/file_vault.ron"
default_profile = "missing"

[profiles]
home = { vault_path = "/tmp/home_vault.ron" }
"#,
    );

    let cfg = Config::create(None, None).unwrap();
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/file_vault.ron"));
}

#[test]
#[serial]
fn unknown_cli_profile_returns_error() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var(
        "KEVI_CONFIG_DIR",
        td.path().join("cfg").to_string_lossy().to_string(),
    );

    write_config_file(
        td.path(),
        r#"
[profiles]
home = { vault_path = "/tmp/home_vault.ron" }
"#,
    );

    let err = Config::create(None, Some("missing".to_string()))
        .expect_err("expected unknown profile error");
    match err {
        ConfigError::UnknownProfile(name) => assert_eq!(name, "missing"),
        other => panic!("unexpected error: {other:?}"),
    }
}
