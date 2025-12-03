use kevi::config::config::Config;
use kevi::core::vault::Vault;
use serial_test::serial;
use std::env;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

fn write_config_file(_dir: &std::path::Path, content: &str) {
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
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    env::remove_var("KEVI_VAULT_PATH");

    // Write a config with a vault_path
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");

    // Also set env var; CLI should still win
    env::set_var("KEVI_VAULT_PATH", "/tmp/env_vault.ron");
    let cli_path = PathBuf::from("/tmp/cli_vault.ron");
    let cfg = Config::create(Some(cli_path.clone()));
    assert_eq!(cfg.vault_path, cli_path);
}

#[test]
#[serial]
fn vault_path_precedence_env_over_file() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    // file config
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");
    // env overrides
    env::set_var("KEVI_VAULT_PATH", "/tmp/env_vault.ron");
    let cfg = Config::create(None);
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/env_vault.ron"));
}

#[test]
#[serial]
fn vault_path_precedence_file_over_default() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    env::remove_var("KEVI_VAULT_PATH");
    write_config_file(td.path(), "vault_path = \"/tmp/cfg_vault.ron\"\n");
    let cfg = Config::create(None);
    assert_eq!(cfg.vault_path, PathBuf::from("/tmp/cfg_vault.ron"));
}

#[test]
#[serial]
fn clipboard_ttl_and_backups_precedence() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    env::remove_var("KEVI_CLIP_TTL");
    env::remove_var("KEVI_BACKUPS");

    // From file when env not set
    write_config_file(td.path(), "clipboard_ttl = 33\nbackups = 4\n");
    let cfg = Config::create(None);
    assert_eq!(cfg.clipboard_ttl, Some(33));
    assert_eq!(cfg.backups, Some(4));

    // Env overrides file
    env::set_var("KEVI_CLIP_TTL", "99");
    env::set_var("KEVI_BACKUPS", "7");
    let cfg2 = Config::create(None);
    assert_eq!(cfg2.clipboard_ttl, Some(99));
    assert_eq!(cfg2.backups, Some(7));
}

#[test]
#[serial]
fn default_vault_path_uses_platform_data_dir_under_home() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    env::remove_var("KEVI_VAULT_PATH");
    env::remove_var("KEVI_DATA_DIR");

    // Ensure no config file
    let _ = fs::remove_file(PathBuf::from(env::var("KEVI_CONFIG_DIR").unwrap()).join("kevi").join("config.toml"));

    // Force data_dir to be deterministic via override
    let data_root = td.path().join("data");
    env::set_var("KEVI_DATA_DIR", data_root.to_string_lossy().to_string());
    let cfg = Config::create(None);
    let expected = data_root.join("kevi").join("vault.ron");
    assert_eq!(cfg.vault_path, expected);
}

#[test]
#[serial]
fn backups_env_is_propagated_from_config_on_vault_create() {
    let td = tempdir().unwrap();
    env::set_var("HOME", td.path());
    env::set_var("KEVI_CONFIG_DIR", td.path().join("cfg").to_string_lossy().to_string());
    env::remove_var("KEVI_BACKUPS");
    let vault_path = td.path().join("vault.ron");
    // Construct config with backups value
    let cfg = Config {
        vault_path: vault_path.clone(),
        clipboard_ttl: None,
        backups: Some(5),
        generator_length: None,
        generator_words: None,
        generator_sep: None,
        avoid_ambiguous: None,
    };
    let _vault = Vault::create(&cfg);
    let b = env::var("KEVI_BACKUPS").expect("env set by Vault::create");
    assert_eq!(b, "5");
}
