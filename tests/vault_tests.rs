use kevi::config::config::Config;
use kevi::core::entry::VaultEntry;
use kevi::core::store::{load_vault_file, save_vault_file};
use kevi::core::vault::{GetField, Vault};
use secrecy::SecretString;
use std::env;
use std::path::PathBuf;
use tempfile::tempdir;

fn setup_vault_path(file_name: &str) -> PathBuf {
    let dir = tempdir().unwrap();
    dir.path().join(file_name)
}

#[tokio::test]
async fn test_handle_get_existing_entry() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultEntry {
        label: "gettest".into(),
        username: Some(SecretString::new("user".into())),
        password: SecretString::new("secret".into()),
        notes: Some("note".into()),
    };

    save_vault_file(&[entry.clone()], &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault
        .handle_get("gettest", GetField::Password, true, None, false, false)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_handle_rm_existing_entry() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultEntry {
        label: "rmtest".into(),
        username: None,
        password: SecretString::new("pw".into()),
        notes: None,
    };

    save_vault_file(&[entry.clone()], &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault.handle_rm("rmtest", true).await;
    assert!(result.is_ok());

    let loaded = load_vault_file(&path, pw).unwrap();
    assert!(loaded.iter().find(|e| e.label == "rmtest").is_none());
}
