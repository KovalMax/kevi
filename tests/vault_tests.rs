use kevi::api::{
    load_vault_file, save_vault_file, AddOptions, Config, GetField, Vault, VaultData, VaultEntry,
};
use secrecy::SecretString;
use std::env;
use std::path::PathBuf;
use tempfile::tempdir;

fn setup_vault_path(file_name: &str) -> PathBuf {
    let dir = tempdir().unwrap();
    dir.path().join(file_name)
}

#[tokio::test]
#[serial_test::serial]
async fn test_handle_get_existing_entry() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultData {
        entries: vec![VaultEntry {
            label: "gettest".into(),
            username: Some(SecretString::new("user".into())),
            password: SecretString::new("secret".into()),
            notes: Some("note".into()),
        }],
        otps: vec![],
    };

    save_vault_file(&entry, &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault
        .handle_get("gettest", GetField::Password, true, None, false, false)
        .await;
    assert!(result.is_ok());
    vault
        .handle_get("gettest", GetField::Password, true, None, true, false)
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn test_handle_rm_existing_entry() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultData {
        entries: vec![VaultEntry {
            label: "rmtest".into(),
            username: None,
            password: SecretString::new("pw".into()),
            notes: None,
        }],
        otps: vec![],
    };

    save_vault_file(&entry, &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault.handle_rm("rmtest", true).await;
    assert!(result.is_ok());

    let loaded = load_vault_file(&path, pw).unwrap();
    assert!(!loaded.entries.iter().any(|e| e.label == "rmtest"));
}

#[tokio::test]
#[serial_test::serial]
async fn test_handle_get_missing_entry_is_ok() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultData {
        entries: vec![],
        otps: vec![],
    };

    save_vault_file(&entry, &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault
        .handle_get("missing", GetField::Password, true, None, false, false)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
#[serial_test::serial]
async fn test_handle_get_empty_optional_field_is_ok() {
    let path = setup_vault_path("vault.ron");
    let pw = "testpw";
    let entry = VaultData {
        entries: vec![VaultEntry {
            label: "no-notes".into(),
            username: None,
            password: SecretString::new("secret".into()),
            notes: None,
        }],
        otps: vec![],
    };

    save_vault_file(&entry, &path, pw).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", pw);
    let result = vault
        .handle_get("no-notes", GetField::Notes, true, None, false, false)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
#[serial_test::serial]
async fn show_and_list_cover_optional_values_json_and_missing_entries() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vault.ron");
    let password = "test-password";
    let data = VaultData {
        entries: vec![
            VaultEntry {
                label: "GitHub".into(),
                username: Some(SecretString::new("alice".into())),
                password: SecretString::new("hidden-secret".into()),
                notes: Some("work account".into()),
            },
            VaultEntry {
                label: "Local".into(),
                username: Some(SecretString::new("".into())),
                password: SecretString::new("other-secret".into()),
                notes: None,
            },
        ],
        otps: vec![],
    };
    save_vault_file(&data, &path, password).unwrap();
    let config = Config::create(Some(path), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", password);

    vault.handle_show("GitHub", false).await.unwrap();
    vault.handle_show("GitHub", true).await.unwrap();
    vault.handle_show("Local", false).await.unwrap();
    assert!(vault.handle_show("missing", false).await.is_err());

    vault.handle_list(None, false, true).await.unwrap();
    vault.handle_list(None, true, true).await.unwrap();
    vault
        .handle_list(Some("git".into()), true, false)
        .await
        .unwrap();
    vault
        .handle_list(Some("absent".into()), false, false)
        .await
        .unwrap();
}

#[tokio::test]
#[serial_test::serial]
async fn add_rejects_duplicate_and_rm_missing_entry_without_mutation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("vault.ron");
    let password = "test-password";
    let data = VaultData {
        entries: vec![VaultEntry {
            label: "existing".into(),
            username: None,
            password: SecretString::new("secret".into()),
            notes: None,
        }],
        otps: vec![],
    };
    save_vault_file(&data, &path, password).unwrap();
    let config = Config::create(Some(path.clone()), None).unwrap();
    let vault = Vault::create(&config);
    env::set_var("KEVI_PASSWORD", password);
    vault
        .handle_add(AddOptions {
            generate: true,
            length: None,
            no_lower: false,
            no_upper: false,
            no_digits: false,
            no_symbols: false,
            allow_ambiguous: false,
            passphrase: false,
            words: None,
            sep: None,
            label: Some("existing".into()),
            user: Some("alice".into()),
            notes: Some("note".into()),
        })
        .await
        .unwrap();
    vault.handle_rm("absent", true).await.unwrap();
    assert_eq!(load_vault_file(&path, password).unwrap().entries.len(), 1);
}
