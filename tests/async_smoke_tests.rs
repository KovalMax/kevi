use kevi::config::app_config::Config;
use kevi::core::entry::VaultEntry;
use kevi::core::store::save_vault_file;
use kevi::core::vault::Vault;
use secrecy::SecretString;
use tempfile::tempdir;

#[tokio::test]
async fn vault_handle_header_async_ok() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed a minimal encrypted vault
    let entries: Vec<VaultEntry> = vec![VaultEntry {
        label: "x".into(),
        username: Some(SecretString::new("u".into())),
        password: SecretString::new("p".into()),
        notes: None,
    }];
    save_vault_file(&entries, &path, pw).expect("seed vault");

    // Run async header handler
    let cfg = Config::create(Some(path.clone()), None).unwrap();
    let v = Vault::create(&cfg);
    let res = v.handle_header().await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn vault_handle_list_async_ok() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    // Seed with two entries
    let entries: Vec<VaultEntry> = vec![
        VaultEntry {
            label: "alpha".into(),
            username: None,
            password: SecretString::new("a".into()),
            notes: None,
        },
        VaultEntry {
            label: "beta".into(),
            username: Some(SecretString::new("b".into())),
            password: SecretString::new("b".into()),
            notes: None,
        },
    ];
    save_vault_file(&entries, &path, pw).expect("seed vault");

    // Provide password via env to avoid prompt
    std::env::set_var("KEVI_PASSWORD", pw);

    let cfg = Config::create(Some(path.clone()), None).unwrap();
    let v = Vault::create(&cfg);
    // Run list without query/json to exercise async path
    let res = v.handle_list(None, false, false).await;
    assert!(res.is_ok());
}
