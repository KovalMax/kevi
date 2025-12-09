use kevi::core::entry::VaultEntry;
use kevi::core::store::{load_vault_file, save_vault_file};
use secrecy::{ExposeSecret, SecretString};
use tempfile::tempdir;

#[test]
fn test_add_and_get_entry() {
    let dir = tempdir().unwrap();
    let _path = dir.path().join("vault.ron");
    let pw = "testpw";

    let entry = VaultEntry {
        label: "testsite".into(),
        username: Some(SecretString::new("tester".into())),
        password: SecretString::new("1234".into()),
        notes: None,
    };

    let vault = vec![entry.clone()];
    save_vault_file(&vault, &_path, pw).unwrap();

    let loaded = load_vault_file(&_path, pw).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].label, "testsite");
    assert_eq!(
        loaded[0].username.as_ref().unwrap().expose_secret(),
        "tester"
    );
    assert_eq!(loaded[0].password.expose_secret(), "1234");
}

#[test]
fn test_remove_entry() {
    let dir = tempdir().unwrap();
    let _path = dir.path().join("vault.ron");
    let pw = "testpw";

    let mut vault = vec![
        VaultEntry {
            label: "one".into(),
            username: None,
            password: SecretString::new("p1".into()),
            notes: None,
        },
        VaultEntry {
            label: "two".into(),
            username: None,
            password: SecretString::new("p2".into()),
            notes: None,
        },
    ];
    save_vault_file(&vault, &_path, pw).unwrap();

    vault.retain(|e| e.label != "one");
    save_vault_file(&vault, &_path, pw).unwrap();

    let reloaded = load_vault_file(&_path, pw).unwrap();
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].label, "two");
}
