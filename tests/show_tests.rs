use assert_cmd::Command;
use kevi::core::entry::VaultEntry;
use kevi::core::store::save_vault_file;
use secrecy::SecretString;
use tempfile::tempdir;

#[test]
fn show_command_prints_details_masked_by_default() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    let entries = vec![VaultEntry {
        label: "mysite".into(),
        username: Some(SecretString::new("alice".into())),
        password: SecretString::new("secret123".into()),
        notes: Some("noteZ".into()),
    }];
    save_vault_file(&entries, &path, pw).unwrap();

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("show")
        .arg("mysite")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());

    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(out.contains("Label:    mysite"));
    assert!(out.contains("Username: alice"));
    assert!(out.contains("Notes:    noteZ"));
    assert!(out.contains("Password: ********"));
    assert!(!out.contains("secret123"));
}

#[test]
fn show_command_reveals_password_with_flag() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let pw = "pw";

    let entries = vec![VaultEntry {
        label: "mysite".into(),
        username: Some(SecretString::new("alice".into())),
        password: SecretString::new("secret123".into()),
        notes: Some("noteZ".into()),
    }];
    save_vault_file(&entries, &path, pw).unwrap();

    let mut cmd = Command::cargo_bin("kevi").unwrap();
    cmd.env("KEVI_PASSWORD", pw)
        .arg("show")
        .arg("mysite")
        .arg("--reveal-password")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());

    let assert = cmd.assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    assert!(out.contains("Label:    mysite"));
    assert!(out.contains("Username: alice"));
    assert!(out.contains("Notes:    noteZ"));
    assert!(out.contains("Password: secret123"));
}
