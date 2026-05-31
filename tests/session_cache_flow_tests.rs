use assert_cmd::Command;
use kevi::api::{dk_session_file_for, save_vault_file, VaultData, VaultEntry};
use secrecy::SecretString;
use tempfile::tempdir;

fn seed_vault(path: &std::path::Path, master_password: &str, label: &str, secret: &str) {
    let data = VaultData {
        entries: vec![VaultEntry {
            label: label.into(),
            username: Some(SecretString::new("user@example.com".into())),
            password: SecretString::new(secret.to_string().into()),
            notes: Some("seeded".to_string()),
        }],
        otps: vec![],
    };
    save_vault_file(&data, path, master_password).expect("seed vault");
}

#[test]
fn unlock_then_get_uses_cached_key_and_lock_clears_it() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "github", "s3cr3t");

    let dk_path = dk_session_file_for(&path);
    if dk_path.exists() {
        std::fs::remove_file(&dk_path).expect("remove stale session");
    }

    let mut unlock_cmd = Command::cargo_bin("kevi").expect("binary");
    unlock_cmd
        .env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("unlock")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--ttl")
        .arg("60");
    unlock_cmd.assert().success();

    assert!(dk_path.exists(), "unlock should create derived-key session");

    let mut get_cmd = Command::cargo_bin("kevi").expect("binary");
    get_cmd
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("get")
        .arg("github")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--field")
        .arg("password")
        .arg("--no-copy")
        .arg("--echo");
    get_cmd
        .assert()
        .success()
        .stdout(predicates::str::contains("s3cr3t"));

    let mut lock_cmd = Command::cargo_bin("kevi").expect("binary");
    lock_cmd
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("lock")
        .arg("--path")
        .arg(path.to_string_lossy().to_string());
    lock_cmd.assert().success();

    assert!(
        !dk_path.exists(),
        "lock should remove derived-key session file"
    );
}

#[test]
fn get_once_bypasses_cached_key_and_does_not_create_session() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "mail", "mail-secret");

    let dk_path = dk_session_file_for(&path);
    if dk_path.exists() {
        std::fs::remove_file(&dk_path).expect("remove stale session");
    }

    let mut get_once_cmd = Command::cargo_bin("kevi").expect("binary");
    get_once_cmd
        .env("KEVI_PASSWORD", "pw")
        .arg("get")
        .arg("mail")
        .arg("--path")
        .arg(path.to_string_lossy().to_string())
        .arg("--field")
        .arg("password")
        .arg("--echo")
        .arg("--no-copy")
        .arg("--once");
    get_once_cmd
        .assert()
        .success()
        .stdout(predicates::str::contains("mail-secret"));

    assert!(
        !dk_path.exists(),
        "--once must not create a derived-key session"
    );
}
