use assert_cmd::Command;
use kevi::api::{dk_session_file_for, save_vault_file, VaultData, VaultEntry};
use secrecy::SecretString;
use tempfile::tempdir;

#[cfg(target_os = "linux")]
fn cache_flow_test_dir() -> tempfile::TempDir {
    let home = std::env::var_os("HOME").expect("CI provides a protected home directory");
    tempfile::tempdir_in(home).expect("create fixture below protected home")
}

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
#[cfg(all(unix, not(target_os = "macos")))]
fn unlock_then_get_uses_cached_key_and_lock_clears_it() {
    let td = cache_flow_test_dir();
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "github", "s3cr3t");

    let dk_path = dk_session_file_for(&path).unwrap();
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
        .env_remove("KEVI_PASSWORD")
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

    // Production lock intentionally contacts every native target, even in file mode.
    // Exercise the same handler using a no-native adapter in this deterministic suite.
    struct FilesOnly;
    impl kevi::api::CacheCleanup for FilesOnly {
        fn native(&self, _: &str) -> kevi::api::VaultResult<()> {
            Ok(())
        }
        fn file(&self, path: &std::path::Path) -> kevi::api::VaultResult<()> {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(kevi::api::CacheError::Delete.into()),
            }
        }
    }
    let config = kevi::api::Config::create(Some(path.clone()), None).unwrap();
    kevi::api::Vault::create(&config)
        .handle_lock_with(&FilesOnly)
        .unwrap();

    assert!(
        !dk_path.exists(),
        "lock should remove derived-key session file"
    );
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn explicit_unlock_wrong_password_and_ttl_zero_preserve_existing_session() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "demo", "dummy-secret");
    let mut first = Command::cargo_bin("kevi").unwrap();
    first
        .env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["unlock", "--ttl", "60", "--path"])
        .arg(&path)
        .assert()
        .success();
    let file = dk_session_file_for(&path).unwrap();
    let original = std::fs::read(&file).unwrap();
    let mut wrong = Command::cargo_bin("kevi").unwrap();
    wrong
        .env("KEVI_PASSWORD", "wrong")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["unlock", "--path"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
    assert_eq!(original, std::fs::read(&file).unwrap());
    let mut zero = Command::cargo_bin("kevi").unwrap();
    zero.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["unlock", "--ttl", "0", "--path"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicates::str::contains("no session created"));
    assert_eq!(original, std::fs::read(&file).unwrap());
    let mut once = Command::cargo_bin("kevi").unwrap();
    once.env("KEVI_PASSWORD", "wrong")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["get", "demo", "--once", "--echo", "--no-copy", "--path"])
        .arg(&path)
        .assert()
        .failure();
    assert_eq!(original, std::fs::read(&file).unwrap());
}

#[test]
fn explicit_unlock_persistence_failure_is_nonzero_without_cached_claim() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "demo", "dummy");
    std::fs::create_dir(dk_session_file_for(&path).unwrap()).unwrap();
    let mut command = Command::cargo_bin("kevi").unwrap();
    command
        .env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["unlock", "--path"])
        .arg(&path)
        .assert()
        .failure()
        .stdout(predicates::str::is_empty());
}

#[test]
#[cfg(all(unix, not(target_os = "macos")))]
fn init_publishes_after_creation_and_cache_warning_keeps_json_stdout_clean() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let mut init = Command::cargo_bin("kevi").unwrap();
    init.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("init")
        .arg(&path)
        .assert()
        .success()
        .stderr(predicates::str::contains("Insecure file cache"));
    let session = dk_session_file_for(&path).unwrap();
    assert!(session.exists());
    assert!(!path.with_extension("dksession").exists());
    let mut list = Command::cargo_bin("kevi").unwrap();
    let output = list
        .env_remove("KEVI_PASSWORD")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["list", "--json", "--path"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value.is_array());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Insecure file cache"));
    let mut otp = Command::cargo_bin("kevi").unwrap();
    let output = otp
        .env_remove("KEVI_PASSWORD")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["otp", "list", "--json", "--path"])
        .arg(&path)
        .assert()
        .success()
        .get_output()
        .clone();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value.is_array());
}

#[test]
#[cfg(target_os = "macos")]
fn explicit_file_cache_selection_warns_and_never_persists_on_macos() {
    let td = tempdir().unwrap();
    let path = td.path().join("vault.ron");
    let mut init = Command::cargo_bin("kevi").unwrap();
    init.env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .arg("init")
        .arg(&path)
        .assert()
        .success()
        .stderr(predicates::str::contains("unsupported on macOS"));
    let session = dk_session_file_for(&path).unwrap();
    assert!(!session.exists());

    let mut unlock = Command::cargo_bin("kevi").unwrap();
    unlock
        .env("KEVI_PASSWORD", "pw")
        .env("KEVI_INSECURE_CACHE_FALLBACK", "1")
        .args(["unlock", "--path"])
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicates::str::contains("unsupported on macOS"));
    assert!(!session.exists());
}

#[test]
fn get_once_bypasses_cached_key_and_does_not_create_session() {
    let td = tempdir().expect("tempdir");
    let path = td.path().join("vault.ron");
    seed_vault(&path, "pw", "mail", "mail-secret");

    let dk_path = dk_session_file_for(&path).unwrap();
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
