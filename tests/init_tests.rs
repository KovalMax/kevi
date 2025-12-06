use kevi::config::config::Config;
use kevi::core::vault::Vault;
use std::env;
use std::fs;
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

#[tokio::test]
async fn test_init_creates_encrypted_vault() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.ron");
    let path_str = path.to_string_lossy().to_string();

    // Ensure password available non-interactively
    env::set_var("KEVI_PASSWORD", "initpw");

    let config = Config::create(None);
    let vault = Vault::create(&config);
    vault.handle_init(Some(&path_str)).await.unwrap();

    let bytes = fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"KEVI"), "vault file must start with KEVI header");

    #[cfg(target_family = "unix")]
    {
        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "vault file permissions should be 0600 on Unix");
    }
}
