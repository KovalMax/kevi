use anyhow::Result;
use kevi::core::crypto::{decrypt_vault, encrypt_vault};

#[tokio::test]
async fn test_encryption_decryption() -> Result<()> {
    // Simulate encryption with a master password
    let password = "master_secret";
    let encrypted = encrypt_vault(b"some secret data", password)?;

    // Decrypt it and check if the decrypted data matches
    let decrypted = decrypt_vault(&encrypted, password)?;
    assert_eq!(decrypted, b"some secret data");

    Ok(())
}
