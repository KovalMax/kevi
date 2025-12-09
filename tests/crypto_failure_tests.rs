use anyhow::Result;
use kevi::core::crypto::{decrypt_vault, encrypt_vault};

#[test]
fn test_wrong_password_fails() {
    let pw_ok = "correct horse";
    let pw_bad = "battery staple";
    let ct = encrypt_vault(b"top secret", pw_ok).expect("encrypt ok");
    let res = decrypt_vault(&ct, pw_bad);
    assert!(res.is_err(), "decryption with wrong password should fail");
}

#[test]
fn test_tamper_detection() -> Result<()> {
    let pw = "pass";
    let mut ct = encrypt_vault(b"payload", pw)?;
    // Flip a bit in ciphertext tail (after header)
    let len = ct.len();
    if len > 5 {
        ct[len - 5] ^= 0x01;
    }
    let res = decrypt_vault(&ct, pw);
    assert!(res.is_err(), "tampered ciphertext must not decrypt");
    Ok(())
}

#[test]
fn test_header_prefix_is_kevi() -> Result<()> {
    let pw = "pw";
    let ct = encrypt_vault(b"data", pw)?;
    assert!(ct.starts_with(b"KEVI"));
    Ok(())
}
