use kevi::api::{
    decrypt_vault, default_params, encrypt_vault, validate_kdf_params, HeaderError,
    MAX_KDF_ITERATIONS, MAX_KDF_LANES, MAX_KDF_MEMORY_KIB,
};

#[test]
fn kdf_policy_accepts_defaults_and_exact_limits() {
    assert!(
        validate_kdf_params(default_params().0, default_params().1, default_params().2).is_ok()
    );
    assert!(validate_kdf_params(MAX_KDF_MEMORY_KIB, MAX_KDF_ITERATIONS, MAX_KDF_LANES).is_ok());
    for params in [
        (MAX_KDF_MEMORY_KIB + 1, 1, 1),
        (8, MAX_KDF_ITERATIONS + 1, 1),
        (8, 1, MAX_KDF_LANES + 1),
        (0, 1, 1),
        (8, 0, 1),
        (7, 1, 1),
        (15, 1, 2),
    ] {
        assert!(
            validate_kdf_params(params.0, params.1, params.2).is_err(),
            "{params:?}"
        );
    }
}

#[test]
fn invalid_header_policy_is_rejected_by_public_decrypt_before_kdf() {
    let ciphertext = encrypt_vault(b"synthetic payload", "synthetic password").unwrap();
    for (offset, value) in [
        (8, MAX_KDF_MEMORY_KIB + 1),
        (12, MAX_KDF_ITERATIONS + 1),
        (16, MAX_KDF_LANES + 1),
        (12, 0),
        (16, 0),
    ] {
        let mut invalid_header = ciphertext.clone();
        invalid_header[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(
            decrypt_vault(&invalid_header, "synthetic password"),
            Err(kevi::api::KeviError::Vault(
                kevi::api::VaultError::InvalidHeader(HeaderError::InvalidKdfParams(_))
            ))
        ));
    }
}

#[test]
fn valid_within_cap_synthetic_vault_roundtrips() {
    let encrypted = encrypt_vault(b"synthetic payload", "synthetic password").unwrap();
    assert_eq!(
        decrypt_vault(&encrypted, "synthetic password").unwrap(),
        b"synthetic payload"
    );
}
