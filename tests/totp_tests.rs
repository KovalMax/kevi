use kevi::otp::handlers::OtpAddOptions;
use kevi::otp::models::{OtpAlgorithm, OtpEntry};
use kevi::otp::totp::{build_totp, validate_totp_params};

fn make_otp_options(
    digits: u32,
    period: u64,
    secret: Option<String>,
    from_uri: Option<String>,
) -> OtpAddOptions {
    OtpAddOptions {
        name: String::new(),
        secret,
        from_uri,
        issuer: None,
        username: None,
        algorithm: OtpAlgorithm::Sha1,
        digits,
        period,
        notes: None,
        on_duplicate_override: false,
    }
}

#[test]
fn map_algo_maps_all_variants() {
    assert!(matches!(
        OtpAlgorithm::map_to_totp(&OtpAlgorithm::Sha1),
        totp_rs::Algorithm::SHA1
    ));
    assert!(matches!(
        OtpAlgorithm::map_to_totp(&OtpAlgorithm::Sha256),
        totp_rs::Algorithm::SHA256
    ));
    assert!(matches!(
        OtpAlgorithm::map_to_totp(&OtpAlgorithm::Sha512),
        totp_rs::Algorithm::SHA512
    ));

    assert_eq!(OtpAlgorithm::Sha1.format().to_string(), "SHA1".to_string());
    assert_eq!(
        OtpAlgorithm::Sha256.format().to_string(),
        "SHA256".to_string()
    );
    assert_eq!(
        OtpAlgorithm::Sha512.format().to_string(),
        "SHA512".to_string()
    );
}

#[test]
fn validate_totp_params_accepts_valid() {
    assert!(validate_totp_params(&make_otp_options(6, 30, Some("test".to_string()), None)).is_ok());
    assert!(validate_totp_params(&make_otp_options(8, 60, None, Some("test".to_string()))).is_ok());
}

#[test]
fn validate_totp_params_rejects_invalid_digits() {
    assert!(
        validate_totp_params(&make_otp_options(5, 30, Some("test".to_string()), None)).is_err()
    );
    assert!(
        validate_totp_params(&make_otp_options(7, 30, Some("test".to_string()), None)).is_err()
    );
    assert!(
        validate_totp_params(&make_otp_options(9, 30, Some("test".to_string()), None)).is_err()
    );
}

#[test]
fn validate_totp_params_rejects_zero_or_negative_period() {
    assert!(validate_totp_params(&make_otp_options(6, 0, Some("test".to_string()), None)).is_err());
    assert!(validate_totp_params(&make_otp_options(
        6,
        u64::MAX,
        Some("test".to_string()),
        None
    ))
    .is_ok()); // still allowed
}

#[test]
fn validate_totp_params_secret_or_from_uri() {
    assert!(validate_totp_params(&make_otp_options(6, 30, None, None)).is_err());
}

#[test]
fn build_totp_generates_6_digits() {
    let entry = OtpEntry {
        name: "test".to_string(),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        issuer: Some("Example".to_string()),
        username: "demo@example.com".to_string(),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
    };

    let totp = build_totp(&entry).expect("Failed to build TOTP");
    let ts = 59;
    let code = totp.generate(ts);
    assert_eq!(code.len(), entry.digits as usize);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}
