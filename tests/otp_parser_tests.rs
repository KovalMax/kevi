use kevi::otp::handlers::OtpAddOptions;
use kevi::otp::models::OtpAlgorithm;
use kevi::otp::parser::parse_otp_entry;

fn make_otp_entry(uri: Option<String>, secret: Option<String>) -> OtpAddOptions {
    OtpAddOptions {
        name: "demo".to_string(),
        secret,
        from_uri: uri,
        issuer: Some("demo".to_string()),
        username: Some("test".to_string()),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: Some("example".to_string()),
        on_duplicate_override: false,
    }
}
#[test]
fn parse_simple_otp_auth_uri() {
    let uri = "otpauth://totp/Example:demo@example.com\
                   ?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    let entry =
        parse_otp_entry(&make_otp_entry(Some(uri.to_string()), None)).expect("valid otp entry");

    assert_eq!(entry.name, "demo");
    assert_eq!(entry.username, "test");
    assert_eq!(entry.issuer.as_deref(), Some("demo"));
    assert_eq!(entry.digits, 6);
    assert_eq!(entry.period, 30);
    assert!(matches!(entry.algorithm, OtpAlgorithm::Sha1));
    assert_eq!(entry.notes.as_deref(), Some("example"));
    assert_eq!(entry.secret, "JBSWY3DPEHPK3PXP".to_string());
}

#[test]
fn parse_otp_secret_from_options() {
    let secret = "JBSWY3DPEHPK3PXP".to_string();
    let entry =
        parse_otp_entry(&make_otp_entry(None, Some(secret.clone()))).expect("valid otp entry");

    assert_eq!(entry.name, "demo");
    assert_eq!(entry.username, "test");
    assert_eq!(entry.issuer.as_deref(), Some("demo"));
    assert_eq!(entry.digits, 6);
    assert_eq!(entry.period, 30);
    assert!(matches!(entry.algorithm, OtpAlgorithm::Sha1));
    assert_eq!(entry.notes.as_deref(), Some("example"));
    assert_eq!(entry.secret, secret);
}

#[test]
fn parse_empty_secret_string() {
    let secret = " ".to_string();
    let err = parse_otp_entry(&make_otp_entry(None, Some(secret.clone()))).unwrap_err();
    let msg = err.to_string();

    assert_eq!(msg, "secret cannot be empty");
}

#[test]
fn parse_otp_auth_uri_with_overrides_like_8_digits() {
    let uri = "otpauth://totp/Example:demo@example.com\
                   ?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA256";
    let entry =
        parse_otp_entry(&make_otp_entry(Some(uri.to_string()), None)).expect("valid otp entry");

    assert_eq!(entry.digits, 6);
    assert_eq!(entry.period, 30);
    assert!(matches!(entry.algorithm, OtpAlgorithm::Sha1));
    assert_eq!(entry.secret, "JBSWY3DPEHPK3PXP".to_string());
}

#[test]
fn parse_otp_auth_uri_invalid_scheme_rejected() {
    let uri = "https://example.com/not-otp";
    let err = parse_otp_entry(&make_otp_entry(Some(uri.to_string()), None)).unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("otpauth"), "unexpected error: {msg}");
}

#[test]
fn parse_otp_auth_uri_missing_secret_rejected() {
    let uri = "otpauth://totp/Example:demo@example.com?issuer=Example";
    let err = parse_otp_entry(&make_otp_entry(Some(uri.to_string()), None)).unwrap_err();
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("secret"), "unexpected error: {msg}");
}
