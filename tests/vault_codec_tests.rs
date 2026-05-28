use kevi::otp::models::{OtpAlgorithm, OtpEntry};
use kevi::vault::codec::RonCodec;
use kevi::vault::models::{VaultData, VaultEntry};
use kevi::vault::ports::VaultCodec;
use secrecy::ExposeSecret;
use secrecy::SecretString;

#[test]
fn ron_codec_round_trip_preserves_data() {
    let codec = RonCodec;

    let entry = VaultEntry {
        label: "example".into(),
        username: Some(SecretString::new("alice".into())),
        password: SecretString::new("s3cret".into()),
        notes: Some("note".to_string()),
    };

    let otp = OtpEntry {
        name: "otp1".into(),
        secret: "BASE32SECRET".to_string(),
        issuer: Some("issuer".to_string()),
        username: "alice".to_string(),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: Some("otp notes".to_string()),
    };

    let data = VaultData {
        entries: vec![entry.clone()],
        otps: vec![otp.clone()],
    };

    let encoded = codec.encode(&data).expect("encode succeeds");
    let decoded = codec.decode(&encoded).expect("decode succeeds");

    let expected_username = entry.username.as_ref().unwrap().expose_secret().to_string();
    let expected_password = entry.password.expose_secret().to_string();

    assert_eq!(decoded.entries.len(), 1);
    let decoded_entry = &decoded.entries[0];
    assert_eq!(decoded_entry.label, entry.label);
    assert_eq!(
        decoded_entry.username.as_ref().unwrap().expose_secret(),
        &expected_username,
    );
    assert_eq!(decoded_entry.password.expose_secret(), expected_password);
    assert_eq!(decoded_entry.notes, entry.notes);

    assert_eq!(decoded.otps.len(), 1);
    let decoded_otp = &decoded.otps[0];
    assert_eq!(decoded_otp.name, otp.name);
    assert_eq!(decoded_otp.secret, otp.secret);
    assert_eq!(decoded_otp.issuer, otp.issuer);
    assert_eq!(decoded_otp.username, otp.username);
    assert_eq!(decoded_otp.digits, otp.digits);
    assert_eq!(decoded_otp.period, otp.period);
    assert!(matches!(decoded_otp.algorithm, OtpAlgorithm::Sha1));
    assert_eq!(decoded_otp.notes, otp.notes);
}

#[test]
fn ron_codec_decode_rejects_invalid_ron() {
    let codec = RonCodec;
    let invalid = b"not valid ron";

    let err = codec.decode(invalid).expect_err("decode should fail");
    let msg = format!("{err}");
    assert!(msg.contains("vault content"));
}
