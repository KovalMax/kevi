use kevi::api::{
    build_totp, copy_with_ttl, load_file_config_with_path, parse_otp_entry, validate_totp_params,
    BypassKeyResolver, ClipboardEngine, DerivedKeyStored, HeaderError, KeviError, OtpAddOptions,
    OtpAlgorithm, VaultData,
};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct MemoryClipboard {
    value: Mutex<String>,
}

impl MemoryClipboard {
    fn new(seed: &str) -> Self {
        Self {
            value: Mutex::new(seed.to_string()),
        }
    }
}

impl ClipboardEngine for MemoryClipboard {
    fn get_contents(&self) -> Result<Option<String>, KeviError> {
        Ok(Some(self.value.lock().unwrap().clone()))
    }

    fn set_contents(&self, contents: &str) -> Result<(), KeviError> {
        *self.value.lock().unwrap() = contents.to_string();
        Ok(())
    }
}

fn make_otp_options() -> OtpAddOptions {
    OtpAddOptions {
        name: "demo".into(),
        secret: Some("JBSWY3DPEHPK3PXP".to_string()),
        from_uri: None,
        issuer: Some("demo".to_string()),
        username: Some("user".to_string()),
        digits: 6,
        period: 30,
        algorithm: OtpAlgorithm::Sha1,
        notes: None,
        on_duplicate_override: false,
    }
}

#[test]
fn api_exports_cover_main_entry_points() {
    let (_cfg_path, _cfg_file) = load_file_config_with_path();
    let _default_data = VaultData::default();
    let _stored = DerivedKeyStored {
        header_fingerprint_hex: "abc".to_string(),
        key_b64: "def".to_string(),
    };
    let _bypass = BypassKeyResolver::new();

    let opts = make_otp_options();
    validate_totp_params(&opts).expect("valid totp params through api");
    let entry = parse_otp_entry(&opts).expect("parse otp entry through api");
    let _totp = build_totp(&entry).expect("build totp through api");

    let engine: Arc<dyn ClipboardEngine> = Arc::new(MemoryClipboard::new("old"));
    let secret = SecretString::new("new".to_string().into());
    copy_with_ttl(engine.clone(), &secret, Duration::from_millis(1)).expect("copy via api");

    let header_error = HeaderError::TooShort;
    let kevi_error: KeviError = header_error.into();
    assert!(kevi_error.to_string().contains("invalid header"));
}
