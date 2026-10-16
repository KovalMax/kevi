use kevi::api::DerivedKey;
use secrecy::SecretBox;
#[test]
fn derived_key_debug_is_redacted() {
    let key = DerivedKey {
        key: SecretBox::new(Box::new(vec![0x42; 32])),
    };
    assert!(format!("{key:?}").contains("REDACTED"));
}
