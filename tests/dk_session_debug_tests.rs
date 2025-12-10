use kevi::session_management::resolver::{
    dk_session_file_for, save_derived_key_session, DerivedKeyStored,
};
use kevi::session_management::session::load;
use secrecy::SecretBox;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn dk_session_debug_is_redacted_and_round_trips() {
    let td = tempdir().unwrap();
    let vault_path = td.path().join("vault.ron");
    let sess_path = dk_session_file_for(&vault_path);

    let fp = "abcd1234";
    let key = SecretBox::new(Box::new(vec![0x42; 32]));
    save_derived_key_session(&sess_path, fp, &key, Duration::from_secs(60)).expect("write");

    // Read back
    let sess: DerivedKeyStored = load(&sess_path).expect("read").expect("present");
    assert_eq!(sess.header_fingerprint_hex, fp);
    // Stored as b64
    assert!(!sess.key_b64.is_empty());

    // Test debug redaction on the Domain Object `DerivedKey`
    let dk = kevi::vault::ports::DerivedKey { key };
    let dbg = format!("{dk:?}");
    // 0x42 in hex is not directly visible, but let's check for REDACTED
    assert!(dbg.contains("<REDACTED>"));
}
