use kevi::core::dk_session::{dk_session_file_for, read_dk_session, write_dk_session};
use secrecy::{ExposeSecret, SecretBox};
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn dk_session_debug_is_redacted_and_round_trips() {
    let td = tempdir().unwrap();
    let vault_path = td.path().join("vault.ron");
    let sess_path = dk_session_file_for(&vault_path);

    let fp = "abcd1234";
    let key = SecretBox::new(Box::new(vec![0x42; 32]));
    write_dk_session(&sess_path, fp, &key, Duration::from_secs(60)).expect("write");

    // Read back
    let sess = read_dk_session(&sess_path).expect("read").expect("present");
    assert_eq!(sess.header_fingerprint_hex, fp);
    assert_eq!(sess.key.expose_secret().len(), 32);

    // Debug must not reveal the key bytes
    let dbg = format!("{sess:?}");
    assert!(!dbg.contains("42"), "debug must not include raw key bytes");
    assert!(dbg.contains("<REDACTED>"));
}
