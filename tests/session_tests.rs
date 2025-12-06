use kevi::core::crypto::header_fingerprint_excluding_nonce;
use kevi::core::crypto::KeviHeader;
use kevi::core::crypto::{default_params, derive_key_argon2id, AEAD_AES256GCM, HEADER_VERSION, KDF_ARGON2ID, NONCE_LEN};
use kevi::core::dk_session::{clear_dk_session, dk_session_file_for, read_dk_session, write_dk_session};
use secrecy::{ExposeSecret, SecretBox};
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn dk_session_write_read_and_expire() {
    let dir = tempdir().unwrap();
    let vault_path = dir.path().join("vault.ron");
    let sess_path = dk_session_file_for(&vault_path);

    // Build a synthetic header to compute fingerprint
    let (m, t, p) = default_params();
    let salt = [0u8; 16];
    let hdr = KeviHeader { version: HEADER_VERSION, kdf_id: KDF_ARGON2ID, aead_id: AEAD_AES256GCM, m_cost_kib: m, t_cost: t, p_lanes: p, salt, nonce: [0u8; NONCE_LEN] };
    let fp = header_fingerprint_excluding_nonce(&hdr);

    // Derive a dummy key and write a session with 1s TTL
    let key = derive_key_argon2id("pw123", &salt, m, t, p).unwrap();
    let key_box = SecretBox::new(Box::new(key.to_vec()));
    write_dk_session(&sess_path, &fp, &key_box, Duration::from_secs(1)).expect("write dk session");

    // Should read back immediately
    let got = read_dk_session(&sess_path).expect("read ok").expect("present");
    assert_eq!(got.header_fingerprint_hex, fp);
    assert_eq!(got.key.expose_secret().len(), 32);

    // On Unix, file perms should be 0600
    #[cfg(target_family = "unix")]
    {
        let meta = std::fs::metadata(&sess_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "dk session file perms should be 0600");
    }

    // Wait for expiry and ensure it's gone
    std::thread::sleep(Duration::from_millis(1200));
    let got2 = read_dk_session(&sess_path).expect("read ok after expire");
    assert!(got2.is_none(), "dk session should be expired");
    assert!(!sess_path.exists(), "expired dk session should be removed");

    // Clear is idempotent
    clear_dk_session(&sess_path).unwrap();
}
