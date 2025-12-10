use kevi::core::entry::VaultEntry;
use secrecy::{ExposeSecret, SecretString};

#[test]
fn serde_round_trip_username_and_password() {
    // Build an entry with a secret username and password
    let entry = VaultEntry {
        label: "label".to_string(),
        username: Some(SecretString::new("user123".into())),
        password: SecretString::new("p@ssw0rd".into()),
        notes: Some("n".to_string()),
    };

    // Serialize to RON and deserialize back
    let s = ron::to_string(&entry).expect("serialize");
    let de: VaultEntry = ron::from_str(&s).expect("deserialize");

    assert_eq!(de.label, "label");
    assert_eq!(de.username.as_ref().unwrap().expose_secret(), "user123");
    assert_eq!(de.password.expose_secret(), "p@ssw0rd");
    assert_eq!(de.notes.as_deref(), Some("n"));
}

#[test]
fn debug_redacts_secrets() {
    let secret = SecretString::new("super-secret".into());
    let dbg = format!("{secret:?}");
    // Should not contain the actual secret and typically contains REDACTED marker
    assert!(
        !dbg.contains("super-secret"),
        "Debug must not reveal secret"
    );
    // Many implementations include REDACTED; allow this to be flexible
    assert!(
        dbg.contains("REDACTED") || dbg.contains("Secret("),
        "Debug should be redacted"
    );
}
