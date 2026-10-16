use kevi::api::{CacheError, Clock, DerivedKeyStored, VaultResult};
use secrecy::SecretBox;
use std::time::Duration;
struct Fixed(u64);
impl Clock for Fixed {
    fn now(&self) -> VaultResult<u64> {
        Ok(self.0)
    }
}
struct Failed;
impl Clock for Failed {
    fn now(&self) -> VaultResult<u64> {
        Err(CacheError::Clock.into())
    }
}
fn issue() -> DerivedKeyStored {
    DerivedKeyStored::issue(
        "identity".into(),
        "fingerprint".into(),
        &SecretBox::new(Box::new(vec![42; 32])),
        Duration::from_secs(30),
        &Fixed(100),
    )
    .unwrap()
}

#[test]
fn fixed_deadline_future_issued_and_exact_expiry_are_checked() {
    let stored = issue();
    for now in [100, 101, 129] {
        assert!(stored.key("identity", "fingerprint", &Fixed(now)).is_ok());
    }
    for now in [99, 130, 131] {
        assert!(stored.key("identity", "fingerprint", &Fixed(now)).is_err());
    }
    let mut invalid = DerivedKeyStored::decode(&stored.encode().unwrap()).unwrap();
    invalid.expires_at_unix = 100;
    assert!(invalid.key("identity", "fingerprint", &Fixed(100)).is_err());
    invalid.expires_at_unix = u64::MAX;
    assert!(invalid.key("identity", "fingerprint", &Fixed(100)).is_err());
}
#[test]
fn checked_deadlines_have_no_arbitrary_ttl_cap() {
    let key = SecretBox::new(Box::new(vec![1; 32]));
    assert!(DerivedKeyStored::issue(
        "i".into(),
        "f".into(),
        &key,
        Duration::from_secs(1_000_000_000),
        &Fixed(100)
    )
    .is_ok());
    for (now, ttl) in [(u64::MAX, 1), (1, u64::MAX), (0, u64::MAX), (100, 0)] {
        assert!(DerivedKeyStored::issue(
            "i".into(),
            "f".into(),
            &key,
            Duration::from_secs(ttl),
            &Fixed(now)
        )
        .is_err());
    }
    assert!(issue().key("identity", "fingerprint", &Failed).is_err());
    assert!(DerivedKeyStored::issue(
        "i".into(),
        "f".into(),
        &key,
        Duration::from_secs(30),
        &Failed
    )
    .is_err());
}
#[test]
fn bounded_schema_rejects_legacy_unknown_and_oversized_payloads() {
    for bytes in [
        br#"{"header_fingerprint_hex":"f","key_b64":"abc"}"#.as_slice(),
        b"not-json",
        b"{}",
    ] {
        assert!(DerivedKeyStored::decode(bytes).is_err());
    }
    assert!(DerivedKeyStored::decode(&vec![b' '; 4097]).is_err());
    let mut stored = issue();
    stored.schema = 2;
    assert!(stored.key("identity", "fingerprint", &Fixed(100)).is_err());
    stored.identity = "x".repeat(4096);
    assert!(stored.encode().is_err());
}
#[test]
fn key_lengths_are_exact_and_debug_never_discloses_encoded_key() {
    for length in [0, 8, 31, 33, 1024] {
        assert!(DerivedKeyStored::issue(
            "i".into(),
            "f".into(),
            &SecretBox::new(Box::new(vec![1; length])),
            Duration::from_secs(30),
            &Fixed(100)
        )
        .is_err());
    }
    let stored = issue();
    let debug = format!("{stored:?}");
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains(&stored.key_b64));
}
