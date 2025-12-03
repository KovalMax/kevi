#[test]
fn test_lock_and_unlock_ok_or_best_effort() {
    #[cfg(all(test, unix, feature = "memlock"))]
    {
        use kevi::core::memlock::{lock_slice, unlock_slice};
        let mut buf = [0u8; 64];
        // On some systems mlock may still be denied; treat failure as best‑effort
        let lock = lock_slice(&mut buf);

        let unlock = unlock_slice(&mut buf);

        assert!(lock.is_ok());
        assert!(unlock.is_ok());
    }
}