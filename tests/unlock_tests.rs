use kevi::api::*;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now(&self) -> VaultResult<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
#[derive(Default)]
struct Cache {
    value: Mutex<Option<DerivedKeyStored>>,
    calls: Mutex<(usize, usize)>,
    fail: bool,
}
fn copy_stored(value: &DerivedKeyStored) -> DerivedKeyStored {
    DerivedKeyStored::decode(&value.encode().unwrap()).unwrap()
}
impl DerivedKeySessionStore for Cache {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        self.calls.lock().unwrap().0 += 1;
        Ok(self.value.lock().unwrap().as_ref().map(copy_stored))
    }
    fn save_cached(&self, value: &DerivedKeyStored, _: Duration) -> VaultResult<()> {
        self.calls.lock().unwrap().1 += 1;
        if self.fail {
            return Err(CacheError::Persist.into());
        }
        *self.value.lock().unwrap() = Some(copy_stored(value));
        Ok(())
    }
    fn clear_cached(&self) -> VaultResult<()> {
        Ok(())
    }
}
#[derive(Default)]
struct Bytes {
    value: Mutex<Vec<u8>>,
    fail: bool,
    writes: Mutex<usize>,
}
impl ByteStore for Bytes {
    fn read(&self) -> VaultResult<Vec<u8>> {
        Ok(self.value.lock().unwrap().clone())
    }
    fn write(&self, value: &[u8]) -> VaultResult<()> {
        *self.writes.lock().unwrap() += 1;
        if self.fail {
            return Err(KeviError::io("injected write failure"));
        }
        *self.value.lock().unwrap() = value.to_vec();
        Ok(())
    }
}
fn resolver(
    cache: Arc<Cache>,
    clock: Arc<TestClock>,
    password: &str,
    ttl: u64,
) -> CachedKeyResolver {
    CachedKeyResolver::with_adapters(cache, clock, Duration::from_secs(ttl), Arc::new(|_| {}))
        .with_password(password.into())
}
fn vault_bytes() -> Vec<u8> {
    encrypt_vault(
        &RonCodec.encode(&VaultData::default()).unwrap(),
        "dummy-password",
    )
    .unwrap()
}

#[test]
fn load_authenticates_and_decodes_before_publication_then_reuses_session() {
    let cache = Arc::new(Cache::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let bytes = Arc::new(Bytes {
        value: Mutex::new(vault_bytes()),
        ..Bytes::default()
    });
    let service = VaultService::new(
        bytes,
        RonCodec,
        resolver(cache.clone(), clock.clone(), "dummy-password", 60),
    );
    service.load().unwrap();
    assert_eq!(cache.calls.lock().unwrap().1, 1);
    clock.0.store(120, Ordering::SeqCst);
    service.load().unwrap();
    assert_eq!(*cache.calls.lock().unwrap(), (2, 1));
    assert_eq!(
        cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .expires_at_unix,
        160
    );
}

#[test]
fn wrong_password_load_and_save_cannot_publish_or_replace_original() {
    let original = vault_bytes();
    for save in [false, true] {
        let cache = Arc::new(Cache::default());
        let bytes = Arc::new(Bytes {
            value: Mutex::new(original.clone()),
            ..Bytes::default()
        });
        let service = VaultService::new(
            bytes.clone(),
            RonCodec,
            resolver(
                cache.clone(),
                Arc::new(TestClock(AtomicU64::new(100))),
                "wrong-password",
                60,
            ),
        );
        if save {
            assert!(service.save(&VaultData::default()).is_err());
        } else {
            assert!(service.load().is_err());
        }
        assert_eq!(cache.calls.lock().unwrap().1, 0);
        assert_eq!(*bytes.writes.lock().unwrap(), 0);
        assert_eq!(*bytes.value.lock().unwrap(), original);
    }
}

#[test]
fn explicit_init_password_reauthenticates_existing_vault_instead_of_using_session_cache() {
    let original = vault_bytes();
    for seed_cache in [false, true] {
        let cache = Arc::new(Cache::default());
        let clock = Arc::new(TestClock(AtomicU64::new(100)));
        if seed_cache {
            unlock_bytes(
                &resolver(cache.clone(), clock.clone(), "dummy-password", 60),
                &original,
            )
            .unwrap();
        }
        let prior_session = cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .map(|session| session.encode().unwrap());
        let bytes = Arc::new(Bytes {
            value: Mutex::new(original.clone()),
            ..Bytes::default()
        });
        let service = VaultService::new(
            bytes.clone(),
            RonCodec,
            CachedKeyResolver::with_adapters(
                cache.clone(),
                clock.clone(),
                Duration::from_secs(60),
                Arc::new(|_| {}),
            )
            .with_fresh_password("wrong-password".into()),
        );

        assert!(service.save(&VaultData::default()).is_err());
        assert_eq!(*bytes.writes.lock().unwrap(), 0);
        assert_eq!(*bytes.value.lock().unwrap(), original);
        assert_eq!(
            cache
                .value
                .lock()
                .unwrap()
                .as_ref()
                .map(|session| session.encode().unwrap()),
            prior_session
        );

        let service = VaultService::new(
            bytes.clone(),
            RonCodec,
            CachedKeyResolver::with_adapters(
                cache.clone(),
                clock,
                Duration::from_secs(60),
                Arc::new(|_| {}),
            )
            .with_fresh_password("dummy-password".into()),
        );
        service.save(&VaultData::default()).unwrap();
        assert_eq!(*bytes.writes.lock().unwrap(), 1);
        assert!(service.load().is_ok());
    }
}

#[test]
fn decode_and_write_failures_do_not_publish() {
    let invalid = encrypt_vault(b"not valid vault data", "dummy-password").unwrap();
    for save in [false, true] {
        let cache = Arc::new(Cache::default());
        let bytes = Arc::new(Bytes {
            value: Mutex::new(invalid.clone()),
            ..Bytes::default()
        });
        let service = VaultService::new(
            bytes.clone(),
            RonCodec,
            resolver(
                cache.clone(),
                Arc::new(TestClock(AtomicU64::new(100))),
                "dummy-password",
                60,
            ),
        );
        if save {
            assert!(service.save(&VaultData::default()).is_err());
        } else {
            assert!(service.load().is_err());
        }
        assert_eq!(cache.calls.lock().unwrap().1, 0);
        assert_eq!(*bytes.writes.lock().unwrap(), 0);
    }
    for original in [Vec::new(), vault_bytes()] {
        let cache = Arc::new(Cache::default());
        let bytes = Arc::new(Bytes {
            value: Mutex::new(original.clone()),
            fail: true,
            ..Bytes::default()
        });
        let service = VaultService::new(
            bytes.clone(),
            RonCodec,
            resolver(
                cache.clone(),
                Arc::new(TestClock(AtomicU64::new(100))),
                "dummy-password",
                60,
            ),
        );
        assert!(service.save(&VaultData::default()).is_err());
        assert_eq!(cache.calls.lock().unwrap().1, 0);
        assert_eq!(*bytes.value.lock().unwrap(), original);
    }
}

#[test]
fn ordinary_authenticated_operations_succeed_uncached_on_persistence_failure() {
    for original in [Vec::new(), vault_bytes()] {
        let cache = Arc::new(Cache {
            fail: true,
            ..Cache::default()
        });
        let bytes = Arc::new(Bytes {
            value: Mutex::new(original),
            ..Bytes::default()
        });
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let sink = warnings.clone();
        let resolver = resolver(
            cache,
            Arc::new(TestClock(AtomicU64::new(100))),
            "dummy-password",
            60,
        )
        .with_warning_sink(Arc::new(move |warning| sink.lock().unwrap().push(warning)));
        let service = VaultService::new(bytes.clone(), RonCodec, resolver);
        service.save(&VaultData::default()).unwrap();
        assert!(!bytes.value.lock().unwrap().is_empty());
        assert_eq!(
            *warnings.lock().unwrap(),
            vec![CacheWarning::Failure(CacheError::Persist)]
        );
    }
}

#[test]
fn explicit_unlock_always_authenticates_and_does_not_poison_prior_cache() {
    let bytes = vault_bytes();
    let cache = Arc::new(Cache::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    unlock_bytes(
        &resolver(cache.clone(), clock.clone(), "dummy-password", 60),
        &bytes,
    )
    .unwrap();
    let original = cache
        .value
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .encode()
        .unwrap();
    assert!(unlock_bytes(&resolver(cache.clone(), clock.clone(), "wrong", 60), &bytes).is_err());
    assert_eq!(
        cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .encode()
            .unwrap(),
        original
    );
    assert_eq!(*cache.calls.lock().unwrap(), (0, 1));
    clock.0.store(120, Ordering::SeqCst);
    unlock_bytes(
        &resolver(cache.clone(), clock.clone(), "dummy-password", 0),
        &bytes,
    )
    .unwrap();
    assert_eq!(
        cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .encode()
            .unwrap(),
        original
    );
    assert_eq!(*cache.calls.lock().unwrap(), (0, 1));
    unlock_bytes(
        &resolver(cache.clone(), clock, "dummy-password", 60),
        &bytes,
    )
    .unwrap();
    assert_eq!(
        cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .expires_at_unix,
        180
    );
    let failed = Arc::new(Cache {
        fail: true,
        ..Cache::default()
    });
    assert!(matches!(
        unlock_bytes(
            &resolver(
                failed,
                Arc::new(TestClock(AtomicU64::new(100))),
                "dummy-password",
                60
            ),
            &bytes
        ),
        Err(KeviError::Cache(CacheError::Persist))
    ));
}

#[test]
fn service_rejects_short_and_oversized_injected_keys_without_panicking() {
    struct InvalidResolver(usize);
    impl KeyResolver for InvalidResolver {
        fn resolve_for_header(&self, _: &KeviHeader) -> VaultResult<DerivedKey> {
            Ok(DerivedKey {
                key: secrecy::SecretBox::new(Box::new(vec![1; self.0])),
            })
        }
        fn resolve_for_new_vault(&self, _: HeaderParams, _: [u8; 16]) -> VaultResult<DerivedKey> {
            self.resolve_for_header(&KeviHeader {
                version: 1,
                kdf_id: KDF_ARGON2ID,
                aead_id: AEAD_AES256GCM,
                m_cost_kib: 32,
                t_cost: 1,
                p_lanes: 1,
                salt: [0; 16],
                nonce: [0; 12],
            })
        }
    }
    let original = vault_bytes();
    for length in [0, 31, 33] {
        for bytes in [Vec::new(), original.clone()] {
            let store = Arc::new(Bytes {
                value: Mutex::new(bytes.clone()),
                ..Bytes::default()
            });
            let service = VaultService::new(store.clone(), RonCodec, InvalidResolver(length));
            assert!(service.save(&VaultData::default()).is_err());
            if !bytes.is_empty() {
                assert!(service.load().is_err());
            }
            assert_eq!(*store.writes.lock().unwrap(), 0);
        }
    }
}

#[test]
fn failed_save_with_fresh_key_leaves_expired_prior_session_unchanged() {
    let original = vault_bytes();
    let cache = Arc::new(Cache::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    unlock_bytes(
        &resolver(cache.clone(), clock.clone(), "dummy-password", 60),
        &original,
    )
    .unwrap();
    let previous = cache
        .value
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .encode()
        .unwrap();
    clock.0.store(160, Ordering::SeqCst);
    let store = Arc::new(Bytes {
        value: Mutex::new(original.clone()),
        fail: true,
        ..Bytes::default()
    });
    let service = VaultService::new(
        store.clone(),
        RonCodec,
        resolver(cache.clone(), clock, "dummy-password", 60),
    );
    assert!(service.save(&VaultData::default()).is_err());
    assert_eq!(
        cache
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .encode()
            .unwrap(),
        previous
    );
    assert_eq!(cache.calls.lock().unwrap().1, 1);
    assert_eq!(*store.value.lock().unwrap(), original);
}
