use kevi::api::*;
use secrecy::{ExposeSecret, SecretBox};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
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
struct Store {
    value: Mutex<Option<DerivedKeyStored>>,
    calls: Mutex<(usize, usize)>,
    fail: Option<CacheError>,
}
fn copy_stored(value: &DerivedKeyStored) -> DerivedKeyStored {
    DerivedKeyStored::decode(&value.encode().unwrap()).unwrap()
}
impl DerivedKeySessionStore for Store {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        self.calls.lock().unwrap().0 += 1;
        if let Some(error) = self.fail {
            return Err(error.into());
        }
        Ok(self.value.lock().unwrap().as_ref().map(copy_stored))
    }
    fn save_cached(&self, stored: &DerivedKeyStored, _: Duration) -> VaultResult<()> {
        self.calls.lock().unwrap().1 += 1;
        if let Some(error) = self.fail {
            return Err(error.into());
        }
        *self.value.lock().unwrap() = Some(copy_stored(stored));
        Ok(())
    }
    fn clear_cached(&self) -> VaultResult<()> {
        *self.value.lock().unwrap() = None;
        Ok(())
    }
}
fn header() -> KeviHeader {
    KeviHeader {
        version: HEADER_VERSION,
        kdf_id: KDF_ARGON2ID,
        aead_id: AEAD_AES256GCM,
        m_cost_kib: 32,
        t_cost: 1,
        p_lanes: 1,
        salt: [7; 16],
        nonce: [0; 12],
    }
}
fn resolver(store: Arc<Store>, clock: Arc<TestClock>, ttl: u64) -> CachedKeyResolver {
    CachedKeyResolver::with_adapters(store, clock, Duration::from_secs(ttl), Arc::new(|_| {}))
        .with_password("dummy-test-password".into())
}

#[test]
fn invalid_header_policy_is_rejected_before_cache_lookup_or_key_publication() {
    let store = Arc::new(Store::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let resolver = resolver(store.clone(), clock, 30);
    let mut invalid = header();
    invalid.m_cost_kib = MAX_KDF_MEMORY_KIB + 1;
    assert!(matches!(
        resolver.acquire_for_header(&invalid),
        Err(KeviError::KdfPolicy(_))
    ));
    assert_eq!(*store.calls.lock().unwrap(), (0, 0));
    assert!(store.value.lock().unwrap().is_none());
}

#[test]
fn acquisition_does_not_publish_and_hits_never_refresh_deadline() {
    let store = Arc::new(Store::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let resolver = resolver(store.clone(), clock.clone(), 30);
    let first = resolver.acquire_for_header(&header()).unwrap();
    assert_eq!(first.origin, KeyOrigin::Fresh);
    assert_eq!(*store.calls.lock().unwrap(), (1, 0));
    resolver.publish(&header(), &first);
    assert_eq!(
        store
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .expires_at_unix,
        130
    );
    clock.0.store(120, Ordering::SeqCst);
    let cached = resolver.acquire_for_header(&header()).unwrap();
    assert_eq!(cached.origin, KeyOrigin::Cached);
    assert_eq!(
        first.derived.key.expose_secret(),
        cached.derived.key.expose_secret()
    );
    resolver.publish(&header(), &cached);
    assert_eq!(*store.calls.lock().unwrap(), (2, 1));
    assert_eq!(
        store
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .expires_at_unix,
        130
    );
    clock.0.store(130, Ordering::SeqCst);
    assert_eq!(
        resolver.acquire_for_header(&header()).unwrap().origin,
        KeyOrigin::Fresh
    );
    assert_eq!(*store.calls.lock().unwrap(), (3, 1));
}

#[test]
fn ttl_zero_has_no_reads_or_writes_and_leaves_prior_session() {
    let store = Arc::new(Store::default());
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let old = resolver(store.clone(), clock.clone(), 60);
    old.persist(
        &header(),
        &DerivedKey {
            key: SecretBox::new(Box::new(vec![9; 32])),
        },
    )
    .unwrap();
    let bytes = store
        .value
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .encode()
        .unwrap();
    let bypass = resolver(store.clone(), clock, 0);
    let acquired = bypass.acquire_for_header(&header()).unwrap();
    bypass.publish(&header(), &acquired);
    assert_eq!(*store.calls.lock().unwrap(), (0, 1));
    assert_eq!(
        bytes,
        store
            .value
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .encode()
            .unwrap()
    );
}

#[test]
fn faults_are_typed_visible_and_explicit_persistence_fails() {
    for kind in [
        CacheError::Denied,
        CacheError::Unavailable,
        CacheError::Malformed,
        CacheError::Persist,
    ] {
        let store = Arc::new(Store {
            fail: Some(kind),
            ..Store::default()
        });
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let sink = warnings.clone();
        let resolver = resolver(store, Arc::new(TestClock(AtomicU64::new(100))), 60)
            .with_warning_sink(Arc::new(move |warning| sink.lock().unwrap().push(warning)));
        let acquired = resolver.acquire_for_header(&header()).unwrap();
        resolver.publish(&header(), &acquired);
        assert_eq!(
            *warnings.lock().unwrap(),
            vec![CacheWarning::Failure(kind); 2]
        );
        assert!(
            matches!(resolver.persist(&header(), &acquired.derived), Err(KeviError::Cache(error)) if error == kind)
        );
    }
}

#[test]
fn mismatched_and_malformed_keys_require_fresh_auth_without_mutation() {
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let valid = DerivedKeyStored::issue(
        "injected-v1".into(),
        header_fingerprint_excluding_nonce(&header()),
        &SecretBox::new(Box::new(vec![1; 32])),
        Duration::from_secs(60),
        clock.as_ref(),
    )
    .unwrap();
    for mutation in 0..5 {
        let mut stored = copy_stored(&valid);
        match mutation {
            0 => stored.header_fingerprint_hex = "wrong".into(),
            1 => stored.identity = "wrong".into(),
            2 => stored.key_b64 = "%%%".into(),
            3 => {
                stored.key_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1; 8])
            }
            _ => {
                stored.key_b64 =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1; 33])
            }
        }
        let before = stored.encode().unwrap();
        let store = Arc::new(Store {
            value: Mutex::new(Some(stored)),
            ..Store::default()
        });
        let resolver = resolver(store.clone(), clock.clone(), 60);
        assert_eq!(
            resolver.acquire_for_header(&header()).unwrap().origin,
            KeyOrigin::Fresh
        );
        assert_eq!(
            before,
            store
                .value
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .encode()
                .unwrap()
        );
        assert_eq!(store.calls.lock().unwrap().1, 0);
    }
}

#[test]
#[serial_test::serial]
fn selection_requires_explicit_opt_in_and_ttl_precedence_is_compatible() {
    std::env::set_var("KEVI_PASSWORD", "dummy");
    std::env::set_var("RUST_TEST_THREADS", "1");
    std::env::set_var("KEVI_PREFER_SECURE_CACHE", "0");
    std::env::remove_var("KEVI_INSECURE_CACHE_FALLBACK");
    assert!(!insecure_fallback_enabled());
    for value in ["", "0", "yes", "TRUE "] {
        std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", value);
        assert!(!insecure_fallback_enabled());
        let (_, warning) = session_store_for_vault(std::path::Path::new("dummy-vault"));
        assert_eq!(warning, None); // Construction is lazy: no native access.
    }
    for value in ["1", "true", "TRUE", "TrUe"] {
        std::env::set_var("KEVI_PREFER_SECURE_CACHE", "1");
        std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", value);
        assert!(insecure_fallback_enabled());
        #[cfg(target_os = "macos")]
        assert_eq!(
            session_store_for_vault(std::path::Path::new("dummy-vault")).1,
            Some(CacheWarning::UnsupportedFile)
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            session_store_for_vault(std::path::Path::new("dummy-vault")).1,
            Some(CacheWarning::InsecureFile)
        );
    }
    std::env::set_var("KEVI_UNLOCK_TTL", "invalid");
    assert_eq!(unlock_ttl(None).as_secs(), 900);
    std::env::set_var("KEVI_UNLOCK_TTL", "12");
    assert_eq!(unlock_ttl(None).as_secs(), 12);
    assert_eq!(unlock_ttl(Some(0)).as_secs(), 0);
    assert_eq!(unlock_ttl(Some(u64::MAX)).as_secs(), u64::MAX);
    std::env::remove_var("KEVI_UNLOCK_TTL");
    std::env::remove_var("KEVI_PASSWORD");
    std::env::remove_var("RUST_TEST_THREADS");
    std::env::remove_var("KEVI_PREFER_SECURE_CACHE");
    std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", "1");
}

#[test]
fn cache_warning_text_explains_each_storage_outcome() {
    assert!(CacheWarning::InsecureFile
        .to_string()
        .contains("not OS-protected"));
    assert!(CacheWarning::UnsupportedFile
        .to_string()
        .contains("unsupported on macOS"));
    assert!(CacheWarning::Failure(CacheError::Denied)
        .to_string()
        .contains("continuing without caching"));
}

#[test]
#[serial_test::serial]
fn selected_file_store_clear_is_idempotent_for_a_missing_cache() {
    let previous = std::env::var_os("KEVI_INSECURE_CACHE_FALLBACK");
    std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", "1");
    let directory = tempfile::tempdir().unwrap();
    let (store, _) = session_store_for_vault(&directory.path().join("vault.ron"));
    store.clear_cached().unwrap();
    store.clear_cached().unwrap();
    match previous {
        Some(value) => std::env::set_var("KEVI_INSECURE_CACHE_FALLBACK", value),
        None => std::env::remove_var("KEVI_INSECURE_CACHE_FALLBACK"),
    }
}

#[test]
fn password_source_and_fresh_password_bypass_cache_reads() {
    let source_calls = Arc::new(AtomicUsize::new(0));
    let calls = source_calls.clone();
    let source = Arc::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok("source-password".to_string())
    });
    let store = Arc::new(Store::default());
    let source_resolver = CachedKeyResolver::new_with_store(store.clone())
        .with_ttl(Duration::from_secs(60))
        .with_password_source(source);
    let fresh = source_resolver.acquire_for_header(&header()).unwrap();
    assert_eq!(fresh.origin, KeyOrigin::Fresh);
    assert_eq!(source_calls.load(Ordering::SeqCst), 1);
    assert_eq!(*store.calls.lock().unwrap(), (1, 0));

    let cached = DerivedKeyStored::issue(
        "injected-v1".into(),
        header_fingerprint_excluding_nonce(&header()),
        &SecretBox::new(Box::new(vec![3; 32])),
        Duration::from_secs(60),
        Arc::new(TestClock(AtomicU64::new(100))).as_ref(),
    )
    .unwrap();
    let store = Arc::new(Store {
        value: Mutex::new(Some(cached)),
        ..Store::default()
    });
    let fresh_resolver = resolver(store.clone(), Arc::new(TestClock(AtomicU64::new(100))), 60)
        .with_fresh_password("fresh-password".into());
    assert_eq!(
        fresh_resolver.acquire_for_header(&header()).unwrap().origin,
        KeyOrigin::Fresh
    );
    assert_eq!(*store.calls.lock().unwrap(), (0, 0));
}

#[test]
#[serial_test::serial]
fn bypass_resolver_uses_environment_password_without_session_io() {
    let previous = std::env::var_os("KEVI_PASSWORD");
    std::env::set_var("KEVI_PASSWORD", "environment-password");
    let bypass = BypassKeyResolver::new();
    let actual = bypass.resolve_for_header(&header()).unwrap();
    let expected = CachedKeyResolver::new_with_store(Arc::new(Store::default()))
        .with_ttl(Duration::ZERO)
        .with_password("environment-password".into())
        .resolve_for_header(&header())
        .unwrap();
    assert_eq!(actual.key.expose_secret(), expected.key.expose_secret());
    match previous {
        Some(value) => std::env::set_var("KEVI_PASSWORD", value),
        None => std::env::remove_var("KEVI_PASSWORD"),
    }
}
