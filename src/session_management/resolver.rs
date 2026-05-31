use crate::cryptography::primitives::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, KeviHeader, AEAD_AES256GCM,
    HEADER_VERSION, KDF_ARGON2ID, KEY_LEN, NONCE_LEN,
};
use crate::domain::VaultResult;
use crate::error::KeviError;
#[cfg(target_os = "macos")]
use crate::session_management::keychain_store::MacOsKeychainSessionStore;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::session_management::keyring_store::LinuxWindowsKeyringSessionStore;
use crate::session_management::session::{load, save};
use crate::vault::ports::{DerivedKey, HeaderParams, KeyResolver};
use base64::{engine::general_purpose, Engine as _};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

type WarningSink = Arc<dyn Fn(&str) + Send + Sync>;

fn default_warning_sink() -> WarningSink {
    Arc::new(|message| eprintln!("⚠️ {message}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedKeyStored {
    pub header_fingerprint_hex: String,
    pub key_b64: String,
}

pub fn dk_session_file_for<P: AsRef<Path>>(vault_path: P) -> PathBuf {
    vault_path.as_ref().with_extension("dksession")
}

pub fn save_derived_key_session(
    path: &std::path::Path,
    fingerprint: &str,
    key: &SecretBox<Vec<u8>>,
    ttl: Duration,
) -> VaultResult<()> {
    let stored = DerivedKeyStored {
        header_fingerprint_hex: fingerprint.to_string(),
        key_b64: general_purpose::STANDARD.encode(key.expose_secret()),
    };
    save(path, &stored, ttl)
}

pub fn clear_derived_key_cache_for_vault(vault_path: &std::path::Path) -> VaultResult<()> {
    let (store, _) = session_store_for_vault(vault_path);
    store.clear_cached()?;

    crate::session_management::session::clear(&vault_path.with_extension("dksession"))?;

    Ok(())
}

pub trait DerivedKeySessionStore: Send + Sync {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>>;
    fn save_cached(&self, stored: &DerivedKeyStored, ttl: Duration) -> VaultResult<()>;
    fn clear_cached(&self) -> VaultResult<()>;
}

pub struct FileDerivedKeySessionStore {
    path: PathBuf,
}

impl FileDerivedKeySessionStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl DerivedKeySessionStore for FileDerivedKeySessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        load::<DerivedKeyStored>(&self.path)
    }

    fn save_cached(&self, stored: &DerivedKeyStored, ttl: Duration) -> VaultResult<()> {
        save(&self.path, stored, ttl)
    }

    fn clear_cached(&self) -> VaultResult<()> {
        crate::session_management::session::clear(&self.path)
    }
}

struct DisabledSessionStore;

impl DerivedKeySessionStore for DisabledSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        Ok(None)
    }

    fn save_cached(&self, _stored: &DerivedKeyStored, _ttl: Duration) -> VaultResult<()> {
        Err(KeviError::vault("secure derived-key cache is unavailable"))
    }

    fn clear_cached(&self) -> VaultResult<()> {
        Ok(())
    }
}

pub trait PasswordResolver {
    fn resolve_password(&self) -> VaultResult<String> {
        if let Ok(pw) = env::var("KEVI_PASSWORD") {
            return Ok(pw);
        }

        inquire::Password::new("Master password")
            .without_confirmation()
            .prompt()
            .map_err(|e| KeviError::prompt(e.to_string()))
    }
}

#[cfg(target_os = "macos")]
struct MacOsHybridSessionStore {
    keychain: MacOsKeychainSessionStore,
}

#[cfg(target_os = "macos")]
impl DerivedKeySessionStore for MacOsHybridSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        self.keychain.load_cached()
    }

    fn save_cached(&self, stored: &DerivedKeyStored, ttl: Duration) -> VaultResult<()> {
        if self.keychain.save_cached(stored, ttl).is_ok() {
            return Ok(());
        }
        Err(KeviError::vault("secure derived-key cache is unavailable"))
    }

    fn clear_cached(&self) -> VaultResult<()> {
        self.keychain.clear_cached()
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
struct KeyringHybridSessionStore {
    keyring: LinuxWindowsKeyringSessionStore,
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
impl DerivedKeySessionStore for KeyringHybridSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        self.keyring.load_cached()
    }

    fn save_cached(&self, stored: &DerivedKeyStored, ttl: Duration) -> VaultResult<()> {
        if self.keyring.save_cached(stored, ttl).is_ok() {
            return Ok(());
        }
        Err(KeviError::vault("secure derived-key cache is unavailable"))
    }

    fn clear_cached(&self) -> VaultResult<()> {
        self.keyring.clear_cached()
    }
}

fn insecure_fallback_enabled() -> bool {
    env::var("KEVI_INSECURE_CACHE_FALLBACK")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn implicit_test_fallback_enabled() -> bool {
    let running_under_test_harness = env::var("RUST_TEST_THREADS").is_ok();
    let has_noninteractive_password = env::var("KEVI_PASSWORD").is_ok();
    let prefer_secure_cache = env::var("KEVI_PREFER_SECURE_CACHE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    running_under_test_harness && has_noninteractive_password && !prefer_secure_cache
}

pub fn session_store_for_vault(
    vault_path: &Path,
) -> (Arc<dyn DerivedKeySessionStore>, Option<String>) {
    if insecure_fallback_enabled() || implicit_test_fallback_enabled() {
        return (
            Arc::new(FileDerivedKeySessionStore::new(
                vault_path.with_extension("dksession"),
            )),
            None,
        );
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(keychain_store) = MacOsKeychainSessionStore::new(vault_path) {
            return (
                Arc::new(MacOsHybridSessionStore {
                    keychain: keychain_store,
                }),
                None,
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        if let Ok(keyring_store) = LinuxWindowsKeyringSessionStore::new(vault_path) {
            return (
                Arc::new(KeyringHybridSessionStore {
                    keyring: keyring_store,
                }),
                None,
            );
        }
    }

    (
        Arc::new(DisabledSessionStore),
        Some(
            "Derived-key cache is disabled because secure OS storage is unavailable. Set KEVI_INSECURE_CACHE_FALLBACK=1 to opt into file-based caching."
                .to_string(),
        ),
    )
}

pub struct CachedKeyResolver {
    session_store: Arc<dyn DerivedKeySessionStore>,
    warning: Option<String>,
    warning_emitted: AtomicBool,
    warning_sink: WarningSink,
}

pub struct CachedKeyResolverBuilder {
    session_store: Arc<dyn DerivedKeySessionStore>,
    warning: Option<String>,
    warning_sink: WarningSink,
}

impl CachedKeyResolverBuilder {
    pub fn from_vault_path(vault_path: &Path) -> Self {
        let (session_store, warning) = session_store_for_vault(vault_path);
        Self {
            session_store,
            warning,
            warning_sink: default_warning_sink(),
        }
    }

    pub fn with_store(session_store: Arc<dyn DerivedKeySessionStore>) -> Self {
        Self {
            session_store,
            warning: None,
            warning_sink: default_warning_sink(),
        }
    }

    pub fn warning(mut self, warning: Option<String>) -> Self {
        self.warning = warning;
        self
    }

    pub fn warning_sink(mut self, warning_sink: WarningSink) -> Self {
        self.warning_sink = warning_sink;
        self
    }

    pub fn build(self) -> CachedKeyResolver {
        CachedKeyResolver {
            session_store: self.session_store,
            warning: self.warning,
            warning_emitted: AtomicBool::new(false),
            warning_sink: self.warning_sink,
        }
    }
}

impl PasswordResolver for CachedKeyResolver {}

impl CachedKeyResolver {
    pub fn new(vault_path: PathBuf) -> Self {
        CachedKeyResolverBuilder::from_vault_path(vault_path.as_path()).build()
    }

    pub fn new_with_store(session_store: Arc<dyn DerivedKeySessionStore>) -> Self {
        CachedKeyResolverBuilder::with_store(session_store).build()
    }

    pub fn new_with_store_and_warning(
        session_store: Arc<dyn DerivedKeySessionStore>,
        warning: Option<String>,
        warning_sink: WarningSink,
    ) -> Self {
        CachedKeyResolverBuilder::with_store(session_store)
            .warning(warning)
            .warning_sink(warning_sink)
            .build()
    }

    fn warn_if_needed(&self) {
        if let Some(message) = &self.warning {
            if !self.warning_emitted.swap(true, Ordering::Relaxed) {
                (self.warning_sink)(message);
            }
        }
    }
}

impl KeyResolver for CachedKeyResolver {
    fn resolve_for_header(&self, hdr: &KeviHeader) -> VaultResult<DerivedKey> {
        let fp = header_fingerprint_excluding_nonce(hdr);
        let cached = match self.session_store.load_cached() {
            Ok(value) => value,
            Err(_) => {
                self.warn_if_needed();
                None
            }
        };

        if let Some(sess) = cached {
            if sess.header_fingerprint_hex == fp {
                if let Ok(vec) = general_purpose::STANDARD.decode(&sess.key_b64) {
                    let mut arr = [0u8; KEY_LEN];
                    if vec.len() >= KEY_LEN {
                        arr.copy_from_slice(&vec[..KEY_LEN]);
                        return Ok(DerivedKey {
                            key: SecretBox::new(Box::new(arr.to_vec())),
                        });
                    }
                }
            }
        }

        let pw = self.resolve_password()?;
        let key_arr = derive_key_argon2id(&pw, &hdr.salt, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));
        let ttl_secs = env::var("KEVI_UNLOCK_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);

        let stored = DerivedKeyStored {
            header_fingerprint_hex: fp,
            key_b64: general_purpose::STANDARD.encode(key_vec.expose_secret()),
        };
        if self
            .session_store
            .save_cached(&stored, Duration::from_secs(ttl_secs))
            .is_err()
        {
            self.warn_if_needed();
        }

        Ok(DerivedKey { key: key_vec })
    }

    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        let pw = self.resolve_password()?;
        let key_arr =
            derive_key_argon2id(&pw, &salt, params.m_cost_kib, params.t_cost, params.p_lanes)?;
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));

        let hdr = KeviHeader {
            version: HEADER_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_AES256GCM,
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_lanes: params.p_lanes,
            salt,
            nonce: [0u8; NONCE_LEN],
        };
        let fp = header_fingerprint_excluding_nonce(&hdr);
        let ttl_secs = env::var("KEVI_UNLOCK_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(900);

        let stored = DerivedKeyStored {
            header_fingerprint_hex: fp,
            key_b64: general_purpose::STANDARD.encode(key_vec.expose_secret()),
        };
        if self
            .session_store
            .save_cached(&stored, Duration::from_secs(ttl_secs))
            .is_err()
        {
            self.warn_if_needed();
        }

        Ok(DerivedKey { key: key_vec })
    }
}

pub struct BypassKeyResolver;

impl PasswordResolver for BypassKeyResolver {}

impl Default for BypassKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BypassKeyResolver {
    pub fn new() -> Self {
        Self
    }
}

impl KeyResolver for BypassKeyResolver {
    fn resolve_for_header(&self, hdr: &KeviHeader) -> VaultResult<DerivedKey> {
        let pw = self.resolve_password()?;
        let key_arr = derive_key_argon2id(&pw, &hdr.salt, hdr.m_cost_kib, hdr.t_cost, hdr.p_lanes)?;
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(key_arr.to_vec())),
        })
    }

    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        let pw = self.resolve_password()?;
        let key_arr =
            derive_key_argon2id(&pw, &salt, params.m_cost_kib, params.t_cost, params.p_lanes)?;
        Ok(DerivedKey {
            key: SecretBox::new(Box::new(key_arr.to_vec())),
        })
    }
}
