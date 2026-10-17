use crate::cryptography::primitives::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, validate_kdf_params, KeviHeader,
};
use crate::domain::VaultResult;
use crate::error::{CacheError, KeviError};
pub use crate::session_management::envelope::DerivedKeyStored;
use crate::session_management::envelope::{Clock, WallClock};
use crate::session_management::{cache_file, identity};
use crate::vault::ports::{AcquiredKey, DerivedKey, HeaderParams, KeyOrigin, KeyResolver};
use secrecy::SecretBox;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

pub type WarningSink = Arc<dyn Fn(CacheWarning) + Send + Sync>;
pub type PasswordSource = Arc<dyn Fn() -> VaultResult<String> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheWarning {
    InsecureFile,
    UnsupportedFile,
    Failure(CacheError),
}

impl std::fmt::Display for CacheWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureFile => formatter
                .write_str("Insecure file cache enabled: derived keys are not OS-protected"),
            Self::UnsupportedFile => formatter.write_str(
                "Insecure file cache is unsupported on macOS because directory ACL safety cannot be verified",
            ),
            Self::Failure(error) => write!(
                formatter,
                "Session cache {error}; continuing without caching"
            ),
        }
    }
}

pub fn default_warning_sink() -> WarningSink {
    Arc::new(|warning| eprintln!("⚠️ {warning}"))
}

pub fn unlock_ttl(override_seconds: Option<u64>) -> Duration {
    Duration::from_secs(
        override_seconds
            .or_else(|| {
                env::var("KEVI_UNLOCK_TTL")
                    .ok()
                    .and_then(|value| value.parse().ok())
            })
            .unwrap_or(900),
    )
}

pub fn insecure_fallback_enabled() -> bool {
    env::var("KEVI_INSECURE_CACHE_FALLBACK")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

pub fn dk_session_file_for(path: impl AsRef<Path>) -> VaultResult<PathBuf> {
    identity::file_for_identity(path.as_ref())
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
        cache_file::read(&self.path)
    }
    fn save_cached(&self, stored: &DerivedKeyStored, _ttl: Duration) -> VaultResult<()> {
        cache_file::write(&self.path, &stored.encode()?)
    }
    fn clear_cached(&self) -> VaultResult<()> {
        cache_file::clear(&self.path)
    }
}

pub fn native_store(account: &str) -> VaultResult<Arc<dyn DerivedKeySessionStore>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Arc::new(
            crate::session_management::keychain_store::MacOsKeychainSessionStore::for_account(
                account,
            ),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(
            crate::session_management::linux_keyring_store::LinuxKeyringSessionStore::for_account(
                account,
            ),
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = account;
        Err(CacheError::Unavailable.into())
    }
}

struct PathSessionStore {
    vault_path: PathBuf,
    insecure: bool,
}
impl PathSessionStore {
    fn current(&self) -> VaultResult<Arc<dyn DerivedKeySessionStore>> {
        if self.insecure {
            Ok(Arc::new(FileDerivedKeySessionStore::new(
                dk_session_file_for(&self.vault_path)?,
            )))
        } else {
            native_store(&identity::path_identity(&self.vault_path)?)
        }
    }
}
impl DerivedKeySessionStore for PathSessionStore {
    fn load_cached(&self) -> VaultResult<Option<DerivedKeyStored>> {
        self.current()?.load_cached()
    }
    fn save_cached(&self, stored: &DerivedKeyStored, ttl: Duration) -> VaultResult<()> {
        self.current()?.save_cached(stored, ttl)
    }
    fn clear_cached(&self) -> VaultResult<()> {
        self.current()?.clear_cached()
    }
}

pub fn session_store_for_vault(
    path: &Path,
) -> (Arc<dyn DerivedKeySessionStore>, Option<CacheWarning>) {
    let insecure = insecure_fallback_enabled();
    #[cfg(target_os = "macos")]
    let warning = insecure.then_some(CacheWarning::UnsupportedFile);
    #[cfg(not(target_os = "macos"))]
    let warning = insecure.then_some(CacheWarning::InsecureFile);
    (
        Arc::new(PathSessionStore {
            vault_path: path.into(),
            insecure,
        }),
        warning,
    )
}

pub trait PasswordResolver {
    fn resolve_password(&self) -> VaultResult<String> {
        if let Ok(password) = env::var("KEVI_PASSWORD") {
            return Ok(password);
        }
        inquire::Password::new("Master password")
            .without_confirmation()
            .prompt()
            .map_err(|error| KeviError::prompt(error.to_string()))
    }
}

pub struct CachedKeyResolver {
    store: Arc<dyn DerivedKeySessionStore>,
    vault_path: Option<PathBuf>,
    clock: Arc<dyn Clock>,
    ttl: Duration,
    sink: WarningSink,
    password: Option<String>,
    force_fresh_password: bool,
    password_source: Option<PasswordSource>,
}

impl CachedKeyResolver {
    pub fn new(path: PathBuf) -> Self {
        Self::for_path_with_sink(path, default_warning_sink())
    }
    pub fn for_path_with_sink(path: PathBuf, sink: WarningSink) -> Self {
        let (store, warning) = session_store_for_vault(&path);
        let resolver = Self {
            vault_path: Some(path),
            ..Self::with_adapters(store, Arc::new(WallClock), unlock_ttl(None), sink)
        };
        if let Some(warning) = warning {
            (resolver.sink)(warning);
        }
        resolver
    }

    pub fn with_adapters(
        store: Arc<dyn DerivedKeySessionStore>,
        clock: Arc<dyn Clock>,
        ttl: Duration,
        sink: WarningSink,
    ) -> Self {
        Self {
            store,
            clock,
            ttl,
            sink,
            vault_path: None,
            password: None,
            force_fresh_password: false,
            password_source: None,
        }
    }
    pub fn new_with_store(store: Arc<dyn DerivedKeySessionStore>) -> Self {
        Self::with_adapters(
            store,
            Arc::new(WallClock),
            unlock_ttl(None),
            default_warning_sink(),
        )
    }
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }
    pub fn with_fresh_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self.force_fresh_password = true;
        self
    }
    pub fn with_password_source(mut self, source: PasswordSource) -> Self {
        self.password_source = Some(source);
        self
    }
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
    pub fn with_warning_sink(mut self, sink: WarningSink) -> Self {
        self.sink = sink;
        self
    }

    fn identity(&self) -> VaultResult<String> {
        self.vault_path.as_ref().map_or_else(
            || Ok("injected-v1".to_string()),
            |path| identity::path_identity(path),
        )
    }
    fn warn(&self, error: KeviError) {
        let kind = match error {
            KeviError::Cache(kind) => kind,
            _ => CacheError::Unavailable,
        };
        (self.sink)(CacheWarning::Failure(kind));
    }
    pub fn persist(&self, header: &KeviHeader, key: &DerivedKey) -> VaultResult<()> {
        validate_kdf_params(header.m_cost_kib, header.t_cost, header.p_lanes)?;
        if self.ttl.is_zero() {
            return Ok(());
        }
        let stored = DerivedKeyStored::issue(
            self.identity()?,
            header_fingerprint_excluding_nonce(header),
            &key.key,
            self.ttl,
            self.clock.as_ref(),
        )?;
        self.store.save_cached(&stored, self.ttl)
    }
    fn fresh(&self, header: &KeviHeader) -> VaultResult<DerivedKey> {
        let password = match &self.password {
            Some(password) => password.clone(),
            None => match &self.password_source {
                Some(source) => source()?,
                None => self.resolve_password()?,
            },
        };
        derive(&password, header)
    }
}

impl PasswordResolver for CachedKeyResolver {}

fn derive(password: &str, header: &KeviHeader) -> VaultResult<DerivedKey> {
    let key = Zeroizing::new(derive_key_argon2id(
        password,
        &header.salt,
        header.m_cost_kib,
        header.t_cost,
        header.p_lanes,
    )?);
    Ok(DerivedKey {
        key: SecretBox::new(Box::new(key.to_vec())),
    })
}

impl KeyResolver for CachedKeyResolver {
    fn resolve_for_header(&self, header: &KeviHeader) -> VaultResult<DerivedKey> {
        self.acquire_for_header(header)
            .map(|acquired| acquired.derived)
    }
    fn acquire_for_header(&self, header: &KeviHeader) -> VaultResult<AcquiredKey> {
        validate_kdf_params(header.m_cost_kib, header.t_cost, header.p_lanes)?;
        if !self.force_fresh_password && !self.ttl.is_zero() {
            let result = (|| {
                let identity = self.identity()?;
                self.store
                    .load_cached()?
                    .map(|stored| {
                        stored.key(
                            &identity,
                            &header_fingerprint_excluding_nonce(header),
                            self.clock.as_ref(),
                        )
                    })
                    .transpose()
            })();
            match result {
                Ok(Some(key)) => {
                    return Ok(AcquiredKey {
                        derived: DerivedKey { key },
                        origin: KeyOrigin::Cached,
                    })
                }
                Ok(None) => {}
                Err(error) => self.warn(error),
            }
        }
        Ok(AcquiredKey {
            derived: self.fresh(header)?,
            origin: KeyOrigin::Fresh,
        })
    }
    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        self.fresh(&crate::session_management::lifecycle::header_for(
            params, salt,
        ))
    }
    fn publish(&self, header: &KeviHeader, acquired: &AcquiredKey) {
        if acquired.origin == KeyOrigin::Fresh {
            if let Err(error) = self.persist(header, &acquired.derived) {
                self.warn(error);
            }
        }
    }
}

#[derive(Default)]
pub struct BypassKeyResolver;
impl BypassKeyResolver {
    pub fn new() -> Self {
        Self
    }
}
impl PasswordResolver for BypassKeyResolver {}
impl KeyResolver for BypassKeyResolver {
    fn resolve_for_header(&self, header: &KeviHeader) -> VaultResult<DerivedKey> {
        derive(&self.resolve_password()?, header)
    }
    fn resolve_for_new_vault(
        &self,
        params: HeaderParams,
        salt: [u8; 16],
    ) -> VaultResult<DerivedKey> {
        self.resolve_for_header(&crate::session_management::lifecycle::header_for(
            params, salt,
        ))
    }
}
