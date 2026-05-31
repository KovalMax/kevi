use crate::config::app_config::{Config, Defaults};
use crate::filesystem::store::FileByteStore;
use crate::session_management::resolver::{BypassKeyResolver, CachedKeyResolver};
use crate::vault::codec::RonCodec;
use crate::vault::ports::{ByteStore, KeyResolver, VaultCodec};
use crate::vault::service::VaultService;
use std::path::PathBuf;
use std::sync::Arc;

pub fn create_vault_service(config: &Config) -> Arc<VaultService> {
    create_vault_service_with_mode(config, false)
}

pub fn create_vault_service_bypass_cache(config: &Config) -> Arc<VaultService> {
    create_vault_service_with_mode(config, true)
}

fn create_vault_service_with_mode(config: &Config, bypass_cache: bool) -> Arc<VaultService> {
    let backups = config.backups.unwrap_or(Defaults::BACKUPS);
    let vault_path: PathBuf = config.vault_path.clone().into();
    let store: Arc<dyn ByteStore> =
        Arc::new(FileByteStore::new_with_backups(vault_path.clone(), backups));
    let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
    let key_resolver: Arc<dyn KeyResolver> = if bypass_cache {
        Arc::new(BypassKeyResolver::new())
    } else {
        Arc::new(CachedKeyResolver::new(vault_path))
    };
    Arc::new(VaultService::new(store, codec, key_resolver))
}
