use crate::domain::VaultResult;
use crate::error::{CacheError, KeviError};
use crate::session_management::{cache_file, identity, resolver::native_store};
use std::collections::BTreeSet;
use std::path::Path;

pub trait CacheCleanup: Send + Sync {
    fn native(&self, account: &str) -> VaultResult<()>;
    fn file(&self, path: &Path) -> VaultResult<()>;
}

pub struct SystemCacheCleanup;
impl CacheCleanup for SystemCacheCleanup {
    fn native(&self, account: &str) -> VaultResult<()> {
        native_store(account)?.clear_cached()
    }
    fn file(&self, path: &Path) -> VaultResult<()> {
        cache_file::clear(path)
    }
}

pub fn clear_with(path: &Path, cleanup: &dyn CacheCleanup) -> VaultResult<()> {
    let mut failures = Vec::new();
    let mut record = |result: VaultResult<()>| {
        if let Err(error) = result {
            let kind = match error {
                KeviError::Cache(kind) => kind,
                _ => CacheError::Delete,
            };
            if kind != CacheError::Missing {
                failures.push(kind);
            }
        }
    };
    let mut spellings = BTreeSet::from([path.to_path_buf()]);
    match std::path::absolute(path) {
        Ok(absolute) => {
            spellings.insert(absolute);
        }
        Err(_) => record(Err(CacheError::Identity.into())),
    }
    match identity::canonical_vault_path(path) {
        Ok(canonical) => {
            spellings.insert(canonical);
        }
        Err(error) => record(Err(error)),
    }
    let protected_spellings = spellings
        .iter()
        .map(|spelling| spelling.as_path())
        .collect::<Vec<_>>();
    match identity::path_identity(path) {
        Ok(identity) => record(cleanup.native(&identity)),
        Err(error) => record(Err(error)),
    }
    match identity::file_for_identity(path) {
        Ok(file) => {
            let safety = crate::session_management::cleanup_file::check_file_directory(&file);
            record(
                safety
                    .and_then(|()| {
                        crate::session_management::cleanup_file::check_target(
                            &protected_spellings,
                            &file,
                        )
                    })
                    .and_then(|()| cleanup.file(&file)),
            );
        }
        Err(error) => record(Err(error)),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(KeviError::CacheCleanup(failures))
    }
}

pub fn clear_derived_key_cache_for_vault(path: &Path) -> VaultResult<()> {
    clear_with(path, &SystemCacheCleanup)
}

#[cfg(test)]
mod tests {
    use super::{CacheCleanup, SystemCacheCleanup};
    use tempfile::tempdir;

    #[test]
    fn system_file_cleanup_is_idempotent_for_a_missing_session() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing-session");
        SystemCacheCleanup.file(&missing).unwrap();
        SystemCacheCleanup.file(&missing).unwrap();
    }
}
