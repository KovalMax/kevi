use crate::domain::VaultResult;
use crate::error::CacheError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub fn canonical_vault_path(path: &Path) -> VaultResult<PathBuf> {
    let absolute = std::path::absolute(path).map_err(|_| CacheError::Identity)?;
    let mut ancestor = absolute.as_path();
    let mut remainder = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut canonical) => {
                for part in remainder.iter().rev() {
                    canonical.push(part);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                remainder.push(
                    ancestor
                        .file_name()
                        .ok_or(CacheError::Identity)?
                        .to_os_string(),
                );
                ancestor = ancestor.parent().ok_or(CacheError::Identity)?;
            }
            Err(_) => return Err(CacheError::Identity.into()),
        }
    }
}

pub fn path_identity(path: &Path) -> VaultResult<String> {
    let canonical = canonical_vault_path(path)?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        canonical.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    return Err(CacheError::Identity.into());
    #[cfg(unix)]
    Ok(format!("path-v1-{}", hex::encode(Sha256::digest(bytes))))
}

pub fn file_for_identity(path: &Path) -> VaultResult<PathBuf> {
    let canonical = canonical_vault_path(path)?;
    Ok(canonical
        .parent()
        .ok_or(CacheError::Identity)?
        .join(format!(".kevi-{}.dksession-v1", path_identity(path)?)))
}
