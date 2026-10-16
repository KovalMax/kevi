use crate::domain::VaultResult;
use crate::error::CacheError;
use crate::session_management::envelope::{DerivedKeyStored, MAX_PAYLOAD_BYTES};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::fs::{self, Metadata};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

fn recognizable_key(fingerprint: &str, encoded: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        && encoded.len() == 44
        && STANDARD
            .decode(encoded)
            .map(Zeroizing::new)
            .is_ok_and(|key| key.len() == 32)
}

fn recognizable_current_session(bytes: &[u8]) -> bool {
    DerivedKeyStored::decode(bytes)
        .is_ok_and(|stored| recognizable_key(&stored.header_fingerprint_hex, &stored.key_b64))
}

fn same_object(first: &Metadata, second: &Metadata) -> VaultResult<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(first.dev() == second.dev() && first.ino() == second.ino())
    }
    #[cfg(windows)]
    {
        // Stable Rust does not expose a supported Windows file identity API.
        // Never authorize deletion using a weaker path/name comparison.
        let _ = (first, second);
        Err(CacheError::Identity.into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (first, second);
        Err(CacheError::Identity.into())
    }
}

pub fn check_target(vault_spellings: &[&Path], candidate: &Path) -> VaultResult<()> {
    let candidate_metadata = match fs::symlink_metadata(candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CacheError::Identity.into()),
    };
    if !candidate_metadata.is_file() || candidate_metadata.file_type().is_symlink() {
        return Err(CacheError::CleanupConflict.into());
    }
    for vault in vault_spellings {
        match fs::metadata(vault) {
            Ok(vault_metadata) if same_object(&vault_metadata, &candidate_metadata)? => {
                return Err(CacheError::CleanupConflict.into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CacheError::Identity.into()),
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(candidate)
        .map_err(|_| CacheError::Denied)?
        .take((MAX_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| CacheError::Unavailable)?;
    if bytes.len() > MAX_PAYLOAD_BYTES
        || bytes.starts_with(b"KEVI")
        || !recognizable_current_session(&bytes)
    {
        return Err(CacheError::CleanupConflict.into());
    }
    Ok(())
}

/// File cleanup requires every directory component to be protected from
/// mutation by other users. Same-user concurrent filesystem mutation is
/// intentionally outside this path-based check's guarantee.
pub fn check_file_directory(candidate: &Path) -> VaultResult<()> {
    match fs::symlink_metadata(candidate) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CacheError::Identity.into()),
        Ok(_) => {}
    }
    #[cfg(target_os = "macos")]
    {
        let _ = candidate;
        // POSIX mode bits do not expose macOS ACL grants. Until those are
        // reliably evaluated, file deletion is not safe to authorize.
        Err(CacheError::CleanupConflict.into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let parent = candidate
            .parent()
            .ok_or(CacheError::Identity)?
            .canonicalize()
            .map_err(|_| CacheError::Identity)?;
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        let effective_uid = unsafe { geteuid() };
        for directory in parent.ancestors() {
            let metadata = fs::metadata(directory).map_err(|_| CacheError::Identity)?;
            let owner = metadata.uid();
            let mode = metadata.permissions().mode();
            if !metadata.is_dir() || (owner != effective_uid && owner != 0) || mode & 0o022 != 0 {
                return Err(CacheError::CleanupConflict.into());
            }
        }
        Ok(())
    }
    #[cfg(not(any(unix, target_os = "macos")))]
    {
        let _ = candidate;
        Err(CacheError::CleanupConflict.into())
    }
}

pub fn clear_recognizable_current_session_file(candidate: &Path) -> VaultResult<()> {
    check_file_directory(candidate)?;
    check_target(&[], candidate)?;
    match fs::remove_file(candidate) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Err(CacheError::Denied.into())
        }
        Err(_) => Err(CacheError::Delete.into()),
    }
}
