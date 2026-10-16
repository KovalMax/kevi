use crate::domain::VaultResult;
use crate::error::CacheError;
use crate::session_management::envelope::DerivedKeyStored;
#[cfg(all(unix, not(target_os = "macos")))]
use crate::session_management::envelope::MAX_PAYLOAD_BYTES;
#[cfg(all(unix, not(target_os = "macos")))]
use std::fs;
#[cfg(all(unix, not(target_os = "macos")))]
use std::fs::OpenOptions;
#[cfg(all(unix, not(target_os = "macos")))]
use std::io::{Read, Write};
use std::path::Path;
#[cfg(all(unix, not(target_os = "macos")))]
use zeroize::Zeroizing;

pub fn read(path: &Path) -> VaultResult<Option<DerivedKeyStored>> {
    #[cfg(any(not(unix), target_os = "macos"))]
    {
        let _ = path;
        Err(CacheError::Unavailable.into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(CacheError::Denied.into())
            }
            Err(_) => return Err(CacheError::Unavailable.into()),
        };
        let mut bytes = Zeroizing::new(Vec::new());
        file.take((MAX_PAYLOAD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CacheError::Unavailable)?;
        DerivedKeyStored::decode(&bytes).map(Some)
    }
}

pub fn write(path: &Path, bytes: &[u8]) -> VaultResult<()> {
    #[cfg(any(not(unix), target_os = "macos"))]
    {
        let _ = (path, bytes);
        Err(CacheError::Unavailable.into())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use ring::rand::{SecureRandom, SystemRandom};
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = path.parent().ok_or(CacheError::Persist)?;
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| CacheError::Persist)?;
        let temporary = parent.join(format!(".kevi-session-{}.tmp", hex::encode(random)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| CacheError::Persist)?;
        let result = (|| {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| CacheError::Persist)?;
            file.write_all(bytes).map_err(|_| CacheError::Persist)?;
            file.sync_all().map_err(|_| CacheError::Persist)?;
            drop(file);
            fs::rename(&temporary, path).map_err(|_| CacheError::Persist)?;
            Ok(())
        })();
        if result.is_err() {
            match fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(CacheError::Persist.into()),
            }
        }
        result
    }
}

pub fn clear(path: &Path) -> VaultResult<()> {
    crate::session_management::cleanup_file::clear_recognizable_current_session_file(path)
}
