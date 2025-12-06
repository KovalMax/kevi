use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Ensure the parent directory of `path` exists and has restrictive permissions on Unix.
pub fn ensure_parent_secure(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create vault directory")?;
        #[cfg(target_family = "unix")]
        {
            let perm = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(parent, perm);
        }
    }
    Ok(())
}

/// Atomically write `bytes` to `path` with secure permissions (0600 on Unix).
pub fn atomic_write_secure(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp_path: PathBuf = path.with_extension("tmp");
    {
        let mut tmp = File::create(&tmp_path).context("Failed to create temporary vault file")?;
        tmp.write_all(bytes)?;
        let _ = tmp.sync_data();
    }

    #[cfg(target_family = "unix")]
    {
        let _ = OpenOptions::new().create(true).write(true).open(&tmp_path);
        let perm = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(&tmp_path, perm);
    }

    fs::rename(&tmp_path, path).context("Failed to replace vault file atomically")?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn set_perm_0600(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_mode(0o600);
        let _ = fs::set_permissions(path, perm);
    }
}

fn backup_path(path: &Path, n: usize) -> PathBuf {
    // Append .n to the filename path
    PathBuf::from(format!("{}.{n}", path.display()))
}

fn backup_count_from_env() -> usize {
    std::env::var("KEVI_BACKUPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2)
}

/// Rotate backups and write atomically, keeping up to N backups.
/// Backups are named `<file>.1`, `<file>.2`, ..., `<file>.N`.
pub fn write_with_backups_n(path: &Path, bytes: &[u8], n: usize) -> Result<()> {
    ensure_parent_secure(path)?;
    if n > 0 {
        // Remove the oldest if exists
        let oldest = backup_path(path, n);
        let _ = fs::remove_file(&oldest);

        // Shift backups: n-1 -> n, ..., 1 -> 2
        for i in (1..=n - 1).rev() {
            let src = backup_path(path, i);
            let dst = backup_path(path, i + 1);
            if src.exists() {
                let _ = fs::rename(&src, &dst);
                #[cfg(target_family = "unix")]
                {
                    set_perm_0600(&dst);
                }
            }
        }

        // Move the current file to .1
        if path.exists() {
            let first = backup_path(path, 1);
            let _ = fs::rename(path, &first);
            #[cfg(target_family = "unix")]
            {
                set_perm_0600(&first);
            }
        }
    }

    // Finally, write the new file atomically
    atomic_write_secure(path, bytes)?;
    Ok(())
}

/// Deprecated: env-coupled variant kept for compatibility. Prefer `write_with_backups_n`.
pub fn write_with_backups(path: &Path, bytes: &[u8]) -> Result<()> {
    let n = backup_count_from_env();
    write_with_backups_n(path, bytes, n)
}
