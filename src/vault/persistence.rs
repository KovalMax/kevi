use crate::cryptography::primitives::{decrypt_vault, encrypt_vault};
use crate::domain::VaultResult;
use crate::error::KeviError;
use crate::filesystem::secure::write_with_backups;
use crate::vault::models::VaultData;
use ron::ser::PrettyConfig;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Load vault file, decrypt, and deserialize into VaultData.
/// Plaintext vaults are NOT supported; files must start with the KEVI header.
pub fn load_vault_file(path: &Path, password: &str) -> VaultResult<VaultData> {
    if !path.exists() {
        return Ok(VaultData::default());
    }

    // Read raw bytes
    let mut file =
        File::open(path).map_err(|e| KeviError::io(format!("Failed to open vault file: {e}")))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| KeviError::io(format!("Failed to read vault file: {e}")))?;

    if buf.is_empty() {
        return Ok(VaultData::default());
    }

    if !buf.is_empty() && !buf.starts_with(b"KEVI") {
        return Err(KeviError::vault(
            "unsupported vault format: missing KEVI header (plaintext is not allowed)",
        ));
    }

    // Encrypted container
    let data = decrypt_vault(&buf, password)
        .map_err(|_| KeviError::vault("Failed to decrypt vault (wrong password?)"))?;

    // Interpret as UTF-8 RON
    let contents = String::from_utf8(data)
        .map_err(|_| KeviError::vault("vault content not valid UTF-8 RON"))?;
    let vault: VaultData =
        ron::from_str(&contents).map_err(|_| KeviError::vault("Failed to parse vault content"))?;
    Ok(vault)
}

/// Serialize VaultData, encrypt with password, and save atomically to disk.
pub fn save_vault_file(data: &VaultData, path: &Path, password: &str) -> VaultResult<()> {
    let pretty = PrettyConfig::new()
        .depth_limit(3)
        .separate_tuple_members(true)
        .enumerate_arrays(true);
    let serialized =
        ron::ser::to_string_pretty(data, pretty).map_err(|e| KeviError::vault(e.to_string()))?;
    let ciphertext = encrypt_vault(serialized.as_bytes(), password)?;
    write_with_backups(path, &ciphertext)
}
