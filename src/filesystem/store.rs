use crate::domain::VaultResult;
use crate::error::KeviError;
use crate::filesystem::secure::write_with_backups_n;
use crate::vault::ports::ByteStore;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub struct FileByteStore {
    path: PathBuf,
    backups: usize,
}

impl FileByteStore {
    /// Construct with backups count resolved from environment (KEVI_BACKUPS) or default 2.
    pub fn new(path: PathBuf) -> Self {
        Self { path, backups: 2 }
    }

    /// Preferred: construct with explicit backups count to avoid env coupling.
    pub fn new_with_backups(path: PathBuf, backups: usize) -> Self {
        Self { path, backups }
    }
}

impl ByteStore for FileByteStore {
    fn read(&self) -> VaultResult<Vec<u8>> {
        let path = &self.path;
        if !Path::new(path).exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(path).map_err(|_| KeviError::vault("Failed to open vault file"))?;

        let mut buf = Vec::new();
        f.read_to_end(&mut buf)
            .map_err(|_| KeviError::vault("Failed to read vault file into buffer"))?;
        Ok(buf)
    }

    fn write(&self, bytes: &[u8]) -> VaultResult<()> {
        match write_with_backups_n(&self.path, bytes, self.backups) {
            Ok(()) => Ok(()),
            Err(e) => Err(KeviError::vault(e.to_string())),
        }
    }
}
