use crate::otp::models::OtpEntry;
use crate::vault::models::VaultData;

pub trait OtpVaultRepository {
    type Error;

    fn load(&self) -> Result<VaultData, Self::Error>;
    fn save(&self, data: &VaultData) -> Result<(), Self::Error>;
}

pub struct OtpDomainService<RepositoryType>
where
    RepositoryType: OtpVaultRepository,
{
    repository: RepositoryType,
}

impl<RepositoryType> OtpDomainService<RepositoryType>
where
    RepositoryType: OtpVaultRepository,
{
    pub fn new(repository: RepositoryType) -> Self {
        Self { repository }
    }

    pub fn upsert_entry(
        &self,
        entry: OtpEntry,
        override_existing: bool,
    ) -> Result<(), OtpUpsertError<RepositoryType::Error>> {
        let mut vault = self.repository.load().map_err(OtpUpsertError::Repository)?;
        match vault.otps.iter().position(|existing| existing.name == entry.name) {
            Some(index) if override_existing => {
                vault.otps[index] = entry;
            }
            Some(_) => {
                return Err(OtpUpsertError::DuplicateEntry(entry.name.to_string()));
            }
            None => vault.otps.push(entry),
        }
        self.repository
            .save(&vault)
            .map_err(OtpUpsertError::Repository)
    }

    pub fn remove_entry(&self, name: &str) -> Result<bool, RepositoryType::Error> {
        let mut vault = self.repository.load()?;
        let before = vault.otps.len();
        vault.otps.retain(|entry| entry.name != name);
        let removed = vault.otps.len() != before;
        if removed {
            self.repository.save(&vault)?;
        }
        Ok(removed)
    }
}

#[derive(Debug, Clone)]
pub enum OtpUpsertError<RepositoryErrorType> {
    DuplicateEntry(String),
    Repository(RepositoryErrorType),
}
