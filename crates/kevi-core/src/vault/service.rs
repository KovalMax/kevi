use crate::vault::models::{VaultData, VaultEntry};

pub trait VaultRepository {
    type Error;

    fn load(&self) -> Result<VaultData, Self::Error>;
    fn save(&self, data: &VaultData) -> Result<(), Self::Error>;
}

pub struct VaultDomainService<R>
where
    R: VaultRepository,
{
    repository: R,
}

impl<R> VaultDomainService<R>
where
    R: VaultRepository,
{
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub fn add_entry(&self, entry: VaultEntry) -> Result<(), R::Error> {
        let mut data = self.repository.load()?;
        data.entries.push(entry);
        self.repository.save(&data)
    }

    pub fn remove_entry(&self, label: &str) -> Result<bool, R::Error> {
        let mut data = self.repository.load()?;
        let before = data.entries.len();
        data.entries.retain(|e| e.label != label);
        let removed = data.entries.len() != before;
        if removed {
            self.repository.save(&data)?;
        }
        Ok(removed)
    }
}
