use crate::domain::VaultResult;
use crate::error::KeviError;
use crate::vault::models::VaultData;
use crate::vault::ports::VaultCodec;
use ron::ser::PrettyConfig;

pub struct RonCodec;

impl VaultCodec for RonCodec {
    fn encode(&self, data: &VaultData) -> VaultResult<Vec<u8>> {
        let pretty = PrettyConfig::new()
            .depth_limit(3)
            .separate_tuple_members(true)
            .enumerate_arrays(true);
        let s = ron::ser::to_string_pretty(data, pretty)?;
        Ok(s.into_bytes())
    }

    fn decode(&self, data: &[u8]) -> VaultResult<VaultData> {
        let s = String::from_utf8(data.to_vec())
            .map_err(|_| KeviError::vault("vault content not valid UTF-8 RON"))?;
        let vault: VaultData =
            ron::from_str(&s).map_err(|_| KeviError::vault("Failed to parse vault content"))?;

        Ok(vault)
    }
}
