use crate::vault::models::VaultEntry;
use crate::vault::ports::VaultCodec;
use anyhow::{anyhow, Context, Result};
use ron::ser::PrettyConfig;

pub struct RonCodec;

impl VaultCodec for RonCodec {
    fn encode(&self, entries: &[VaultEntry]) -> Result<Vec<u8>> {
        let pretty = PrettyConfig::new()
            .depth_limit(3)
            .separate_tuple_members(true)
            .enumerate_arrays(true);
        let s = ron::ser::to_string_pretty(entries, pretty)?;
        Ok(s.into_bytes())
    }

    fn decode(&self, data: &[u8]) -> Result<Vec<VaultEntry>> {
        let s = String::from_utf8(data.to_vec())
            .map_err(|_| anyhow!("vault content not valid UTF-8 RON"))?;
        let vault: Vec<VaultEntry> = ron::from_str(&s).context("Failed to parse vault content")?;
        Ok(vault)
    }
}
