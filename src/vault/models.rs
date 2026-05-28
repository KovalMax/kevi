use crate::cryptography::types::secret_string;
use crate::cryptography::types::secret_string_option;
use crate::domain::EntryLabel;
use crate::otp::models::OtpEntry;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    pub label: EntryLabel,
    #[serde(default, with = "secret_string_option")]
    pub username: Option<SecretString>,
    #[serde(with = "secret_string")]
    pub password: SecretString,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
    pub otps: Vec<OtpEntry>,
}

// Options for the add command, constructed by CLI layer
#[derive(Debug, Clone)]
pub struct AddOptions {
    pub generate: bool,
    pub length: Option<u16>,
    pub no_lower: bool,
    pub no_upper: bool,
    pub no_digits: bool,
    pub no_symbols: bool,
    pub allow_ambiguous: bool,
    pub passphrase: bool,
    pub words: Option<u16>,
    pub sep: Option<String>,
    pub label: Option<EntryLabel>,
    pub user: Option<String>,
    pub notes: Option<String>,
}
