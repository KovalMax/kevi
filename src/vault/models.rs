use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultEntry {
    pub label: String,
    #[serde(default, with = "crate::cryptography::types::secret_string_option")]
    pub username: Option<SecretString>,
    #[serde(with = "crate::cryptography::types::secret_string")]
    pub password: SecretString,
    pub notes: Option<String>,
}
