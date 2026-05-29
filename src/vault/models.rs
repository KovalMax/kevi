use crate::domain::EntryLabel;
pub use kevi_core::vault::models::{VaultData, VaultEntry};

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
