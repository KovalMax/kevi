//! Domain types shared across modules to reduce primitive obsession and clarify intent.
//! Re-exported from `kevi-core`.

use crate::error::KeviError;
pub use kevi_core::domain::{EntryLabel, OtpName, ProfileName, VaultPath};

/// Domain type for vault filesystem locations.
pub type VaultResult<T> = Result<T, KeviError>;
