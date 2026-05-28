//! Domain types shared across modules to reduce primitive obsession and clarify intent.
//! Currently, it includes `VaultPath` for vault filesystem locations, `ProfileName` for
//! configuration profile identifiers, `EntryLabel` for vault entry keys, and `OtpName`
//! for OTP entry identifiers.

use crate::error::KeviError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// Domain type for vault filesystem locations.
pub type VaultResult<T> = Result<T, KeviError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VaultPath(pub PathBuf);

impl VaultPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl From<PathBuf> for VaultPath {
    fn from(path: PathBuf) -> Self {
        VaultPath(path)
    }
}

impl From<VaultPath> for PathBuf {
    fn from(path: VaultPath) -> Self {
        path.0
    }
}

impl AsRef<Path> for VaultPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl fmt::Display for VaultPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

impl PartialEq<PathBuf> for VaultPath {
    fn eq(&self, other: &PathBuf) -> bool {
        &self.0 == other
    }
}

impl PartialEq<VaultPath> for PathBuf {
    fn eq(&self, other: &VaultPath) -> bool {
        self == &other.0
    }
}

/// Domain type for profile identifiers in config and CLI flows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileName(pub String);

impl ProfileName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for ProfileName {
    fn from(name: String) -> Self {
        ProfileName(name)
    }
}

impl From<&str> for ProfileName {
    fn from(name: &str) -> Self {
        ProfileName(name.to_string())
    }
}

impl From<ProfileName> for String {
    fn from(name: ProfileName) -> Self {
        name.0
    }
}

impl AsRef<str> for ProfileName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for ProfileName {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<ProfileName> for String {
    fn eq(&self, other: &ProfileName) -> bool {
        self == &other.0
    }
}

/// Domain type for entry labels (keys) within a vault.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EntryLabel(pub String);

impl EntryLabel {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for EntryLabel {
    fn from(label: String) -> Self {
        EntryLabel(label)
    }
}

impl From<&str> for EntryLabel {
    fn from(label: &str) -> Self {
        EntryLabel(label.to_string())
    }
}

impl From<EntryLabel> for String {
    fn from(label: EntryLabel) -> Self {
        label.0
    }
}

impl AsRef<str> for EntryLabel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for EntryLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for EntryLabel {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<&str> for EntryLabel {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<EntryLabel> for &str {
    fn eq(&self, other: &EntryLabel) -> bool {
        *self == other.0
    }
}

/// Domain type for OTP entry identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OtpName(pub String);

impl OtpName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for OtpName {
    fn from(name: String) -> Self {
        OtpName(name)
    }
}

impl From<&str> for OtpName {
    fn from(name: &str) -> Self {
        OtpName(name.to_string())
    }
}

impl From<OtpName> for String {
    fn from(name: OtpName) -> Self {
        name.0
    }
}

impl AsRef<str> for OtpName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for OtpName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<String> for OtpName {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<OtpName> for String {
    fn eq(&self, other: &OtpName) -> bool {
        self == &other.0
    }
}

impl PartialEq<&str> for OtpName {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}
