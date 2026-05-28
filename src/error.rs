//! Top-level user-facing error types.

use inquire::InquireError;
use std::string::FromUtf8Error;
use thiserror::Error;

use crate::config::app_config::ConfigError;
use crate::cryptography::primitives::HeaderError;

#[derive(Debug, Error)]
pub enum KeviError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Vault error: {0}")]
    Vault(String),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("TUI error: {0}")]
    Tui(String),
    #[error("CLI error: {0}")]
    Cli(String),
    #[error("Prompt error: {0}")]
    Prompt(String),
    #[error("Generator error: {0}")]
    Generator(String),
    #[error("Common error: {0}")]
    Common(String),
}

impl KeviError {
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    pub fn vault(msg: impl Into<String>) -> Self {
        Self::Vault(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    pub fn tui(msg: impl Into<String>) -> Self {
        Self::Tui(msg.into())
    }

    pub fn cli(msg: impl Into<String>) -> Self {
        Self::Cli(msg.into())
    }

    pub fn prompt(msg: impl Into<String>) -> Self {
        Self::Prompt(msg.into())
    }
    pub fn generator(msg: impl Into<String>) -> Self {
        Self::Generator(msg.into())
    }
    pub fn common(msg: impl Into<String>) -> Self {
        Self::Common(msg.into())
    }
}

impl From<ConfigError> for KeviError {
    fn from(err: ConfigError) -> Self {
        KeviError::Config(err.to_string())
    }
}

impl From<HeaderError> for KeviError {
    fn from(err: HeaderError) -> Self {
        KeviError::Vault(format!("Failed to parse header - {err}"))
    }
}

impl From<InquireError> for KeviError {
    fn from(err: InquireError) -> Self {
        KeviError::Prompt(err.to_string())
    }
}

impl From<serde_json::Error> for KeviError {
    fn from(err: serde_json::Error) -> Self {
        KeviError::Vault(err.to_string())
    }
}

impl From<anyhow::Error> for KeviError {
    fn from(err: anyhow::Error) -> Self {
        KeviError::Common(err.to_string())
    }
}

impl From<ron::Error> for KeviError {
    fn from(err: ron::Error) -> Self {
        KeviError::Vault(err.to_string())
    }
}

impl From<FromUtf8Error> for KeviError {
    fn from(err: FromUtf8Error) -> Self {
        KeviError::Common(err.to_string())
    }
}
