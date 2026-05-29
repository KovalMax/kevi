//! Top-level user-facing error types.

use inquire::InquireError;
use std::io;
use std::string::FromUtf8Error;
use thiserror::Error;
use tokio::task::JoinError;

use crate::config::app_config::ConfigError;
use crate::cryptography::primitives::HeaderError;

pub type AppResult<T> = Result<T, KeviError>;
pub type OtpResult<T> = Result<T, OtpError>;
pub type TuiResult<T> = Result<T, TuiError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("{0}")]
    Message(String),
    #[error("invalid header: {0}")]
    InvalidHeader(#[from] HeaderError),
}

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("otp entry \"{0}\" already exists; use --on-duplicate-override to replace")]
    DuplicateEntry(String),
    #[error("no OTP entry found with name '{0}'")]
    EntryNotFound(String),
    #[error("nothing to do: use --echo or remove --no-copy")]
    NothingToDo,
    #[error("digits must be 6 or 8")]
    InvalidDigits,
    #[error("period must be positive")]
    InvalidPeriod,
    #[error("either --secret or --from-uri must be provided")]
    MissingSecretSource,
    #[error("secret cannot be empty")]
    EmptySecret,
    #[error("failed to parse OTP URI: {0}")]
    InvalidUri(String),
    #[error("invalid TOTP secret (expected Base32): {0}")]
    InvalidSecretBase32(String),
    #[error("failed to serialize JSON output: {0}")]
    Json(#[from] serde_json::Error),
    #[error("prompt error: {0}")]
    Prompt(#[from] InquireError),
    #[error("task join error: {0}")]
    TaskJoin(#[from] JoinError),
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal error: {0}")]
    Io(#[from] io::Error),
    #[error("task join error: {0}")]
    TaskJoin(#[from] JoinError),
    #[error("{0}")]
    Message(String),
}

#[derive(Debug, Error)]
pub enum KeviError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("OTP error: {0}")]
    Otp(#[from] OtpError),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("TUI error: {0}")]
    Tui(#[from] TuiError),
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
        Self::Config(ConfigError::InvalidProfile(msg.into()))
    }

    pub fn vault(msg: impl Into<String>) -> Self {
        Self::Vault(VaultError::Message(msg.into()))
    }

    pub fn otp(msg: impl Into<String>) -> Self {
        Self::Otp(OtpError::Message(msg.into()))
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    pub fn tui(msg: impl Into<String>) -> Self {
        Self::Tui(TuiError::Message(msg.into()))
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

impl From<HeaderError> for KeviError {
    fn from(err: HeaderError) -> Self {
        KeviError::Vault(VaultError::InvalidHeader(err))
    }
}

impl From<InquireError> for KeviError {
    fn from(err: InquireError) -> Self {
        KeviError::Prompt(err.to_string())
    }
}

impl From<serde_json::Error> for KeviError {
    fn from(err: serde_json::Error) -> Self {
        KeviError::vault(err.to_string())
    }
}

impl From<ron::Error> for KeviError {
    fn from(err: ron::Error) -> Self {
        KeviError::vault(err.to_string())
    }
}

impl From<FromUtf8Error> for KeviError {
    fn from(err: FromUtf8Error) -> Self {
        KeviError::Common(err.to_string())
    }
}
