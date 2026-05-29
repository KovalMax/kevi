use inquire::InquireError;
use kevi::api::{ConfigError, HeaderError, KeviError};
use serde::ser::Error;

#[test]
fn kevi_error_constructor_messages() {
    let cfg = KeviError::config("missing vault");
    assert!(matches!(cfg, KeviError::Config(_)));
    assert_eq!(cfg.to_string(), "profile \"missing vault\" is missing a vault_path");

    let vault = KeviError::vault("io failure");
    assert!(matches!(vault, KeviError::Vault(_)));
    assert_eq!(vault.to_string(), "Vault error: io failure");

    let crypto = KeviError::crypto("bad key");
    assert!(matches!(crypto, KeviError::Crypto(_)));
    assert_eq!(crypto.to_string(), "Cryptography error: bad key");

    let io = KeviError::io("disk full");
    assert!(matches!(io, KeviError::Io(_)));
    assert_eq!(io.to_string(), "I/O error: disk full");

    let tui = KeviError::tui("render failed");
    assert!(matches!(tui, KeviError::Tui(_)));
    assert_eq!(tui.to_string(), "TUI error: render failed");

    let cli = KeviError::cli("invalid args");
    assert!(matches!(cli, KeviError::Cli(_)));
    assert_eq!(cli.to_string(), "CLI error: invalid args");

    let gen = KeviError::generator("empty pool");
    assert!(matches!(gen, KeviError::Generator(_)));
    assert_eq!(gen.to_string(), "Generator error: empty pool");

    let prompt = KeviError::prompt("password is wrong");
    assert!(matches!(prompt, KeviError::Prompt(_)));
    assert_eq!(prompt.to_string(), "Prompt error: password is wrong");

    let common = KeviError::common("invalid args");
    assert!(matches!(common, KeviError::Common(_)));
    assert_eq!(common.to_string(), "Common error: invalid args");
}

#[test]
fn kevi_error_from_error_uses_display() {
    let err = ConfigError::UnknownProfile("work".to_string());
    let ke: KeviError = err.into();
    assert!(matches!(ke, KeviError::Config(_)));
    assert_eq!(
        ke.to_string(),
        "profile \"work\" is not defined in config.toml"
    );

    let err2 = ConfigError::InvalidProfile("home".to_string());
    let ke2: KeviError = err2.into();
    assert_eq!(
        ke2.to_string(),
        "profile \"home\" is missing a vault_path"
    );

    let head_err = HeaderError::TooShort;
    let to_ke: KeviError = head_err.into();
    assert!(matches!(to_ke, KeviError::Vault(_)));
    assert_eq!(
        to_ke.to_string(),
        "Vault error: invalid header: ciphertext too short for header"
    );

    let inq_err = InquireError::OperationCanceled;
    let to_ke: KeviError = inq_err.into();
    assert!(matches!(to_ke, KeviError::Prompt(_)));
    assert_eq!(
        to_ke.to_string(),
        "Prompt error: Operation was canceled by the user"
    );

    let value = String::from_utf8(vec![0, 159]);
    assert!(value.is_err());
    let to_ke: KeviError = value.unwrap_err().into();
    assert!(matches!(to_ke, KeviError::Common(_)));
    assert_eq!(
        to_ke.to_string(),
        "Common error: invalid utf-8 sequence of 1 bytes from index 1"
    );

    let serde_err = serde_json::Error::custom("invalid json");
    let to_ke: KeviError = serde_err.into();
    assert!(matches!(to_ke, KeviError::Vault(_)));
    assert_eq!(to_ke.to_string(), "Vault error: invalid json")
}
