mod app;
mod cli;
mod config;
mod cryptography;
mod domain;
mod error;
mod filesystem;
mod otp;
mod session_management;
mod tui;
mod vault;

pub mod api {
    pub use crate::cli::runner::run;

    pub use crate::config::app_config::{
        load_file_config_with_path, save_file_config, Config, ConfigError, Defaults, FileConfig,
        FileProfileConfig, ProfileConfig,
    };

    pub use crate::domain::{EntryLabel, OtpName, ProfileName, VaultPath, VaultResult};

    pub use crate::error::{
        AppResult, KeviError, OtpError, OtpResult, TuiError, TuiResult, VaultError,
    };

    pub use crate::cryptography::generator::{
        estimate_bits_char_mode, estimate_bits_passphrase, strength_label, DefaultPasswordGenerator,
    };
    pub use crate::cryptography::memlock::{lock_slice, unlock_slice};
    pub use crate::cryptography::primitives::{
        decrypt_vault, default_params, derive_key_argon2id, encrypt_vault,
        header_fingerprint_excluding_nonce, HeaderError, KeviHeader, AEAD_AES256GCM,
        HEADER_VERSION, KDF_ARGON2ID, NONCE_LEN, SALT_LEN,
    };

    pub use crate::filesystem::clipboard::{copy_with_ttl, ClipboardEngine};
    pub use crate::filesystem::store::FileByteStore;

    pub use crate::session_management::resolver::{
        dk_session_file_for, save_derived_key_session, BypassKeyResolver, CachedKeyResolver,
        DerivedKeyStored,
    };
    pub use crate::session_management::session::{clear, load};

    pub use crate::tui::app::{App, FormField, Mode, View};
    pub use crate::tui::views::confirm::render_confirm;
    pub use crate::tui::views::details::render_details;
    pub use crate::tui::views::form::render_form;
    pub use crate::tui::views::list::render_list;

    pub use crate::otp::handlers::{
        OtpAddOptions, OtpGetOptions, OtpHandlers, OtpListOptions, OtpRemoveOptions,
    };
    pub use crate::otp::models::{OtpAlgorithm, OtpEntry};
    pub use crate::otp::parser::parse_otp_entry;
    pub use crate::otp::totp::{build_totp, validate_totp_params};

    pub use crate::vault::codec::RonCodec;
    pub use crate::vault::handlers::{GetField, Vault};
    pub use crate::vault::models::{AddOptions, VaultData, VaultEntry};
    pub use crate::vault::persistence::{load_vault_file, save_vault_file};
    pub use crate::vault::ports::{
        ByteStore, CoreRng, DerivedKey, GenPolicy, HeaderParams, KeyResolver, PasswordGenerator,
        VaultCodec,
    };
    pub use crate::vault::service::VaultService;
}
