//! Application configuration loading and precedence handling.
//! Resolves vault paths, clipboard/backups/generator defaults from CLI/env/config/defaults.

use crate::domain::{ProfileName, VaultPath};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use thiserror::Error;

pub struct Defaults;

impl Defaults {
    pub const CLIPBOARD_TTL: Option<u64> = None;
    pub const BACKUPS: usize = 2;
    pub const GENERATOR_LENGTH: Option<u16> = None;
    pub const GENERATOR_WORDS: Option<u16> = None;
    pub const GENERATOR_SEP: Option<&'static str> = None;
    pub const AVOID_AMBIGUOUS: Option<bool> = Some(false);
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("profile \"{0}\" is not defined in config.toml")]
    UnknownProfile(String),
    #[error("profile \"{0}\" is missing a vault_path")]
    InvalidProfile(String),
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FileConfig {
    pub vault_path: Option<String>,
    pub clipboard_ttl: Option<u64>,
    pub backups: Option<usize>,
    // Generator defaults (optional)
    pub generator_length: Option<u16>,
    pub generator_words: Option<u16>,
    pub generator_sep: Option<String>,
    pub avoid_ambiguous: Option<bool>,

    // Profile management
    pub default_profile: Option<String>,
    pub profiles: Option<HashMap<String, FileProfileConfig>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileProfileConfig {
    pub vault_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub vault_path: VaultPath,
    pub clipboard_ttl: Option<u64>,
    pub backups: Option<usize>,
    // Generator defaults (optional)
    pub generator_length: Option<u16>,
    pub generator_words: Option<u16>,
    pub generator_sep: Option<String>,
    pub avoid_ambiguous: Option<bool>,

    pub default_profile: Option<ProfileName>,
    pub profiles: HashMap<ProfileName, ProfileConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProfileConfig {
    pub vault_path: VaultPath,
}

impl Config {
    pub fn create(path: Option<PathBuf>, profile: Option<String>) -> Result<Self, ConfigError> {
        // 1) Load config file if present
        let file_cfg = load_file_config();

        // 2) Resolve vault path precedence
        let vault_path = resolve_vault_path(path, profile.as_deref(), &file_cfg)?;

        // 3) Resolve clipboard TTL precedence: env > config file > None (use command default)
        let clipboard_ttl = env::var("KEVI_CLIP_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .or(file_cfg.clipboard_ttl)
            .or(Defaults::CLIPBOARD_TTL);

        // 4) Resolve backups precedence: env > config file > None (library default is 2)
        let backups = env::var("KEVI_BACKUPS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .or(file_cfg.backups)
            .or(Some(Defaults::BACKUPS));

        // 5) Generator defaults precedence: env > config file > None
        let gen_len = env::var("KEVI_GEN_LENGTH")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .or(file_cfg.generator_length)
            .or(Defaults::GENERATOR_LENGTH);
        let gen_words = env::var("KEVI_GEN_WORDS")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .or(file_cfg.generator_words)
            .or(Defaults::GENERATOR_WORDS);
        let gen_sep = env::var("KEVI_GEN_SEP")
            .ok()
            .or(file_cfg.generator_sep)
            .or_else(|| Defaults::GENERATOR_SEP.map(String::from));
        let avoid_amb = env::var("KEVI_AVOID_AMBIGUOUS")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .or(file_cfg.avoid_ambiguous)
            .or(Defaults::AVOID_AMBIGUOUS);

        let profiles = file_cfg
            .profiles
            .unwrap_or_default()
            .into_iter()
            .map(|(name, p)| {
                (
                    ProfileName::from(name),
                    ProfileConfig {
                        vault_path: VaultPath::from(PathBuf::from(p.vault_path)),
                    },
                )
            })
            .collect();

        Ok(Config {
            vault_path,
            clipboard_ttl,
            backups,
            generator_length: gen_len,
            generator_words: gen_words,
            generator_sep: gen_sep,
            avoid_ambiguous: avoid_amb,
            default_profile: file_cfg.default_profile.map(ProfileName::from),
            profiles,
        })
    }
}

fn resolve_vault_path(
    cli_path: Option<PathBuf>,
    cli_profile: Option<&str>,
    file_cfg: &FileConfig,
) -> Result<VaultPath, ConfigError> {
    if let Some(p) = cli_path {
        return Ok(VaultPath::from(p));
    }

    if let Some(name) = cli_profile {
        if let Some(profiles) = file_cfg.profiles.as_ref() {
            if let Some(prof) = profiles.get(name) {
                return Ok(VaultPath::from(PathBuf::from(&prof.vault_path)));
            }
        }
        return Err(ConfigError::UnknownProfile(name.to_string()));
    }

    if let Ok(p) = env::var("KEVI_VAULT_PATH") {
        return Ok(VaultPath::from(PathBuf::from(p)));
    }

    if let Some(default_name) = file_cfg.default_profile.as_deref() {
        if let Some(profs) = file_cfg.profiles.as_ref() {
            if let Some(prof) = profs.get(default_name) {
                return Ok(VaultPath::from(PathBuf::from(&prof.vault_path)));
            }
        }
        // If default_profile points to a missing profile, ignore it and fall through
    }

    if let Some(p) = file_cfg.vault_path.as_ref() {
        return Ok(VaultPath::from(PathBuf::from(p)));
    }

    Ok(default_vault_path())
}

fn load_file_config() -> FileConfig {
    let (_, cfg) = load_file_config_with_path();
    cfg
}

pub fn load_file_config_with_path() -> (PathBuf, FileConfig) {
    // Allow tests/users to override config dir via KEVI_CONFIG_DIR; else use platform default
    let cfg_dir = if let Ok(p) = env::var("KEVI_CONFIG_DIR") {
        PathBuf::from(p)
    } else {
        dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
    };
    let path = cfg_dir.join("kevi").join("config.toml");
    let cfg = if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(s) = String::from_utf8(bytes) {
            toml::from_str::<FileConfig>(&s).unwrap_or_default()
        } else {
            FileConfig::default()
        }
    } else {
        FileConfig::default()
    };
    (path, cfg)
}

pub async fn save_file_config(path: &PathBuf, cfg: &FileConfig) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(cfg).map_err(std::io::Error::other)?;
    std::fs::write(path, s)
}

fn default_vault_path() -> VaultPath {
    // Prefer platform data_dir, allow override via KEVI_DATA_DIR, fallback to ~/.kevi/vault.ron
    if let Ok(base) = env::var("KEVI_DATA_DIR") {
        return VaultPath::from(PathBuf::from(base).join("kevi").join("vault.ron"));
    }
    if let Some(mut p) = dirs::data_dir() {
        p.push("kevi");
        p.push("vault.ron");
        return VaultPath::from(p);
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    VaultPath::from(PathBuf::from(&home).join(".kevi").join("vault.ron"))
}
