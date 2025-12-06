use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
struct FileConfig {
    pub vault_path: Option<String>,
    pub clipboard_ttl: Option<u64>,
    pub backups: Option<usize>,
    // Generator defaults (optional)
    pub generator_length: Option<u16>,
    pub generator_words: Option<u16>,
    pub generator_sep: Option<String>,
    pub avoid_ambiguous: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub vault_path: PathBuf,
    pub clipboard_ttl: Option<u64>,
    pub backups: Option<usize>,
    // Generator defaults (optional)
    pub generator_length: Option<u16>,
    pub generator_words: Option<u16>,
    pub generator_sep: Option<String>,
    pub avoid_ambiguous: Option<bool>,
}

impl Config {
    pub fn create(path: Option<PathBuf>) -> Self {
        // 1) Load config file if present
        let file_cfg = load_file_config();

        // 2) Resolve vault path precedence: CLI > env(KEVI_VAULT_PATH) > config file > default
        let vault_path = if let Some(p) = path {
            p
        } else if let Ok(p) = env::var("KEVI_VAULT_PATH") {
            PathBuf::from(p)
        } else if let Some(p) = file_cfg.vault_path.as_ref() {
            PathBuf::from(p)
        } else {
            default_vault_path()
        };

        // 3) Resolve clipboard TTL precedence: env > config file > None (use command default)
        let clipboard_ttl = env::var("KEVI_CLIP_TTL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .or(file_cfg.clipboard_ttl);

        // 4) Resolve backups precedence: env > config file > None (library default is 2)
        let backups = env::var("KEVI_BACKUPS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .or(file_cfg.backups);

        // 5) Generator defaults precedence: env > config file > None
        let gen_len = env::var("KEVI_GEN_LENGTH")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .or(file_cfg.generator_length);
        let gen_words = env::var("KEVI_GEN_WORDS")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .or(file_cfg.generator_words);
        let gen_sep = env::var("KEVI_GEN_SEP").ok().or(file_cfg.generator_sep);
        let avoid_amb = env::var("KEVI_AVOID_AMBIGUOUS")
            .ok()
            .and_then(|s| s.parse::<bool>().ok())
            .or(file_cfg.avoid_ambiguous);

        Config {
            vault_path,
            clipboard_ttl,
            backups,
            generator_length: gen_len,
            generator_words: gen_words,
            generator_sep: gen_sep,
            avoid_ambiguous: avoid_amb,
        }
    }
}

fn load_file_config() -> FileConfig {
    // Allow tests/users to override config dir via KEVI_CONFIG_DIR; else use platform default
    let cfg_dir = if let Ok(p) = env::var("KEVI_CONFIG_DIR") {
        PathBuf::from(p)
    } else {
        dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
    };
    let path = cfg_dir.join("kevi").join("config.toml");
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(s) = String::from_utf8(bytes) {
            if let Ok(cfg) = toml::from_str::<FileConfig>(&s) {
                return cfg;
            }
        }
    }
    FileConfig::default()
}

fn default_vault_path() -> PathBuf {
    // Prefer platform data_dir, allow override via KEVI_DATA_DIR, fallback to ~/.kevi/vault.ron
    if let Ok(base) = env::var("KEVI_DATA_DIR") {
        return PathBuf::from(base).join("kevi").join("vault.ron");
    }
    if let Some(mut p) = dirs::data_dir() {
        p.push("kevi");
        p.push("vault.ron");
        return p;
    }
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(&home).join(".kevi").join("vault.ron")
}
