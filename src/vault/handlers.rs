use crate::config::app_config::Config;
use crate::cryptography::generator::{
    estimate_bits_char_mode, estimate_bits_passphrase, strength_label, DefaultPasswordGenerator,
    SystemRng,
};
use crate::cryptography::primitives::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, parse_kevi_header, AEAD_AES256GCM,
    KDF_ARGON2ID,
};
use crate::filesystem::clipboard::{
    copy_with_ttl, environment_warning, ttl_seconds, SystemClipboardEngine,
};
use crate::filesystem::store::FileByteStore;
use crate::session_management::resolver::{
    dk_session_file_for, save_derived_key_session, BypassKeyResolver, CachedKeyResolver,
};
use crate::session_management::session::clear;
use crate::vault::codec::RonCodec;
use crate::vault::models::VaultEntry;
use crate::vault::persistence::save_vault_file;
use crate::vault::ports::{ByteStore, GenPolicy, KeyResolver, PasswordGenerator, Rng, VaultCodec};
use crate::vault::service::VaultService;
use anyhow::{anyhow, Result};
use inquire::{Confirm, Password, Text};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::env;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::spawn_blocking;

#[derive(Copy, Clone, Debug)]
pub enum GetField {
    Password,
    User,
    Notes,
}

pub struct Vault<'a> {
    config: &'a Config,
    service: Arc<VaultService>,
}

impl<'a> Vault<'a> {
    pub fn create(config: &'a Config) -> Self {
        // Compose default adapters
        let backups = config.backups.unwrap_or(2);
        let store: Arc<dyn ByteStore> = Arc::new(FileByteStore::new_with_backups(
            config.vault_path.clone(),
            backups,
        ));
        let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
        let key_resolver: Arc<dyn KeyResolver> =
            Arc::new(CachedKeyResolver::new(config.vault_path.clone()));
        let service = Arc::new(VaultService::new(store, codec, key_resolver));

        Vault { config, service }
    }

    pub async fn handle_header(&self) -> Result<()> {
        let path = self.config.vault_path.clone();
        let bytes = spawn_blocking(move || fs::read(&path))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        match parse_kevi_header(&bytes) {
            Ok((hdr, _off)) => {
                let kdf = match hdr.kdf_id {
                    KDF_ARGON2ID => "Argon2id",
                    other => {
                        let _ = other;
                        "Unknown"
                    }
                };
                let aead = match hdr.aead_id {
                    AEAD_AES256GCM => "AES-256-GCM",
                    other => {
                        let _ = other;
                        "Unknown"
                    }
                };
                let salt_hex: String = hdr.salt.iter().map(|b| format!("{b:02x}")).collect();
                let nonce_hex: String = hdr.nonce.iter().map(|b| format!("{b:02x}")).collect();
                println!("KEVI header:");
                println!("  version: {}", hdr.version);
                println!("  kdf: {} ({})", kdf, hdr.kdf_id);
                println!("  aead: {} ({})", aead, hdr.aead_id);
                println!("  argon2 m_cost_kib: {}", hdr.m_cost_kib);
                println!("  argon2 t_cost: {}", hdr.t_cost);
                println!("  argon2 p_lanes: {}", hdr.p_lanes);
                println!("  salt: {salt_hex}");
                println!("  nonce: {nonce_hex}");
                Ok(())
            }
            Err(e) => Err(anyhow!("Failed to parse header: {}", e)),
        }
    }

    pub async fn handle_get(
        &self,
        key: &str,
        field: GetField,
        no_copy: bool,
        ttl_override: Option<u64>,
        echo: bool,
        once: bool,
    ) -> Result<()> {
        // Load entries, optionally bypassing session cache for this call using a temp resolver
        let vault = if once {
            let store: Arc<dyn ByteStore> =
                Arc::new(FileByteStore::new(self.config.vault_path.clone()));
            let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
            let resolver: Arc<dyn KeyResolver> = Arc::new(BypassKeyResolver::new());
            let svc = Arc::new(VaultService::new(store, codec, resolver));
            spawn_blocking(move || svc.load())
                .await
                .map_err(|_| anyhow!("task join error"))??
        } else {
            let svc = self.service.clone();
            spawn_blocking(move || svc.load())
                .await
                .map_err(|_| anyhow!("task join error"))??
        };
        let entry = match vault.iter().find(|e| e.label == key) {
            Some(e) => e,
            None => {
                println!("❌ No entry found with key '{key}'");
                return Ok(());
            }
        };

        // Extract selected field as string (without leaking by default)
        let selected: Option<String> = match field {
            GetField::Password => Some(entry.password.expose_secret().to_string()),
            GetField::User => entry
                .username
                .as_ref()
                .map(|u| u.expose_secret().to_string()),
            GetField::Notes => entry.notes.clone(),
        };

        let Some(value) = selected else {
            println!("❌ Field is empty for '{key}'");
            return Ok(());
        };

        // Echo to stdout if requested
        if echo {
            println!("{value}");
            if no_copy {
                return Ok(());
            }
        }

        // If no_copy is set, and we didn't early-return, do nothing further
        if no_copy {
            return Ok(());
        }

        // Determine TTL with precedence via shared helper
        let ttl_secs = ttl_seconds(self.config, ttl_override);
        let ttl = Duration::from_secs(ttl_secs);

        // Copy to clipboard with TTL
        if let Some(warn) = environment_warning() {
            eprintln!("⚠️ {warn}");
        }
        match SystemClipboardEngine::new() {
            Ok(engine_impl) => {
                let engine =
                    Arc::new(engine_impl) as Arc<dyn crate::filesystem::clipboard::ClipboardEngine>;
                let secret = SecretString::new(value.into());
                if let Err(e) = copy_with_ttl(engine, &secret, ttl) {
                    eprintln!("⚠️ Failed to copy to clipboard: {e}");
                } else {
                    // Successful copy: do not print secrets or confirmations to stdout by default.
                }
            }
            Err(e) => {
                eprintln!("⚠️ Clipboard not available: {e}");
            }
        }

        Ok(())
    }

    pub async fn handle_show(&self, key: &str, reveal_password: bool) -> Result<()> {
        let svc = self.service.clone();
        let entries = spawn_blocking(move || svc.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;

        if let Some(entry) = entries.iter().find(|e| e.label == key) {
            println!("Label:    {}", entry.label);
            if let Some(user) = &entry.username {
                println!("Username: {}", user.expose_secret());
            } else {
                println!("Username: (none)");
            }
            if let Some(notes) = &entry.notes {
                println!("Notes:    {notes}");
            } else {
                println!("Notes:    (none)");
            }

            if reveal_password {
                println!("Password: {}", entry.password.expose_secret());
            } else {
                println!("Password: ******** (use --reveal-password to show)");
            }
        } else {
            anyhow::bail!("entry '{}' not found", key);
        }
        Ok(())
    }

    pub async fn handle_add(&self, opts: AddOptions) -> Result<()> {
        // Load existing entries first
        let svc_load = self.service.clone();
        let mut vault = spawn_blocking(move || svc_load.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;

        // Determine label/username/notes (use provided flags or prompt)
        let label = if let Some(l) = opts.label.clone() {
            l
        } else {
            Text::new("Label (key)").prompt()?
        };
        if vault.iter().any(|e| e.label == label) {
            println!("❌ Entry with label '{label}' already exists.");
            return Ok(());
        }
        let username = if let Some(u) = opts.user.clone() {
            u
        } else {
            Text::new("Username (optional)").with_default("").prompt()?
        };
        let notes = if let Some(n) = opts.notes.clone() {
            n
        } else {
            Text::new("Notes (optional)").with_default("").prompt()?
        };

        // Determine password
        let password = if opts.generate {
            // Build policy
            let mut policy = GenPolicy {
                passphrase: opts.passphrase,
                ..GenPolicy::default()
            };
            if policy.passphrase {
                policy.words = opts
                    .words
                    .or(self.config.generator_words)
                    .unwrap_or(GenPolicy::default().words);
                policy.sep = opts
                    .sep
                    .clone()
                    .or(self.config.generator_sep.clone())
                    .unwrap_or_else(|| GenPolicy::default().sep.clone());
            } else {
                policy.length = opts
                    .length
                    .or(self.config.generator_length)
                    .unwrap_or(GenPolicy::default().length);
                policy.lower = !opts.no_lower;
                policy.upper = !opts.no_upper;
                policy.digits = !opts.no_digits;
                policy.symbols = !opts.no_symbols;
                let avoid_from_cfg = self
                    .config
                    .avoid_ambiguous
                    .unwrap_or(GenPolicy::default().avoid_ambiguous);
                policy.avoid_ambiguous = if opts.allow_ambiguous {
                    false
                } else {
                    avoid_from_cfg
                };
            }
            let rng: Arc<dyn Rng> = Arc::new(SystemRng);
            let gen = DefaultPasswordGenerator::new(rng);
            let generated = gen.generate(&policy)?;
            // Show a basic strength hint (interactive UX), without echoing the secret
            let bits = if policy.passphrase {
                estimate_bits_passphrase(policy.words, crate::cryptography::wordlist::WORDS.len())
            } else {
                estimate_bits_char_mode(&policy)
            };
            println!(
                "🔒 Generated secret strength: {} (~{:.1} bits)",
                strength_label(bits),
                bits
            );
            generated
        } else {
            Password::new("Password").prompt()?
        };

        let entry = VaultEntry {
            label,
            username: if username.is_empty() {
                None
            } else {
                Some(SecretString::new(username.into()))
            },
            password: SecretString::new(password.into()),
            notes: if notes.is_empty() { None } else { Some(notes) },
        };

        vault.push(entry);
        let svc_save = self.service.clone();
        spawn_blocking(move || svc_save.save(&vault))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        println!("✅ Entry saved.");

        Ok(())
    }

    pub async fn handle_rm(&self, key: &str, yes: bool) -> Result<()> {
        // Load to check existence and optionally confirm
        let svc_load = self.service.clone();
        let entries = spawn_blocking(move || svc_load.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;
        if !entries.iter().any(|e| e.label == key) {
            println!("❌ No entry found with key '{key}'");
            return Ok(());
        }

        if !yes {
            let msg = format!("Delete entry '{key}' ?");
            let proceed = Confirm::new(&msg).with_default(false).prompt()?;
            if !proceed {
                println!("❎ Deletion cancelled.");
                return Ok(());
            }
        }

        let svc_rm = self.service.clone();
        let key_owned = key.to_string();
        let removed = spawn_blocking(move || svc_rm.remove_entry(&key_owned))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        if removed {
            println!("🗑️ Entry '{key}' removed.");
        } else {
            // Should not happen due to pre-check, but handle race
            println!("❌ No entry found with key '{key}'");
        }
        Ok(())
    }

    pub async fn handle_list(
        &self,
        query: Option<String>,
        show_users: bool,
        json_mode: bool,
    ) -> Result<()> {
        let svc = self.service.clone();
        let mut entries = spawn_blocking(move || svc.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;

        // Filter by query (case-insensitive) on label
        if let Some(q) = query {
            let ql = q.to_lowercase();
            entries.retain(|e| e.label.to_lowercase().contains(&ql));
        }

        if json_mode {
            // Build JSON array without secrets
            let items: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    if show_users {
                        let user_opt = e.username.as_ref().map(|u| u.expose_secret().to_string());
                        match user_opt {
                            Some(u) if !u.is_empty() => json!({"label": e.label, "username": u}),
                            _ => json!({"label": e.label}),
                        }
                    } else {
                        json!({"label": e.label})
                    }
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            return Ok(());
        }

        if entries.is_empty() {
            println!("(empty)");
            return Ok(());
        }
        for e in entries {
            if show_users {
                let user = e
                    .username
                    .as_ref()
                    .map(|u| u.expose_secret().to_string())
                    .unwrap_or_else(|| "".to_string());
                if user.is_empty() {
                    println!("{}", e.label);
                } else {
                    println!("{}\t{}", e.label, user);
                }
            } else {
                println!("{}", e.label);
            }
        }
        Ok(())
    }

    pub async fn handle_init(&self, path_override: Option<&str>) -> Result<()> {
        // Decide a path
        let target_path = if let Some(p) = path_override {
            std::path::PathBuf::from(p)
        } else {
            self.config.vault_path.clone()
        };

        // Get password (env or prompt twice)
        let master = if let Ok(pw) = env::var("KEVI_PASSWORD") {
            pw
        } else {
            let pw1 = Password::new("Master password")
                .with_help_message("Used to encrypt your vault")
                .without_confirmation()
                .prompt()?;
            let pw2 = Password::new("Confirm password")
                .without_confirmation()
                .prompt()?;
            if pw1 != pw2 {
                return Err(anyhow::anyhow!("Passwords do not match"));
            }
            pw1
        };

        // Save an empty vault
        let empty: Vec<VaultEntry> = Vec::new();
        let path_clone = target_path.clone();
        let master_clone = master.clone();
        spawn_blocking(move || save_vault_file(&empty, &path_clone, &master_clone))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        println!(
            "✅ Initialized encrypted vault at {}",
            target_path.display()
        );
        Ok(())
    }

    pub async fn handle_unlock(&self, ttl_override: Option<u64>) -> Result<()> {
        // TTL precedence
        let ttl_secs = ttl_override
            .or_else(|| {
                env::var("KEVI_UNLOCK_TTL")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .unwrap_or(900);
        let ttl = Duration::from_secs(ttl_secs);

        // Read vault header (must exist)
        let path = self.config.vault_path.clone();
        let bytes = spawn_blocking(move || fs::read(&path))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        let (hdr, _off) = parse_kevi_header(&bytes).map_err(|e| anyhow!("invalid header: {e}"))?;

        // Get passphrase
        let password = if let Ok(pw) = env::var("KEVI_PASSWORD") {
            pw
        } else {
            Password::new("Master password")
                .without_confirmation()
                .prompt()?
        };

        // Derive key and write dk-session bound to header
        let key_arr = derive_key_argon2id(
            &password,
            &hdr.salt,
            hdr.m_cost_kib,
            hdr.t_cost,
            hdr.p_lanes,
        )?;
        let fp = header_fingerprint_excluding_nonce(&hdr);
        let dk_path = dk_session_file_for(&self.config.vault_path);
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));
        spawn_blocking(move || save_derived_key_session(&dk_path, &fp, &key_vec, ttl))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        println!("🔓 Unlocked for {ttl_secs}s (derived key cached).");
        Ok(())
    }

    pub async fn handle_lock(&self) -> Result<()> {
        let dk_path = dk_session_file_for(&self.config.vault_path);
        spawn_blocking(move || clear(&dk_path))
            .await
            .map_err(|_| anyhow!("task join error"))??;
        println!("🔒 Locked (derived-key session cleared).");
        Ok(())
    }
}

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
    pub label: Option<String>,
    pub user: Option<String>,
    pub notes: Option<String>,
}
