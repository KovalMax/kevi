use crate::app::wiring::{create_vault_service, create_vault_service_bypass_cache};
use crate::config::app_config::Config;
use crate::cryptography::generator::{
    estimate_bits_char_mode, estimate_bits_passphrase, strength_label, DefaultPasswordGenerator,
    SystemRng,
};
use crate::cryptography::primitives::{
    derive_key_argon2id, header_fingerprint_excluding_nonce, parse_kevi_header, AEAD_AES256GCM,
    KDF_ARGON2ID,
};
use crate::cryptography::wordlist::WORDS;
use crate::domain::{EntryLabel, VaultResult};
use crate::error::KeviError;
use crate::filesystem::clipboard::{
    copy_with_ttl_using_system_clipboard, environment_warning, report_clipboard_copy_result,
    ttl_seconds,
};
use crate::session_management::resolver::{
    clear_derived_key_cache_for_vault, dk_session_file_for, save_derived_key_session,
};
use crate::vault::models::{AddOptions, VaultData, VaultEntry};
use crate::vault::persistence::save_vault_file;
use crate::vault::ports::{CoreRng, GenPolicy, PasswordGenerator};
use crate::vault::service::VaultService;
use inquire::{Confirm, Password, Text};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::env;
use std::fmt::Display;
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

impl Display for GetField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetField::Password => write!(f, "Password"),
            GetField::User => write!(f, "Username"),
            GetField::Notes => write!(f, "notes"),
        }
    }
}

pub struct Vault<'config> {
    config: &'config Config,
    service: Arc<VaultService>,
}

fn join_error(context: &str) -> KeviError {
    KeviError::vault(format!("{context} (task join error)"))
}

fn vault_error<E: Display>(context: &str, err: E) -> KeviError {
    KeviError::vault(format!("{context} - {err}"))
}

impl<'config> Vault<'config> {
    pub fn create(config: &'config Config) -> Self {
        let service = create_vault_service(config);

        Vault { config, service }
    }

    fn read_service(&self, once: bool) -> Arc<VaultService> {
        if once {
            create_vault_service_bypass_cache(self.config)
        } else {
            self.service.clone()
        }
    }

    async fn load_vault(service: Arc<VaultService>) -> VaultResult<VaultData> {
        spawn_blocking(move || service.load())
            .await
            .map_err(|_| join_error("loading vault"))?
            .map_err(|error| vault_error("failed to load vault", error))
    }

    async fn save_vault(service: Arc<VaultService>, data: VaultData) -> VaultResult<()> {
        spawn_blocking(move || service.save(&data))
            .await
            .map_err(|_| join_error("saving vault"))?
            .map_err(|error| vault_error("failed to save vault", error))
    }

    fn find_entry_by_label<'vault_data>(
        vault_data: &'vault_data VaultData,
        key: &str,
    ) -> Option<&'vault_data VaultEntry> {
        vault_data.entries.iter().find(|entry| entry.label == key)
    }

    fn has_entry(vault_data: &VaultData, key: &str) -> bool {
        vault_data.entries.iter().any(|entry| entry.label == key)
    }

    fn print_entry_not_found(key: &str) {
        println!("❌ No entry found with key '{key}'");
    }

    pub async fn handle_header(&self) -> VaultResult<()> {
        let path: std::path::PathBuf = self.config.vault_path.clone().into();
        let bytes = spawn_blocking(move || fs::read(&path))
            .await
            .map_err(|_| join_error("reading vault file"))?
            .map_err(|e| vault_error("failed to read vault file", e))?;
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
            Err(e) => Err(KeviError::from(e)),
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
    ) -> VaultResult<()> {
        let vault = Self::load_vault(self.read_service(once)).await?;
        let entry = match Self::find_entry_by_label(&vault, key) {
            Some(e) => e,
            None => {
                Self::print_entry_not_found(key);
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
        let secret = SecretString::new(value.into());
        report_clipboard_copy_result(copy_with_ttl_using_system_clipboard(&secret, ttl));

        Ok(())
    }

    pub async fn handle_show(&self, key: &str, reveal_password: bool) -> VaultResult<()> {
        let data = Self::load_vault(self.service.clone()).await?;

        if let Some(entry) = Self::find_entry_by_label(&data, key) {
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
            return Err(KeviError::vault(format!("entry '{key}' not found")));
        }
        Ok(())
    }

    pub async fn handle_add(&self, opts: AddOptions) -> VaultResult<()> {
        let mut vault = Self::load_vault(self.service.clone()).await?;

        // Determine label/username/notes (use provided flags or prompt)
        let label = if let Some(l) = opts.label.clone() {
            l
        } else {
            EntryLabel::from(Text::new("Label (key)").prompt()?)
        };
        if vault.entries.iter().any(|e| e.label == label) {
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
            let rng: Arc<dyn CoreRng<Error = KeviError>> = Arc::new(SystemRng);
            let gen = DefaultPasswordGenerator::new(rng);
            let generated = gen.generate(&policy)?;
            // Show a basic strength hint (interactive UX), without echoing the secret
            let bits = if policy.passphrase {
                estimate_bits_passphrase(policy.words, WORDS.len())
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

        vault.entries.push(entry);
        Self::save_vault(self.service.clone(), vault).await?;
        println!("✅ Entry saved.");

        Ok(())
    }

    pub async fn handle_rm(&self, key: &str, yes: bool) -> VaultResult<()> {
        // Load to check existence and optionally confirm
        let data = Self::load_vault(self.service.clone()).await?;
        if !Self::has_entry(&data, key) {
            Self::print_entry_not_found(key);
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
            .map_err(|_| join_error("removing entry"))?
            .map_err(|e| vault_error("failed to remove entry", e))?;
        if removed {
            println!("🗑️ Entry '{key}' removed.");
        } else {
            // Should not happen due to pre-check, but handle race
            Self::print_entry_not_found(key);
        }
        Ok(())
    }

    pub async fn handle_list(
        &self,
        query: Option<String>,
        show_users: bool,
        json_mode: bool,
    ) -> VaultResult<()> {
        let mut data = Self::load_vault(self.service.clone()).await?;

        // Filter by query (case-insensitive) on a label
        if let Some(q) = query {
            let ql = q.to_lowercase();
            data.entries
                .retain(|e| e.label.as_str().to_lowercase().contains(&ql));
        }

        if json_mode {
            // Build JSON array without secrets
            let items: Vec<serde_json::Value> = data
                .entries
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

        if data.entries.is_empty() {
            println!("(empty)");
            return Ok(());
        }
        for e in data.entries {
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

    pub async fn handle_init(&self, path_override: Option<&str>) -> VaultResult<()> {
        // Decide a path
        let target_path = if let Some(p) = path_override {
            std::path::PathBuf::from(p)
        } else {
            self.config.vault_path.clone().into()
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
                return Err(KeviError::vault("Passwords do not match"));
            }
            pw1
        };

        // Save an empty vault
        let empty = VaultData {
            entries: Vec::new(),
            otps: Vec::new(),
        };
        let path_clone = target_path.clone();
        let master_clone = master.clone();
        spawn_blocking(move || save_vault_file(&empty, &path_clone, &master_clone))
            .await
            .map_err(|_| join_error("initializing vault"))?
            .map_err(|e| vault_error("failed to initialize vault", e))?;
        println!(
            "✅ Initialized encrypted vault at {}",
            target_path.display()
        );
        Ok(())
    }

    pub async fn handle_unlock(&self, ttl_override: Option<u64>) -> VaultResult<()> {
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
        let path: std::path::PathBuf = self.config.vault_path.clone().into();
        let bytes = spawn_blocking(move || fs::read(&path))
            .await
            .map_err(|_| join_error("reading vault file"))?
            .map_err(|e| vault_error("failed to read vault file", e))?;
        let (hdr, _off) =
            parse_kevi_header(&bytes).map_err(|e| vault_error("invalid header", e))?;

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
        )
        .map_err(|e| vault_error("failed to derive key", e))?;
        let fp = header_fingerprint_excluding_nonce(&hdr);
        let dk_path = dk_session_file_for(&self.config.vault_path);
        let key_vec = SecretBox::new(Box::new(key_arr.to_vec()));
        spawn_blocking(move || save_derived_key_session(&dk_path, &fp, &key_vec, ttl))
            .await
            .map_err(|_| join_error("saving derived key session"))?
            .map_err(|e| vault_error("failed to save derived key session", e))?;
        println!("🔓 Unlocked for {ttl_secs}s (derived key cached).");
        Ok(())
    }

    pub async fn handle_lock(&self) -> VaultResult<()> {
        let vault_path = self.config.vault_path.clone();
        spawn_blocking(move || clear_derived_key_cache_for_vault(vault_path.as_path()))
            .await
            .map_err(|_| join_error("clearing derived key session"))?
            .map_err(|e| vault_error("failed to clear derived key session", e))?;
        println!("🔒 Locked (derived-key session cleared).");
        Ok(())
    }
}
