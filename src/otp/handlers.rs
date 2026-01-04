use crate::config::app_config::Config;
use crate::filesystem::clipboard::{
    copy_with_ttl, environment_warning, ttl_seconds, ClipboardEngine, SystemClipboardEngine,
};
use crate::filesystem::store::FileByteStore;
use crate::otp::models::OtpAlgorithm;
use crate::otp::parser::parse_otp_entry;
use crate::otp::totp::{build_totp, validate_totp_params};
use crate::session_management::resolver::BypassKeyResolver;
use crate::vault::codec::RonCodec;
use crate::vault::ports::{ByteStore, KeyResolver, VaultCodec};
use crate::vault::service::VaultService;
use anyhow::{anyhow, Result};
use inquire::Confirm;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::spawn_blocking;

pub struct OtpHandlers<'a> {
    config: &'a Config,
    service: Arc<VaultService>,
}

#[derive(Debug, Clone)]
pub struct OtpAddOptions {
    pub name: String,
    pub secret: Option<String>,
    pub from_uri: Option<String>,
    pub issuer: Option<String>,
    pub username: Option<String>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: OtpAlgorithm,
    pub notes: Option<String>,
    pub on_duplicate_override: bool,
}

#[derive(Debug, Clone)]
pub struct OtpGetOptions {
    pub name: String,
    pub no_copy: bool,
    pub echo: bool,
    pub at: Option<u64>,
    pub once: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct OtpListOptions {
    pub query: Option<String>,
    pub json: bool,
}

#[derive(Debug, Clone)]
pub struct OtpRemoveOptions {
    pub name: String,
    pub yes: bool,
}

impl<'a> OtpHandlers<'a> {
    pub fn create(config: &'a Config, service: Arc<VaultService>) -> Self {
        Self { config, service }
    }

    fn service_once(&self) -> Arc<VaultService> {
        let store: Arc<dyn ByteStore> =
            Arc::new(FileByteStore::new(self.config.vault_path.clone()));
        let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
        let resolver: Arc<dyn KeyResolver> = Arc::new(BypassKeyResolver::new());
        Arc::new(VaultService::new(store, codec, resolver))
    }

    /// Add or update a TOTP entry
    pub async fn handle_add(&self, opts: &OtpAddOptions) -> Result<()> {
        validate_totp_params(opts)?;

        // Load vault
        let svc_load = self.service.clone();
        let mut vault = spawn_blocking(move || svc_load.load())
            .await?
            .map_err(|_| anyhow!("task join error"))?;

        // Determine base entry from uri or manual args
        let entry = parse_otp_entry(opts)?;
        // Validate by constructing a TOTP
        build_totp(&entry)?;

        let exists = vault.otps.iter().position(|o| o.name == entry.name);
        match exists {
            Some(idx) if opts.on_duplicate_override => {
                vault.otps[idx] = entry;
            }
            Some(_) => {
                anyhow::bail!(
                    "otp entry \"{}\" already exists; use --on-duplicate-override to replace",
                    opts.name
                );
            }
            None => vault.otps.push(entry),
        }

        let svc_save = self.service.clone();
        spawn_blocking(move || svc_save.save(&vault))
            .await
            .map_err(|_| anyhow!("task join error"))??;

        println!("✅ OTP entry saved.");
        Ok(())
    }

    /// Generate a TOTP code and copy/print it
    pub async fn handle_get(&self, opts: OtpGetOptions) -> Result<()> {
        if !opts.echo && opts.no_copy && !opts.json {
            anyhow::bail!("nothing to do: use --echo or remove --no-copy");
        }

        // Load vault (optionally bypass cache)
        let svc = if opts.once {
            self.service_once()
        } else {
            self.service.clone()
        };

        let vault = spawn_blocking(move || svc.load())
            .await?
            .map_err(|_| anyhow!("task join error"))?;

        let entry = match vault.otps.iter().find(|o| o.name == opts.name) {
            Some(e) => e,
            None => {
                println!("❌ No OTP entry found with name '{}'.", opts.name);
                return Ok(());
            }
        };

        let totp = build_totp(entry)?;
        let timestamp = opts.at.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs()
        });
        let code = totp.generate(timestamp);

        if opts.json {
            let out = json!({
                "name": entry.name,
                "code": code,
                "period": entry.period,
                "digits": entry.digits,
                "algorithm": entry.algorithm.format(),
                "issuer": entry.issuer,
                "at": timestamp,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            return Ok(());
        }

        if opts.echo {
            println!("{code}");
        }

        if opts.no_copy {
            return Ok(());
        }

        let ttl_secs = ttl_seconds(self.config, None);
        let ttl = Duration::from_secs(ttl_secs);
        if let Some(warn) = environment_warning() {
            eprintln!("⚠️ {warn}");
        }
        match SystemClipboardEngine::new() {
            Ok(engine_impl) => {
                let engine = Arc::new(engine_impl) as Arc<dyn ClipboardEngine>;
                let secret = secrecy::SecretString::new(code.clone().into());
                if let Err(e) = copy_with_ttl(engine, &secret, ttl) {
                    eprintln!("⚠️ Failed to copy to clipboard: {e}");
                }
            }
            Err(e) => eprintln!("⚠️ Clipboard not available: {e}"),
        }

        Ok(())
    }

    /// List OTP entries
    pub async fn handle_list(&self, opts: OtpListOptions) -> Result<()> {
        let svc = self.service.clone();
        let mut data = spawn_blocking(move || svc.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;

        if let Some(q) = opts.query.as_ref() {
            let ql = q.to_lowercase();
            data.otps.retain(|o| o.name.to_lowercase().contains(&ql));
        }

        if opts.json {
            let items: Vec<serde_json::Value> = data
                .otps
                .iter()
                .map(|o| {
                    json!({
                        "name": o.name,
                        "issuer": o.issuer,
                        "period": o.period,
                        "digits": o.digits,
                        "algorithm": o.algorithm.format(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&items)?);
            return Ok(());
        }

        if data.otps.is_empty() {
            println!("(empty)");
            return Ok(());
        }

        for o in data.otps {
            match &o.issuer {
                Some(iss) => println!(
                    "{}\t{}\t{}s\t{} digits\t{}",
                    o.name,
                    iss,
                    o.period,
                    o.digits,
                    o.algorithm.format()
                ),
                None => println!(
                    "{}\t{}s\t{} digits\t{}",
                    o.name,
                    o.period,
                    o.digits,
                    o.algorithm.format()
                ),
            }
        }

        Ok(())
    }

    /// Remove an OTP entry
    pub async fn handle_remove(&self, opts: OtpRemoveOptions) -> Result<()> {
        let svc_load = self.service.clone();
        let data = spawn_blocking(move || svc_load.load())
            .await
            .map_err(|_| anyhow!("task join error"))??;

        if !data.otps.iter().any(|o| o.name == opts.name) {
            println!("❌ No OTP entry found with name '{}'.", opts.name);
            return Ok(());
        }

        if !opts.yes {
            let msg = format!("Delete OTP entry '{}'?", opts.name);
            let proceed = Confirm::new(&msg).with_default(false).prompt()?;
            if !proceed {
                println!("❎ Deletion cancelled.");
                return Ok(());
            }
        }

        let svc_rm = self.service.clone();
        let name_owned = opts.name.clone();
        let removed = spawn_blocking(move || {
            let mut vault = svc_rm.load()?;
            let before = vault.otps.len();
            vault.otps.retain(|o| o.name != name_owned);
            let changed = vault.otps.len() != before;
            if changed {
                svc_rm.save(&vault)?;
            }
            Ok::<bool, anyhow::Error>(changed)
        })
        .await
        .map_err(|_| anyhow!("task join error"))??;

        if removed {
            println!("🗑️ OTP entry '{}' removed.", opts.name);
        } else {
            println!("❌ No OTP entry found with name '{}'.", opts.name);
        }

        Ok(())
    }
}
