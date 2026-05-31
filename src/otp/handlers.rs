use crate::app::wiring::create_vault_service_bypass_cache;
use crate::config::app_config::Config;
use crate::domain::OtpName;
use crate::error::{OtpError, OtpResult};
use crate::filesystem::clipboard::{
    copy_with_ttl_using_system_clipboard, environment_warning, ttl_seconds, ClipboardCopyError,
};
use crate::otp::models::OtpAlgorithm;
use crate::otp::parser::parse_otp_entry;
use crate::otp::totp::{build_totp, validate_totp_params};
use crate::vault::models::VaultData;
use crate::vault::service::VaultService;
use inquire::Confirm;
use kevi_core::otp::service::{OtpDomainService, OtpUpsertError, OtpVaultRepository};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::task::spawn_blocking;

pub struct OtpHandlers<'config> {
    config: &'config Config,
    service: Arc<VaultService>,
}

#[derive(Debug, Clone)]
pub struct OtpAddOptions {
    pub name: OtpName,
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
    pub name: OtpName,
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
    pub name: OtpName,
    pub yes: bool,
}

impl<'config> OtpHandlers<'config> {
    pub fn create(config: &'config Config, service: Arc<VaultService>) -> Self {
        Self { config, service }
    }

    fn service_once(&self) -> Arc<VaultService> {
        create_vault_service_bypass_cache(self.config)
    }

    fn read_service(&self, once: bool) -> Arc<VaultService> {
        if once {
            self.service_once()
        } else {
            self.service.clone()
        }
    }

    async fn load_vault(service: Arc<VaultService>) -> OtpResult<VaultData> {
        spawn_blocking(move || service.load())
            .await
            .map_err(|error| OtpError::Message(error.to_string()))?
            .map_err(|error| OtpError::Message(error.to_string()))
    }

    fn find_otp_entry<'vault_data>(
        vault_data: &'vault_data VaultData,
        name: &OtpName,
    ) -> Option<&'vault_data crate::otp::models::OtpEntry> {
        vault_data.otps.iter().find(|entry| &entry.name == name)
    }

    fn has_otp_entry(vault_data: &VaultData, name: &OtpName) -> bool {
        vault_data.otps.iter().any(|entry| &entry.name == name)
    }

    fn print_otp_entry_not_found(name: &OtpName) {
        println!("❌ {}", OtpError::EntryNotFound(name.to_string()));
    }

    /// Add or update a TOTP entry
    pub async fn handle_add(&self, opts: &OtpAddOptions) -> OtpResult<()> {
        validate_totp_params(opts)?;

        // Determine base entry from uri or manual args
        let entry = parse_otp_entry(opts)?;
        // Validate by constructing a TOTP
        build_totp(&entry)?;

        let domain_service = OtpDomainService::new(VaultServiceOtpRepository {
            service: self.service.as_ref(),
        });
        match domain_service.upsert_entry(entry, opts.on_duplicate_override) {
            Ok(()) => {}
            Err(OtpUpsertError::DuplicateEntry(duplicate_name)) => {
                return Err(OtpError::DuplicateEntry(duplicate_name));
            }
            Err(OtpUpsertError::Repository(error)) => {
                return Err(OtpError::Message(error.to_string()));
            }
        }

        println!("✅ OTP entry saved.");
        Ok(())
    }

    /// Generate a TOTP code and copy/print it
    pub async fn handle_get(&self, opts: OtpGetOptions) -> OtpResult<()> {
        if !opts.echo && opts.no_copy && !opts.json {
            return Err(OtpError::NothingToDo);
        }

        let vault = Self::load_vault(self.read_service(opts.once)).await?;

        let entry = match Self::find_otp_entry(&vault, &opts.name) {
            Some(e) => e,
            None => {
                Self::print_otp_entry_not_found(&opts.name);
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
        let secret = secrecy::SecretString::new(code.clone().into());
        match copy_with_ttl_using_system_clipboard(&secret, ttl) {
            Ok(()) => {}
            Err(ClipboardCopyError::Unavailable(error)) => {
                eprintln!("⚠️ Clipboard not available: {error}");
            }
            Err(ClipboardCopyError::CopyFailed(error)) => {
                eprintln!("⚠️ Failed to copy to clipboard: {error}");
            }
        }

        Ok(())
    }

    /// List OTP entries
    pub async fn handle_list(&self, opts: OtpListOptions) -> OtpResult<()> {
        let mut data = Self::load_vault(self.service.clone()).await?;

        if let Some(q) = opts.query.as_ref() {
            let ql = q.to_lowercase();
            data.otps
                .retain(|o| o.name.as_str().to_lowercase().contains(&ql));
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
    pub async fn handle_remove(&self, opts: OtpRemoveOptions) -> OtpResult<()> {
        let data = Self::load_vault(self.service.clone()).await?;

        if !Self::has_otp_entry(&data, &opts.name) {
            Self::print_otp_entry_not_found(&opts.name);
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
        let name_owned = opts.name.to_string();
        let removed = spawn_blocking(move || {
            let domain_service = OtpDomainService::new(VaultServiceOtpRepository {
                service: svc_rm.as_ref(),
            });
            domain_service.remove_entry(&name_owned)
        })
        .await
        .map_err(|e| OtpError::Message(e.to_string()))?
        .map_err(|e| OtpError::Message(e.to_string()))?;

        if removed {
            println!("🗑️ OTP entry '{}' removed.", opts.name);
        } else {
            Self::print_otp_entry_not_found(&opts.name);
        }

        Ok(())
    }
}

struct VaultServiceOtpRepository<'service> {
    service: &'service VaultService,
}

impl<'service> OtpVaultRepository for VaultServiceOtpRepository<'service> {
    type Error = crate::error::KeviError;

    fn load(&self) -> crate::domain::VaultResult<VaultData> {
        self.service.load()
    }

    fn save(&self, data: &VaultData) -> crate::domain::VaultResult<()> {
        self.service.save(data)
    }
}
