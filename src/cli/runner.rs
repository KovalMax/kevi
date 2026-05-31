use crate::app::wiring::create_vault_service;
use crate::cli::clap_models::{
    Cli, Commands, GetFieldArg, OtpAlgorithmArg, OtpCommand, ProfileCommand,
};
use crate::config::app_config::{
    load_file_config_with_path, save_file_config, Config, FileProfileConfig,
};
use crate::domain::{EntryLabel, OtpName};
use crate::error::KeviError;
use crate::otp::handlers::{
    OtpAddOptions, OtpGetOptions, OtpHandlers, OtpListOptions, OtpRemoveOptions,
};
use crate::otp::models::OtpAlgorithm;
use crate::tui;
use crate::vault::handlers::{GetField, Vault};
use crate::vault::models::AddOptions;
use crate::vault::service::VaultService;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

fn load_config(path: Option<PathBuf>, profile: Option<String>) -> Result<Config, KeviError> {
    Config::create(path, profile).map_err(KeviError::from)
}

pub async fn run() -> Result<(), KeviError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault
                .handle_init(config.vault_path.as_path().to_str())
                .await?;
        }
        Commands::Header { path } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_header().await?;
        }
        Commands::Show {
            key,
            reveal_password,
            path,
        } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_show(&key, reveal_password).await?;
        }
        Commands::Get {
            key,
            path,
            field,
            no_copy,
            echo,
            ttl,
            once,
        } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            let field_core = match field {
                GetFieldArg::Password => GetField::Password,
                GetFieldArg::User => GetField::User,
                GetFieldArg::Notes => GetField::Notes,
            };
            vault
                .handle_get(&key, field_core, no_copy, ttl, echo, once)
                .await?
        }
        Commands::Add {
            path,
            generate,
            length,
            no_lower,
            no_upper,
            no_digits,
            no_symbols,
            allow_ambiguous,
            passphrase,
            words,
            sep,
            label,
            user,
            notes,
        } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            let opts = AddOptions {
                generate,
                length,
                no_lower,
                no_upper,
                no_digits,
                no_symbols,
                allow_ambiguous,
                passphrase,
                words,
                sep,
                label: label.map(EntryLabel::from),
                user,
                notes,
            };
            vault.handle_add(opts).await?;
        }
        Commands::Rm { key, path, yes } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_rm(&key, yes).await?;
        }
        Commands::List {
            path,
            show_users,
            query,
            json,
        } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_list(query, show_users, json).await?;
        }
        Commands::Unlock { path, ttl } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_unlock(ttl).await?;
        }
        Commands::Lock { path } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_lock().await?;
        }
        Commands::Tui { path } => {
            let config = load_config(path.map(PathBuf::from), cli.profile.clone())?;
            tui::launch(&config)
                .await
                .map_err(|e| KeviError::tui(e.to_string()))?;
        }
        Commands::Profile(cmd) => {
            handle_profile_commands(cmd).await?;
        }
        Commands::Otp(cmd) => {
            handle_otp_commands(cmd, cli.profile.clone()).await?;
        }
    }

    Ok(())
}

async fn handle_profile_commands(cmd: ProfileCommand) -> Result<(), KeviError> {
    let (path, mut cfg) = load_file_config_with_path();
    let profiles = cfg.profiles.get_or_insert_with(Default::default);

    match cmd {
        ProfileCommand::List => {
            let default = cfg.default_profile.as_deref();
            if profiles.is_empty() {
                println!("No profiles defined.");
            } else {
                println!("Profiles:");
                for (name, p) in profiles {
                    if Some(name.as_str()) == default {
                        println!("  {name} -> {} (default)", p.vault_path);
                    } else {
                        println!("  {name} -> {}", p.vault_path);
                    }
                }
            }
        }
        ProfileCommand::Show { name } => {
            if let Some(p) = profiles.get(&name) {
                println!("profile: {name}\n  vault_path: {}", p.vault_path);
            } else {
                return Err(ProfileCommandError::Message(format!(
                    "profile \"{name}\" is not defined; run `kevi profile list` to see available profiles"
                ))
                .into());
            }
        }
        ProfileCommand::Add {
            name,
            path: vault_path,
            on_duplicate_override,
        } => {
            if profiles.contains_key(&name) && !on_duplicate_override {
                return Err(ProfileCommandError::Message(format!(
                    "profile \"{name}\" already exists; use --on-duplicate-override to update it"
                ))
                .into());
            }
            profiles.insert(
                name.clone(),
                FileProfileConfig {
                    vault_path: vault_path.clone(),
                },
            );
            println!("Profile \"{name}\" set to vault_path: {vault_path}");
        }
        ProfileCommand::Rm { name } => {
            if cfg.default_profile.as_deref() == Some(name.as_str()) {
                return Err(ProfileCommandError::Message(format!(
                    "cannot remove default profile \"{name}\"; run `kevi profile default --clear` or change default first"
                ))
                .into());
            }
            if profiles.remove(&name).is_some() {
                println!("Removed profile \"{name}\".");
            } else {
                return Err(ProfileCommandError::Message(format!(
                    "profile \"{name}\" is not defined; run `kevi profile list`."
                ))
                .into());
            }
        }
        ProfileCommand::Default { name, clear } => {
            if clear {
                cfg.default_profile = None;
                println!("Default profile cleared.");
            } else if let Some(name) = name {
                if profiles.contains_key(&name) {
                    cfg.default_profile = Some(name.clone());
                    println!("Default profile set to \"{name}\".");
                } else {
                    return Err(ProfileCommandError::Message(format!(
                        "profile \"{name}\" is not defined; run `kevi profile list`."
                    ))
                    .into());
                }
            } else {
                match cfg.default_profile.as_deref() {
                    Some(name) => println!("Default profile: {name}"),
                    None => println!("No default profile set."),
                }
            }
        }
    }

    save_file_config(&path, &cfg)
        .await
        .map_err(ProfileCommandError::from)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum ProfileCommandError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<ProfileCommandError> for KeviError {
    fn from(err: ProfileCommandError) -> Self {
        KeviError::cli(err.to_string())
    }
}

fn map_algo_arg(arg: OtpAlgorithmArg) -> OtpAlgorithm {
    match arg {
        OtpAlgorithmArg::Sha1 => OtpAlgorithm::Sha1,
        OtpAlgorithmArg::Sha256 => OtpAlgorithm::Sha256,
        OtpAlgorithmArg::Sha512 => OtpAlgorithm::Sha512,
    }
}

async fn handle_otp_commands(cmd: OtpCommand, profile: Option<String>) -> Result<(), KeviError> {
    match cmd {
        OtpCommand::Add {
            name,
            secret,
            from_uri,
            issuer,
            username,
            digits,
            period,
            algorithm,
            notes,
            on_duplicate_override,
            path,
        } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpAddOptions {
                name: OtpName::from(name),
                secret,
                from_uri,
                issuer,
                username,
                digits,
                period,
                algorithm: map_algo_arg(algorithm),
                notes,
                on_duplicate_override,
            };
            handlers.handle_add(&opts).await.map_err(KeviError::from)
        }
        OtpCommand::Get {
            name,
            path,
            no_copy,
            echo,
            at,
            once,
            json,
        } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpGetOptions {
                name: OtpName::from(name),
                no_copy,
                echo,
                at,
                once,
                json,
            };
            handlers.handle_get(opts).await.map_err(KeviError::from)
        }
        OtpCommand::List { path, query, json } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpListOptions { query, json };
            handlers.handle_list(opts).await.map_err(KeviError::from)
        }
        OtpCommand::Rm { name, path, yes } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpRemoveOptions {
                name: OtpName::from(name),
                yes,
            };
            handlers.handle_remove(opts).await.map_err(KeviError::from)
        }
    }
}

fn create_config_and_vault_service(
    path: Option<PathBuf>,
    profile: Option<String>,
) -> Result<(Config, Arc<VaultService>), KeviError> {
    let config = load_config(path, profile)?;
    let service = create_vault_service(&config);

    Ok((config, service))
}
