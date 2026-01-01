use crate::cli::clap_models::{
    Cli, Commands, GetFieldArg, OtpAlgorithmArg, OtpCommand, ProfileCommand,
};
use crate::config::app_config::{
    load_file_config_with_path, save_file_config, Config, FileProfileConfig,
};
use crate::filesystem::store::FileByteStore;
use crate::otp::handlers::{
    OtpAddOptions, OtpGetOptions, OtpHandlers, OtpListOptions, OtpRemoveOptions,
};
use crate::otp::models::OtpAlgorithm;
use crate::session_management::resolver::CachedKeyResolver;
use crate::tui;
use crate::vault::codec::RonCodec;
use crate::vault::handlers::Vault;
use crate::vault::models::AddOptions;
use crate::vault::ports::{ByteStore, KeyResolver, VaultCodec};
use crate::vault::service::VaultService;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_init(config.vault_path.to_str()).await?;
        }
        Commands::Header { path } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_header().await?;
        }
        Commands::Show {
            key,
            reveal_password,
            path,
        } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
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
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            let field_core = match field {
                GetFieldArg::Password => crate::vault::handlers::GetField::Password,
                GetFieldArg::User => crate::vault::handlers::GetField::User,
                GetFieldArg::Notes => crate::vault::handlers::GetField::Notes,
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
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
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
                label,
                user,
                notes,
            };
            vault.handle_add(opts).await?;
        }
        Commands::Rm { key, path, yes } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_rm(&key, yes).await?;
        }
        Commands::List {
            path,
            show_users,
            query,
            json,
        } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_list(query, show_users, json).await?;
        }
        Commands::Unlock { path, ttl } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_unlock(ttl).await?;
        }
        Commands::Lock { path } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            let vault = Vault::create(&config);
            vault.handle_lock().await?;
        }
        Commands::Tui { path } => {
            let config = Config::create(path.map(PathBuf::from), cli.profile.clone())?;
            tui::launch(&config).await?;
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

async fn handle_profile_commands(cmd: ProfileCommand) -> anyhow::Result<()> {
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
                anyhow::bail!("profile \"{name}\" is not defined; run `kevi profile list` to see available profiles");
            }
        }
        ProfileCommand::Add {
            name,
            path: vault_path,
            on_duplicate_override,
        } => {
            if profiles.contains_key(&name) && !on_duplicate_override {
                anyhow::bail!(
                    "profile \"{name}\" already exists; use --on-duplicate-override to update it"
                );
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
                anyhow::bail!(
                    "cannot remove default profile \"{name}\"; run `kevi profile default --clear` or change default first"
                );
            }
            if profiles.remove(&name).is_some() {
                println!("Removed profile \"{name}\".");
            } else {
                anyhow::bail!("profile \"{name}\" is not defined; run `kevi profile list`.");
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
                    anyhow::bail!("profile \"{name}\" is not defined; run `kevi profile list`.");
                }
            } else {
                match cfg.default_profile.as_deref() {
                    Some(name) => println!("Default profile: {name}"),
                    None => println!("No default profile set."),
                }
            }
        }
    }

    save_file_config(&path, &cfg).await?;
    Ok(())
}

fn map_algo_arg(arg: OtpAlgorithmArg) -> OtpAlgorithm {
    match arg {
        OtpAlgorithmArg::Sha1 => OtpAlgorithm::Sha1,
        OtpAlgorithmArg::Sha256 => OtpAlgorithm::Sha256,
        OtpAlgorithmArg::Sha512 => OtpAlgorithm::Sha512,
    }
}

async fn handle_otp_commands(cmd: OtpCommand, profile: Option<String>) -> anyhow::Result<()> {
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
                name,
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
            handlers.handle_add(&opts).await
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
                name,
                no_copy,
                echo,
                at,
                once,
                json,
            };
            handlers.handle_get(opts).await
        }
        OtpCommand::List { path, query, json } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpListOptions { query, json };
            handlers.handle_list(opts).await
        }
        OtpCommand::Rm { name, path, yes } => {
            let (config, service) =
                create_config_and_vault_service(path.map(PathBuf::from), profile.clone())?;
            let handlers = OtpHandlers::create(&config, service);
            let opts = OtpRemoveOptions { name, yes };
            handlers.handle_remove(opts).await
        }
    }
}

fn create_config_and_vault_service(
    path: Option<PathBuf>,
    profile: Option<String>,
) -> anyhow::Result<(Config, Arc<VaultService>)> {
    let config = Config::create(path, profile.clone())?;
    let backups = config.backups.unwrap_or(2);
    let store: Arc<dyn ByteStore> = Arc::new(FileByteStore::new_with_backups(
        config.vault_path.clone(),
        backups,
    ));
    let codec: Arc<dyn VaultCodec> = Arc::new(RonCodec);
    let key_resolver: Arc<dyn KeyResolver> =
        Arc::new(CachedKeyResolver::new(config.vault_path.clone()));
    let service = Arc::new(VaultService::new(store, codec, key_resolver));

    Ok((config, service))
}
