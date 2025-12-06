use crate::cli::cli::{Cli, Commands, GetFieldArg};
use crate::config::config::Config;
use crate::core::vault::Vault;
use crate::tui;
use clap::Parser;
use std::path::PathBuf;

mod cli;

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_init(config.vault_path.to_str()).await?;
        }
        Commands::Header { path } => {
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_header().await?;
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
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            let field_core = match field {
                GetFieldArg::Password => crate::core::vault::GetField::Password,
                GetFieldArg::User => crate::core::vault::GetField::User,
                GetFieldArg::Notes => crate::core::vault::GetField::Notes,
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
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            let opts = crate::core::vault::AddOptions {
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
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_rm(&key, yes).await?;
        }
        Commands::List {
            path,
            show_users,
            query,
            json,
        } => {
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_list(query, show_users, json).await?;
        }
        Commands::Unlock { path, ttl } => {
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_unlock(ttl).await?;
        }
        Commands::Lock { path } => {
            let config = Config::create(path.map(PathBuf::from));
            let vault = Vault::create(&config);
            vault.handle_lock().await?;
        }
        Commands::Tui { path } => {
            let config = Config::create(path.map(PathBuf::from));
            tui::launch(&config).await?;
        }
    }

    Ok(())
}
