use clap::{Parser, Subcommand, ValueEnum};

const KEVI_LONG_VERSION: &str = concat!(
"version: ", env!("CARGO_PKG_VERSION"), "\n",
"git sha: ", env!("KEVI_GIT_SHA"), "\n",
"build time (UTC): ", env!("KEVI_BUILD_TIME"), "\n",
"target: ", env!("KEVI_TARGET"), "\n",
"features: ", env!("KEVI_FEATURES")
);

#[derive(Parser)]
#[command(
    name = "kevi",
    version = env!("CARGO_PKG_VERSION"),
    long_version = KEVI_LONG_VERSION,
    about = " 🦾 Kevi — Secure CLI Vault"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Get secret by key and copy to clipboard
    Get {
        /// Entry label (key)
        key: String,
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Which field to retrieve
        #[arg(long, value_enum, default_value = "password")]
        field: GetFieldArg,
        /// Do not copy to clipboard
        #[arg(long)]
        no_copy: bool,
        /// Print the selected field to stdout (use with --no-copy for safe piping)
        #[arg(long)]
        echo: bool,
        /// Clipboard TTL in seconds (overrides KEVI_CLIP_TTL)
        #[arg(long)]
        ttl: Option<u64>,
        /// Bypass the session cache for this command (derive key from passphrase without caching)
        #[arg(long)]
        once: bool,
    },
    /// Inspect and print the encrypted vault header (no secrets are revealed)
    Header {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
    },
    /// Initialize a new vault
    Init {
        /// Vault file path
        path: Option<String>,
    },

    /// Add a new key and secret
    Add {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Generate a password instead of prompting
        #[arg(long)]
        generate: bool,
        /// Generated password length (character mode)
        #[arg(long)]
        length: Option<u16>,
        /// Disable lowercase letters in generation
        #[arg(long)]
        no_lower: bool,
        /// Disable uppercase letters in generation
        #[arg(long)]
        no_upper: bool,
        /// Disable digits in generation
        #[arg(long)]
        no_digits: bool,
        /// Disable symbols in generation
        #[arg(long)]
        no_symbols: bool,
        /// Allow ambiguous characters like O/0/I/l/|
        #[arg(long)]
        allow_ambiguous: bool,
        /// Passphrase mode (ignore length/classes; use words + sep)
        #[arg(long)]
        passphrase: bool,
        /// Number of words for passphrase mode
        #[arg(long)]
        words: Option<u16>,
        /// Separator string for passphrase mode
        #[arg(long)]
        sep: Option<String>,
        /// Optional label (key) to avoid interactive prompt
        #[arg(long)]
        label: Option<String>,
        /// Optional username value (empty if omitted)
        #[arg(long)]
        user: Option<String>,
        /// Optional notes value (empty if omitted)
        #[arg(long)]
        notes: Option<String>,
    },

    /// Remove an entry by key
    Rm {
        key: String,
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
    /// List entries (labels only by default)
    List {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Show usernames alongside labels
        #[arg(long)]
        show_users: bool,
        /// Filter labels by substring (case-insensitive)
        #[arg(long)]
        query: Option<String>,
        /// Output JSON array (machine-readable). Includes `username` only when --show-users is set.
        #[arg(long)]
        json: bool,
    },
    /// Unlock a session cache for a TTL in seconds (default from KEVI_UNLOCK_TTL or 900)
    Unlock {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Clear session cache
    Lock {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
    },
    /// Launch the interactive Terminal UI
    Tui {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum GetFieldArg {
    Password,
    User,
    Notes,
}