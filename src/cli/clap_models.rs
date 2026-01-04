use clap::{Parser, Subcommand, ValueEnum};

const KEVI_LONG_VERSION: &str = concat!(
    "version: ",
    env!("CARGO_PKG_VERSION"),
    "\n",
    "git sha: ",
    env!("KEVI_GIT_SHA"),
    "\n",
    "build time (UTC): ",
    env!("KEVI_BUILD_TIME"),
    "\n",
    "target: ",
    env!("KEVI_TARGET"),
    "\n",
    "features: ",
    env!("KEVI_FEATURES")
);

#[derive(Parser)]
#[command(
    name = "kevi",
    version = env!("CARGO_PKG_VERSION"),
    long_version = KEVI_LONG_VERSION,
    about = " 🦾 Kevi — Secure CLI Vault"
)]
pub struct Cli {
    /// Named profile from config.toml to resolve the vault path
    #[arg(long)]
    pub profile: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage one-time passwords (TOTP)
    #[command(subcommand)]
    Otp(OtpCommand),
    /// Manage named vault profiles
    #[command(subcommand)]
    Profile(ProfileCommand),

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
    /// Show entry details (optionally revealing password)
    Show {
        /// Entry label
        key: String,
        /// Reveal the password in plain text
        #[arg(long)]
        reveal_password: bool,
        /// Vault file path override
        #[arg(long)]
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

#[derive(Subcommand, Debug, Clone)]
pub enum OtpCommand {
    /// Add or update a TOTP entry
    Add {
        /// Entry label (name)
        name: String,
        /// Base32 secret (mutually exclusive with --from-uri)
        #[arg(long, value_name = "BASE32", conflicts_with = "from_uri")]
        secret: Option<String>,
        /// otpauth:// URI to parse (mutually exclusive with --secret)
        #[arg(long, value_name = "URI", conflicts_with = "secret")]
        from_uri: Option<String>,
        /// Optional issuer
        #[arg(long)]
        issuer: Option<String>,
        /// Optional username of an account
        #[arg(long)]
        username: Option<String>,
        /// Number of digits in generated code (6 or 8)
        #[arg(long, value_parser = clap::value_parser!(u32).range(6..=8), default_value = "6")]
        digits: u32,
        /// Time step in seconds
        #[arg(long, default_value = "30")]
        period: u64,
        /// Algorithm for HMAC
        #[arg(long, value_enum, default_value = "sha1")]
        algorithm: OtpAlgorithmArg,
        /// Optional notes
        #[arg(long)]
        notes: Option<String>,
        /// Overwrite existing entry if it already exists
        #[arg(long = "on-duplicate-override")]
        on_duplicate_override: bool,
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
    },

    /// Generate a TOTP code for an entry
    Get {
        /// Entry label (name)
        name: String,
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Do not copy to clipboard
        #[arg(long)]
        no_copy: bool,
        /// Print the code to stdout
        #[arg(long)]
        echo: bool,
        /// Generate code for a specific timestamp (seconds since Unix epoch)
        #[arg(long)]
        at: Option<u64>,
        /// Bypass the session cache for this command (derive key from passphrase without caching)
        #[arg(long)]
        once: bool,
        /// Output JSON
        #[arg(long)]
        json: bool,
    },

    /// List TOTP entries
    List {
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Filter labels by substring (case-insensitive)
        #[arg(long)]
        query: Option<String>,
        /// Output JSON array (machine-readable)
        #[arg(long)]
        json: bool,
    },

    /// Remove a TOTP entry by name
    Rm {
        /// Entry label (name)
        name: String,
        /// Vault file path override
        #[arg(long)]
        path: Option<String>,
        /// Do not ask for confirmation
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OtpAlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProfileCommand {
    /// List all profiles
    List,

    /// Show details of a profile
    Show { name: String },

    /// Add or update a profile
    Add {
        name: String,
        #[arg(long, value_name = "FILE")]
        path: String,
        /// Overwrite an existing profile if it already exists
        #[arg(long = "on-duplicate-override")]
        on_duplicate_override: bool,
    },

    /// Remove a profile
    Rm { name: String },

    /// View or modify the default profile
    Default {
        /// Name of the profile to set as default; omit to just show the current default
        name: Option<String>,
        /// Clear any existing default profile
        #[arg(long = "clear")]
        clear: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum GetFieldArg {
    Password,
    User,
    Notes,
}
