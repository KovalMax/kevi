![ci workflow](https://github.com/KovalMax/kevi/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/github/KovalMax/kevi/graph/badge.svg?token=FOG7F18PST)](https://codecov.io/github/KovalMax/kevi)

# Kevi — encrypted CLI vault

---

Kevi is a secure, terminal‑first password and secrets manager written in Rust.  
It stores all entries in a single encrypted vault using Argon2id for key derivation and AES‑256‑GCM for authenticated encryption.

Kevi focuses on:

- Simple, script‑friendly CLI
- Strong, modern cryptography
- Sensible defaults and minimal configuration
- First‑class support for TOTP (2FA) secrets via `totp-rs`

---

## Features

- **Encrypted vault:**
  - Argon2id KDF with configurable memory/time parameters
  - AES‑256‑GCM for authenticated encryption
  - Atomically writes with backup rotation on save
- **Password management:**
  - Add, get, list, edit, remove entries
  - Strong password/passphrase generator with configurable policy
  - Clipboard integration with configurable TTL
- Derived‑key **session caching** to avoid re‑typing the master passphrase repeatedly.
- **TOTP / OTP:**
  - Store TOTP secrets (Base32 or `otpauth://` URI)
  - Generate current codes
  - List and remove OTP entries in the vault
- **Config & profiles:**
  - `config.toml` with profiles and default vault path
  - CLI/env/config/defaults precedence for options
- **TUI:**
  - Ratatui‑based UI for browsing, editing, adding, and copying credentials

> For a detailed description of the cryptography, threat model, and
> operational security guidance, see [`SECURITY.md`](SECURITY.md).
---

## Installation

```bash
cargo install kevi
```
Or from a source:
```bash
git clone https://github.com/<you>/kevi.git
cd kevi
cargo build --release
```
The resulting binary will be at ```target/release/kevi```

Concepts
---

### Vault

All secrets live in a single **vault file**, which is an encrypted
binary file written in the Kevi format. The vault contains a list of
"entries" each with:

* A **label** (name)
* An optional **username**
* A **password** (or other secret string)
* Optional **notes**

The vault is encrypted with a key derived from your **master
password** using Argon2id. The key and vault contents are never stored
in plaintext on disk.

### Entries

An entry is a single named record in the vault, identified by its
label. You typically use labels like `github`, `email`, `bank`, etc.

For example, an entry might look like:

* label: `github`
* username: `alice`
* password: `...`
* notes: `personal account`

### Clipboard and echoing

Kevi encourages workflows where your actual secrets are kept off the
terminal screen as much as practical:

* By default, when you `get` an entry, Kevi will **copy the
  requested field (usually the password) to the clipboard** and show a
  small textual confirmation.
* You can use `--echo` to print a field to standard output (for
  scripts or when clipboard is not available).
* You can use `--no-copy` to avoid touching the clipboard.

See the usage examples below for concrete combinations.

### Configuration and vault location

Kevi uses a configuration file to find the default vault path and
other options. On Unix‑like systems, the config lives in

```text
$XDG_CONFIG_HOME/kevi/config.toml
```

If `XDG_CONFIG_HOME` is not set, a platform‑specific default config
directory is used (for example `~/.config/kevi/config.toml` on many
Linux distributions). Similar conventions apply on macOS and Windows
via the `dirs` crate.

You can override configuration via **command‑line flags** or
**environment variables**:

* `--path` – explicit path to the vault file for a command.
* `KEVI_VAULT_PATH` – environment variable specifying a default vault
  path.
* `KEVI_CONFIG_DIR` – override the config directory.
* `KEVI_DATA_DIR` – override the data directory (where the default
  vault is stored).

There are additional environment variables for clipboard TTL and
generator defaults; see the configuration section below.

## Quick start
### Initialize a vault

```bash
#Uses default location (config and data dirs)
kevi init
```

You will be prompted for a master password.

The vault is stored as an encrypted RON file (e.g., vault.ron) in the data directory.

### Add a password entry
```bash
# interactively enter username, password, notes, or let Kevi generate one
kevi add

# or specify all fields explicitly
kevi add \
  --label github \
  --user alice \
  --password 's3cret' \
  --notes 'personal account'
```
You can also tell Kevi to generate a random password instead of
supplying one explicitly; see the `add` command help.

### Get and copy a password
```bash
# Prints nothing, copies password to clipboard for the configured TTL
kevi get github

# Prints the password to stdout, no clipboard interaction
kevi get github --echo --no-copy

# Prints nothing, copies user to clipboard for the configured TTL
kevi get github --field user
```

### List

List entries in the vault:

```bash
kevi list [--query <TERM>] [--show-users] [--json]
```

Options:

* `--query` – filter labels by a case‑insensitive substring.
* `--show-users` – include usernames in the output.
* `--json` – output in JSON format.

### `unlock` and `lock`

Kevi supports caching a derived key in a session file to avoid
repeatedly entering your master password.

```bash
kevi unlock [--ttl <SECONDS>]

kevi lock
```

* `unlock` derives a key from your password, binds it to the vault
  header via a fingerprint, and stores it in a small session file with
  a TTL.
* `lock` removes the session file so future operations will prompt for
  the password again.

## OTP / TOTP usage
#### Kevi can store and generate TOTP (time‑based OTP) codes alongside your passwords, using totp-rs under the hood.

### Add an OTP secret
#### You can add a TOTP secret either as a Base32 key or as an otpauth://URI

### From a Base32 secret
```bash
kevi otp add github-2fa \
  --secret JBSWY3DPEHPK3PXP \
  --issuer GitHub \
  --username you@example.com \
  --digits 6 \
  --period 30
```
- ```--secret``` is the Base32‑encoded key exported from your authenticator.
- ```--issuer```, ```--username```, ```--digits```, ```--period```, ```--algorithm``` override defaults when needed.

### From an otpauth URI
```bash
kevi otp add github-2fa --from-uri "otpauth://totp/GitHub:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```
- Kevi parses the URI, extracts secret, issuer, digits, period, and algorithm.
- CLI flags (like ```--name```, ```--issuer```, ```--username```, ```--digits```, ```--period```, ```--algorithm```) can still override the parsed values.

If an entry with the same name exists:
- Without flags, add fails with an error.
- To replace it, use:
```bash
kevi otp add github-2fa \
  --secret NEWSECRETBASE32 \
  --on-duplicate-override
```

### Generate and copy OTP codes
To generate the current TOTP code for an existing OTP entry:
```bash
# Generate and copy to clipboard (default behavior)
kevi otp get github-2fa
```
Useful flags:
- ```--echo```: also print the code to stdout, e.g.:
- ```--no-copy```: do not touch the clipboard.
- ```--json```: print a JSON object with metadata:
- ```--at <unix_ts>```: generate the code at a specific timestamp (for debugging):
- ```--once```: bypass any session cache and always ask for the vault password to derive the key (if your resolver supports that semantics).

```bash
kevi otp get github-2fa --echo --no-copy

kevi otp get github-2fa --json --no-copy

kevi otp get github-2fa --at 1700000000 --echo --no-copy
```

The clipboard TTL is taken from config/environment or defaults (e.g. ```KEVI_CLIP_TTL```).

### List OTP entries
#### To list all OTP entries stored in the vault:
```bash
kevi otp list

#example output:
github-2fa   GitHub   30s   6 digits   SHA1
work-2fa     Work     30s   6 digits   SHA1
```
#### Filter by name:
```bash
kevi otp list --query github
```
#### JSON output (suitable for scripting):
```bash
kevi otp list --json
```
Each item includes ```name```, ```issuer```, ```digits```, ```period```, and ```algorithm```.

### Remove an OTP entry
#### Remove an OTP entry by name:
```bash
# With confirmation
kevi otp rm github-2fa
```
#### Use ```--yes``` (or the flag you defined) to skip the confirmation prompt:
```bash
kevi otp rm github-2fa --yes
```
If the entry does not exist, Kevi prints a friendly message and exits successfully.

## Profiles

You can define named profiles in your `config.toml` (or via CLI) to avoid passing `--path` for different vaults.

Manage profiles via the CLI:

```bash
# Add or update a profile
kevi profile add work --path /home/alice/work/kevi-work.ron --on-duplicate-override

# List and inspect profiles
kevi profile list
kevi profile show work

# Set or clear default profile
kevi profile default work
kevi profile default --clear
```

Use a profile with any command:

```bash
kevi --profile work list
kevi --profile work get github --field password --echo --no-copy
kevi --profile work tui
```

Profiles only change **which vault file** is used; they do not change the cryptography or security model.

Environment variables can override some of these:

* `KEVI_VAULT_PATH` – override `vault_path`.
* `KEVI_CLIP_TTL` – override `clipboard_ttl_secs`.
* `KEVI_BACKUPS` – override `backups`.
* `KEVI_GEN_LENGTH`, `KEVI_GEN_*` – override password generator
  defaults.


TUI usage
---------

Run:

```bash
kevi tui [--path <FILE>]
```

This opens an interactive TUI built on top of the `ratatui` and
`crossterm` crates. Exact key bindings may evolve, but typical
behaviors include:

* **Navigation** – use arrow keys, `j/k`, or PageUp/PageDown to move
  through the list of entries.
* **Search/filter** – start typing or use a dedicated search key to
  filter by label.
* **Copy password** – press `Enter` on a selected entry to copy its
  password to the clipboard; a short message appears indicating the
  clipboard TTL.
* **Copy username** – press `u` to copy the username of the selected
  entry to the clipboard.
* **Details view** – open a detailed view of an entry showing label,
  username, notes, and a masked password. Future versions may support
  an explicit reveal toggle.

The TUI is designed to avoid printing passwords to the screen by
default; operations are oriented around copying to the clipboard.

## Configuration
### Kevi reads configuration from:
1. CLI flags
2. Environment variables
3. ```config.toml``` (e.g. ```~/.config/kevi/config.toml```)
4. Built‑in defaults

### Example ```config.toml```:
```toml
vault_path = "/home/user/.local/share/kevi/vault.ron"
clipboard_ttl = 20
backups = 3

default_profile = "work"

[profiles.work]
vault_path = "/home/user/.local/share/kevi/work-vault.ron"

[profiles.personal]
vault_path = "/home/user/.local/share/kevi/personal-vault.ron"
``` 

### Typical fields include:
* `vault_path` – default path to the vault file.
* `clipboard_ttl` – how long secrets stay in the clipboard
  (approximate; depends on platform support).
* `backups` – how many historical versions of the vault file to keep
  when writing.

### Some env overrides:
- ```KEVI_VAULT_PATH``` – override vault path
- ```KEVI_CLIP_TTL``` – clipboard TTL in seconds
- ```KEVI_BACKUPS``` – number of rotated backups
- ```KEVI_CONFIG_DIR```, ```KEVI_DATA_DIR``` – override config/data roots

## Security notes
- Kevi uses Argon2id for key derivation and AES‑256‑GCM for encryption.
- Secrets (passwords, OTP secrets) are kept in memory using ```secrecy``` to avoid accidental logging.
- Best‑effort ```mlock``` is available on Unix via the ```memlock``` feature to protect sensitive memory from swapping.
- Clipboard integration respects TTL but cannot protect against all OS‑level attacks; treat clipboard as a convenience, not a strong boundary.

Development
-----------

### Running tests and linters

From the project root:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

On Linux, you can also run tests with the `memlock` feature enabled:

```bash
cargo test --all --features memlock
```

### Code coverage

If you have `cargo-llvm-cov` installed, you can generate coverage
locally with:

```bash
cargo llvm-cov --workspace --no-cfg-coverage --html
```

This will create an HTML report under a `coverage-html` directory.

### Continuous Integration

This repository includes a GitHub Actions workflow that runs:

* `cargo fmt --all` (format check)
* `cargo clippy --all-targets --all-features -- -D warnings`
* `cargo build --all`
* `cargo test --all` (with and without `memlock` on Linux)
* `cargo audit` (via a dedicated job)
* `cargo llvm-cov` for coverage reporting

You can mirror these steps locally before pushing changes.

### Contributing

Contributions, bug reports, and feature ideas are welcome. When
submitting a pull request:

* Run `cargo fmt`, `cargo clippy`, and `cargo test` locally.
* Try to include tests for new functionality where practical.
* Avoid logging or printing secrets; prefer redacted debug output.