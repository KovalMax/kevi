![ci workflow](https://github.com/KovalMax/kevi/actions/workflows/ci.yml/badge.svg)

# Kevi — encrypted CLI vault
===================================================

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
  - Atomic writes with backup rotation on save
- **Password management:**
  - Add, get, list, edit, remove entries
  - Strong password/passphrase generator with configurable policy
  - Clipboard integration with configurable TTL
- **TOTP / OTP:**
  - Store TOTP secrets (Base32 or `otpauth://` URI)
  - Generate current codes
  - List and remove OTP entries in the vault
- **Config & profiles:**
  - `config.toml` with profiles and default vault path
  - CLI/env/config/defaults precedence for options
- **TUI (optional):**
  - Ratatui‑based UI for browsing and copying credentials

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
kevi add github
```

### Get and copy a password
```bash
# Prints nothing, copies password to clipboard for the configured TTL
kevi get github
```

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

### From an otpauth://URI
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