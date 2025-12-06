# Kevi — Secure CLI Vault

Kevi is a secure command‑line key/secret vault. Secrets are encrypted at rest using Argon2id key derivation and
AES‑256‑GCM with an authenticated header. Clipboard operations auto‑clear after a TTL. A minimal TUI is included. A
derived‑key session cache is available to reduce prompts without storing the passphrase.

## Features

- Encrypted vault with an authenticated header (Argon2id + AES‑256‑GCM)
- Strong file handling: atomically writes, strict permissions, rotating encrypted backups
- Clipboard copy with TTL and previous content restore (safe‑by‑default, no secret stdout)
- Session unlock/lock with derived‑key cache (bound to header params + salt; never stores the passphrase)
- Generator: strong passwords (char‑mode) and passphrases (bundled curated wordlist), with configurable defaults
- Minimal TUI: list/search, copy password/username (never renders secrets)

## Install

```
cargo install --path .
# or run from source
cargo run -- <command>
```

Releases:

- Tagged builds publish artifacts for Linux/macOS/Windows (see GitHub Releases).
- Each archive includes a stripped binary, SBOM (CycloneDX, Linux build), and SHA256 checksums.
- Verify build metadata:
  ```
  kevi --version
  # example output:
  # version: 0.1.0
  # git sha: abcdef123456
  # build time (UTC): 2025-12-03T12:00:00Z
  # target: x86_64-unknown-linux-gnu
  # features: default
  ```

## Quick start

```
# Initialize a new vault
kevi init --path ~/.kevi/vault.ron

# Add an entry (interactive)
kevi add --path ~/.kevi/vault.ron

# Get (copy to clipboard, default TTL 20s; prints nothing by default)
kevi get my-label --path ~/.kevi/vault.ron

# Echo the field to stdout without copying (for safe piping)
kevi get my-label --no-copy --echo --path ~/.kevi/vault.ron
```

## Commands

- `kevi init [--path <vault>]` — create a new encrypted vault
- `kevi get <label> [--path <vault>] [--field password|user|notes] [--no-copy] [--echo] [--ttl SECONDS] [--once]` —
  retrieve/copy a field; `--once` bypasses session cache
- `kevi add [--path <vault>] [--generate [--length N | --passphrase --words N --sep SEP] --no-lower --no-upper --no-digits --no-symbols --allow_ambiguous] [--label L --user U --notes N]` —
add an entry
- `kevi rm <label> [--path <vault>] [--yes]` — remove an entry (asks for confirmation unless `--yes`)
- `kevi list [--path <vault>] [--show-users] [--query <substr>] [--json]` — list labels (and usernames if requested),
  filterable and machine‑readable
- `kevi unlock [--path <vault>] [--ttl SECONDS]` — cache a derived key for a TTL (header‑bound)
- `kevi lock [--path <vault>]` — clear the derived‑key session cache
- `kevi header [--path <vault>]` — print parsed header (no secrets)
- `kevi tui [--path <vault>]` — launch the minimal terminal UI

## Clipboard behavior

- Default TTL: 20s
- Precedence for TTL in `get`: `--ttl` > `KEVI_CLIP_TTL` > config file > default (20)
- Auto‑restores previous clipboard content after the TTL
- Best‑effort warning in SSH/headless environments (no secrets are printed automatically); consider `--no-copy --echo`
  for piping

## Configuration and paths

Kevi loads `config.toml` from the platform config dir (override with `KEVI_CONFIG_DIR`). Default vault lives under
platform data dir (override base with `KEVI_DATA_DIR`).

Config file example:

```
# ~/.config/kevi/config.toml (Linux/macOS) or %APPDATA%\kevi\config.toml (Windows)
vault_path = "/home/me/.kevi/vault.ron"
clipboard_ttl = 45
backups = 3
# Generator defaults (optional; can be overridden by KEVI_GEN_* env vars or CLI flags)
generator_length = 28
generator_words = 6
generator_sep = ":"
avoid_ambiguous = true
```

Precedence rules:

- Vault path: CLI `--path` > `KEVI_VAULT_PATH` > config file > default (from data dir)
- Clipboard TTL: CLI `--ttl` (in `get`) > `KEVI_CLIP_TTL` > config file > default (20)
- Backups kept: `KEVI_BACKUPS` > config file > default (2)
- Generator defaults: CLI flags > `KEVI_GEN_*`/`KEVI_AVOID_AMBIGUOUS` env > config file > internal defaults

Related env vars:

- `KEVI_VAULT_PATH`, `KEVI_CLIP_TTL`, `KEVI_BACKUPS`
- `KEVI_GEN_LENGTH`, `KEVI_GEN_WORDS`, `KEVI_GEN_SEP`, `KEVI_AVOID_AMBIGUOUS`
- `KEVI_CONFIG_DIR` (override config location), `KEVI_DATA_DIR` (override data root for default vault)

## Backups

Rotating, encrypted backups are kept as `<vault>.1`, `<vault>.2`, … up to a configured count (default 2).

- Preferred: set `backups` in `~/.config/kevi/config.toml`.
- Env override (optional): `KEVI_BACKUPS`.
- Set to `0` to disable.

## Security guarantees (short)

- Data at rest is encrypted with Argon2id (per‑file salt and encoded params) and AES‑256‑GCM.
- The header is bound as AEAD Associated Data for tamper detection.
- Unix permissions: directories 0700, files 0600 (best‑effort on other platforms).
- Derived‑key session cache binds to header params + salt; salt remains stable per vault; only nonce rotates per save.
- Optional best‑effort memory locking (`--features memlock` on Unix) for derived keys during crypto operations.
- The TUI never renders secrets; copy actions use TTL and restore previous clipboard.

See SECURITY.md for the threat model and limitations.

## TUI

```
kevi tui --path ~/.kevi/vault.ron
```

Keybindings: `q` quit, `j/k` or arrows to navigate, `/` search, `Enter` copy password, `u` copy username.

Theme: NES/SEGA‑inspired palette (blue/red accents on dark background). See `docs/tui.md`.

## Header inspection

```
kevi header --path ~/.kevi/vault.ron
```

Prints version, KDF/AEAD ids, Argon2 params, salt/nonce (hex). No plaintext secrets are revealed.

## Development

CI enforces: `cargo fmt --check`, `clippy -D warnings`, tests, and `cargo audit`.

Optional hardening:

- Build/tests with `memlock` (Linux): `cargo test --features memlock`

Release helpers:

- Local reproducible build script: `scripts/release.sh` (produces stripped binary + SHA256SUMS)
- CI release workflow runs on tags `v*` and uploads artifacts and checksums; optional signing supported if minisign
  secret is configured.

### Fuzzing

Kevi includes fuzz targets (optional, for contributors) using `cargo-fuzz`:

```
cargo install cargo-fuzz

# Header parser should never panic on arbitrary input
cargo fuzz run fuzz_target_header_parse

# RON decoder robustness
cargo fuzz run fuzz_target_ron_codec
```

See `docs/fuzzing.md` for details. Fuzzing is non-blocking in CI; run it locally for deeper coverage.
