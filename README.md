<p align="center">
  <img src="assets/app_logo.svg" width="220" alt="Kevi logo">
  <h1 align="center">Kevi — encrypted CLI vault</h1>
</p>

<p align="center">
  <a title="Build Status" target="_blank" href="https://github.com/KovalMax/kevi/actions/workflows/ci.yml"><img alt="ci badge icon" src="https://github.com/KovalMax/kevi/actions/workflows/ci.yml/badge.svg"></a>
  <a title="Code Coverage" target="_blank" href="https://github.com/KovalMax/kevi"><img src="https://codecov.io/github/KovalMax/kevi/graph/badge.svg?token=FOG7F18PST" alt="code coverage badge"></a>
</p>


### Kevi is a Rust, terminal-first password and secrets manager. It keeps everything in a single encrypted vault (Argon2id + AES-256-GCM), works well in headless and local setups, and ships an optional TUI for browsing and editing.

## Why Kevi
- Single encrypted file, easy to back up and sync
- CLI-first UX with an optional Ratatui interface
- Fast unlock cache with TTL; explicit `kevi lock` to clear it
- Clipboard helper with TTL and SSH/headless warnings (`--no-copy` / `--echo` available)
- Built‑in generator (passwords or passphrases) with env/config overrides
- TOTP storage and code generation with JSON output for scripting
- Profiles for multi-vault setups; configurable vault paths and backups

## Who Kevi is for

- You want a local, terminal-first password manager with one encrypted vault file.
- You prefer scripting and automation-friendly commands with JSON output when needed.
- You want optional TUI convenience without depending on a full desktop app.

Kevi is likely not a fit if you need a built-in sync service, web sharing flows, or multi-user access control out of the box.

## Quick start
```bash
# install from crates.io (if published there)
cargo install kevi

# or build from source
cargo build --release
./target/release/kevi --help

# create a vault (prompts for a master password)
kevi init --path ~/.kevi/vault.ron

# add your first secret
kevi add --label github --user you@example.com --generate

# fetch it (copies to clipboard by default)
kevi get github --echo

# add an OTP entry and fetch a code
kevi otp add github --from-uri "otpauth://..."
kevi otp get github --echo

# browse/edit via TUI
kevi tui
```

## Most used commands

- `kevi init --path <FILE>`: create vault.
- `kevi add --label <KEY> --generate`: add entry.
- `kevi get <KEY> --echo`: print field (clipboard copy is default unless `--no-copy`).
- `kevi list --query <SUBSTR>`: find entries quickly.
- `kevi unlock --ttl <SECONDS>` / `kevi lock`: manage derived-key cache.
- `kevi otp add|get|list|rm ...`: manage and generate TOTP codes.

## Defaults at a glance

- Clipboard TTL: `20s`.
- Unlock cache TTL: `900s`.
- Backups per write: `2`.
- Generator defaults: length `20`, lower+upper+digits+symbols on, ambiguous avoided, passphrase off (6 words, `:` separator).

## How Kevi picks paths and TTLs
- Vault resolution (highest precedence): `--path` → `--profile` (from config) → `KEVI_VAULT_PATH` → `config.toml` `vault_path` → default `$KEVI_DATA_DIR/kevi/vault.ron` (or `~/.kevi/vault.ron`).
- Clipboard TTL: CLI `--ttl` → env `KEVI_CLIP_TTL` → config `clipboard_ttl` → default `20s`.
- Unlock cache TTL: CLI `--ttl` → env `KEVI_UNLOCK_TTL` → default `900s`.
  Invalid environment values retain the `900s` fallback. Deadlines are fixed when persisted; cache hits never extend them. TTL `0` bypasses cache reads/writes for that invocation and **leaves any existing session untouched**.
- Generator: CLI flags override `KEVI_GEN_*` env vars, which override `config.toml` generator keys, which override built-in defaults.
- Backups kept per write: env `KEVI_BACKUPS` → config `backups` → built-in default.

## Common first-run pitfalls

- `kevi get` and `kevi otp get` copy to clipboard by default. Use `--no-copy` (and usually `--echo`) when running over SSH/headless.
- `KEVI_PASSWORD` enables non-interactive usage; without it, commands that need a key may prompt.
- `--once` bypasses the derived-key cache for that command and does not refresh cache state.
- If output seems empty, verify you are targeting the expected vault path/profile (`--path` / `--profile`).

## CLI commands and options
Global option: `--profile <name>` resolves vault path via a named profile before other fallbacks.

### Core vault

- `kevi init [--path <FILE>]` — Create a new encrypted vault file and set a master password.
  - `--path <FILE>`: vault file to create (else resolution rules apply); prompts for master password or uses `KEVI_PASSWORD`.
- `kevi header [--path <FILE>]` — Print vault header metadata without decrypting secrets.
  - `--path <FILE>`: vault file to inspect; prints header (no secrets).
- `kevi add [--path <FILE>] [--generate] [--length <N>] [--no-lower] [--no-upper] [--no-digits] [--no-symbols] [--allow-ambiguous] [--passphrase] [--words <N>] [--sep <STR>] [--label <STR>] [--user <STR>] [--notes <STR>]` — Add a new entry, optionally generating the secret.
  - `--path <FILE>`: vault override.
  - `--generate`: create a password instead of prompting.
  - `--length <N>`: generated password length (character mode).
  - `--no-lower|--no-upper|--no-digits|--no-symbols`: disable that class.
  - `--allow-ambiguous`: permit ambiguous chars (O/0/I/l/|).
  - `--passphrase`: switch generator to passphrase mode.
  - `--words <N>`: passphrase word count.
  - `--sep <STR>`: passphrase separator.
  - `--label <STR>`: entry label (key) to skip prompt.
  - `--user <STR>`: username value (optional).
  - `--notes <STR>`: notes value (optional).
- `kevi get <key> [--path <FILE>] [--field password|user|notes] [--no-copy] [--echo] [--ttl <SECONDS>] [--once]` — Retrieve an entry field, copy to clipboard by default, or print.
  - `--path <FILE>`: vault override.
  - `--field password|user|notes`: which field to return (default password).
  - `--no-copy`: do not write to clipboard.
  - `--echo`: print to stdout.
  - `--ttl <SECONDS>`: clipboard TTL override.
  - `--once`: bypass session cache (derive key without caching).
- `kevi show <key> [--reveal-password] [--path <FILE>]` — Display entry details in the terminal.
  - `--reveal-password`: print password in plaintext.
  - `--path <FILE>`: vault override.
- `kevi list [--path <FILE>] [--show-users] [--query <SUBSTR>] [--json]` — List stored entries with optional filters/output.
  - `--path <FILE>`: vault override.
  - `--show-users`: include usernames.
  - `--query <SUBSTR>`: case-insensitive filter on labels.
  - `--json`: machine-readable array (includes username only with `--show-users`).
- `kevi rm <key> [--path <FILE>] [--yes]` — Remove an entry by key.
  - `--path <FILE>`: vault override.
  - `--yes`: skip confirmation.
- `kevi unlock [--path <FILE>] [--ttl <SECONDS>]` — Always authenticate a fresh password against the vault before caching a derived key. Persistence failure returns a nonzero exit status; TTL `0` authenticates without creating a session.
  - `--path <FILE>`: vault override.
  - `--ttl <SECONDS>`: unlock cache TTL override.
- `kevi lock [--path <FILE>]` — Attempt cleanup of the current native account and current-format file entry, independent of the selected backend. Legacy accounts and historical file names are not inspected, imported, migrated, or removed; existing legacy entries may remain and do not make current-session cleanup fail. Current file targets must pass safe parent/ancestor and identity checks. Ambiguous or unsafe current files are preserved and reported as partial cleanup failures; other current targets are still attempted. File cleanup fails closed where safety cannot be verified, including macOS ACLs and Windows.
- The public session-file `clear` API is guarded cleanup of the current cache format, not a generic serialized-session delete. It removes only a bounded, valid current envelope from a verified directory. Legacy RON envelopes, generic `save<T>` output, bare key-shaped records, ordinary/vault/ambiguous files are preserved; a missing file is a no-op. Generic `save<T>`/`load<T>` retain their signatures, but both return `CacheError::Unavailable` on macOS and Windows/non-Unix platforms because safe generic file storage is not established there. On supported Unix platforms (excluding macOS), they provide generic expiring file-session persistence; output remains ineligible for guarded deletion.
  Generic `save<T>` treats zero TTL as a no-I/O success on every platform and rejects nonzero fractional-second TTLs with `CacheError::InvalidTtl` before platform availability checks; persisted TTLs are never silently rounded down.
   - Current file cleanup checks are path-based and do not protect against same-user concurrent filesystem mutation; see `SECURITY.md`.
  - `--path <FILE>`: vault override.
- `kevi tui [--path <FILE>]` — Launch the interactive TUI against the resolved vault.
  - `--path <FILE>`: vault override for the TUI.

### OTP (TOTP)

- `kevi otp add <name> [--secret <BASE32> | --from-uri <URI>] [--issuer <STR>] [--username <STR>] [--digits <6|8>] [--period <SECONDS>] [--algorithm sha1|sha256|sha512] [--notes <STR>] [--on-duplicate-override] [--path <FILE>]` — Create or update a TOTP entry.
  - `--secret <BASE32>`: raw secret (exclusive with `--from-uri`).
  - `--from-uri <URI>`: otpauth URI to parse (exclusive with `--secret`).
  - `--issuer <STR>`: issuer label.
  - `--username <STR>`: account name.
  - `--digits <6|8>`: code length (default 6).
  - `--period <SECONDS>`: step size (default 30).
  - `--algorithm sha1|sha256|sha512`: HMAC algorithm (default sha1).
  - `--notes <STR>`: notes.
  - `--on-duplicate-override`: replace existing entry if present.
  - `--path <FILE>`: vault override.
- `kevi otp get <name> [--path <FILE>] [--no-copy] [--echo] [--json] [--at <UNIX_TS>] [--once]` — Generate a TOTP code for an entry and copy/print it.
  - `--path <FILE>`: vault override.
  - `--no-copy`: skip clipboard.
  - `--echo`: print code.
  - `--json`: structured output.
  - `--at <UNIX_TS>`: generate code for specific timestamp.
  - `--once`: bypass session cache.
- `kevi otp list [--path <FILE>] [--query <SUBSTR>] [--json]` — List OTP entries with optional filters/output.
  - `--path <FILE>`: vault override.
  - `--query <SUBSTR>`: case-insensitive filter on names.
  - `--json`: machine-readable array.
- `kevi otp rm <name> [--path <FILE>] [--yes]` — Remove a TOTP entry by name.
  - `--path <FILE>`: vault override.
  - `--yes`: skip confirmation.

### Profiles (multi-vault)

- `kevi profile list` — Show all configured profiles and the default, if set.
  - No options; prints profiles and default.
- `kevi profile show <name>` — Display details for a single profile.
  - No extra options; prints one profile.
- `kevi profile add <name> --path <FILE> [--on-duplicate-override]` — Create or update a profile pointing to a vault path.
  - `--path <FILE>`: vault path for the profile (required flag).
  - `--on-duplicate-override`: replace existing profile.
- `kevi profile rm <name> [--yes]` — Delete a profile (not the active default).
  - `--yes`: skip confirmation (cannot remove active default).
- `kevi profile default [<name>] [--clear]` — View, set, or clear the default profile.
  - `<name>`: set default profile; omit to show current.
  - `--clear`: remove default profile.

#### Profile examples

```bash
# add two vault profiles
kevi profile add work --path ~/.kevi/work.ron
kevi profile add personal --path ~/.kevi/personal.ron

# set default profile
kevi profile default work

# use default profile
kevi list

# override per command
kevi --profile personal list
```

### JSON output examples

```bash
# vault list as JSON
kevi list --json

# OTP code as JSON (for scripts)
kevi otp get github --json
```

## Configuration & environment

- Config file: `$XDG_CONFIG_HOME/kevi/config.toml` (or `~/.config/kevi/config.toml`); override base dir with `KEVI_CONFIG_DIR`.
- Data dir: `$XDG_DATA_HOME/kevi` (or `~/.local/share/kevi`); override with `KEVI_DATA_DIR`.
- `config.toml` keys: `vault_path`, `clipboard_ttl`, `backups`, `default_profile`, `[profiles.<name>].vault_path`, generator defaults (`generator_length`, `generator_words`, `generator_sep`, `avoid_ambiguous`).
- Env vars: `KEVI_PASSWORD`, `KEVI_VAULT_PATH`, `KEVI_CLIP_TTL`, `KEVI_UNLOCK_TTL`, `KEVI_BACKUPS`, `KEVI_GEN_LENGTH`, `KEVI_GEN_WORDS`, `KEVI_GEN_SEP`, `KEVI_AVOID_AMBIGUOUS`.
- Precedence: CLI flags → env vars → config file → built‑in defaults.

### Derived-key cache

- All cache-producing flows, including `init`, implicit vault operations and `unlock`, default to OS-protected storage: macOS Security Framework, Linux Secret Service, or Windows Credential Manager. Explicit `init` passwords authenticate an existing vault before replacement; a cached key cannot override the supplied password. There is no automatic file/sample/keyutils fallback.
- Only `KEVI_INSECURE_CACHE_FALLBACK=1` or case-insensitive `true` opts into an **insecure base64 key file** and emits a warning. `KEVI_PASSWORD` and test-harness variables do not change storage selection; `KEVI_PREFER_SECURE_CACHE` has no effect. File persistence is supported only on Unix platforms other than macOS: macOS ACL grants are not reliably checked, so this mode is rejected and file cleanup is fail-closed there; Windows/non-Unix also fail closed.
- A versioned envelope binds the exact 32-byte key to a canonical absolute path identity, header fingerprint, issue time and fixed expiry. Existing symlinks resolve to the same identity; the file namespace includes the full path identity and does not replace the vault's extension. Legacy or expiryless sessions are not read or imported. Authenticate again to create a current-format session; existing legacy entries are left untouched. Secure mode never reads the insecure cache file.
- Fresh keys are published only after successful authenticated decode or successful creation/save. Existing ciphertext is authenticated before replacement. Ordinary vault operations can succeed uncached with a warning; explicit `unlock` cannot falsely claim persistence. CLI/OTP warnings use stderr; TUI warnings are queued visibly without printing into its active terminal.
- Expiry means refusal to reuse, **not scheduled deletion or physical erasure**. Checks use wall time: clock rollback can extend the effective lifetime; no cross-process monotonic-clock guarantee is made. `--once` performs no cache reads, writes or refreshes.
- `lock` targets only the current native account and current-format file path. It does not inspect, import, migrate, or delete legacy accounts or historical file names; those entries may remain without affecting current-lock status. Current file cleanup requires safe parent/ancestor directories and a file-identity check; macOS and Windows fail closed where those properties cannot be established. Ambiguous current files are preserved and reported as partial failures. Lock does not scan stores or discover unknown names, renames, or hard-link aliases. Its guarantee requires quiescence: **no overlapping cache writers**, including work begun before lock that could publish afterward. It does not revoke keys already in memory or prevent later writes.
- Native macOS/Linux/Windows disposable-store verification is still required before claiming cross-platform readiness. Deterministic fake/file tests and file-only CI are not native-store evidence. See [SECURITY.md](SECURITY.md).

## Security notes

- Argon2id KDF, AES‑256‑GCM encryption; secrets handled with `secrecy`.
- Direct `decrypt_vault` calls hold the derived key in zeroizing ownership through
  decryption; this does not guarantee erasure of KDF/compiler temporaries or
  library-internal copies.

Vault headers are accepted only up to Argon2id parameters of 128 MiB memory,
5 iterations, and 2 lanes (with valid Argon2 minima). Headers outside this
policy are rejected, not silently adjusted. If an older vault exceeds these
limits, preserve a backup and contact support; do not overwrite the only copy.

### Release verification

Releases use stable `vX.Y.Z` tags that must exactly match the package version
(currently `v0.4.0`). Published assets include platform archives, the Linux
CycloneDX SBOM, and `SHA256SUMS.txt`. A configured signing key must produce
`SHA256SUMS.txt.minisig` or release publication fails. Without one, the release
includes `RELEASE-SIGNATURE-STATUS.txt` explicitly identifying it as unsigned.
Checksum/signature verification is meaningful only when the verifier obtains
the trusted minisign public key independently through a trusted distribution
channel; no public key is embedded or provided here. Confirm that trust key is
available before relying on signed release verification. From the asset
directory, verify signed manifests with `minisign -Vm SHA256SUMS.txt -P
<trusted-public-key>` and then verify archives/SBOM with
`sha256sum -c SHA256SUMS.txt`. If status says unsigned, the manifest has no
authenticity signature; compare it through an independently trusted channel
before relying on its hashes.
- Optional `memlock` feature on Unix to reduce swapping risk.
- Clipboard TTL is best‑effort and platform-dependent; prefer `--no-copy`/`--echo` in sensitive or remote sessions.
- Kevi stores data in one encrypted local file; it does not include a built-in remote sync backend.

## Development

```bash
KEVI_INSECURE_CACHE_FALLBACK=1 cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Inspect tests before running on a personal machine. File opt-in does **not** prevent native access by production `lock`; deterministic cleanup tests inject a no-native adapter. Some existing workspace tests also access the system clipboard. Use disposable stores/clipboard and temporary config/data directories for those tests; this cache change has not verified those native paths.

On Linux, you can also run tests with the `memlock` feature enabled:

```bash
cargo test --workspace --features memlock
```

### Code coverage

If you have `cargo-llvm-cov` installed, you can generate coverage locally with:

```bash
cargo llvm-cov --workspace --no-cfg-coverage --html
```

This will create an HTML report under a `coverage-html` directory.

### Continuous Integration

This repository includes a GitHub Actions workflow that runs:

* `cargo fmt --all` (format check)
* `cargo clippy --workspace --all-targets --all-features -- -D warnings`
* `cargo build --workspace`
* `KEVI_INSECURE_CACHE_FALLBACK=1 cargo test --workspace` (with and without `memlock` on Linux)
* `cargo audit` (via a dedicated job; findings block in the job log without requiring write access to publish a Check API result)
* `cargo llvm-cov` for coverage reporting

You can mirror these steps locally before pushing changes.

### Contributing

Contributions, bug reports, and feature ideas are welcome. When submitting a pull request:

* Run checks in this order: `KEVI_INSECURE_CACHE_FALLBACK=1 cargo test --workspace` first, then `cargo fmt --all`, then `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
* Try to include tests for new functionality where practical.
* Avoid logging or printing secrets; prefer redacted debug output.
