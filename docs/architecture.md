### Kevi architecture (ports/adapters + services)

Kevi follows a ports/adapters (hexagonal) architecture to keep the domain logic decoupled from infrastructure. This
enables testing with mocks and evolving the underlying storage/crypto/UX.

#### Domain model

- `core::entry::VaultEntry` — a single vault item.
    - `label: String`
    - `username: Option<SecretString>`
    - `password: SecretString`
    - `notes: Option<String>`

#### Ports (traits)

- `core::ports::VaultCodec` — serialize/deserialize entries (`RON` currently).
- `core::ports::ByteStore` — read/write raw bytes (atomic, permission‑safe under the hood).
- `core::ports::KeyResolver` — resolve a derived key bound to the vault header; uses a header‑fingerprint‑scoped cache.
- `core::ports::{HeaderParams, DerivedKey}` — helper types for key resolution.
- `core::ports::Rng` — randomness for deterministic tests.
- `core::ports::{GenPolicy, PasswordGenerator}` — password/passphrase generation.

#### Services

- `core::service::VaultService`
    - Orchestrates: `store.read()` → parse header → `KeyResolver.resolve_for_header()` → `decrypt_vault_with_key()` →
      `codec.decode()` → mutate → `codec.encode()` → `encrypt_vault_with_key()` (reuse salt/params) → `store.write()`.
    - Loads/saves using a header‑bound derived‑key cache, not a passphrase.
    - Helpers to add/remove entries.

#### Adapters (infrastructure)

- `core::adapters::RonCodec` — `ron` encoding with pretty config.
- `core::adapters::FileByteStore` — file R/W. Accepts a backups count at construction and uses
  `core::fs_secure::write_with_backups_n` for atomic writes, rotation, and Unix perms.
- `core::adapters::CachedKeyResolver` — resolves a derived key for a given header; backs it with `core::dk_session` (
  header‑fingerprinted, TTL‑bound).

#### Crypto container

- `core::crypto` implements the v1 container: `KeviHeader` + AES‑GCM ciphertext, header bound as AEAD AAD.
  `parse_kevi_header` validates inputs and surfaces typed errors.

#### Clipboard

- `core::clipboard::{ClipboardEngine, SystemClipboardEngine}` — abstraction over system clipboard.
- `core::clipboard::copy_with_ttl` — copies and restores previous content after TTL.
- Policy helpers are centralized: `clipboard::ttl_seconds(config, override)` and
  `clipboard::environment_warning()` are used by both CLI and TUI.

#### File I/O security

- `core::fs_secure` provides `ensure_parent_secure`, `atomic_write_secure`, and `write_with_backups_n` enforcing 0700
  dirs/0600 files on Unix.
- Backups are rotated per a configured count (default 2) and remain encrypted.

#### Session cache

- `core::dk_session` stores a short‑lived derived‑key session alongside the vault (`.dksession`) with expiry. Used by
  `CachedKeyResolver` and CLI `unlock/lock`. The cache is bound to the header fingerprint (excludes nonce) to prevent
  cross‑vault reuse.

#### Config

- `config::config::Config::create(path_override)` merges precedence: CLI > env > config file > defaults (see README).

#### CLI and TUI

- CLI (`cli`) wires to `core::vault::Vault`, which composes default adapters and calls `VaultService`.
- TUI (`tui`) uses the same service stack; never renders secrets; supports copy actions with TTL.

#### Testing

- Unit tests on crypto (roundtrip, tamper/wrong password), generator, session, and TUI rendering.
- Integration tests for CLI commands (`assert_cmd`): `get`, `add`, `rm`, `list`, `header`, `unlock/lock`, backups,
  config precedence.
- Style guard in CI forbids inline `use` statements and inline module bodies (except `mod tests {}`) in sources.
