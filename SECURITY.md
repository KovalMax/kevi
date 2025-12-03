### Security Policy

#### Supported versions

Kevi is under active development. Always use the latest released version. Older versions may lack fixes or features.

#### Reporting a vulnerability

Please do not open public issues for security vulnerabilities. Instead:

- Email the maintainers (or repository security contact) with details and a proof of concept if available.
- Allow a reasonable disclosure window to validate, fix, and release a patched version.

We will acknowledge receipt within 72 hours and provide status updates as we triage and remediate.

#### Threat model (scope)

In scope:

- Local file theft and offline cracking of the vault file.
- Accidental leakage via logs or clipboard persistence.
- Vault tampering (header/ciphertext modification) — must be detected.

Out of scope (cannot be fully mitigated by Kevi alone):

- Compromised host (malware, keyloggers, rootkits).
- Kernel memory scraping, cold-boot attacks, DMA attacks.
- Users explicitly exporting plaintext (if supported) or leaking secrets out of band.

#### Security properties

- Data at rest is encrypted using Argon2id KDF (per‑file salt and stored cost parameters) and AES‑256‑GCM.
- The file header is authenticated as AEAD Associated Data, preventing parameter‑swap attacks and detecting tampering.
- Clipboard operations auto‑clear after a TTL and attempt to restore prior content. Clipboard policy and environment
  warnings (SSH/headless) are centralized and consistently applied across CLI and TUI.
- Session cache stores a derived key bound to the vault header (KDF params + salt), not the passphrase.
- Optional best‑effort memory locking (mlock) can be enabled on Unix via the `memlock` feature; failures to lock do not
  crash and keys are zeroized after use.
- Fuzzing targets exist for the header parser and the RON codec to reduce parser/decoder panics. See `docs/fuzzing.md`.
- On Unix, directories and files are created with restrictive permissions (0700 for directories, 0600 for files).
  Windows/macOS receive best‑effort protection (documented limitations may apply).
- Rotating encrypted backups are kept per configured count (default 2) and remain encrypted.

#### Handling of secrets in memory

- Secret fields use `secrecy::SecretString` and avoid accidental logging via redacted Debug implementations.
- Avoid cloning secrets; convert to owned values only at UI edges (e.g., clipboard). Memory scrubbing is best‑effort.
- Derived keys are held transiently during crypto operations and are zeroized afterwards; when the `memlock` feature is
  enabled, the key buffer is best‑effort locked with `mlock` for the operation’s duration.

#### Fuzzing

- We use libFuzzer via `cargo-fuzz` to exercise `parse_kevi_header` and the RON codec decoder. Crashes found by fuzzing
  are treated as security bugs if they cause panics in release builds or enable denial‑of‑service via crafted inputs.

#### Session cache

- Kevi supports a session unlock with TTL to reduce repeated prompts. The cache contains a derived key (not the
  passphrase), is bound to the vault header (salt + algorithm IDs), is stored locally with strict permissions, and
  expires automatically. Use only on trusted machines.
