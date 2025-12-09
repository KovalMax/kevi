Security model and cryptography
===============================

This document explains Kevi’s security goals, the cryptography it uses,
and how to use it safely in practice.

It is aimed at technically minded users who want to understand what
Kevi does – and does not – protect against.


Threat model
------------

### Goals

Kevi is designed to protect against:

* **Offline attackers** who obtain a copy of your vault file but do
  not know your master password.
* **Opportunistic access** to your machine where an attacker cannot
  easily read process memory or intercept keystrokes but might access
  files.
* **Accidental leakage** of secrets through debug output, log
  messages, or unredacted `Debug` formatting.

### Non‑goals

Kevi is **not** intended to protect against:

* A fully compromised operating system (root access, kernel‑level
  malware, keyloggers, or screen capture).
* An attacker who can watch your terminal or clipboard in real time
  while you use Kevi.
* Coercion or social engineering attacks.

In other words, Kevi aims to provide strong protection for data at
rest and reasonable hygiene for data in use, but it cannot compensate
for a compromised platform or hostile physical environment.


Cryptography
------------

Kevi’s cryptographic primitives and parameters are implemented in
`src/core/crypto.rs`.

### Key derivation – Argon2id

Kevi derives an encryption key from your master password using the
**Argon2id** key derivation function:

* Algorithm: `Argon2id` (`argon2::Algorithm::Argon2id`)
* Version: `0x13` (`argon2::Version::V0x13`)
* Output key length: 32 bytes (256 bits)

Default parameters (as of 2025) are defined in `default_params()`:

* Memory cost: `64 * 1024` KiB = **64 MiB**
* Time cost: `3` iterations
* Parallelism: `1` lane

These values are chosen as a conservative baseline for an interactive
CLI tool on modern hardware. You can think of them as:

* High enough to make large‑scale brute‑force attacks expensive.
* Still fast enough that unlocking the vault is tolerable on a typical
  developer workstation.

Argon2id is resistant to GPU and ASIC optimization and combines
benefits of Argon2i and Argon2d.

### Vault encryption – AES‑256‑GCM

Vault contents are encrypted and authenticated with **AES‑256‑GCM**
using the `ring` crate’s AEAD API:

* Algorithm identifier: `AEAD_AES256GCM = 1` (internal constant)
* Key length: 32 bytes (256‑bit key)
* Nonce length: 12 bytes (96 bits), `NONCE_LEN = 12`

Encryption workflow (`encrypt_vault` / `encrypt_vault_with_key`):

1. A random 16‑byte salt is generated (`SALT_LEN = 16`).
2. A random 12‑byte nonce is generated for AES‑GCM.
3. A header is constructed containing:
   * Magic bytes: `"KEVI"`
   * Version: `1`
   * KDF identifier: `2` (Argon2id)
   * AEAD identifier: `1` (AES‑256‑GCM)
   * Argon2 parameters `(m_cost_kib, t_cost, p_lanes)`
   * Salt (16 bytes)
   * Nonce (12 bytes)
4. The header is used as **associated data (AAD)** for AES‑GCM, so any
   tampering with the header is detected.
5. The plaintext vault is encrypted in place and an authentication tag
   is appended.
6. The final ciphertext is `header || ciphertext || tag`.

Decryption (`decrypt_vault` / `decrypt_vault_with_key`) reverses this
process:

1. Parse and validate the header.
2. Derive the key from the stored salt and parameters using Argon2id.
3. Use the header as AAD and the stored nonce as the AEAD nonce.
4. Decrypt the ciphertext and verify the authentication tag.

Any change to the header, nonce, or ciphertext will cause decryption
to fail.

### Header fingerprinting

Kevi computes a **header fingerprint** (excluding the nonce) to bind
derived‑key sessions to a specific vault configuration:

* Function: `header_fingerprint_excluding_nonce` (SHA‑256 over
  selected header fields).
* Inputs: header magic, version, KDF/AEAD IDs, Argon2 parameters,
  and salt.
* Output: a hex‑encoded 256‑bit fingerprint string.

This fingerprint is used to ensure that a cached derived key is only
re‑used with vaults that have the same cryptographic configuration,
preventing accidental key reuse across incompatible vaults.


Derived‑key sessions
--------------------

To avoid repeatedly typing your master password, Kevi supports
short‑lived **derived‑key sessions** managed by commands like
`unlock` and `lock`.

### Session files

The flow is roughly:

1. When you run `kevi unlock`, Kevi:
   * Derives a key from your password and the vault header.
   * Computes the header fingerprint (excluding nonce).
   * Wraps the derived key in a `SecretBox` (from the `secrecy`
     crate) to help avoid accidental leaks.
   * Serializes this and writes it to a **session file** with a TTL.
2. When you run another command (e.g. `get`), Kevi first tries to read
   the session file and verify:
   * the TTL has not expired,
   * the fingerprint matches the current vault header.
   If everything checks out, the cached derived key is used without
   prompting for the master password.
3. `kevi lock` deletes the session file, forcing the next operation to
   prompt for your password again.

Tests (see `tests/session_tests.rs`) verify that:

* Session files are only accepted when not expired.
* The fingerprint is checked and mismatches cause the cache to be
  ignored.
* File permissions on Unix are restrictive (no world‑readable
  sessions).

### Security considerations for sessions

* A session file contains material that can be used to decrypt your
  vault without the master password while it is valid.
* Protect your home directory and temporary directories accordingly.
* Keep session TTLs short on shared or less trusted machines.
* Use `kevi lock` when stepping away from your desk or switching
  users.


Memory safety and secret handling
---------------------------------

### Secret types

Kevi uses the `secrecy` crate (e.g. `SecretString`, `SecretBox`) to
store sensitive values like passwords in memory:

* Secrets are wrapped in types that discourage accidental exposure
  (e.g. `Debug` implementations are redacted).
* Tests (see `tests/secret_handling_tests.rs`) ensure that the `Debug`
  representation of secrets does **not** contain the raw secret and
  instead shows a redacted form.

Where appropriate, the `zeroize` crate is used by dependencies to
clear memory when secrets are dropped.

### memlock (optional)

On Unix‑like systems, enabling the `memlock` feature attempts to lock
process memory containing sensitive data to prevent it from being
swapped to disk.

* This relies on OS primitives like `mlock` / `mlockall`.
* It is a **best‑effort** mitigation and may require additional OS
  configuration (e.g. raising `RLIMIT_MEMLOCK`).
* When enabled, tests (`tests/memlock.rs`) exercise the
  lock/unlock path.

Even with memlock enabled, it is still possible for secrets to leak
through other channels (logs, crash dumps, etc.), so normal caution is
still required.


Clipboard handling
------------------

Kevi integrates with the system clipboard via crates such as
`copypasta` and `x11-clipboard` (on X11). Clipboard behavior is:

* **Opt‑in visibility**:
  * By default, secrets are copied to clipboard instead of being
    printed.
  * `--echo` is required to print a secret to stdout.
* **TTL (time‑to‑live)**:
  * Kevi uses a configurable TTL after which it will attempt to clear
    the clipboard or overwrite it with dummy data.
  * The exact reliability of clipboard clearing depends heavily on the
    platform and other applications.

Security implications:

* Any application running under your user account may read the
  clipboard.
* Clipboard contents may be stored in clipboard managers or history
  tools.
* Use short TTLs and avoid copying secrets on shared machines.

When running in the TUI, key bindings such as `Enter` and `u` copy
passwords or usernames to the clipboard without printing them to the
terminal.


Filesystem, backups, and permissions
------------------------------------

### Vault file

* The vault is a single binary file whose path is configured via
  config or CLI options.
* The file begins with a `KEVI` magic header followed by version and
  cryptographic parameters.
* All actual secret material (labels, usernames, passwords, notes) is
  encrypted; there is no plaintext metadata beyond what the header
  contains.

You should:

* Ensure your vault file lives on storage you control.
* Use filesystem permissions to prevent other users from reading it
  directly.

### Backups

Kevi can keep a configured number of backup copies of the vault file
when writing changes.

* Backups are encrypted in the same way as the primary vault.
* However, the **old ciphertext** may still be useful to an attacker
  attempting to perform offline analysis.

Recommendations:

* Limit the number of backups if you are concerned about exposure of
  historical data.
* Secure backup locations (external drives, cloud sync) to the same
  degree as the primary vault file.

### Session file permissions

On Unix‑like systems, tests assert that session files are created with
restrictive permissions (no group/world read access). This ensures
that another unprivileged user on the same machine cannot trivially
read your cached keys.


Operational guidance
--------------------

### Choosing a master password

Because Kevi’s security ultimately depends on your master password,
you should:

* Use a **strong, unique passphrase**, preferably generated or derived
  from a long random word sequence.
* Avoid reusing passwords from other services.
* Consider using a passphrase of at least 4–6 random words or 16+
  random characters.

### Using Kevi safely day‑to‑day

* Prefer copying passwords to clipboard over echoing them in the
  terminal when practical.
* Keep clipboard TTLs short, especially on shared or unmanaged
  machines.
* Use `kevi lock` or end your session when stepping away from your
  desk.
* Keep your operating system and Rust toolchain up to date.

### Limitations and future work

Some limitations and potential future improvements:

* There is currently no built‑in multi‑device sync; you are
  responsible for syncing the vault file if needed.
* There is no hardware‑backed key storage (e.g. TPM, Secure Enclave)
  integration yet.
* Side‑channel resistance (timing, cache) relies largely on
  well‑reviewed upstream libraries (`ring`, `argon2`, etc.), but
  Kevi itself has not undergone a formal audit.

If you rely on Kevi for high‑value secrets, consider having your
deployment or configuration reviewed by someone familiar with applied
cryptography and secure systems design.
