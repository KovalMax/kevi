Security model and cryptography
===============================

This document explains Kevi's security goals, the cryptography it uses,
and how to use it safely in practice.

It is aimed at technically minded users who want to understand what
Kevi does - and does not - protect against.


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

### Non-goals

Kevi is **not** intended to protect against:

* A fully compromised operating system (root access, kernel-level
  malware, keyloggers, or screen capture).
* An attacker who can watch your terminal or clipboard in real time
  while you use Kevi.
* Coercion or social engineering attacks.

In other words, Kevi aims to provide strong protection for data at
rest and reasonable hygiene for data in use, but it cannot compensate
for a compromised platform or hostile physical environment.


Cryptography
------------

Kevi's cryptographic primitives and parameters are implemented in
`src/cryptography/primitives.rs`.

### Key derivation - Argon2id

Kevi derives an encryption key from your master password using the
**Argon2id** key derivation function:

* Algorithm: `Argon2id` (`argon2::Algorithm::Argon2id`)
* Version: `0x13` (`argon2::Version::V0x13`)
* Output key length: 32 bytes (256 bits)

Default parameters (as of 2025) are defined in `default_params()`:

* Memory cost: `64 * 1024` KiB = **64 MiB**
* Time cost: `3` iterations
* Parallelism: `1` lane

Vault headers are accepted only within the following supported policy:
memory at most 131072 KiB (128 MiB), iterations at most 5, and lanes at
most 2. All parameters must be positive and satisfy Argon2's minimum
memory requirement of eight KiB per lane. The policy is checked while
parsing the header and again at the KDF boundary, before derived-key cache
lookup or KDF work. Values are rejected, never clamped. A vault exceeding
these limits cannot be opened by this version; preserve a backup and
contact support for a separately designed recovery/migration path. Do not
overwrite the only copy of such a vault.

The selected maximum tuple (128 MiB, 5 iterations, 2 lanes) completed three
synthetic serial Linux/arm64 container runs at a median 0.305294 seconds
and reported 137100 kB process peak RSS. This was on one Apple Silicon host,
with one CPU and a 256 MiB memory+swap cgroup limit. It is not evidence for
Windows, slower devices, concurrency, or historical vault compatibility.

These values are chosen as a conservative baseline for an interactive
CLI tool on modern hardware. You can think of them as:

* High enough to make large-scale brute-force attacks expensive.
* Still fast enough that unlocking the vault is tolerable on a typical
  developer workstation.

Argon2id is resistant to GPU and ASIC optimization and combines
benefits of Argon2i and Argon2d.

### Vault encryption - AES-256-GCM

Vault contents are encrypted and authenticated with **AES-256-GCM**
using the `ring` crate's AEAD API:

* Algorithm identifier: `AEAD_AES256GCM = 1` (internal constant)
* Key length: 32 bytes (256-bit key)
* Nonce length: 12 bytes (96 bits), `NONCE_LEN = 12`

Encryption workflow (`encrypt_vault` / `encrypt_vault_with_key`):

1. A random 16-byte salt is generated (`SALT_LEN = 16`).
2. A random 12-byte nonce is generated for AES-GCM.
3. A header is constructed containing:
   * Magic bytes: `"KEVI"`
   * Version: `1`
   * KDF identifier: `2` (Argon2id)
   * AEAD identifier: `1` (AES-256-GCM)
   * Argon2 parameters `(m_cost_kib, t_cost, p_lanes)`
   * Salt (16 bytes)
   * Nonce (12 bytes)
4. The header is used as **associated data (AAD)** for AES-GCM, so any
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

For direct `decrypt_vault` calls, the returned fixed-size derived-key array is
immediately placed in `zeroize::Zeroizing` and remains zeroizing-owned through
the decryption call, including error exits. This limits exposure of that owned
array; it does not guarantee erasure of KDF/compiler temporaries, Argon2 or AEAD
internal copies, or copies outside this function.

Any change to the header, nonce, or ciphertext will cause decryption
to fail.

### Header fingerprinting

Kevi computes a **header fingerprint** (excluding the nonce) to bind
derived-key sessions to a specific vault configuration:

* Function: `header_fingerprint_excluding_nonce` (SHA-256 over
  selected header fields).
* Inputs: header magic, version, KDF/AEAD IDs, Argon2 parameters,
  and salt.
* Output: a hex-encoded 256-bit fingerprint string.

This fingerprint is used to ensure that a cached derived key is only
re-used with vaults that have the same cryptographic configuration,
preventing accidental key reuse across incompatible vaults.


Derived-key sessions
--------------------

To avoid repeatedly typing your master password, Kevi supports
short-lived **derived-key sessions** managed by commands like
`unlock` and `lock`.

### Storage and authentication

Cache writes default to macOS Security Framework, explicitly selected Linux
Secret Service, or explicitly selected Windows Credential Manager. There is no
automatic insecure, sample-store or keyutils fallback. `KEVI_PASSWORD`,
`RUST_TEST_THREADS` and the obsolete `KEVI_PREFER_SECURE_CACHE` do not downgrade
storage. Only `KEVI_INSECURE_CACHE_FALLBACK=1` or case-insensitive `true` selects
the insecure file adapter, with a warning. An encoded key file is not encrypted:
anyone obtaining its key bytes can decrypt matching vault ciphertext, even after
the application's expiry deadline. Keep it out of backups and shared directories.

File writes on Unix use an unpredictable, exclusively created temporary in the
destination directory, mode `0600` from creation, checked permissions/write/sync/
replacement, and cleanup on failure. They do not reuse the vault's older generic
write helper. File mode is available only on Unix platforms other than macOS.
macOS ACLs can grant directory mutation despite restrictive POSIX mode bits, and
this application does not reliably inspect those ACLs; explicit file-cache
selection is therefore rejected there. Windows and other non-Unix platforms also
fail closed. This is not a vault-wide filesystem rewrite or a physical-erasure
guarantee.

Acquisition and publication are separate. Existing loads authenticate and decode
before publishing a fresh key. Existing saves authenticate/decode the original
ciphertext before replacement and publish only after a successful write. Creation
uses the same lifecycle and publishes after the final vault identity exists.
Explicit `unlock` always derives afresh and authenticates the same bytes whose
header supplies the fingerprint, even when another valid session exists. Wrong
passwords or failed writes do not replace a prior session. Explicit persistence
failure returns nonzero; ordinary authenticated operations may succeed uncached
with a sanitized typed warning. CLI/OTP warnings go to stderr; the TUI uses a
bounded, typed visible queue, including startup and runtime failures.

### Envelope, identity and expiry

All current backends use the same versioned envelope: losslessly encoded canonical
absolute-path identity, header fingerprint, issue/expiry timestamps and an exact
32-byte derived key. Encoded payloads are bounded to 4096 bytes. Unknown schemas,
old expiryless payloads, invalid timestamps, future issue times, fingerprint/path
mismatches and malformed/short/oversized keys are rejected. Reauthenticate to
migrate: secure mode does not import file keys. Reads do not eagerly delete stale
entries, avoiding deletion races with newly published sessions.

Existing symlinks resolve to a common identity. New files use a path-identity
namespace rather than replacing the vault extension. Missing-path cleanup resolves
the nearest existing ancestor and remaining components where possible. Hard-link
aliases, unknown historical paths and renames are not generally discoverable.

TTL precedence is unlock flag, `KEVI_UNLOCK_TTL`, then 900 seconds; invalid
environment values retain the default. The deadline is fixed at persistence:
cache hits never renew it. Checked arithmetic rejects unrepresentable deadlines,
without an arbitrary maximum TTL. Entries are expired at the exact expiry
boundary. TTL zero bypasses reads and writes for that invocation and leaves
previous sessions untouched; `--once` likewise performs no cache I/O or refresh.

Expiry is a reuse check, not a scheduled purge or physical erasure. It relies on
wall time: rollback can lengthen effective lifetime. No cross-process monotonic
time guarantee is provided. Cached keys remain sensitive regardless of timestamps.

### Lock and verification limits

`lock` attempts all bounded applicable current-native, current-file and known
legacy native-account/file targets, regardless of backend selection. It removes
only recognizable session payloads. Legacy RON removal requires the exact
supported envelope (`expires_at_unix` with nested `data` containing only the
fingerprint and encoded key); bare key-shaped objects and records with unknown
fields are ambiguous and preserved. Every file target, current and legacy,
requires Unix directory metadata to establish that the canonical parent and each
ancestor is owned by the effective user or root and has no group- or
other-write permission bits. Otherwise the file is preserved, cleanup is
reported as a sanitized partial failure, and remaining targets are still
attempted. File cleanup fails closed on macOS because ACL grants are not reliably
evaluated, and on platforms where directory safety cannot be verified
(including Windows). The selected vault, aliases to that vault,
encrypted vaults at legacy cache names, and other ambiguous files are preserved
and reported as cleanup conflicts. Missing entries succeed; resolution, provider
and deletion failures are sanitized, aggregated and return nonzero after
attempting the remainder. No broad store search or secret import is performed.

On macOS, the explicit insecure file-cache backend is unsupported: it will not
read or persist key files, and lock will preserve current and legacy file
targets while still attempting other cleanup targets.

The guarantee is **quiescent only**: it excludes overlapping cache writes,
including operations begun before lock which may publish afterward. The legacy
directory check is a path-based permission/ownership assessment, not a
handle-bound delete; same-user concurrent filesystem mutation can replace a path
after inspection and remains outside the guarantee. Do not interpret a path
recheck as closing that race. Lock does not revoke already acquired in-memory
keys or prevent later writes. Unknown historical identities, renames and hard
links require separate user-managed cleanup.

The public `kevi::api::clear` session-file helper is guarded cache cleanup, not a
generic serialized-session delete. It accepts bounded RON session envelopes only
in the supported expiry/data/key schema and recognized derived-key session
payloads; generic `save<T>` output, arbitrary files, bare key-shaped objects,
encrypted vaults, symlinks and ambiguous content are preserved with a typed
cleanup error. Missing paths are a no-op. The generic `save<T>` and `load<T>`
APIs retain their signatures, but fail with `CacheError::Unavailable` on macOS
and non-Unix platforms (including Windows), without reading or writing a path,
because safe generic file-session storage is not established there. Zero TTL is
still a no-I/O success on every platform. Nonzero fractional-second TTLs are
rejected as `CacheError::InvalidTtl` before platform availability checks, so a
persisted deadline is never silently shortened. On supported
Unix platforms excluding macOS, the generic APIs use file persistence, but their
serialized content is not implicitly eligible for guarded deletion.
On macOS, Windows and other platforms where directory safety cannot be established,
existing files fail closed. This API's path-based checks share the same
same-user-concurrent-mutation limitation described above.

Regression coverage uses injected clocks, fake faults, temporary Unix file stores,
and CLI/service/TUI contracts. These are not proof of native secure-store behavior.
Disposable-store macOS, Linux and Windows verification has **not been run** and
is required before a cross-platform-ready claim. Production lock contacts native
stores even with file opt-in; deterministic tests inject cleanup adapters instead.
Existing full-workspace clipboard tests require a disposable clipboard as well.

Untrusted vault headers above the enforced per-call maxima are rejected before
Argon2 work. Repeated requests and concurrent calls can still consume resources
up to the per-call policy; no aggregate concurrency/resource bound is promised.
Historical vaults above the supported limits are not guaranteed to remain
accessible. Comprehensive memory hardening and vault-wide filesystem hardening
are outside this change.

### Release artifact verification

Release archives and the Linux SBOM are covered by the final `SHA256SUMS.txt`.
When configured, signing that exact final manifest is required to succeed and
produces `SHA256SUMS.txt.minisig`; absent signing configuration is explicitly
marked unsigned. A valid signature only establishes authenticity when verified
against a minisign public key obtained independently from a trusted channel.
No trusted public key is currently supplied by this project; arranging that
distribution is a prerequisite for consumers to rely on signed releases.


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

After Argon2id returns a derived-key array, Kevi immediately places that array
in zeroizing ownership, then copies it once into the long-lived secret type.
The temporary derivation array is zeroized when that owner drops, including
when secret allocation or construction unwinds. This does not make a claim
about copies internal to the KDF or memory already copied by the allocator.

The file-cache reader owns serialized payload bytes in a zeroizing buffer from
allocation through decode, including malformed and oversized-read paths. The
decoded envelope's encoded key string and the decoded key buffer are also
zeroized. This does not establish that serializer/parser internals or payload
buffers returned by native-store adapters are wiped; caller-owned input bytes
are outside the file-reader guarantee.

### memlock (optional)

On Unix-like systems, enabling the `memlock` feature attempts to lock
process memory containing sensitive data to prevent it from being
swapped to disk.

* This relies on OS primitives like `mlock` / `mlockall`.
* It is a **best-effort** mitigation and may require additional OS
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

* **Opt-in visibility**:
  * By default, secrets are copied to clipboard instead of being
    printed.
  * `--echo` is required to print a secret to stdout.
* **TTL (time-to-live)**:
  * Kevi uses a configurable TTL, after which it will attempt to clear
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

On Unix-like systems, tests assert that session files are created with
restrictive permissions (no group/world read access). This ensures
that another unprivileged user on the same machine cannot trivially
read your cached keys.


Operational guidance
--------------------

### Choosing a master password

Because Kevi's security ultimately depends on your master password,
you should:

* Use a **strong, unique passphrase**, preferably generated or derived
  from a long random word sequence.
* Avoid reusing passwords from other services.
* Consider using a passphrase of at least 4-6 random words or 16+
  random characters.

### Using Kevi safely day-to-day

* Prefer copying passwords to clipboard over echoing them in the
  terminal when practical.
* Keep clipboard TTLs short, especially on shared or unmanaged
  machines.
* Use `kevi lock` or end your session when stepping away from your
  desk.
* Keep your operating system and Rust toolchain up to date.

### Limitations and future work

Some limitations and potential future improvements:

* There is currently no built-in multi-device sync; you are
  responsible for syncing the vault file if needed.
* There is no hardware-backed key storage (e.g. TPM, Secure Enclave)
  integration yet.
* Side-channel resistance (timing, cache) relies largely on
  well-reviewed upstream libraries (`ring`, `argon2`, etc.), but
  Kevi itself has not undergone a formal audit.

If you rely on Kevi for high-value secrets, consider having your
deployment or configuration reviewed by someone familiar with applied
cryptography and secure systems design.


Security disclosures
--------------------

If you believe you found a security issue, please report it privately
to the maintainers instead of opening a public issue with exploit
details.

Include, when possible:

* Affected version/commit.
* Reproduction steps or proof of concept.
* Impact assessment and any suggested mitigations.

We will triage reports as quickly as possible and coordinate disclosure
timing for confirmed vulnerabilities.
