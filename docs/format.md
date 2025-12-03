### Kevi vault container format (v1)

This document describes the on-disk container used by Kevi to store an encrypted vault. The entire file consists of a
fixed-size header followed by an AEAD ciphertext. The header itself is authenticated via AEAD Associated Data (AAD),
providing strong tamper detection.

Header layout (little-endian):

- magic: 4 bytes = `"KEVI"`
- version: `u16` = `1`
- kdf_id: `u8` — 2 = Argon2id
- aead_id: `u8` — 1 = AES-256-GCM (2 reserved for ChaCha20-Poly1305)
- m_cost_kib: `u32` — Argon2 memory cost in KiB
- t_cost: `u32` — Argon2 iterations
- p_lanes: `u32` — Argon2 parallel lanes
- salt: `[u8; 16]` — KDF salt
- nonce: `[u8; 12]` — AEAD nonce

Immediately after the header starts the ciphertext:

```
[header (fixed size)] [ciphertext || tag]
```

Semantics:

- KDF: Argon2id with parameters encoded in the header. The derived key length is 32 bytes (AES-256).
- AEAD: AES-256-GCM. The header bytes (from the very beginning to the end of the nonce) are used as AEAD AAD. This binds
  the parameters to the ciphertext and prevents parameter swapping.
- Nonce: 96-bit unique per encryption (random). Key/nonce reuse must not occur for AES-GCM.
- Salt stability: For an existing vault, the KDF salt and cost parameters remain stable across saves to enable
  header‑bound derived‑key caching; a fresh AEAD nonce is generated for each save.

Defaults (as of 2025):

- Argon2id defaults: `m_cost_kib = 65536` (64 MiB), `t_cost = 3`, `p_lanes = 1`.

Versioning and evolution:

- `version` enables future format changes. Files with unknown versions are rejected with a clear error message.
- Unknown `kdf_id`/`aead_id` values are rejected.
- Tunable parameters (Argon2 costs) are stored per-file to allow future changes without migration.

Security properties:

- Data at rest is encrypted with AEAD; any tampering (including header/ciphertext modification) results in decryption
  failure.
- The header contains no plaintext secrets. Salt and nonce are non-secret.

### Error semantics (parsing/opening)

When opening a vault, the implementation performs strict header parsing before attempting decryption. Typical
user‑facing errors include:

- "Failed to parse header: invalid magic" — file does not start with `KEVI` and is not a valid vault.
- "Failed to parse header: ciphertext too short for header" — file is truncated.
- "Failed to parse header: unsupported version" — vault is from an unknown future version; upgrade Kevi.
- "Failed to parse header: unsupported kdf/aead" — algorithm identifiers are not supported.
- "Failed to decrypt vault (wrong password?)" — authentication failed (wrong password or tampered ciphertext).

The CLI `kevi header --path <vault>` prints the parsed header fields and returns a non‑zero exit code on errors. The
header never contains plaintext secrets.
