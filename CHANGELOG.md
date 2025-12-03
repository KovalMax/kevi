### Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and adheres to Semantic Versioning when releases begin.

#### Unreleased

- PR22: Release packaging scaffolding
    - Embed build metadata in `--version` (git SHA, build time UTC, target, features)
    - Add release workflow (GitHub Actions) to build artifacts for Linux/macOS/Windows
    - Generate SBOM (CycloneDX) and SHA256 checksums; optional signing hooks

- PR23: Simplification & duplication reduction
    - Removed legacy password session and unused traits/adapters (KeySource, CryptoEngine, EnvOrPromptKeySource,
      CachedKeySource)
    - Unified crypto: password-based helpers now delegate to key-based AEAD path
    - Centralized clipboard TTL/environment warnings in `core::clipboard`
    - `get --once` now uses a no-cache `BypassKeyResolver` via the service (no bespoke decrypt path)
    - Minor tidy: shared helpers in CLI/TUI; docs updated to reflect simplified architecture

#### 0.1.0 (pre-release dev)

- Security foundation (PRs 1–21): Argon2id + AES‑GCM container, header tool, clipboard TTL/restores, derived‑key session
  cache, TUI v1.5, config precedence, backups, memlock (optional), fuzz targets.
