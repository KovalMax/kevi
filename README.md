![ci workflow](https://github.com/KovalMax/kevi/actions/workflows/ci.yml/badge.svg)

Kevi — encrypted CLI vault and TUI password manager
===================================================

Kevi is a local, file‑based password and secrets vault focused on:

* **Strong, modern cryptography** (Argon2id + AES‑256‑GCM)
* **Simple CLI workflows** for scripting and automation
* A **terminal user interface (TUI)** for interactive browsing
* Careful handling of in‑memory secrets and clipboard usage

Kevi does **not** try to be a cloud sync solution. It is designed as a
single‑machine (or manually synced) vault for users who prefer having
full control over their secret storage.

> For a detailed description of the cryptography, threat model, and
> operational security guidance, see [`SECURITY.md`](SECURITY.md).


Features
--------

* Encrypted vault file with a simple binary format starting with the
  magic header `KEVI`.
* Password‑based key derivation using **Argon2id** with conservative
  defaults (64 MiB memory, 3 iterations, 1 lane).
* Authenticated encryption using **AES‑256‑GCM** via the `ring` crate.
* **CLI** commands for adding, listing, querying, and retrieving
  secrets.
* **TUI** (terminal UI) for interactive navigation and quick copying
  to clipboard.
* **Clipboard integration** with configurable time‑to‑live (TTL).
* Derived‑key **session caching** (optional) to avoid re‑typing the
  master passphrase repeatedly.


Installation
------------

### Prerequisites

* Rust toolchain (stable) and Cargo. You can install them via
  <https://rustup.rs/>.

Kevi is a regular Rust binary crate. You can install it from the
project directory or, if published, directly from crates.io.

### Install from source (this repository)

Clone the repository and run:

```bash
cargo install --path .
```

This will build and install a `kevi` binary into your Cargo
`bin` directory (usually `~/.cargo/bin`). Make sure this directory is
on your `PATH`.

You can also run Kevi without installing it globally:

```bash
cargo run -- <args...>
```


Concepts
--------

### Vault

All secrets live in a single **vault file**, which is an encrypted
binary file written in the Kevi format. The vault contains a list of
"entries", each with:

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


Quick start
-----------

### 1. Initialize a new vault

```bash
kevi init --path /path/to/my-vault.ron
```

You will be prompted for a master password. Choose a strong phrase
that you can remember.

If you omit `--path`, Kevi will use the default vault path, which is
derived from the configuration and data directory.

### 2. Add an entry

```bash
kevi add my-site \
  --user alice \
  --password 's3cret' \
  --notes 'personal account' \
  --path /path/to/my-vault.ron
```

You can also tell Kevi to generate a random password instead of
supplying one explicitly; see the `add` command help.

### 3. Get an entry’s password (clipboard)

```bash
kevi get my-site --field password --path /path/to/my-vault.ron
```

By default, this will:

* Decrypt the vault using your master password.
* Find the `my-site` entry.
* Copy the password to the clipboard for a configured duration.

### 4. Get and print a field (no clipboard)

```bash
kevi get my-site --field password --echo --no-copy --path /path/to/my-vault.ron
```

This:

* **Prints** the password to standard output.
* Does **not** copy anything to the clipboard.

You can substitute `--field user` or `--field notes` to print the
username or notes instead.

### 5. Launch the TUI

```bash
kevi tui --path /path/to/my-vault.ron
```

This opens an interactive terminal UI where you can search, select,
and copy fields. See below for key bindings.


CLI usage
---------

The CLI uses standard Unix‑style subcommands. You can always run:

```bash
kevi --help
kevi <subcommand> --help
```

for up‑to‑date usage information.

### Global options

Common global options include:

* `--path <FILE>` – path to the vault file (overrides config/env).
* `--version` – print version information, including git SHA,
  build time, target triple, and enabled features.

### Important subcommands

The exact set may evolve, but typical commands include:

* `init` – create a new vault file and set a master password.
* `add` – add a new entry (interactive or from flags).
* `rm` – remove an entry by label.
* `list` – list entries, optionally filtering by query and
  outputting JSON.
* `get` – retrieve a specific field from an entry, optionally copying
  to clipboard or echoing to stdout.
* `unlock` – pre‑derive and cache a key in a short‑lived session
  file so subsequent operations do not prompt for the password.
* `lock` – clear the cached derived‑key session.
* `header` – inspect the vault header (version, parameters) without
  decrypting contents.
* `tui` – launch the terminal user interface.

#### `init`

Create a new vault file:

```bash
kevi init [--path <FILE>]
```

Options commonly include:

* `--path` – where to create the vault; if omitted, the default path
  from the configuration is used.

#### `add`

Add a new entry:

```bash
kevi add <label> [--user <USERNAME>] [--password <PASS>] [--generate] [--length N]
```

Typical options:

* `--user` – set the username.
* `--password` – provide an explicit password.
* `--generate` – generate a random password using the built‑in
  generator.
* `--length` – length for generated passwords.

If neither `--password` nor `--generate` is supplied, Kevi may prompt
you interactively (depending on CLI behavior).

#### `get`

Retrieve a field from an entry:

```bash
kevi get <label> --field <password|user|notes> [--no-copy] [--echo]
```

Behaviors:

* Without `--no-copy`, the field is copied to the clipboard.
* With `--echo`, the field is printed to stdout.
* You can combine `--echo` and `--no-copy` to avoid clipboard usage
  entirely.

Example:

```bash
kevi get github --field password --echo --no-copy
```

#### `list`

List entries in the vault:

```bash
kevi list [--query <TERM>] [--show-users] [--json]
```

Options:

* `--query` – filter labels by a case‑insensitive substring.
* `--show-users` – include usernames in the output.
* `--json` – output machine‑readable JSON instead of human text.

#### `unlock` and `lock`

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

Session files are stored with restrictive file permissions on
Unix‑like systems; see `SECURITY.md` for details.


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


Configuration
-------------

The configuration file is a TOML document, for example:

```toml
vault_path = "/home/alice/.local/share/kevi/vault.ron"
clipboard_ttl_secs = 30
backups = 3

[generator]
length = 24
include_digits = true
include_upper = true
include_lower = true
include_symbols = true

[profiles]
  [profiles.work]
  vault_path = "/home/alice/work/kevi-work.ron"

  [profiles.personal]
  vault_path = "/home/alice/.local/share/kevi/vault.ron"
```

Typical fields include:

* `vault_path` – default path to the vault file.
* `clipboard_ttl_secs` – how long secrets stay in the clipboard
  (approximate; depends on platform support).
* `backups` – how many historical versions of the vault file to keep
  when writing.
* `[generator]` – defaults for password generation.
* `[profiles]` – named vault configurations.

### Profiles

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

See `SECURITY.md` for operational advice on choosing clipboard TTLs
and backup settings.


Security overview (short)
-------------------------

At a high level:

* Kevi uses **Argon2id** for password‑based key derivation with
  parameters tuned for CLI use on modern machines.
* The vault data is encrypted and authenticated with
  **AES‑256‑GCM** (via the `ring` crate).
* The file format starts with a `KEVI` magic header and encodes all
  cryptographic parameters and a random salt and nonce.
* In‑memory secrets are stored in types such as `SecretString` from
  the `secrecy` crate, which aim to reduce accidental leakage.
* Optional **memlock** support can limit swapping secrets to disk on
  supported Unix platforms.
* Clipboard usage is explicit and configurable, with best‑effort
  clearing after a TTL.

For a deep dive into threat model, algorithms, and limitations, see
[`SECURITY.md`](SECURITY.md).


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

* `cargo fmt` (format check)
* `cargo clippy`
* `cargo build`
* `cargo test` (with and without `memlock` on Linux)
* `cargo audit` (via a dedicated job)
* `cargo-llvm-cov` for coverage reporting

You can mirror these steps locally before pushing changes.

### Contributing

Contributions, bug reports, and feature ideas are welcome. When
submitting a pull request:

* Run `cargo fmt`, `cargo clippy`, and `cargo test` locally.
* Try to include tests for new functionality where practical.
* Avoid logging or printing secrets; prefer redacted debug output.

Please see `SECURITY.md` for expectations around handling sensitive
data when developing new features.
