### Kevi TUI — minimal terminal interface

The Kevi TUI provides a safe, keyboard‑driven view of your vault. It never renders secrets; copy actions place values on
the clipboard with a TTL and restore previous clipboard content after expiry.

Launch:

```
kevi tui --path /path/to/vault.ron
```

If no session is unlocked, Kevi will use the cached session file if present or prompt for the master password.

#### Keybindings

- `q` — quit
- `j` / `Down` — next item
- `k` / `Up` — previous item
- `/` — enter search mode
- `Esc` — exit search mode
- `Enter` — copy password of the selected entry (TTL applies)
- `u` — copy username of the selected entry (TTL applies)

Search mode: type to filter by label (case‑insensitive). `Enter` or `Esc` leaves search mode.

#### Clipboard TTL

The clipboard TTL used by the TUI follows the same precedence as CLI `get` (sans flag):

`KEVI_CLIP_TTL` > config file `clipboard_ttl` > default (20s)

#### Clipboard environment warnings

When the environment looks headless or remote (for example, `SSH_CONNECTION` is set or both `DISPLAY` and
`WAYLAND_DISPLAY` are unset on Unix), Kevi prints a best‑effort warning before attempting to copy to the clipboard.
Consider using `--no-copy --echo` on the CLI for secure piping if clipboard is unavailable.

#### Theme

The TUI uses an NES/SEGA‑inspired palette:

- Background: Black, Foreground: White
- Primary: Blue, Accent: Red
- Muted: DarkGray, Selection: Cyan (bold)

These styles are centralized in `tui::theme` and applied consistently to titles, lists, and toast messages.

#### Safety properties

- Labels are the only on‑screen content derived from entries.
- Passwords/usernames are never rendered; they are only copied to the clipboard on explicit action.
- Errors and toasts never include secret values.
