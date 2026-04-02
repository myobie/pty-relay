# pty-relay

> **Experimental** — this is pre-release software. APIs, protocols, and
> on-disk formats may change without notice. Data stored by this tool may
> be lost on upgrade. Do not rely on it for anything you can't recreate.

Remote access to [pty](https://github.com/myobie/pty) sessions over an
end-to-end encrypted WebSocket tunnel. Connect from a browser, phone, or
another terminal.

```
Client (browser / CLI)
    ↕ Noise NK encrypted WebSocket
Self-hosted relay (Node.js)
    ↕ Unix socket
pty session (bash, vim, etc.)
```

The relay pairs connections and forwards opaque binary frames. All
terminal data is end-to-end encrypted — the relay never sees plaintext.

## Quick setup

Start a relay on your machine:

```bash
pty-relay serve --tailscale --auto-approve --allow-new-sessions
```

That's it. Open the printed Tailscale URL from any device on your
tailnet. You can also scan the QR code from your phone.

For maximum security, omit the flags:

```bash
pty-relay serve
```

Without flags: each client must be approved, and remote session creation
is disabled (clients can only attach to sessions you've already started
with `pty run`).

### Running in the background

```bash
pty-relay serve -d --tailscale --auto-approve --allow-new-sessions
```

This wraps the relay in a detached [pty](https://github.com/myobie/pty)
session and prints the token URL. Reattach with `pty attach relay-daemon`,
stop with `pty kill relay-daemon`.

## Install

Requires [pty](https://github.com/myobie/pty) (>= 0.8.0) and Node.js 22+.

```bash
git clone https://github.com/myobie/pty
git clone https://github.com/myobie/pty-relay
(cd pty && npm install && npm link)
(cd pty-relay && npm install && npm link @myobie/pty && npm link)
```

This uses `npm link` so pty-relay resolves `@myobie/pty` from your
local checkout. Changes to either repo are reflected immediately.

Verify:

```bash
pty-relay --version
pty-relay doctor
```

`pty-relay doctor` prints a diagnostic report (Node version, OS,
keychain status, external tools) that's safe to share when
troubleshooting — it does not print secrets.

### System requirements

- **Node.js 22+** (for native TypeScript execution)
- **macOS, Linux, or Windows** (keychain backend via `@napi-rs/keyring`)
- **A working system keyring** for the zero-prompt experience:
  - macOS: Keychain (always available)
  - Windows: Credential Manager (always available)
  - Linux desktop: GNOME Keyring or KDE Wallet via Secret Service
  - Linux server: no keyring by default — use a passphrase
- **Optional:** `tailscale` CLI (for `--tailscale`), `qrencode` (for QR)

## Connecting

From the CLI:

```bash
pty-relay connect <token-url>
```

Or open the token URL in a browser — the relay serves a web terminal.

If the URL has no session name, you'll be prompted to pick one. Press
`Ctrl+\` to detach from a session.

### Reconnection

If the network drops (laptop sleep, WiFi change, etc.), the client
automatically reconnects with exponential backoff and re-attaches to the
same session. Terminal state is fully restored. Press `Ctrl+\` during
the reconnect wait to detach instead.

## Client approval

By default, each new client must be approved. Three ways:

**Interactive TUI:**

```bash
pty-relay clients
```

Navigate with arrows, approve with Enter, revoke with `r`.

**CLI:**

```bash
pty-relay clients list
pty-relay clients approve <id>
pty-relay clients revoke <id>
```

**Pre-auth invite URLs:**

```bash
pty-relay clients invite --label "iPhone"
```

Prints an invite URL that auto-approves on first use.

**Skip approval (convenience):**

```bash
pty-relay serve --auto-approve
```

### How approval works

- CLI clients save their approved token to the encrypted known-hosts
  store. Reconnections are seamless.
- Browser clients save the token to `localStorage`. The URL in the
  address bar never changes — safe to bookmark and sync.
- Revoking a token deny-lists it. The client gets an immediate error,
  clears its stored token, and re-enters the approval queue.

## Commands

```
pty-relay serve [port]        Run self-hosted relay (default: 8099)
pty-relay connect <url>       Connect to a session (or pick from list)
pty-relay ls                  List known hosts and their sessions
pty-relay forget <host>       Remove a saved host
pty-relay clients             Interactive client approval TUI
pty-relay clients list        Static table (use --json for JSON)
pty-relay clients approve <id>
pty-relay clients revoke <id>
pty-relay clients invite [--label <name>]
pty-relay init                Initialize secret storage
pty-relay reset               Delete all saved credentials
pty-relay set-name <label>    Set a custom name for this machine
pty-relay doctor              Print environment info
pty-relay version             Print the version

Options:
  -d, --detach                Detach into a pty session
  --name <label>              Session name for -d (default: relay-daemon)
  --allow-new-sessions        Allow remote clients to create new sessions
  --auto-approve              Skip client approval
  --tailscale                 Enable Tailscale HTTPS
  --config-dir <dir>          Config directory
  --passphrase-file <path>    Passphrase from file (non-interactive)
  --backend <b>               init: keychain | passphrase
  --force                     Skip confirmation (init/reset)
  --spawn <name>              Create a new remote session (for connect)
  --cwd <dir>                 Working directory for spawned session
  --json                      JSON output (for ls, clients list)
```

## Credentials at rest

All sensitive files are encrypted at rest. There is no plaintext
fallback.

- **System keychain** (default when available): macOS Keychain, Windows
  Credential Manager, Linux Secret Service. No prompts.
- **Passphrase** (fallback): Argon2id + XChaCha20-Poly1305. Prompted on
  first run.

### Non-interactive use

```bash
PTY_RELAY_PASSPHRASE=... pty-relay serve
pty-relay serve --passphrase-file /path/to/passphrase
```

### Forgot your passphrase?

No recovery. `pty-relay reset --force` deletes everything. Every client
has to re-approve.

## Security model

**Protected:**
- Traffic on the network (Noise NK, forward secrecy)
- Files at rest (XChaCha20-Poly1305 via keychain or passphrase)
- Other users on the same machine (0o600 permissions)

**Not protected:**
- Same-user malware while the daemon is running
- Physical access to an unlocked machine
- A compromised Google account with synced bookmarks (base URL is a
  capability, but the per-client approval token is in localStorage)

## How it works

**Noise NK** — the token URL embeds the daemon's Curve25519 public key
and a pairing secret. Each connection gets a fresh handshake with unique
session keys. The relay only sees the hash for pairing.

**Multi-client** — up to 10 concurrent clients, each with its own
encrypted tunnel via separate WebSocket connections.

**Auto-reconnect** — clients detect dead connections via ping/pong
timeouts and sleep/wake clock drift. Reconnects with exponential backoff,
re-attaches to the same session. Terminal state restored via pty's
SCREEN packet.

## Testing

```bash
npx vitest run                                          # unit tests
npx vitest run --config integration/vitest.config.ts    # integration
npx playwright test --config integration/playwright.config.ts  # browser
```

## Building the browser client

```bash
npm run build:browser
```

Output in `browser/dist/` is committed to git — no build step needed
to run. Only rebuild after editing `browser/src/`.

## License

MIT
