# pty-relay

> **Experimental** — pre-release software. APIs, protocols, and on-disk
> formats may change without notice. Do not rely on it for anything you
> can't recreate.

Remote access to [pty](https://github.com/myobie/pty) sessions over an
end-to-end encrypted WebSocket tunnel. Connect from a browser, phone, or
another terminal. Two modes:

- **Self-hosted** (`pty-relay local start`) — one process runs a
  lightweight relay + daemon on your machine. No accounts, no email.
  Auth is the `#pk.secret` fragment in the token URL printed on startup.
  Great for a laptop talking to a desktop over Tailscale or a LAN.

- **Public relay** (`pty-relay server signin`) — your daemon connects
  outbound to a multi-tenant relay at `relay.pty.computer`. Email +
  TOTP auth, account-scoped devices, works over any NAT. Great for
  reaching your machines from anywhere.

Both modes use the same Noise-encrypted session protocol; the relay
only sees opaque binary frames.

## Install

Requires [pty](https://github.com/myobie/pty) (>= 0.10.0) and Node.js
22+ for native TypeScript execution.

```bash
npm install -g @myobie/pty @myobie/pty-relay
```

Verify:

```bash
pty-relay --version
pty-relay doctor
```

`pty-relay doctor` prints a diagnostic report (Node version, OS,
keychain status, external tools) safe to share when troubleshooting —
it does not print secrets.

### System requirements

- **Node.js 22+**
- **macOS, Linux, or Windows**
- **A working system keyring** for the zero-prompt experience:
  - macOS: Keychain (always available)
  - Windows: Credential Manager (always available)
  - Linux desktop: GNOME Keyring or KDE Wallet via Secret Service
  - Linux server: no keyring by default — use a passphrase
- **Optional:** `tailscale` CLI (for `--tailscale`), `qrencode` (for QR)

## Quickstart — self-hosted

```bash
pty-relay init
pty-relay local start --tailscale --auto-approve --allow-new-sessions
```

Prints a token URL. Open it in a browser, scan the QR from your phone,
or on another machine run:

```bash
pty-relay connect <token-url>
```

For maximum security, drop the convenience flags:

```bash
pty-relay local start
```

Each new client then has to be approved (see [Client approval](#client-approval-self-hosted)),
and remote session creation is disabled (clients can only attach to
sessions you've already started with `pty run`).

### Running in the background

```bash
pty-relay local start -d --tailscale --auto-approve --allow-new-sessions
```

Wraps the relay in a detached [pty](https://github.com/myobie/pty)
session and prints the token URL. Reattach with
`pty attach relay-daemon`, stop with `pty kill relay-daemon`.

Check status any time:

```bash
pty-relay local status              # pid / label / pubkey / client count
pty-relay local status --show-token # also print the token URL
```

## Quickstart — public relay

### This machine as a daemon

```bash
pty-relay init
pty-relay server signin --email you@example.com --relay https://relay.pty.computer
```

Prompts for the 6-digit code emailed to you, then (on a fresh account)
prints an `otpauth://` URL to add to an authenticator app. Then:

```bash
pty-relay server start
```

Leave it running in the foreground, or run detached:

```bash
pty-relay server start -d
# reattach: pty attach relay-server
# stop:     pty kill   relay-server
```

### Another machine as a client

```bash
pty-relay init
pty-relay client signin --email you@example.com --relay https://relay.pty.computer
```

Prompts for an email code and a current 6-digit TOTP code from your
authenticator. Then:

```bash
pty-relay server hosts --merge   # pull the account's daemons into known-hosts
pty-relay client ls              # list sessions on each daemon
pty-relay client connect <label>
```

### More daemons / more clients

- **Another daemon on the same account**: `pty-relay server signin` with
  the same email. The relay asks for the current TOTP from your app
  (proof that you control an existing daemon).
- **Another account-wide client**: `pty-relay client signin` with the
  same email + TOTP.
- **A pinned client (scoped to one daemon)**: on the daemon,
  `pty-relay server mint` prints a one-time preauth URL. On the
  joining device, `pty-relay client join <url>` claims it. The
  resulting client key can only reach that one daemon — the relay
  enforces the pin.

### Rotating, revoking, deleting

- `pty-relay server rotate --role <daemon|client>` — two-step Ed25519
  rotation. Add `--complete` to finalize.
- `pty-relay server revoke <label-or-key>` — kick a device off the
  account. Prompts for confirmation.
- `pty-relay server delete-account` — nuke the whole account on the
  relay. Prompts for confirmation.
- `pty-relay local reset` — wipe just the self-hosted daemon's local
  state on this machine. Preserves public-relay enrollment.
- `pty-relay reset` — nuke everything in the config dir.

## Command reference

### `pty-relay local` — self-hosted relay on this machine

```
local start [port]              Run the relay (default: 8099)
  --tailscale                     Proxy HTTPS via 'tailscale serve'
  --auto-approve                  Skip the per-client approval TUI
  --allow-new-sessions            Let remote clients spawn pty sessions
  -d [--name <label>]             Run detached in a 'pty' session
local status [--show-token]     Daemon state: pid, label, pubkey, client count
local reset [--force]           Wipe self-hosted daemon state only
```

### `pty-relay server` — public-relay account management (daemon side)

```
server signin --email <addr>    Register this machine as a daemon
  [--label <name>]                  (defaults to OS hostname)
  [--relay <url>]                   (defaults to http://localhost:4000)
server start                    Run the daemon attached to a public relay
  [--allow-new-sessions]
  -d [--name <label>]               Run detached in a 'pty' session
                                     (default label: relay-server)
server mint                     Mint a preauth URL (daemon-pinned client)
  [--ttl-seconds N]
  [--totp-code <code>]
server status [--json]          Account, daemon key, client key, pin info
server hosts [--merge]          List devices on the account; --merge adds
                                 daemons to known-hosts
server rotate --role <daemon|client> [--complete]
server revoke <label-or-key> [-y] [--force]
server add-email <email>
server delete-account [-y]
server totp show                Print the TOTP secret (re-add to authenticator)
server totp code                Print the current 6-digit code
```

### `pty-relay client` — use sessions exposed by daemons

```
client signin --email <addr>    Register this machine as an account-wide
  [--label <name>]                 client (account must exist)
  [--relay <url>]
client join <preauth-url>       Claim a preauth (produces a daemon-pinned
  [--label <name>]                 client key)
  [--totp-code <code>]
client ls                       List known hosts and their sessions
client connect <host-or-url>    Attach to a remote pty session
client peek <host> <session>    Print a session's current screen
client send <host> <session>    Send input
client tag <host> <session>     Show / set tags
client events <host>            Follow a daemon's events
client rename <old> <new>       Rename a saved known-host entry
client forget <host-label>      Remove a saved host
```

Session commands transparently handle both self-hosted (token URL) and
public-relay hosts via known-hosts.

### Top-level

```
init                            Initialize the encrypted secret store
reset [--force]                 Nuke everything in the config dir (prompts)
doctor                          Print environment / diagnostics
set-name <label>                Set the label this daemon advertises
clients                         Interactive client-approval TUI (self-hosted)
clients list | approve | revoke | invite
version                         Print the version

Global flags:
  --config-dir <dir>              Override config directory
  --passphrase-file <path>        Passphrase from file (non-interactive)
```

## Client approval (self-hosted)

By default, each new client has to be approved. Three ways:

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

**Pre-auth invite URL:**

```bash
pty-relay clients invite --label "iPhone"
```

Prints an invite URL that auto-approves on first use.

**Skip approval entirely:**

```bash
pty-relay local start --auto-approve
```

### How approval works

- CLI clients save their approved token to the encrypted known-hosts
  store. Reconnections are seamless.
- Browser clients save the token to `localStorage`. The URL in the
  address bar never changes — safe to bookmark.
- Revoking a token deny-lists it. The client gets an immediate error
  and re-enters the approval queue.

## Reconnection

On both transports, if the network drops (laptop sleep, WiFi change,
mobile switch) the client reconnects with exponential backoff and
re-attaches to the same session. Terminal state is fully restored via
pty's SCREEN packet. Press `Ctrl+\` during the reconnect wait to
detach instead.

Revocation (close code 4001) is terminal — the daemon exits, and the
client surfaces a clear error rather than looping on 401.

## Credentials at rest

All sensitive files are encrypted at rest. No plaintext fallback.

- **System keychain** (default when available): macOS Keychain, Windows
  Credential Manager, Linux Secret Service. No prompts.
- **Passphrase** (fallback): Argon2id + XChaCha20-Poly1305. Prompted on
  first run.

### Non-interactive use

```bash
PTY_RELAY_PASSPHRASE=... pty-relay local start
pty-relay local start --passphrase-file /path/to/passphrase
```

### Forgot your passphrase?

No recovery. `pty-relay reset --force` deletes everything. Every client
has to re-approve, every public-relay device has to re-enroll.

## Security model

**Protected:**

- Session traffic is end-to-end encrypted between client and daemon.
  The relay (self-hosted or public) only sees opaque frames.
- Noise NK handshake with fresh per-session ephemeral keys (forward
  secrecy).
- Public-relay client-pair connections add Noise KK, so both ends
  authenticate each other's static keys too.
- All HTTP + WS auth on the public relay is v2-canonical Ed25519
  signatures: signed payload binds to method + path + body/query hash.
  A captured signature for one endpoint can't be replayed against
  another.
- Preauth-minted client keys are **daemon-pinned** server-side — they
  can only reach the minting daemon, never siblings on the account.
- Daemon keys and client keys have strictly separate roles. A daemon
  key cannot open a client-pair WebSocket, and vice versa.
- Files at rest: XChaCha20-Poly1305 via keychain or passphrase-derived
  key. `0o600` on all secret files.

**Not protected:**

- Same-user malware on a machine where the daemon is running.
- Physical access to an unlocked machine.
- A compromised email inbox (someone with inbox access plus your TOTP
  can enroll devices; email + TOTP are the two factors).

### Public-relay specifics

- Email + TOTP for signin. TOTP secret is generated on the first
  daemon signup for the account and persisted on every subsequent
  daemon that joins — any daemon can mint preauths.
- Clients never receive the TOTP secret.
- Adding another daemon to an existing account requires a current TOTP
  code from an already-enrolled daemon (proof-of-control).
- Account-wide client signin is email + TOTP; the relay rejects if the
  account doesn't exist or has no active daemon yet.

## Troubleshooting

- `pty-relay doctor` — environment, tool availability, config dir.
- `pty-relay local status` / `pty-relay server status` — per-mode
  state.
- `PTY_RELAY_DEBUG=1 pty-relay …` — verbose logging on connection
  lifecycles.

## Contributing

### Working on pty-relay itself

```bash
git clone https://github.com/myobie/pty
git clone https://github.com/myobie/pty-relay
(cd pty && npm install && npm link)
(cd pty-relay && npm install && npm link @myobie/pty && npm link)
```

The `npm link` step resolves `@myobie/pty` from your local checkout so
changes to either repo are reflected immediately.

### Layout

```
src/
  cli.ts                 top-level dispatch
  commands/
    local/               self-hosted daemon (start, status, reset)
    server/              public-relay daemon (signin, mint, etc.)
    client/              public-relay client (signin, join)
    connect.ts, ls.ts, peek.ts, …   session commands (both modes)
    start.ts, start-shared.ts       self-hosted daemon internals
  crypto/                Noise (NK + KK), Ed25519 signing, TOTP
  relay/                 HTTP client, WS primary + per-client, known-hosts
  storage/               encrypted secret store (keychain + passphrase)
  terminal/              CLI terminal bridge
browser/                 web UI (vanilla TS, bundled)
test/                    unit tests (vitest)
integration/             end-to-end tests with real pty sessions
```

### Running tests

```bash
npx vitest run                                          # unit
npx vitest run --config integration/vitest.config.ts    # integration
npx playwright test --config integration/playwright.config.ts  # browser
npx tsc --noEmit                                        # typecheck
```

### Building the browser client

```bash
npm run build:browser
```

Output in `browser/dist/` is committed to git — no build step needed to
run. Only rebuild after editing `browser/src/`.

### Architecture notes

- **Session protocol** is transport-agnostic. The same
  `handleSessionControlMessage` dispatcher handles `list / attach /
  peek / send / tag / events_subscribe / spawn` for both self-hosted
  and public-mode daemons.
- **Noise** has one token-driven engine (`src/crypto/noise.ts`)
  supporting NK and KK. Pattern selection is driven by the relay's
  `paired` frame metadata.
- **Public-relay wire contract** is v2 canonical signed payloads (see
  `src/crypto/signing.ts`). Any change to the signed bytes must match
  the Elixir relay byte-for-byte.
- **Storage** has two backends behind `SecretStore`; callers never see
  plaintext-on-disk paths.

## License

MIT
