# Research and future work

Notes on ideas that aren't in v0.1.0 but are worth considering. Not promises,
just a scratchpad.

---

## System keychain integration

Right now, all secrets are stored as plaintext files on disk, protected only by
filesystem permissions (`0o600`):

- Daemon: Curve25519 private key, pairing secret (`config.json`)
- Daemon: client tokens (`clients.json`)
- Client: saved token URLs (`hosts` file) — each URL is a full credential
  granting access to that daemon's sessions

All three contain material that grants access and must be protected equally.
The client `hosts` file is often overlooked but is as sensitive as the
daemon's `config.json` — a leaked `hosts` file is equivalent to leaking every
token URL you've ever connected to.

An opt-in `--keychain` flag could store these in the system keychain instead:
macOS Keychain, Windows Credential Manager, or Linux Secret Service (GNOME
Keyring / KDE Wallet). Applies to both the daemon (`serve`) and the client
(`connect`, `ls`, interactive TUI).

### Library choice: `@napi-rs/keyring`

`keytar` (the old standard) was archived December 2022. The modern replacement
is `@napi-rs/keyring` — Rust-based native bindings, actively maintained, used by
Azure SDK and Microsoft auth libraries.

- macOS: Security.framework directly
- Linux: Secret Service via D-Bus (works with GNOME Keyring and KDE Wallet,
  no libsecret C dependency)
- Windows: Credential Manager via DPAPI
- Pre-built binaries for common platforms — no compile step on install

### Secure Enclave is not an option

Apple's Secure Enclave only supports P-256 ECDSA, not Curve25519 or Ed25519.
Using it would mean re-architecting the protocol around a different curve,
which isn't worth the security trade-off for this use case.

macOS Keychain items *can* be marked "non-exportable" and bound to the login
session, which gives "OS login protection" without requiring the Secure Enclave.

### Design sketch

```bash
pty-relay serve --keychain   # store secrets in system keychain
pty-relay serve              # file-based (current behavior, default)
```

- `@napi-rs/keyring` becomes an optional dependency (dynamic import)
- First run with `--keychain`: migrate existing secrets into the keychain
- Subsequent runs: load from keychain
- Headless servers (no keyring running, no DBus session): fall back to files,
  but the user **MUST** provide a passphrase. No silent plaintext fallback —
  if there's no keychain, encryption at rest via passphrase is required.
  Argon2id to derive a key, XChaCha20-Poly1305 to encrypt the secrets file.
  The daemon (or client) prompts for the passphrase on start (or reads it
  from a `PTY_RELAY_PASSPHRASE` env var for non-interactive environments).
  This applies to every sensitive file: daemon `config.json`, daemon
  `clients.json`, client `hosts` file.
- No protocol changes, no new features — just a storage backend swap

### Trade-offs

**Pros**: protects against backup leaks, accidental exposure, casual filesystem
access. On macOS, Touch ID can gate per-session unlock. Familiar UX on Linux
desktops.

**Cons**: adds a native dependency (even if optional). Headless Linux has no
keyring — needs file fallback anyway. Keychain prompts can be annoying. Config
is no longer "just copy the files" portable.

### Priority

Post-v0.1.0. Worth doing for v0.2.

---

## Client approval: future enhancements

The client approval system (shipped in v0.1.0) covers the basics. Some
directions for later:

- **Interactive approval prompt in the `serve` TUI**: currently you have to run
  `pty-relay clients approve <id>` from another terminal. An interactive prompt
  in the daemon's output when a client is pending would be nicer.
- **Client labels**: when approving, the operator can set a label. Currently
  pending entries are unlabeled until approved. Maybe the hello message's
  `label` field should auto-populate a suggested label.
- **Expiring tokens**: pre-auth invite tokens could have a TTL. "This invite
  expires in 24 hours."
- **One-time tokens**: an invite that can only be used once, then auto-revoked.
- **IP/network restrictions**: limit a token to a specific Tailscale node or
  subnet.

---

## Session sharing

Currently each client gets its own tunnel to the daemon, but they all share the
same pty session state via the `pty` session manager. Multiple clients attached
to the same session see the same output and can type.

This already works, but there's room for:

- **Read-only clients**: attach without sending keystrokes. Useful for pair
  programming where one person drives and others watch.
- **Follow mode**: attach but only receive screen updates, no interactive
  keyboard at all (like `pty peek` but remote).

---

## Mobile apps

A native iOS/Android app would be nicer than the web client for phones. The
browser client works but has keyboard limitations.

Rough sketch:
- SwiftUI + WKWebView, with the token injected via `window.PTY_RELAY_TOKEN`
  before page load (the web client already supports this injection point)
- Host list stored in Keychain
- QR scanner for importing token URLs
- Push notifications for client approval requests (requires a push server —
  probably not worth it)

---

## Cross-connect / topology

If you have pty-relay running on multiple machines, you can't currently connect
to session B from machine A through a single token. Each machine's daemon is
independent. You'd need separate token URLs for each daemon.

Possible approaches:
- **Pure topology**: one daemon maintains a list of sibling daemons (manual
  config), shows them in its web UI, you click through to connect directly to
  each
- **Cross-connect via token sharing**: one daemon holds tokens for sibling
  daemons and proxies requests. One QR code → access to all machines. Bigger
  blast radius if that token leaks.
- **Daemon as gateway**: daemon proxies requests to siblings without the client
  ever seeing the sibling tokens. Client trusts the gateway daemon, gateway
  trusts siblings.

The daemon-as-gateway model is probably the right trade-off: the blast radius
stays per-daemon, but the UX is "one QR, access everything."

Needs more thought before implementing.

---

## Authentication beyond token URLs

Today, anyone with the token URL can try to connect (subject to approval).
Token URLs are secrets — if they leak, the client approval system helps, but
it's still a recovery step, not prevention.

Alternatives to consider:
- **Public key auth**: client has an Ed25519 keypair, daemon has a list of
  trusted client public keys. Client signs a challenge on connect. No shared
  secret in the URL.
- **Passkey / WebAuthn**: for the browser client, use a hardware-backed passkey
  to authenticate. Daemon verifies the passkey against a registered credential.
- **TPM/Secure Enclave** on the daemon side: use hardware-backed signing keys
  for the daemon itself, so the daemon's identity can't be stolen from the
  filesystem.

These are all bigger changes than keychain integration and would require
protocol updates.
