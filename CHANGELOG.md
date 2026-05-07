# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Pre-1.0 we reserve the right to break on minor bumps.

## [Unreleased]

### Added

- `pty-relay local start --mosh` (beta) — opt-in mosh-style predictive
  local echo in the web UI. Printable keystrokes are written into the
  terminal immediately and reconciled against server output as it
  arrives, hiding round-trip latency for echo-style typing. Auto-
  disabled in alternate-screen mode (vim, htop, anything full-screen)
  to avoid corrupting programmatic cursor placement. Off by default;
  enable with `--mosh` on daemon startup. Beta because we want real-
  world feedback on the rollback heuristic before turning it on by
  default. Issue #12.
- Web UI now wraps the printed `Token URL` and `Tailscale` lines in
  OSC 8 hyperlinks so terminals that support the protocol render
  them as clickable links. Plain URLs are still emitted when stdout
  is piped or `NO_COLOR` is set. Issue #13.
- Web UI session-overview list shows session age (`3m`, `2h`, `5d`)
  and supports a new `age` sort. Issue #4.
- Web UI attach page has a collapsible "Info" panel showing the
  attached session's tags, command, cwd, age, and aliases. Hidden
  by default; opening shrinks the terminal slightly rather than
  overlapping it. Issue #5.
- Terminal font-size control in the web UI (`A−` / `A+` toolbar
  buttons), bounded to [10, 32] px and persisted via localStorage.
  Issue #8.
- Mobile keyboard input-mode toggle (`abc` / `ABC`) lets you
  disable autocorrect / autocapitalize / autocomplete / spellcheck
  for shell-style input where OS assists do more harm than good.
  Persisted per-device. Issue #10.
- `pty-relay local start --skip-osc8-confirm` skips the click-to-
  confirm prompt for OSC 8 hyperlinks in the web terminal. Default
  behavior shows a confirm() so users can review the URL before
  navigating (visible label can mismatch the underlying target).
  Issue #2.
- `pty-relay server reset --email <addr>` requests an account-key
  reset from the public relay when locked out. Sends an
  unauthenticated POST to `/api/account/reset`; the relay emails a
  confirmation link gated by a current TOTP code. Confirming
  revokes every key on the account but leaves the account, emails,
  TOTP secret, and ACLs intact — re-enroll a fresh daemon with
  `pty-relay server signin --email <addr>`. The relay returns
  `{status: "maybe_sent"}` regardless of whether the email matches
  a real account, so this command never enumerates accounts.

### Fixed

- Web UI: mobile session-list layout no longer renders horizontally
  shifted off-screen. The container had `overflow-y: auto` which
  per CSS spec promoted `overflow-x` from `visible` to `auto`,
  letting iOS Safari land first paint scrolled left of zero when
  any row's cwd or tag value was wider than the viewport. Both
  axes are now explicitly clipped, and rows can shrink to 0
  everywhere they could previously force overflow. Issue #6.

### Changed

- `pty-relay local start --tailscale` now binds the underlying
  HTTP/WebSocket server to `127.0.0.1` by default, instead of all
  interfaces. With `tailscale serve` proxying tailnet traffic to
  loopback, the LAN-facing listener was an unintentional secondary
  ingress. The new `--bind <addr>` flag lets you override (e.g.
  `--bind 0.0.0.0` to restore the previous LAN behavior). Without
  `--tailscale`, the historical all-interfaces default is unchanged.
  Closes #1.

  **Migration:** if you were running `local start --tailscale` and
  relying on connecting to `<lan-ip>:<port>` from another machine on
  the LAN, add `--bind 0.0.0.0` to your invocation.

### Initial public release

- Self-hosted mode (`pty-relay local start`): one-process relay +
  daemon, `#pk.secret` token URLs, optional Tailscale proxy.
- Public-relay mode against `relay.pty.computer`: email + TOTP
  account; `server signin`, `server start`, `server mint`; account-
  wide clients via `client signin`; daemon-pinned clients via
  `server mint` + `client join`.
- Shared session commands (`client ls / connect / peek / send / tag
  / events`) work for both modes.
- Noise NK + KK for end-to-end encryption. v2 canonical Ed25519
  signed payloads bind every signed HTTP + WS request to method +
  path + body/query hash.
- Strict single-role keys, daemon-pinned preauths, revocation via
  close code 4001.
- Credentials encrypted at rest (system keychain or passphrase).
- Depends on [pty](https://github.com/myobie/pty) >= 0.10.0 and
  Node.js 22+.

[Unreleased]: https://github.com/myobie/pty-relay/commits/main
