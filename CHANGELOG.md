# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Pre-1.0 we reserve the right to break on minor bumps.

## [Unreleased]

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
