# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Pre-1.0 we reserve the right to break on minor bumps.

## [Unreleased]

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
