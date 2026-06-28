# Pre-shared-key authentication (design)

> **Status:** Design proposal — answers brief-006 (PSK auth for the
> relay, so headless / non-interactive server provisioning works
> without the interactive token-URL pairing + approval flow). No
> code yet. cos surfaces to Nathan for signoff before any build.

## Motivation

The interactive flow (token URL + operator approval) is the right
default for desktop users but it's friction when a friend is
provisioning a fleet of headless servers. PSK lets both sides agree
on a single secret out-of-band and skip the interactive step.

## TL;DR

Add a `Noise_NKpsk2` variant alongside the existing `Noise_NK` —
PSK is mixed into the handshake at message 2 (after `es`), so the
relay's existing daemon-key authentication is *preserved* and PSK is
an *additional* authenticator, not a replacement.

CLI surface:

```
# Server
pty-relay local start --psk-file <path>   # PSK from disk (preferred)
PTY_RELAY_PSK=<key> pty-relay local start # PSK from env

# Client
pty-relay connect --psk-file <path> <token-url>
PTY_RELAY_PSK=<key> pty-relay connect <token-url>
```

Both `--psk` (as a CLI flag) and bare positional PSKs are **explicitly
not supported** — process-list leaks defeat the headless friendliness.

Coexists with `--tailscale` (PSK is at the encrypted-tunnel layer;
tailscale is the transport). Coexists with the existing token URL
(PSK doesn't replace it — see "Layering" below).

## Hypotheses validated

### 1. Does the existing Noise implementation support adding PSK?

**Yes, with a small extension.** `src/crypto/noise.ts` is a hand-
written Noise engine that processes a fixed set of tokens
(`e`, `ee`, `es`, `se`, `ss` per `src/crypto/noise.ts:207`). The
Noise spec adds one more token — `psk` — that's a 1-line case
addition in the engine: mix the 32-byte PSK into the chaining key
via `MixKeyAndHash`.

The `Pattern` type at `src/crypto/noise.ts:215-228` already supports
arbitrary token sequences, so adding `Noise_NKpsk2` is just a new
`Pattern` constant alongside `NK` and `KK`:

```ts
export const NKpsk2: Pattern = {
  name: "Noise_NKpsk2_25519_ChaChaPoly_BLAKE2b",
  preMessages: { initiator: [], responder: ["s"] },
  messages: [
    ["e", "es"],          // → e, es                (msg 1)
    ["e", "ee", "psk"],   // ← e, ee, psk           (msg 2: PSK mix here)
  ],
};
```

(`psk2` = PSK mixed at message *2*; alternatives noted in §4.)

The `Handshake` constructor takes a `Pattern`, so callers picking
NK vs KK vs NKpsk2 already works. Where the PSK *itself* lives in
the constructor needs a small interface widening:

```ts
export interface HandshakeOptions extends HandshakeKeys {
  pattern: Pattern;
  initiator: boolean;
  preSharedKey?: Uint8Array;   // ← new, required when pattern uses `psk`
}
```

### 2. Which PSK pattern?

**`Noise_NKpsk2`** (PSK mixed at message 2, after `e`, `ee`).

| Pattern    | When PSK mixes                          | Pros                                                                | Cons                                                                   |
|------------|-----------------------------------------|---------------------------------------------------------------------|------------------------------------------------------------------------|
| `NKpsk0`   | Before message 1 (`psk, e, es`)         | Simplest                                                            | Initiator emits an encrypted-but-PSK-mixed message before the responder has authenticated anything. A peer who *doesn't* have the PSK still sees a valid-looking ciphertext. |
| `NKpsk1`   | After `es` in message 1                 | PSK + responder's static key both authenticate message 1            | Slightly more complex; responder's first reply can't carry the PSK contribution from this side |
| `NKpsk2`   | After `ee` in message 2 (recommended)   | PSK + ephemeral-ephemeral + static all mixed before transport keys are split. Responder authenticates the initiator on message 2; PSK is the gate. | One more round-trip before app data flows (same as plain NK, which already does 2). |
| `NKpsk2+0` | PSK at both 0 and 2                     | Defense-in-depth                                                    | Complexity for marginal benefit                                        |

`NKpsk2` matches the Noise spec recommendation for "interactive
PSK + pubkey auth" and gives us: **token URL pubkey AUTHENTICATES the
responder, PSK AUTHORIZES the initiator.** Two-factor at the Noise
layer.

### 3. Key derivation from a user-supplied string

Nathan's friend types a PSK on the command line / writes it to a
file. The Noise spec requires a 32-byte PSK; user-supplied strings
are usually shorter and lower-entropy. Two routes:

- **Require a 32-byte hex / base64 string and refuse anything else.**
  Clean spec, no derivation. Hard to memorize.
- **Accept any string and derive 32 bytes via Argon2id.** Same KDF the
  passphrase store already uses (`src/storage/passphrase-store.ts`).
  Gives the user a "passphrase" affordance.

**Proposal: require a 32-byte URL-safe-base64-encoded value
(`PTY_RELAY_PSK=<43-char-b64u>`) for v1.** A `pty-relay psk-gen`
helper (or just suggest `openssl rand -base64 32 | tr +/ -_ | tr -d
=` in docs) produces one. Defers the KDF question to a v2 if Nathan
wants the human-readable affordance.

Rationale: PSK is a machine-to-machine secret; treating it like an
SSH key (binary, generated, copied) matches the headless use case
better than treating it like a password.

### 4. Coexistence with the existing token / approval flow

PSK does **not** replace the token URL or daemon-key handshake.
Layering:

1. WS upgrade with the token URL's `#pk.secret` fragment — proves
   the client knows the pairing secret (today's gate).
2. Noise NKpsk2 handshake with daemon's static pubkey + PSK — proves
   the client AND knows the PSK (new gate).
3. Operator-approval queue (`--auto-approve` to skip, same as today).

A peer who has the token URL but no PSK fails at step 2. A peer who
has the PSK but no token URL fails at step 1. PSK is purely
additive — the operator opts in.

Default behavior (no `--psk`/`--psk-file`/`PTY_RELAY_PSK`): use plain
`Noise_NK`, identical to today.

`--psk` set on the server: only accept connections from peers that
present a matching PSK. Reject `Noise_NK`-only handshakes.

`--psk` set on the client + token URL: opt into NKpsk2; if the server
doesn't have a matching PSK the handshake fails cleanly.

### 5. CLI surface (headless-friendly)

In priority order (first found wins):
1. `--psk-file <path>` — read PSK from file. File is `mode 0600`
   (warned-on if not). Whitespace-trimmed.
2. `PTY_RELAY_PSK` env var.

We deliberately **don't** support `--psk <key>` as a positional flag
— `ps`/`/proc/<pid>/cmdline` would leak it. Same reasoning the
existing `--passphrase-file` exists alongside no `--passphrase`.

Server-side, `--psk-file` is read once at start time and held in the
daemon's memory. No automatic reload; PSK rotation = restart the
daemon. (Future: SIGHUP rotation, but defer.)

### 6. Signaling: how does the client tell the server "I have a PSK"?

Two paths:

- **Implicit (URL fragment widening)**: extend the token URL with an
  optional `psk` parameter — e.g.
  `#pk.secret.<32-byte-b64-of-the-psk-hash>`. The fragment carries the
  HASH only (so the URL alone doesn't unlock the daemon); the client
  must also have the PSK. Risk: token URLs grow noticeably; the
  fragment becomes a 3-tuple grammar.
- **Explicit (WS query param)**: the client adds
  `?psk_required=1` to the upgrade URL. The server consults its
  daemon-state to confirm a PSK is configured; replies with
  `paired{noise_pattern: "NKpsk2"}` if so, or rejects with a clear
  error if not.

**Proposal: WS query param**. Keeps the token URL grammar stable;
keeps the protocol contract explicit (the relay knows which pattern
to negotiate before the Noise bytes start flowing). The relay's
existing `paired` frame already carries a metadata object
(`src/relay/relay-connection.ts:63`'s `PairedMeta`), so adding an
optional `noise_pattern` field there is trivial.

### 7. Coexistence with `--tailscale`

PSK and tailscale operate at different layers. Tailscale provides
the encrypted transport between the client and the daemon's tailnet
endpoint; Noise + PSK provides end-to-end encryption + auth INSIDE
that. Either can be used independently. Configuring both is the
expected use case for "the friend's headless server fleet" — tailscale
for network reachability, PSK for unattended auth.

Concretely: nothing in `src/serve/server.ts` or `src/commands/start.ts`
needs to change for tailscale to coexist with PSK. The WS upgrade
goes through tailscale's HTTPS proxy as today; the encrypted Noise
session inside is what gets the PSK extension.

## Threat model & rotation

What PSK adds:
- **Stronger authorization gate** for clients that have the token
  URL. Without PSK an attacker who stole the URL (screenshot,
  shoulder-surfing) could pair; with PSK they still need the second
  factor.
- **Headless-friendly enrollment** — no operator approval round-trip
  needed for fleet provisioning.

What PSK does NOT add:
- **End-to-end encryption** — Noise NK already gives that.
- **Daemon identity verification** — the static-pubkey-in-URL already
  gives that.
- **Replay protection** beyond what Noise's handshake counters
  already provide.

Rotation: PSK lives in a file (or env). To rotate, generate a new
PSK, distribute, restart daemons and clients. The relay's existing
client-approval state (revocations, etc.) is untouched. Future SIGHUP
reload is noted as nice-to-have but explicitly out of scope for v1.

Compromise recovery: if the PSK leaks, generate a new one. Existing
client tokens still work (PSK is orthogonal to the per-client
approval flow). If the operator wants to invalidate client tokens
too, that's a `pty-relay clients revoke <id>` — the existing surface.

## File map (when approved)

**New:**
- `src/crypto/noise.ts` — add `Noise_NKpsk2` pattern constant + `psk`
  token case in the engine. ~30 LOC.
- `src/relay/psk.ts` — read PSK from `--psk-file` / `PTY_RELAY_PSK`,
  validate it's 32 bytes, parse base64url. ~50 LOC.
- `test/noise-psk.test.ts` — pattern round-trip + reject-on-wrong-PSK
  + the `psk` token vector from the Noise test corpus.
- `test/psk-loader.test.ts` — file + env priority, file-mode warning,
  base64url decode validation.

**Modified:**
- `src/commands/start.ts` — accept `psk?: Uint8Array | null` in
  options; refuse `Noise_NK` connections when set.
- `src/commands/connect.ts` + `src/terminal/client-connection.ts` —
  same options shape on the client side; opt into NKpsk2 when set.
- `src/relay/relay-connection.ts` — `PairedMeta` adds optional
  `noise_pattern`; server side negotiates.
- `src/cli.ts` — `--psk-file` flag plumbing on both `local start`
  and `connect`. Help text. No `--psk` positional flag (intentional).

Roughly **300 LOC + tests**, single PR after design approval.

## Open questions for Nathan

1. **KDF or raw bytes?** Proposal: raw 32-byte URL-safe-base64 for v1.
   Argon2id-derivation if you want human-readable PSKs in v2. Confirm
   v1 shape.
2. **`pty-relay psk-gen` helper subcommand?** Trivial (one line of
   `crypto.randomBytes(32).toString("base64url")`) but a one-liner
   doc note ("`openssl rand -base64 32 | tr +/ -_ | tr -d =`")
   covers it. Skip?
3. **PSK rotation UX**: today's proposal is "restart the daemon."
   That's fine for headless servers (the supervisor respawns them
   anyway) but rough for desktop. Is desktop a use case for PSK at
   all, or is it always machine-to-machine? My read of the brief
   says machine-to-machine; if desktop matters too, we'd want SIGHUP
   reload.
4. **Public-relay mode (`pty-relay server *`) interaction**: the
   public-relay account model already does PSK-like auth via the
   account's Ed25519 keys + TOTP. PSK in `local start` mode is
   orthogonal. Should `server start` get the same flag, or is PSK a
   self-hosted-only feature? My read: self-hosted only for v1. The
   public-relay account model is the right answer for the multi-
   tenant case.
5. **Audit logging**: should the daemon log each PSK auth attempt
   (success + fail) with peer info? Useful for the headless fleet
   case. Proposal: yes, structured log line at INFO. No per-failure
   IP-blocklist or similar — too easy to get wrong.

## Out of scope (per the brief)

- Replacing the existing token URL pairing — PSK is additive.
- Public-relay mode integration — covered by account auth already.
- PSK rotation without restart — SIGHUP reload is noted as a follow-
  up but not v1.
- Anything that touches the relay protocol's frame format — PSK
  lives inside the Noise handshake, transparent to the framing layer.

## Implementation phasing (when approved)

1. **Noise PSK engine extension** — add the `psk` token case + the
   `NKpsk2` pattern; vector tests from the Noise corpus. Self-
   contained, no protocol changes; lands as a unit.
2. **PSK loader** — file + env reading, validation, base64url
   decode. Unit tests.
3. **Server side** — `--psk-file` plumbing through `local start`;
   refuse plain-NK connections when PSK is set; advertise NKpsk2 in
   the `paired` frame.
4. **Client side** — `--psk-file` plumbing through `connect`; opt
   into NKpsk2 based on the `paired`-frame metadata.
5. **Integration test** — server with PSK + client with PSK = ok;
   server with PSK + client without = handshake fails; server
   without + client with = handshake fails (server doesn't advertise
   NKpsk2 so the client's NKpsk2 attempt mismatches). Each test
   spins up the real daemon + a real connect attempt, no mocks.

Each phase is one commit, end-to-end-reviewable in isolation. Phase
1 is the Noise extension and the load-bearing primitive; the rest
follow naturally.
