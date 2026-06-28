# SSH transport for pty-relay (design)

> **Status:** Design proposal — answers brief-010 ("relay should Just
> Work™ over plain SSH"). No code yet. cos surfaces to Nathan for
> signoff before any build.

## TL;DR

For an SSH-reachable host, **the pty-relay daemon is not needed at
all** for CLI operations. The pty-relay CLI can shell out to
`ssh <host> pty <cmd>` and every read/write/event subcommand Just
Works because pty already speaks JSON over Unix sockets and ssh
already handles auth, transport, and binary stdio.

The relay server (`pty-relay local start` / `pty-relay server serve`)
keeps its value for: (a) NAT-only hosts that can't accept inbound SSH,
(b) the web UI which needs an HTTPS+WebSocket endpoint, (c) the
multi-tenant public-relay account model.

Recommended addition: an `ssh://[user@]host[:port]` peer identifier
that joins the existing self-hosted-URL and public-relay-pubkey forms
in `known-hosts`. Resolves to a shell-out at command time.

## Hypotheses validated

### 1. Do we need the relay server for SSH-reachable hosts?

**No.** The relay's value is its three jobs: NAT traversal, end-to-end
encrypted transport with daemon-key auth, and multi-tenant account
plumbing. SSH already provides the first two for ssh-reachable hosts.

`pty` itself exposes every operation the relay surfaces — see
`pty --help` (`pty list --json`, `pty peek`, `pty send`, `pty kill`,
`pty tag`, `pty events --json`, `pty attach`). All of these go over
Unix sockets at `~/.local/state/pty/<name>.sock`, owned by the user
running pty. Running them via `ssh user@host pty <op>` gives you the
same surface, with ssh's auth as the gate.

Citations:
- `pty --help` output (above the dashed line): `list --json`,
  `peek`, `send`, `kill`, `tag`, `events --json`, `attach`.
- `src/commands/start-shared.ts:25` ("Handled types: list, attach,
  peek, send, tag, events_subscribe, spawn") — the relay's session
  vocabulary mirrors pty's CLI surface. The relay is a transport
  for these RPCs; over SSH the transport disappears.
- `src/relay/session-bridge.ts:35-45` — the relay bridges to the
  same `getSocketPath(session)` that `pty` writes to locally. SSH +
  the local `pty` binary on the remote side gets you the same end
  state without the daemon.

What the relay does that SSH doesn't:
- **NAT traversal**: relay daemon connects outbound to a public
  endpoint (`relay.pty.computer` or a self-hosted instance reachable
  via Tailscale); clients reach it via that endpoint. SSH-reachable
  hosts are by definition NOT NAT'd from the client's side, so this
  doesn't matter for the ssh:// case.
- **Web UI**: the in-browser xterm.js + Noise tunnel
  (`browser/src/main.ts`) needs an HTTPS endpoint + WebSocket. SSH
  doesn't expose that. Web UI access still needs the relay.
- **Public-relay accounts**: email + TOTP + cross-device enrollment
  (`src/commands/server/*`, `src/storage/public-account.ts`). Not
  relevant to the ssh:// peer case — ssh has its own key model.

### 2. Is `ssh://[user@]host[:port]` the right peer identifier?

**Yes.** It's the standard URL form for ssh endpoints, it composes
cleanly with the existing `KnownHost` schema, and it doesn't fight
rsync/git's `host:path` syntax the way our self-hosted token URLs do
(`http://host/#pk.secret` contains `:` and `#` that rsync's
host-splitter mangles — see phase-5's `seedKnownHostLabel` workaround
in `integration/exec-rsync.test.ts`).

Concretely:

```ts
// src/relay/known-hosts.ts — widen KnownHost
export interface KnownHost {
  label: string;
  // …existing fields…
  /** SSH-reachable peer: ssh://[user@]host[:port]. The session lives
   *  on the remote side at the same getSocketPath; the local
   *  pty-relay CLI shells out to `ssh user@host pty <cmd>`. */
  sshUrl?: string;
}
```

Resolution at command time:

```ts
// src/relay/host-resolve.ts — add ssh branch
export type ResolvedHost =
  | { kind: "self"; label: string; url: string }
  | { kind: "public"; label: string; target: PublicTarget; role?: "daemon" | "client" }
  | { kind: "ssh"; label: string; sshUrl: string };
```

URL grammar (RFC 3986 with the SSH scheme):
- `ssh://user@host:port` — user + port both optional.
- Default user: `$USER` (matches OpenSSH).
- Default port: 22.
- No path component; the session selector is a separate CLI arg
  (e.g. `pty-relay connect myhost demo`).

Why not just store `user@host` as the label without a scheme:
- Conflates label-as-identifier with transport choice (relay-served
  hosts can also have `user@host`-shaped labels).
- Makes future transports harder to add cleanly.
- The `ssh://` prefix is self-documenting in `pty-relay ls` output.

### 3. `pty-relay ls` over ssh — concrete sketch

The minimal slice. Lives in `src/commands/ls.ts` (existing) plus a new
`src/relay/transport-ssh.ts` (proposed) that exposes one function
matching `listRemoteSessions`'s shape:

```ts
// src/relay/transport-ssh.ts
export async function listSshRemoteSessions(
  sshUrl: string,
): Promise<RemoteSession[]> {
  // `ssh user@host pty list --json` — pty already supports --json.
  const { userHostPort } = parseSshUrl(sshUrl);
  const out = await execFileAsync("ssh", [
    "-o", "BatchMode=yes",                    // never prompt for password
    "-o", "ConnectTimeout=10",
    userHostPort,
    "pty", "list", "--json",
  ]);
  return JSON.parse(out.stdout) as RemoteSession[];
}
```

In `ls.ts` the existing flow becomes:

```ts
const resolved = await resolveHost(label, store);
let sessions: RemoteSession[];
switch (resolved.kind) {
  case "self":   sessions = await listRemoteSessions(resolved.url); break;
  case "public": sessions = await listPublicRemoteSessions(resolved.target); break;
  case "ssh":    sessions = await listSshRemoteSessions(resolved.sshUrl); break;
}
```

That's the whole change for the headline use case. **<100 LOC + tests**.

Error handling:
- ssh exit code 255 (connection failed) → `pty-relay: cannot reach
  <host>` + the ssh stderr verbatim.
- `pty: command not found` (pty not installed on the remote) → clear
  hint: "Install pty on <host>: …".
- JSON parse failure on stdout → fall back to "is the remote pty
  out-of-date?" hint.

### 4. Composition with smalltalk sync + the existing relay

Smalltalk sync uses rsync over ssh today (per the brief). An ssh://
peer composes naturally: the host portion of the ssh URL is exactly
what rsync wants in its `<host>:<path>` syntax, no transformation
needed. Adding ssh:// to known-hosts means smalltalk sync can read the
same labels the user already typed into `pty-relay`.

Coexistence with the existing relay transport (`#pk.secret`,
public-relay) is structural — three branches off a single `ResolvedHost`
discriminator. Each command picks the transport at runtime from the
resolved kind; no code path needs to know about both.

Subcommand support matrix:

| Subcommand          | Self-hosted | Public-relay | ssh:// |
|---------------------|-------------|--------------|--------|
| `ls`                | ✅          | ✅           | ✅ via `pty list --json` |
| `peek`              | ✅          | ✅           | ✅ via `pty peek` |
| `send`              | ✅          | ✅           | ✅ via `pty send` |
| `tag`               | ✅          | ✅           | ✅ via `pty tag` |
| `events`            | ✅          | ✅           | ✅ via `pty events --json` (long-lived ssh pipe) |
| `connect`           | ✅          | ✅           | ✅ via `ssh -t host pty attach` |
| `exec` (rsync/git)  | ✅          | ❌ (not wired) | ✅ via `ssh host <argv>` |
| Web UI access       | ✅ (via tailscale or LAN) | ✅ | ❌ — needs HTTPS endpoint |
| Notifications       | ✅ event-stream | ✅       | ✅ over long-lived ssh pipe |

## Adoption story

> "You have ssh access to a machine. You're done."

```bash
# On the remote machine — same as today, no relay setup.
pty install   # (or however the user got pty)

# On the local machine — one-time:
pty-relay add ssh://me@hostname
# (or just use ssh:// URLs ad-hoc; the `add` step is optional)

# Daily use:
pty-relay ls hostname
pty-relay peek hostname demo
pty-relay connect hostname demo
pty-relay send hostname demo "echo hi\n"
pty-relay rsync src/ hostname:/tmp/dst/
```

No daemon to start, no token URL to copy, no operator approval, no
email/TOTP. The auth is whatever the user's `~/.ssh/config` says (key,
agent, ProxyJump, multiplexed control socket — all of it).

## Minimal first slice (recommended)

**One subcommand: `pty-relay ls ssh://host`** (or `pty-relay ls <label>`
where `<label>` was added via `pty-relay add ssh://host`).

LOC budget:
- `src/relay/transport-ssh.ts` (new) — ~50 lines incl. the ssh URL
  parser + `listSshRemoteSessions` + a `pingSsh` helper.
- `src/relay/known-hosts.ts` — add `sshUrl?` to `KnownHost`, two extra
  lines in `parseHost`, one extra case in the `host` field migration.
- `src/relay/host-resolve.ts` — add the `ssh` branch.
- `src/commands/ls.ts` — switch on `resolved.kind`.
- A new `pty-relay add ssh://host` subcommand in `src/cli.ts` — ~30
  lines.
- `test/known-hosts-ssh.test.ts` — schema round-trip + label resolve.
- `integration/ssh-ls.test.ts` — skips if `ssh -V` not on PATH;
  otherwise stands up an `ssh localhost` loopback + spawns `pty run
  -d -- bash` + drives `pty-relay ls`. Verifies the JSON parse path
  and the missing-binary error.

**Total: ~250 LOC + tests. One PR, design-already-approved.**

## Open questions for Nathan

1. **`pty-relay add` UX**: `pty-relay add ssh://me@host` saves a
   known-host entry. Should the auto-label be the hostname (`host`)
   or `user@host`? My instinct: hostname-only is friendlier and
   matches how people refer to remote hosts in conversation. The user
   portion lives in the URL.

2. **TUI / interactive picker**: `pty-relay` (no args) is the
   interactive TUI today. Should ssh:// peers show up alongside self-
   hosted + public-relay peers there? My instinct: yes, with a small
   transport indicator in the host column (e.g. `[ssh]` / `[self]` /
   `[relay]`). Implementation is one extra branch in the TUI's render
   path.

3. **Auth pass-through**: ssh inherits `~/.ssh/config`, agent
   forwarding, etc. — we don't need to do anything. But should
   `pty-relay add ssh://host` *verify* connectivity before saving?
   My instinct: yes, run `ssh -o BatchMode=yes host pty --version` as
   a smoke test, refuse to save if it fails. Saves the user from
   `pty-relay ls` failing later with an opaque error.

4. **Web UI access for ssh:// hosts**: out of scope per the brief,
   but worth flagging as a follow-up. The cleanest answer is probably
   "the web UI is a relay-only feature; if you want browser access to
   an ssh:// host, ssh-tunnel to the local pty-relay's UI port." Not
   a blocker.

5. **PSK design (brief-006) interaction**: PSK adds a fourth peer
   model (token-less, headless-friendly relay auth). It's
   transport-orthogonal to ssh:// — they coexist. No design conflict.
   PSK design should land before its build; brief-010 ssh:// can
   ship independently.

## Out of scope (per the brief)

- UI / mobile app.
- NAT-traversal changes (the relay's NAT story is unchanged).
- Reworking the existing relay-server transport.
- Web UI access for ssh:// hosts (deferred per Q4 above).
- Any code beyond the design itself — this doc is the deliverable.

## File map (Phase-1 build, when approved)

**New:**
- `src/relay/transport-ssh.ts` — list / peek / send / tag / events /
  connect / exec wrappers around `ssh <host> pty <op>`.
- `test/transport-ssh.test.ts` — URL parser + error message shape.
- `integration/ssh-ls.test.ts` — end-to-end via ssh loopback.

**Modified:**
- `src/relay/known-hosts.ts` — add `sshUrl?` field.
- `src/relay/host-resolve.ts` — add `ssh` branch.
- `src/commands/ls.ts`, `peek.ts`, `send.ts`, `tag.ts`, `events.ts`,
  `connect.ts` — switch on `resolved.kind`.
- `src/cli.ts` — `add` subcommand + help text.

## Implementation phasing (when approved)

1. Schema + resolver: `KnownHost.sshUrl` + `ResolvedHost.ssh`. Tests.
2. `ls` over ssh + the `pty-relay add` subcommand. End-to-end test.
3. `peek` / `send` / `tag` — same shape, mechanical.
4. `events` over a long-lived ssh pipe (`ssh host pty events --json`
   streams JSONL until ssh dies; restart on connection drop).
5. `connect` (interactive attach) via `ssh -t host pty attach`.
6. `exec` / `rsync` / `git` — extend the phase-5 wrappers to
   recognize ssh:// peers + route through ssh directly (no exec
   channel needed since ssh already does what the exec channel
   carries).

Each phase is one commit, end-to-end-testable, reviewable in
isolation. The phase-1 slice (~250 LOC) is the headline; subsequent
phases follow the same shape and are <100 LOC each.
