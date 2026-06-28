# Channel-multiplexed relay protocol (v2)

> **Status:** Design proposal — implementation tracked in
> [`feat/channel-mux`](https://github.com/myobie/pty-relay/tree/feat/channel-mux).
> Not yet on `main`. Cite this doc when reviewing the implementation;
> divergences land here first.

This document specifies a successor to the v1 single-stream relay
protocol. v1 carried exactly one logical stream over each Noise
session — the bytes of a `@myobie/pty` packet stream attached to a
specific session. v2 multiplexes many independent **channels** over the
same Noise session and admits more than one **channel mode**, so a
single client connection can interleave terminal I/O with non-PTY
workloads (rsync today; git, file transfer, exec one-shots next).

## Why

v1 reached its ceiling once we wanted any non-PTY workload:

- `rsync` over the relay needs raw stdio — its wire protocol gets
  mangled by PTY line discipline (`ICRNL`, `OPOST`, …). It also needs
  three logical sub-streams (stdin / stdout / stderr) within one
  connection — three Noise sessions per `rsync` invocation is wasteful
  and complicates the daemon side.
- The same shape applies to `git` (also using raw-stdio remote helpers
  by default) and to any future plain `exec` use case.
- Once we have multiple modes, we want them to coexist on one client
  connection so the operator's UX stays "one tunnel per peer," not
  "one tunnel per task."

v1's discriminator was implicit (`if (firstByte === 0x7b) parseJSON else
forwardPtyPacket`) — it can't carry a second mode without growing
fragile heuristics. v2 makes the framing explicit and the mode
discoverable from the channel-open negotiation.

## Backwards compatibility

**None.** v1 and v2 are wire-incompatible. `PROTOCOL_VERSION` bumps
from `1` to `2`. The `paired` frame (`src/relay/relay-connection.ts`,
`PairedMeta`) gains a required `protocol_version: 2` field; either side
seeing a mismatch closes the WS immediately with a structured error.
Concretely:

- v2 daemon + v1 client: daemon's `paired` frame says `protocol_version:
  2`; v1 client doesn't know the field and would fail-open. Daemon
  instead closes the WS with code `1002` ("protocol error") and an
  error JSON body so a v1 user gets a clear "upgrade your client"
  hint rather than silent confusion.
- v1 daemon + v2 client: client sees no `protocol_version` in `paired`,
  refuses to handshake, closes with a "your daemon is too old" message.

myobie is the only user; no migration window is needed. The v1 code
path is deleted in the same PR that lands v2 — no compatibility shim,
no `protocolVersion >= 2 ? ... : ...` branches.

## Frame format

Every Noise-decrypted plaintext frame is:

```
+------------------+------+----------------+
| channel-id u32BE | type | payload (rest) |
+------------------+------+----------------+
       4 bytes        1B      0..N bytes
```

- `channel-id` (u32 big-endian, bytes 0–3) — `0` is the connection
  control channel; `1..(2³²-1)` are data channels.
- `type` (u8, byte 4) — per-channel frame type. Values defined per
  channel mode below; `0x00 DATA` is universal.
- `payload` (bytes 5..end) — opaque to the framing layer; interpreted
  per-channel-mode. Empty payloads are allowed (used by EOF on stdin
  and ping/pong).

There is no length prefix on the payload. The Noise transport already
boundary-preserves; one Noise plaintext = one channel frame.

**Minimum frame size:** 5 bytes (channel-id + type, empty payload).
Frames shorter than 5 bytes close the connection.

**Maximum frame size:** 64 KiB (`MAX_FRAME_BYTES = 65_536`). Larger
logical payloads (rsync stdout chunks, scrollback dumps) are split
across multiple `DATA` frames on the same channel. The 64 KiB ceiling
matches Noise's per-message ciphertext budget on libsodium and gives a
comfortable cap for memory accounting without forcing excessive
fragmentation.

## Channel 0 — connection control

Channel 0 carries JSON messages only. Every frame on channel 0 has
`type = 0x00 JSON`. Payload is UTF-8 JSON.

```
+------------+------+----------------+
| 0x00000000 | 0x00 | {"type":"…",…} |
+------------+------+----------------+
```

Channel 0 cannot carry binary; it's the negotiation surface. Receivers
that get a non-zero `type` on channel 0 close the connection.

### Control messages

#### `channel_open` (initiator → responder)

Either side can open a channel. In practice the **client** opens
channels and the **daemon** acknowledges; the wire grammar is
symmetric so future server-push use cases (e.g. unsolicited event
push) can reuse it.

```json
{
  "type": "channel_open",
  "id": 1,
  "mode": "pty" | "exec",
  // mode-specific fields follow
}
```

**`pty` mode fields:**

```json
{
  "type": "channel_open",
  "id": 1,
  "mode": "pty",
  "session": "demo",
  "cols": 80,
  "rows": 24
}
```

**`exec` mode fields:**

```json
{
  "type": "channel_open",
  "id": 2,
  "mode": "exec",
  "argv": ["rsync", "--server", "-vlogDtprze.iLsfxC", ".", "/dst"],
  "env": null,         // optional; null/absent means inherit daemon's env
  "cwd": null          // optional; null/absent means daemon's $HOME
}
```

`id` rules:
- Must be `>= 1`, `<= 65535` for v2 (16-bit cap is informal — u32 stays
  in the wire format for future room).
- Must not collide with an open channel on this connection. Reuse of a
  closed id is allowed but not encouraged; let the counter advance.
- The opener chooses the id.

#### `channel_open_ack` (responder → initiator)

```json
{ "type": "channel_open_ack", "id": 1 }
```

Bridge is wired and ready. After this point, **data frames may flow on
this id** in either direction.

#### `channel_open_error` (responder → initiator)

```json
{
  "type": "channel_open_error",
  "id": 2,
  "code": "mode_not_enabled" |
          "argv_not_allowed" |
          "session_not_found" |
          "spawn_failed" |
          "id_collision" |
          "channel_limit",
  "message": "human-readable reason"
}
```

Hard reject. The `id` is now closed; the initiator should retry under a
fresh id or surface the error.

#### `channel_close` (either side)

```json
{
  "type": "channel_close",
  "id": 1,
  "reason": "client_detach" | "operator_close" | "peer_lost" | "protocol_error" | "exit"
}
```

Tears down the channel. Either side can send it. After sending or
receiving `channel_close` for an id, no more frames on that id are
valid.

#### `channel_exit` (responder → initiator, `exec` only)

```json
{
  "type": "channel_exit",
  "id": 2,
  "exit_code": 0,
  "signal": null
}
```

The child process ended. `exit_code` is the integer exit status when
the child exited normally; `signal` is the POSIX signal name (e.g.
`"SIGTERM"`) when the child was killed. Exactly one of the two is
non-null. The responder follows `channel_exit` with `channel_close
{reason:"exit"}` to fully tear down.

#### `keepalive` (either side)

```json
{ "type": "keepalive" }
```

No-op. Recommended cadence: every 30 s of idle. Tracking the most
recent inbound `keepalive` lets either side detect a stuck half-open
WS without per-channel state.

#### `error` (responder → initiator, channel 0)

Catch-all for non-channel-scoped errors (protocol violation, frame
size cap, etc):

```json
{ "type": "error", "code": "frame_too_large", "message": "…" }
```

The sender follows this with WS close.

## Channel modes

### `pty` mode

Carries a `@myobie/pty` session's packet stream — exactly what
`SessionBridge` already proxies in v1. The `DATA` frame's payload is
the bytes of one pty packet (ATTACH/INPUT/OUTPUT/RESIZE/DETACH).

Frame types:
- `0x00 DATA` — pty packet bytes.

There are no `pty`-specific control frames at the channel-protocol
layer; resize is a pty packet inside the data stream (as it is today).
Keeping that structure means the v2 port of `SessionBridge` is
mechanical — the inner pty packet handling doesn't change.

### `exec` mode

Carries raw stdio for an exec'd child process. The `DATA` frame's
payload is prefixed with a 1-byte **sub-stream id**:

```
+--------------+-----------------+
| sub-stream u8 | byte payload   |
+--------------+-----------------+
        1 B          0..N bytes
```

Sub-stream values:
- `0x00 STDIN` — client → daemon; bytes are written to the child's
  stdin.
- `0x01 STDOUT` — daemon → client; bytes were read from the child's
  stdout.
- `0x02 STDERR` — daemon → client; bytes were read from the child's
  stderr.

Sub-streams are unidirectional; receiving an out-of-direction sub-stream
(e.g. `STDOUT` from the client) is a protocol error → close.

**EOF on stdin** is carried as a `DATA` frame with sub-stream `STDIN`
and an empty byte payload. The daemon closes the child's stdin fd.
Sending more `STDIN` frames after EOF is a protocol error.

**STDOUT/STDERR EOF** is implicit: when the child exits, both fds are
drained and then `channel_exit` is sent. No separate EOF marker.

Frame types:
- `0x00 DATA` — stdio (with sub-stream prefix as above).
- `0x01 SIGNAL` — client → daemon; payload is the ASCII signal name
  (`"SIGINT"`, `"SIGTERM"`, …). Used for Ctrl+C from the local rsync
  driver propagating to the remote child. Daemon refuses signals
  outside an allow-list (`SIGINT`, `SIGTERM`, `SIGHUP`); others
  silently ignored.

## Daemon-side architecture

```
                 ┌─────────────────────────┐
                 │ ClientRelayConnection   │  (existing; v2 just feeds
                 │  decrypted Uint8Array   │   it through the framing
                 └────────────┬────────────┘   parser instead of the
                              │                v1 7b-vs-pty branch)
                              │ frame
                              ▼
                 ┌─────────────────────────┐
                 │ ChannelDispatcher       │  routes by channel-id
                 │  - channel 0: control   │
                 │  - else: registry[id]   │
                 └─────────┬───────────────┘
                  ┌────────┼─────────┐
                  ▼        ▼         ▼
            ┌──────────┐ ┌──────────┐ ┌──────────┐
            │ control  │ │ Session  │ │   Exec   │
            │ handler  │ │ Bridge   │ │  Bridge  │
            └──────────┘ │ (pty)    │ │ (exec)   │
                         └──────────┘ └──────────┘
                              │            │
                              ▼            ▼
                       pty Unix       child_process
                       socket          .spawn()
```

### `ChannelRegistry`

Pure data structure. No I/O.

```ts
interface ChannelRegistry {
  open(id: number, handler: ChannelHandler): void;   // throws on collision
  close(id: number): void;                            // idempotent
  get(id: number): ChannelHandler | undefined;
  size(): number;
  has(id: number): boolean;
  ids(): number[];                                    // for `channel_close`
                                                      // cascade on connection drop
}
```

`ChannelHandler` is the interface implemented by `SessionBridge` and
`ExecBridge`:

```ts
interface ChannelHandler {
  mode: "pty" | "exec";
  onFrame(type: number, payload: Uint8Array): void;
  close(reason: string): void;
}
```

The registry is owned by the per-connection daemon state object. When
the WS connection closes (peer drop, revoke, etc), the registry cascades
`close()` to every handler.

### Lifecycle

1. Client sends `channel_open` on channel 0.
2. Daemon's control handler validates: mode allowed by flag? argv on
   allow-list? session exists (pty)? id not already taken?
3. On any reject: `channel_open_error`, no state change.
4. On accept: construct the bridge, register it under `id`,
   send `channel_open_ack`.
5. Both sides flow `DATA` frames on `id`.
6. Termination: either side sends `channel_close` (or daemon sends
   `channel_exit` followed by its own close on exec exit). Receiver
   closes the bridge, unregisters from the registry.

### `SessionBridge` (port from v1)

Existing class at `src/relay/session-bridge.ts:22`. Port surface is
mechanical:
- Constructor takes the channel-id; emit/receive go through the
  dispatcher rather than directly to the RelayConnection's `send`.
- Adapt the existing `attach` / `handleRelayData` / `close` methods to
  the `ChannelHandler` interface.
- pty packet bytes are passed through verbatim in `DATA` frames.

### `ExecBridge` (new)

```ts
class ExecBridge implements ChannelHandler {
  mode = "exec" as const;

  constructor(
    private channelId: number,
    private send: (frame: OutgoingFrame) => void,
    private spawn: SpawnFn,                 // injectable for tests
    private opts: { argv: string[]; env?: NodeJS.ProcessEnv; cwd?: string },
  ) {}

  start(): void;                            // calls spawn(); wires events
  onFrame(type: number, payload: Uint8Array): void;
                                            // sub-stream demux; signal handling
  close(reason: string): void;              // kills child if alive
}
```

The injectable `SpawnFn` is the key to unit testability — production
binds it to `child_process.spawn`; tests pass a stub that returns a
fake child with controllable streams.

## Error handling

| Condition                                | Response                                                                                       |
|------------------------------------------|------------------------------------------------------------------------------------------------|
| Frame < 5 bytes                          | Send `{type:"error",code:"frame_too_short"}` on channel 0, then WS close (`1002`).             |
| Frame > `MAX_FRAME_BYTES`                | Same as above with `code:"frame_too_large"`.                                                   |
| Channel 0 with non-zero `type`           | Same as above with `code:"control_frame_type"`.                                                |
| Channel-0 JSON parse failure             | `code:"control_frame_json"`.                                                                   |
| Unknown channel id (data frame)          | Log + drop. Optionally send `channel_close` for the unknown id. Don't tear down the WS — a stale frame post-close is benign and shouldn't kill the whole connection. |
| `channel_open` with `mode` not enabled   | `channel_open_error` with `code:"mode_not_enabled"`. (Channel 0 stays up; this is per-channel.)|
| `channel_open` with `argv[0]` not allowed| `channel_open_error` with `code:"argv_not_allowed"`.                                           |
| `channel_open` exec spawn fails (ENOENT) | `channel_open_error` with `code:"spawn_failed"`, `message: err.message`.                       |
| `channel_open` id collision              | `channel_open_error` with `code:"id_collision"`. Initiator picks a new id.                     |
| Exceeded concurrent channel cap          | `channel_open_error` with `code:"channel_limit"`. (v1 cap: `MAX_CHANNELS = 16`.)                |
| Sub-stream id out of `{0,1,2}` on exec   | `channel_close` with `reason:"protocol_error"`; that channel only.                              |
| `STDIN` sub-stream from daemon → client  | Same.                                                                                          |
| `STDOUT`/`STDERR` from client → daemon   | Same.                                                                                          |
| `STDIN` after EOF on stdin               | Same.                                                                                          |

Connection-level errors (the first four rows) close the WS. Per-channel
errors close only that channel — the rest of the connection survives.
This split matters when `pty` and `exec` channels coexist: a buggy
exec'd helper shouldn't drop your terminal session.

## Security gates

### `--allow-exec` daemon flag

Off by default. Mirrors `--allow-new-sessions`
(`src/commands/start-shared.ts:302`):

- `pty-relay local start --allow-exec` — flag set in the daemon's
  options object, plumbed to the control handler.
- Default-off: `channel_open` with `mode:"exec"` returns
  `channel_open_error code:"mode_not_enabled"`.
- Confirmation prompt at daemon startup, parallel to
  `--skip-allow-new-sessions-confirmation` (a `--skip-allow-exec-confirmation`
  twin keeps `pty.toml`-driven permanent sessions running without an
  interactive prompt).

The `pty` channel mode is **always** enabled — turning it off would
break every existing use case. Mode toggles are per-mode; the surface
is "exec is an opt-in expansion."

### Argv allow-list

A daemon-side allow-list of permitted `argv[0]` values:

```ts
// src/relay/exec-allow-list.ts (proposed)
export const EXEC_ALLOW_LIST: ReadonlyArray<string> = ["rsync"] as const;
```

v1 ships with **only `rsync`** in the allow-list. When `git`-over-relay
lands, that adds `"git"` to the array — no protocol change, no daemon
re-architecture. The shape we're locking in:

1. Compile-time constant array of allowed `argv[0]` basenames.
2. Daemon resolves the requested `argv[0]` to a basename (strip path).
3. Reject if not in the list.

What v1 **does not** do (intentionally):
- No per-arg validation (e.g. "rsync may not use `--rsync-path`"). The
  daemon trusts argv contents once `argv[0]` is allowed. Justification:
  the threat model is "operator's own laptops, already paired"; per-arg
  scrubbing is brittle and rsync's flags are too rich for a useful
  allow-list.
- No user-configurable allow-list at runtime. Adding `git` is a code
  change + recompile + reinstall. Keeps the deployment story simple
  and the threat model auditable. Revisit if the friction outgrows
  the safety.

### Threat model in one paragraph

Anyone holding a valid relay token already has full operator account
privileges — they can `connect` to a shell session and inject keystrokes.
Raw exec doesn't grant new privileges; it just removes the PTY
round-trip for binary-clean transports. The Noise NK handshake still
pins the daemon's pubkey (no MITM); the relay still sees only
ciphertext (no payload inspection). The `--allow-exec` gate is
defense-in-depth: an operator running `pty-relay local start` without
the flag can't be surprised by an exec channel even if the client's
key is stolen.

## Test plan

The whole point of this redesign is to let us unit-test the
multiplexer in isolation. Pure modules, injectable seams, no I/O in
the hot path.

### Framing (pure)

- `src/relay/channel-framing.ts` (proposed):
  ```ts
  export function encodeFrame(channelId: number, type: number, payload: Uint8Array): Uint8Array;
  export function decodeFrame(bytes: Uint8Array): { ok: true; channelId: number; type: number; payload: Uint8Array } | { ok: false; code: string };
  ```
- Tests in `test/channel-framing.test.ts`:
  - Round-trip property: `decode(encode(c,t,p)).{channelId,type,payload}` equals input for randomly generated `(c,t,p)`.
  - Boundary cases: empty payload, max-size payload, channel-id `0`, channel-id `0xffffffff`.
  - Malformed: 0-byte input, 4-byte input, oversize input → structured error.

### `ChannelRegistry` (pure)

- `src/relay/channel-registry.ts` (proposed):
  ```ts
  export class ChannelRegistry { ... }
  ```
- Tests in `test/channel-registry.test.ts`:
  - open/get/close/size happy path.
  - id collision throws.
  - close idempotent.
  - cascade `close` on all ids.

### `ExecBridge` (injectable spawn)

- `src/relay/exec-bridge.ts` (proposed):
  ```ts
  export interface SpawnFn {
    (argv: string[], opts: { env?: NodeJS.ProcessEnv; cwd?: string }): FakeChild;
  }
  export class ExecBridge implements ChannelHandler {
    constructor(channelId: number, send: SendFn, spawn: SpawnFn, opts: ExecOpts);
    // ...
  }
  ```
- Tests in `test/exec-bridge.test.ts` with a fake spawn:
  - stdout bytes emitted by fake child → `DATA` frame with sub-stream `0x01`.
  - stderr → sub-stream `0x02`.
  - Inbound `DATA` sub-stream `0x00` → fake stdin receives bytes.
  - Empty `STDIN` payload → fake stdin.end() called.
  - `STDIN` after EOF → channel closed with `protocol_error`.
  - Fake child `exit(0)` → `channel_exit {exit_code:0}` then `channel_close`.
  - Fake child killed by SIGTERM → `channel_exit {signal:"SIGTERM"}`.
  - `close("reason")` while child is alive → child is killed with SIGTERM.

### `ChannelDispatcher` (with a fake registry + fake send)

- Tests in `test/channel-dispatcher.test.ts`:
  - Channel-0 JSON parsing happy path (handles every defined message).
  - Channel-0 unknown `type` → `error` on channel 0 + close signal.
  - Data frame for unknown channel id → drop + log (assert no throw).
  - Forwarding: data frame for known id → handler's `onFrame` called.

### End-to-end (separate from unit tests)

- `integration/exec-rsync.test.ts` (Phase 5):
  - Real `pty-relay local start --allow-exec` daemon.
  - Real `pty-relay rsync` client driving real rsync against a tempdir tree.
  - Assert byte-identical copy via `shasum`.
  - Assert resume works (kill mid-copy, retry, completes).

This lives under `integration/` and runs via
`npm run test:integration` so it's gated behind the slower lane and
doesn't slow down the unit `npm test`.

## Open questions for review

1. **Flow control / backpressure.** WebSocket has TCP-level
   backpressure, but with multiplexed channels we could have
   head-of-line blocking: a slow STDOUT reader on one channel stalls
   STDIN writes on another. v1 proposal: **rely on TCP backpressure
   alone, no per-channel credit windows**. Revisit if rsync benchmarks
   show head-of-line problems. Adding SSH-style flow control later is a
   protocol expansion (new `channel_window_adjust` message), not a
   rewrite.
2. **64 KiB frame cap.** Sized to fit comfortably in Noise's
   per-message ciphertext budget. Alternatives: 32 KiB (cheaper memory
   accounting, more fragmentation), 1 MiB (fewer frames, more memory
   per pending decrypt). 64 KiB is the SSH default and a known-good
   pick. Confirm with myobie before implementation.
3. **Resize for pty channels.** Currently a pty packet inside the
   stream (one less translation layer). Could lift to the
   channel-protocol layer as a `RESIZE` frame type. **Proposal: leave
   it in the pty packet stream.** Lifting it gains nothing unless we
   want to multiplex multiple pty channels with shared resize logic —
   not on the roadmap.
4. **Channel id selection: client-monotonic or random?** Both work.
   Monotonic counters are debug-friendly (sequence number tells you
   when in the connection a channel was opened); random ids avoid the
   theoretical race where the client reuses an id the daemon hasn't
   yet acked closed. **Proposal: client-monotonic starting at 1, never
   reused within a connection.** The `id_collision` error code handles
   the race trivially: the client retries with `id + 1`.
5. **Multiplexing pty channels.** v1 supported one pty channel per
   connection. v2 admits multiple, but is there a use case? **Proposal:
   v1 of the implementation caps to one pty channel per connection.**
   The protocol allows N; the implementation gates it via a
   `MAX_PTY_CHANNELS = 1` constant we can lift later without protocol
   changes.
6. **Channel cap.** `MAX_CHANNELS = 16` per connection. Arbitrary,
   easy to raise. Big enough for "your terminal session + a couple of
   rsync transfers"; small enough that a buggy client can't flood the
   daemon. Confirm.

## File map (Phase 2+, for reference)

- `src/relay/channel-framing.ts` — new pure module: encode/decode.
- `src/relay/channel-registry.ts` — new pure module: registry.
- `src/relay/channel-dispatcher.ts` — new: routes inbound frames to
  channel 0 control or to a registered handler.
- `src/relay/channel-control.ts` — new: JSON message handler for
  channel 0.
- `src/relay/session-bridge.ts` — modified: implement `ChannelHandler`,
  drop the direct `relay.send` call site.
- `src/relay/exec-bridge.ts` — new: `ExecBridge` implementing
  `ChannelHandler` with injectable spawn.
- `src/relay/exec-allow-list.ts` — new: compile-time argv allow-list.
- `src/commands/start.ts` + `src/commands/start-shared.ts` — modified:
  wire `--allow-exec` flag; replace the v1 "0x7b vs pty packet" branch
  with the new dispatcher.
- `src/commands/rsync.ts` — new: user-facing `pty-relay rsync src dst`
  wrapper that exec's real rsync with `-e 'pty-relay rsync-transport <label>'`.
- `src/commands/rsync-transport.ts` — new: the `-e` shim that rsync
  invokes; opens an exec channel and bridges its own stdio.
- `src/commands/exec.ts` — new (optional, low-level): `pty-relay exec
  <label> -- <argv>` for direct exec without rsync wrapping. Useful
  for `git` when that ships.
- `src/cli.ts` — register new subcommands + `--allow-exec` flag.
- `test/channel-framing.test.ts` — new.
- `test/channel-registry.test.ts` — new.
- `test/channel-dispatcher.test.ts` — new.
- `test/exec-bridge.test.ts` — new.
- `integration/exec-rsync.test.ts` — new (Phase 5).

## Phasing (for the implementer)

Phase 2 (this PR's next commit, once design is approved):
- Framing module + tests.
- ChannelRegistry + tests.
- ChannelDispatcher + tests.
- Channel-0 control handler + tests.
- No bridges yet — the old SessionBridge still hangs off the old code
  path so the daemon keeps working in dev.

Phase 3:
- Port `SessionBridge` to `ChannelHandler`.
- Replace the v1 "0x7b vs pty packet" branch in `ClientRelayConnection`
  / `attemptConnect` with a call into the dispatcher.
- `pty` channels work end-to-end through the new framing.

Phase 4:
- `ExecBridge` + argv allow-list + `--allow-exec` flag.
- `pty-relay rsync` and `pty-relay rsync-transport` commands.

Phase 5:
- End-to-end integration test.

Each phase is one commit. Land them serially on `feat/channel-mux`,
keeping the doc updated if any decision changes during implementation.
