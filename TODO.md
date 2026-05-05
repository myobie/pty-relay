# TODO

Things we want to do, but not yet. Each entry is a deliberate "later" —
the current focus is making the existing model work super well before
we start widening the surface.

## Per-PTY public sharing with read-only / write modes

**Originally:** [#11 — Support publicly sharing individual PTYs with
read-only or write access](https://github.com/myobie/pty-relay/issues/11)
(closed in favor of this entry).

**Idea.** Today, access in pty-relay is modeled per *daemon*: once a
client is paired with a host, it can list, attach, send input to, and
spawn against any session on that host. The request is for a finer-
grained model where a single PTY can be shared as a public (or semi-
public) endpoint, with at least two access tiers:

- **read-only** — viewers can watch output but cannot send input
- **writable** — authorized users can interact with the PTY

Probable shape:

- per-PTY share links/tokens (not per-host)
- permission encoded in the token or in a server-side policy keyed by
  the token
- read-only is the safe default
- support revocation, expiry, and an audit trail

**Why we're delaying.** The current model — daemon-pinned auth, Noise
NK end-to-end, single-role keys, account-wide vs. daemon-pinned
clients — still has rough edges we want to smooth out first. Examples:
the daily-use `connect` flow, the public-relay enrollment story, web-
UI usability (issues #2-10, #13), and the just-landed `--mosh` beta
all need to feel solid. Adding a per-session sharing layer on top of a
model still in flux would either constrain the model prematurely or
quickly accumulate special cases.

We'll come back to this once the per-host model feels boring.

**Notes for whoever picks it up.**

- This crosses the daemon ↔ relay boundary. The Elixir public relay
  (`../pty-public-relay/`) currently has one role for clients; adding
  a "viewer" role with input-blocked semantics is non-trivial.
- The self-hosted relay (`src/serve/server.ts`) is simpler — input
  blocking can live entirely in the daemon's session bridge. A
  share-link in self-hosted mode is just a pre-approved client token
  with a flag.
- Read-only is naturally enforced at the daemon: drop `MSG_DATA` and
  `MSG_RESIZE` packets from the viewer; only forward `MSG_DATA` /
  `MSG_SCREEN` *toward* them.
- Bracketed-paste, Ctrl-C, etc. all flow through the same data path,
  so once `MSG_DATA` is filtered, the read-only guarantee covers them
  all. No per-keystroke logic.
