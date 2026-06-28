/**
 * Compile-time allow-list of executables that may be run over an
 * `exec` channel. See `docs/channel-protocol.md` § "Argv allow-list".
 *
 * Why compile-time:
 *   - The daemon trusts the operator who started it. The allow-list is
 *     defense-in-depth against an attacker who steals a relay token
 *     widening the surface from "interactive shell only" to "arbitrary
 *     remote exec." Code change + re-install is a small ceiling that
 *     matches the threat model.
 *   - No per-arg validation. The threat model doesn't justify the
 *     brittleness — rsync's flags are too rich (and operator-trusted
 *     binaries like git compose into ssh / hooks etc).
 *
 * Adding a new entry: append the basename here, recompile, ship.
 * No protocol change, no daemon re-architecture.
 */

export const EXEC_ALLOW_LIST: ReadonlyArray<string> = [
  "rsync",
  // git's smart-protocol clones invoke `git-upload-pack` (read) and
  // `git-receive-pack` (write) directly — NOT `git upload-pack` as a
  // subcommand. We keep `git` here too so future plumbing (e.g.
  // `pty-relay exec <host> git fsck`) just works, but the
  // `git-upload-pack` / `git-receive-pack` entries are what unlock
  // `git clone <host>:<repo>` over the relay.
  "git",
  "git-upload-pack",
  "git-receive-pack",
] as const;

/**
 * Resolve the requested `argv[0]` to a basename (strip any path prefix
 * the client supplied) and check against the allow-list. Returns the
 * canonical basename when allowed; `null` when rejected. Callers
 * translate `null` into a `channel_open_error{code:"argv_not_allowed"}`.
 */
export function checkArgvAllowed(argv0: string): string | null {
  if (typeof argv0 !== "string" || argv0.length === 0) return null;
  // basename without spawning path.basename to keep this pure /
  // browser-friendly.
  const slash = Math.max(argv0.lastIndexOf("/"), argv0.lastIndexOf("\\"));
  const basename = slash >= 0 ? argv0.slice(slash + 1) : argv0;
  return EXEC_ALLOW_LIST.includes(basename) ? basename : null;
}
