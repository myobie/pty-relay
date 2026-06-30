/**
 * SSH transport for ssh-reachable peers — see `docs/ssh-transport.md`.
 *
 * For peers identified by an `ssh://[user@]host[:port]` URL the relay
 * daemon isn't needed at all: `pty` already exposes every read/write
 * op as a CLI subcommand with `--json`, and ssh handles auth +
 * transport + binary stdio. We shell out to `ssh <userHost> pty <op>`
 * and parse the result.
 *
 * Phase-1 scope: URL parsing + `listSshRemoteSessions` (the headline
 * `pty-relay ls ssh://host` slice). Subsequent ops (peek / send / tag
 * / events / connect / exec) extend this module with the same shape:
 * one function per `pty` subcommand, each just an ssh shell-out + a
 * minimal output parser.
 */

import { execFile, spawn as childSpawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import type { RemoteSession } from "./relay-client.ts";
import { log } from "../log.ts";

const execFileAsync = promisify(execFile);

/** Default ssh port — matches OpenSSH. */
const DEFAULT_SSH_PORT = 22;

/** Parsed shape of an `ssh://[user@]host[:port]` URL.
 *
 *  `userHost` is the `[user@]host` segment ssh wants as its first
 *  positional arg. `port` is provided separately because ssh takes
 *  `-p <port>` rather than baking it into the host arg. */
export interface ParsedSshUrl {
  /** Bare `[user@]host` string suitable for `ssh <userHost> …`. */
  userHost: string;
  /** Defaults to 22. Set explicitly when the URL had a `:port`. */
  port: number;
}

/**
 * Parse an `ssh://[user@]host[:port]` URL. Throws a clear error for
 * malformed input so the CLI dispatcher can render it without
 * wrapping.
 *
 * Examples:
 *   ssh://host                 → { userHost: "host",       port: 22 }
 *   ssh://me@host              → { userHost: "me@host",    port: 22 }
 *   ssh://me@host:2222         → { userHost: "me@host",    port: 2222 }
 *   ssh://host:2222            → { userHost: "host",       port: 2222 }
 */
export function parseSshUrl(input: string): ParsedSshUrl {
  if (typeof input !== "string") {
    throw new Error("ssh URL must be a string");
  }
  if (!input.startsWith("ssh://")) {
    throw new Error(`ssh URL must start with ssh:// (got: ${input})`);
  }

  // Pull off the `ssh://` prefix and then split on `:` for the port
  // (right-most colon only, so user-info that contains `:` doesn't
  // confuse us — though ssh URIs don't carry passwords).
  const rest = input.slice("ssh://".length);
  if (rest.length === 0) {
    throw new Error("ssh URL has no host (got: ssh://)");
  }
  // Refuse path components — the URL is a peer identifier, not a
  // resource locator. Trailing slash is allowed and ignored.
  const slashIdx = rest.indexOf("/");
  const beforeSlash =
    slashIdx === -1 ? rest : slashIdx === rest.length - 1 ? rest.slice(0, -1) : null;
  if (beforeSlash === null) {
    throw new Error(`ssh URL must not carry a path (got: ${input})`);
  }

  // Identify the port (last colon, only when it's after the @ if any).
  const atIdx = beforeSlash.lastIndexOf("@");
  const colonSearchFrom = atIdx === -1 ? 0 : atIdx + 1;
  const colonIdx = beforeSlash.indexOf(":", colonSearchFrom);

  let userHost: string;
  let port: number;
  if (colonIdx === -1) {
    userHost = beforeSlash;
    port = DEFAULT_SSH_PORT;
  } else {
    userHost = beforeSlash.slice(0, colonIdx);
    const portStr = beforeSlash.slice(colonIdx + 1);
    const parsed = parseInt(portStr, 10);
    if (!Number.isFinite(parsed) || parsed < 1 || parsed > 65535) {
      throw new Error(`ssh URL has invalid port "${portStr}" (got: ${input})`);
    }
    port = parsed;
  }

  if (userHost.length === 0 || userHost.endsWith("@")) {
    throw new Error(`ssh URL has empty host (got: ${input})`);
  }
  // Reject empty user-info segment (`@host` form).
  const atSplit = userHost.indexOf("@");
  if (atSplit === 0) {
    throw new Error(`ssh URL has empty user-info (got: ${input})`);
  }
  // Reject empty host segment after the user (`me@` was already
  // caught above by endsWith).
  if (atSplit > 0 && atSplit === userHost.length - 1) {
    throw new Error(`ssh URL has empty host (got: ${input})`);
  }

  return { userHost, port };
}

/**
 * `true` iff the string looks like an ssh URL. Cheap discriminator for
 * the host-resolve dispatch — full validation happens in
 * `parseSshUrl`.
 */
export function looksLikeSshUrl(s: string): boolean {
  return typeof s === "string" && s.startsWith("ssh://");
}

/**
 * Default options applied to every `ssh` invocation. Centralized so a
 * future caller can override via a per-call options arg without each
 * subcommand redefining them.
 *
 *   -o BatchMode=yes        Never prompt for passwords. Connectivity
 *                           failures fail fast rather than blocking
 *                           on input that won't come.
 *   -o ConnectTimeout=10    Short-circuit DNS / TCP hangs.
 *   -p <port>               Honor the ssh:// URL's port.
 */
function baseSshArgs(parsed: ParsedSshUrl): string[] {
  const args = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
  ];
  if (parsed.port !== DEFAULT_SSH_PORT) {
    args.push("-p", String(parsed.port));
  }
  return args;
}

/**
 * Run `ssh <userHost> pty list --json` on the peer and parse the
 * result into the same `RemoteSession[]` shape `listRemoteSessions`
 * returns for the relay transport. Lets `ls.ts` consume both paths
 * uniformly.
 *
 * Errors are surfaced with the most actionable message we can build
 * from ssh / pty's stderr — "ssh: connect to host …" / "pty: command
 * not found" are pre-translated into hints the operator can act on.
 */
export async function listSshRemoteSessions(
  sshUrl: string,
): Promise<RemoteSession[]> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "list begin", { userHost: parsed.userHost, port: parsed.port });

  const args = [...baseSshArgs(parsed), parsed.userHost, "pty", "list", "--json"];
  let stdout: string;
  try {
    const result = await execFileAsync("ssh", args, {
      timeout: 15_000,
      encoding: "utf-8",
    });
    stdout = result.stdout;
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }

  let parsedSessions: unknown;
  try {
    parsedSessions = JSON.parse(stdout);
  } catch {
    throw new Error(
      `pty list --json on ${sshUrl} returned non-JSON output. Is pty up-to-date on the remote?`,
    );
  }
  if (!Array.isArray(parsedSessions)) {
    throw new Error(
      `pty list --json on ${sshUrl} returned ${typeof parsedSessions}, expected an array.`,
    );
  }
  return parsedSessions as RemoteSession[];
}

/**
 * Probe ssh connectivity with the cheapest viable round-trip: `ssh
 * <host> pty --version`. Used by `pty-relay add ssh://…` to refuse a
 * save that wouldn't be usable.
 *
 * Returns the pty version string on success; throws with the
 * translated error on failure.
 */
export async function probeSshPeer(sshUrl: string): Promise<string> {
  const parsed = parseSshUrl(sshUrl);
  const args = [...baseSshArgs(parsed), parsed.userHost, "pty", "--version"];
  try {
    const { stdout } = await execFileAsync("ssh", args, {
      timeout: 15_000,
      encoding: "utf-8",
    });
    return stdout.trim();
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }
}

/**
 * Run `ssh <userHost> pty peek <session> …` and return the screen as a
 * string. Mirrors `peekRemoteSession`'s shape so `peek.ts`'s dispatch
 * stays clean.
 */
export async function peekSshRemoteSession(
  sshUrl: string,
  session: string,
  opts: {
    plain?: boolean;
    full?: boolean;
    wait?: string[];
    timeoutSec?: number;
  } = {},
): Promise<{ screen: string }> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "peek begin", { userHost: parsed.userHost, session });
  const remote: string[] = ["pty", "peek"];
  if (opts.plain) remote.push("--plain");
  if (opts.full) remote.push("--full");
  if (opts.wait && opts.wait.length > 0) {
    for (const w of opts.wait) remote.push("--wait", w);
  }
  if (opts.timeoutSec) remote.push("-t", String(opts.timeoutSec));
  remote.push(session);
  const args = [...baseSshArgs(parsed), parsed.userHost, ...remote];
  // Per-call timeout outlives any --wait poll the remote pty does. Add
  // 5s grace so we always lose the race to remote pty's own timeout.
  const timeoutMs =
    opts.wait && opts.wait.length > 0
      ? (opts.timeoutSec ? opts.timeoutSec * 1000 : 60_000) + 5_000
      : 15_000;
  try {
    const { stdout } = await execFileAsync("ssh", args, {
      timeout: timeoutMs,
      encoding: "utf-8",
      // peek output is bounded by the remote terminal's scrollback;
      // 8 MB is more than any sane terminal but caps a runaway.
      maxBuffer: 8 * 1024 * 1024,
    });
    return { screen: stdout };
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }
}

/**
 * Run `ssh <userHost> pty send <session> …`. `pty send` takes one or
 * more `--seq` flags for ordered input; the friend-facing `pty-relay
 * send` already prepares these and hands us the list.
 */
export async function sendSshRemoteSession(
  sshUrl: string,
  session: string,
  data: string[],
  opts: { delayMs?: number; paste?: boolean } = {},
): Promise<void> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "send begin", { userHost: parsed.userHost, session, chunks: data.length });
  const remote: string[] = ["pty", "send"];
  for (const chunk of data) {
    remote.push("--seq", chunk);
  }
  if (opts.delayMs !== undefined) {
    remote.push("--with-delay", String(opts.delayMs / 1000));
  }
  if (opts.paste) remote.push("--paste");
  remote.push(session);
  const args = [...baseSshArgs(parsed), parsed.userHost, ...remote];
  try {
    await execFileAsync("ssh", args, {
      timeout: 15_000,
      encoding: "utf-8",
    });
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }
}

/**
 * Run `ssh <userHost> pty tag <session> …` and parse the JSON tag map
 * the remote prints. Mirrors `tagRemoteSession`'s return shape.
 */
export async function tagSshRemoteSession(
  sshUrl: string,
  session: string,
  opts: { set?: Record<string, string>; remove?: string[] } = {},
): Promise<{ tags: Record<string, string> }> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "tag begin", {
    userHost: parsed.userHost,
    session,
    setCount: opts.set ? Object.keys(opts.set).length : 0,
    removeCount: opts.remove?.length ?? 0,
  });
  const remote: string[] = ["pty", "tag", "--json", session];
  for (const k of opts.remove ?? []) {
    remote.push("--rm", k);
  }
  for (const [k, v] of Object.entries(opts.set ?? {})) {
    remote.push(`${k}=${v}`);
  }
  const args = [...baseSshArgs(parsed), parsed.userHost, ...remote];
  let stdout: string;
  try {
    const result = await execFileAsync("ssh", args, {
      timeout: 15_000,
      encoding: "utf-8",
    });
    stdout = result.stdout;
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }
  let tags: unknown;
  try {
    tags = JSON.parse(stdout);
  } catch {
    throw new Error(
      `pty tag --json on ${sshUrl} returned non-JSON output. Is pty up-to-date on the remote?`,
    );
  }
  if (typeof tags !== "object" || tags === null || Array.isArray(tags)) {
    throw new Error(
      `pty tag --json on ${sshUrl} returned ${Array.isArray(tags) ? "array" : typeof tags}, expected an object.`,
    );
  }
  return { tags: tags as Record<string, string> };
}

/**
 * Run `ssh <userHost> pty kill <session>`. The remote pty CLI handles
 * the actual termination; we just propagate exit + stderr.
 */
export async function killSshRemoteSession(
  sshUrl: string,
  session: string,
): Promise<void> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "kill begin", { userHost: parsed.userHost, session });
  const args = [...baseSshArgs(parsed), parsed.userHost, "pty", "kill", session];
  try {
    await execFileAsync("ssh", args, {
      timeout: 15_000,
      encoding: "utf-8",
    });
  } catch (err) {
    throw translateSshError(err, sshUrl);
  }
}

/** Stop a long-lived follow handle returned by `followSshRemoteEvents`. */
export interface SshEventsSubscription {
  /** Terminate the remote-side pty events stream + close ssh. */
  close(): void;
}

/**
 * Spawn `ssh <userHost> pty events --json [--session <name>]` and
 * stream the JSONL output to `onEvent` for each parsed line. The
 * handle's `close()` SIGINT-kills the ssh process, which the remote
 * pty translates into a clean events-stream shutdown.
 *
 * No reconnect loop here — ssh's own retry semantics are the right
 * tool. If the operator wants persistence, they wrap `pty-relay
 * events <peer>` in a supervisor (e.g. systemd Restart=always).
 */
export function followSshRemoteEvents(
  sshUrl: string,
  opts: {
    session?: string;
    onEvent: (evt: unknown) => void;
    onError: (err: Error) => void;
    onExit: (code: number | null) => void;
  },
): SshEventsSubscription {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "events follow begin", {
    userHost: parsed.userHost,
    session: opts.session,
  });
  const remote: string[] = ["pty", "events", "--json"];
  if (opts.session) {
    remote.push("--session", opts.session);
  }
  const args = [...baseSshArgs(parsed), parsed.userHost, ...remote];
  const child = childSpawn("ssh", args, {
    stdio: ["ignore", "pipe", "pipe"],
  });

  let buf = "";
  child.stdout?.setEncoding("utf-8");
  child.stdout?.on("data", (chunk: string) => {
    buf += chunk;
    // JSONL — emit one event per newline.
    let idx: number;
    while ((idx = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (line.length === 0) continue;
      try {
        opts.onEvent(JSON.parse(line));
      } catch (err: any) {
        opts.onError(
          new Error(`bad JSON from ${sshUrl}: ${err?.message ?? err}`),
        );
      }
    }
  });

  let stderrBuf = "";
  child.stderr?.setEncoding("utf-8");
  child.stderr?.on("data", (chunk: string) => {
    stderrBuf += chunk;
    // Keep the buffer bounded — pre-translation in close handler.
    if (stderrBuf.length > 4096) stderrBuf = stderrBuf.slice(-4096);
  });

  child.on("error", (err: Error) => {
    opts.onError(err);
  });

  child.on("close", (code) => {
    if (code !== 0 && code !== null && stderrBuf.trim().length > 0) {
      // Run the same translation as one-shot ssh calls so the operator
      // sees the same friendly hints (pty-not-found, host-unreachable).
      opts.onError(
        translateSshError({ stderr: stderrBuf, message: `ssh exited ${code}` }, sshUrl),
      );
    }
    opts.onExit(code);
  });

  return {
    close(): void {
      if (!child.killed) {
        try { child.kill("SIGINT"); } catch {}
      }
    },
  };
}

/**
 * Spawn `ssh -t <userHost> pty attach <session>` with inherited stdio.
 * `-t` forces TTY allocation so the remote pty sees a real terminal
 * and can drive the alt-screen / cursor / sigwinch dance. Returns a
 * Promise that resolves with the child's exit code (or null on a
 * signal) so the caller can `process.exit(code)`.
 */
export function attachSshRemoteSession(
  sshUrl: string,
  session: string,
): Promise<number | null> {
  const parsed = parseSshUrl(sshUrl);
  log("ssh", "attach begin", { userHost: parsed.userHost, session });
  // `-t` is the load-bearing flag here — without it, ssh refuses to
  // allocate a remote PTY for a non-interactive stdin, and `pty
  // attach` ends up wedged. The phase-1 design doc calls this out.
  const args = ["-t", ...baseSshArgs(parsed), parsed.userHost, "pty", "attach", session];
  const child: ChildProcess = childSpawn("ssh", args, {
    stdio: "inherit",
  });
  return new Promise((resolve) => {
    child.on("error", () => resolve(255));
    child.on("close", (code) => resolve(code));
  });
}

/**
 * Convert a raw child_process error into one with a user-friendly
 * message. ssh's exit codes + stderr patterns are well-known enough
 * that we can pre-translate the common cases.
 */
function translateSshError(err: unknown, sshUrl: string): Error {
  const e = err as { code?: unknown; stderr?: unknown; message?: unknown };
  const stderr = typeof e.stderr === "string" ? e.stderr.trim() : "";
  const msg = typeof e.message === "string" ? e.message : "unknown error";

  // The most useful translations: ssh's "command not found"-on-remote
  // (pty isn't installed) and "could not resolve hostname" / "connection
  // refused" (peer unreachable).
  if (stderr.includes("command not found") || stderr.includes("not found")) {
    return new Error(
      `${sshUrl}: pty is not on the remote PATH. Install pty there ` +
        `(see https://github.com/myobie/pty) and re-try.`,
    );
  }
  if (stderr.includes("could not resolve hostname")) {
    return new Error(
      `${sshUrl}: could not resolve hostname. Check ~/.ssh/config or use ` +
        `an IP address.`,
    );
  }
  if (stderr.includes("Connection refused") || stderr.includes("connect to host")) {
    return new Error(`${sshUrl}: ${stderr.split("\n")[0]}`);
  }
  if (stderr.includes("Permission denied")) {
    return new Error(
      `${sshUrl}: ssh permission denied. Check your key / ssh-agent ` +
        `(BatchMode=yes is on, so passwords aren't tried).`,
    );
  }
  // Generic fallback: include the trimmed stderr so the operator sees
  // ssh's verbatim diagnostic alongside our framing.
  const tail = stderr ? `\n${stderr}` : "";
  return new Error(`${sshUrl}: ${msg}${tail}`);
}
