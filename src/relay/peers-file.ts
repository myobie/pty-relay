/**
 * Declarative peers file for non-interactive enrollment.
 *
 * Brief-015 contract: an operator (or config-management script) drops a
 * file of peer URLs at a known XDG-style path, and every `pty-relay`
 * subcommand picks them up at command time without a single
 * imperative call. The file is the writable surface for fleet-style
 * provisioning; the encrypted `hosts` store stays for entries that
 * `connect`/`add`/etc. wrote interactively.
 *
 * File location (first found wins):
 *   1. `$PTY_RELAY_PEERS_FILE`               (explicit override; tests)
 *   2. `$XDG_CONFIG_HOME/pty-relay/peers`    (canonical XDG)
 *   3. `$HOME/.config/pty-relay/peers`       (XDG fallback when unset)
 *
 * Line grammar (one entry per line; any unparseable line is dropped
 * with a one-line warning to stderr so the operator sees the typo
 * without losing every other peer):
 *
 *   <url>                       — peer with auto-derived label
 *   <url>  <label>               — peer with explicit label (1+ spaces or tabs)
 *   # any comment                — ignored
 *                                 — blank lines ignored
 *
 * `<url>` is EITHER:
 *   `ssh://[user@]host[:port]`                       → `KnownHost.sshUrl`
 *   `http://host[:port][/session]#pk.secret[.tok]`   → `KnownHost.url`
 *   `https://host[:port][/session]#pk.secret[.tok]`  → `KnownHost.url`
 *
 * Auto-label: the host's bare hostname (user/port stripped) for ssh,
 * and the URL's host for https. Matches the phase-1 add-flow's
 * convention so operators see consistent labels whether a peer was
 * added imperatively or via the file.
 *
 * Read at COMMAND time, never cached. A freshly-dropped file works
 * with zero setup, no daemon restart.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { parseSshUrl, looksLikeSshUrl } from "./transport-ssh.ts";
import type { KnownHost } from "./known-hosts.ts";
import { log } from "../log.ts";

/** Cheap shape check for `<scheme>://host[:port][/session]#pk.secret[.tok]`.
 *  We don't decode the base64url here — `parseToken` does the
 *  cryptographic length checks at use time and would fail with a
 *  clear error there. Parse-time goal is just "looks like a token
 *  URL, not a typo." */
const TOKEN_URL_SHAPE =
  /^https?:\/\/[^/#\s]+(?:\/[^#\s]*)?#[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$/;

/** Resolved path the peers file would be read from. `null` when none of
 *  the search locations have a file. Exposed so `pty-relay doctor`
 *  and `--help` can surface the current path. */
export function resolvePeersFilePath(): string | null {
  const candidates = peersFileCandidates();
  for (const p of candidates) {
    try {
      // existsSync — not isFile — so a path that turns out to be a
      // directory still flows into `loadPeersFile`'s read attempt,
      // where it surfaces as a clear EISDIR warning instead of a
      // silent "no peers file."
      if (fs.existsSync(p)) return p;
    } catch {
      // unreachable for existsSync, but defensive
    }
  }
  return null;
}

/** All paths inspected, in priority order. Used by error messages so
 *  the operator can see exactly where we looked. */
export function peersFileCandidates(): string[] {
  const out: string[] = [];
  if (process.env.PTY_RELAY_PEERS_FILE) {
    out.push(process.env.PTY_RELAY_PEERS_FILE);
  }
  const xdg = process.env.XDG_CONFIG_HOME;
  if (xdg) {
    out.push(path.join(xdg, "pty-relay", "peers"));
  }
  const home = process.env.HOME || os.homedir();
  if (home) {
    out.push(path.join(home, ".config", "pty-relay", "peers"));
  }
  return out;
}

/** Auto-label for a parsed `ssh://` URL — bare hostname. */
function autoLabelForSsh(sshUrl: string): string {
  const parsed = parseSshUrl(sshUrl);
  // Drop the `user@` prefix; keep just the host.
  const at = parsed.userHost.lastIndexOf("@");
  return at === -1 ? parsed.userHost : parsed.userHost.slice(at + 1);
}

/** Auto-label for an `https://…#pk.secret` URL — bare hostname (URL host
 *  drops port automatically via URL.hostname). */
function autoLabelForToken(tokenUrl: string): string {
  try {
    return new URL(tokenUrl).hostname;
  } catch {
    // parseToken would have caught this; defensive fallback.
    return tokenUrl;
  }
}

/** A single parsed peers-file row, before label de-collision. */
interface ParsedRow {
  /** Original 1-indexed line number, for diagnostics. */
  line: number;
  /** Explicit label from the line if present; null when auto-derive. */
  explicitLabel: string | null;
  /** Either an ssh:// URL or a #pk.secret token URL. */
  url: string;
  /** Discriminator. */
  kind: "ssh" | "token";
}

/**
 * Parse the file's contents into a list of `KnownHost` entries. Pure
 * (no I/O) — `loadPeersFile()` is the I/O entrypoint and delegates here.
 *
 * Bad lines are logged + skipped, not fatal. A typo'd URL on line 7
 * shouldn't take down the other 49 peers in the same file.
 */
export function parsePeersFile(
  contents: string,
  filePathForDiagnostics: string,
): KnownHost[] {
  const rows: ParsedRow[] = [];
  const lines = contents.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const raw = lines[i];
    const trimmed = raw.trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#")) continue;

    // Split on the FIRST whitespace run — everything after is the label.
    // Labels can contain spaces; the URL itself can't, so this is
    // unambiguous.
    const match = trimmed.match(/^(\S+)(?:\s+(.+))?$/);
    if (!match) continue; // unreachable given the trim above, but defensive
    const url = match[1];
    const explicitLabelRaw = match[2]?.trim();
    const explicitLabel = explicitLabelRaw && explicitLabelRaw.length > 0
      ? explicitLabelRaw
      : null;

    if (looksLikeSshUrl(url)) {
      try {
        parseSshUrl(url); // validate but discard
      } catch (err: any) {
        warnSkip(filePathForDiagnostics, lineNum, url, err?.message);
        continue;
      }
      rows.push({ line: lineNum, explicitLabel, url, kind: "ssh" });
    } else if (url.startsWith("http://") || url.startsWith("https://")) {
      if (!TOKEN_URL_SHAPE.test(url)) {
        warnSkip(
          filePathForDiagnostics,
          lineNum,
          url,
          "missing #pk.secret fragment or malformed shape",
        );
        continue;
      }
      rows.push({ line: lineNum, explicitLabel, url, kind: "token" });
    } else {
      warnSkip(
        filePathForDiagnostics,
        lineNum,
        url,
        "expected ssh:// or http(s)://…#pk.secret",
      );
    }
  }

  // De-collide labels: explicit labels win; auto labels get a numeric
  // suffix on collision so a fleet with two `web-1.example.com` rows
  // doesn't silently drop the second.
  const used = new Set<string>();
  const out: KnownHost[] = [];
  for (const row of rows) {
    const wanted =
      row.explicitLabel ??
      (row.kind === "ssh" ? autoLabelForSsh(row.url) : autoLabelForToken(row.url));
    const finalLabel = pickFreeLabel(wanted, used);
    used.add(finalLabel);
    if (row.kind === "ssh") {
      out.push({ label: finalLabel, sshUrl: row.url });
    } else {
      out.push({ label: finalLabel, url: row.url });
    }
  }

  log("peers-file", "parsed", {
    path: filePathForDiagnostics,
    entries: out.length,
    sshCount: out.filter((h) => !!h.sshUrl).length,
    tokenCount: out.filter((h) => !!h.url).length,
  });
  return out;
}

/** Append a numeric suffix until the label is free in `used`. The
 *  encrypted-store's `pickUniqueLabel` is keyed on a distinguisher
 *  (URL host / pubkey); here we don't have a stable distinguisher
 *  per row, so a simple counter is the right tool. */
function pickFreeLabel(wanted: string, used: Set<string>): string {
  if (!used.has(wanted)) return wanted;
  for (let n = 2; ; n++) {
    const candidate = `${wanted}-${n}`;
    if (!used.has(candidate)) return candidate;
  }
}

function warnSkip(
  filePath: string,
  lineNum: number,
  url: string,
  reason: string | undefined,
): void {
  const why = reason ? `: ${reason}` : "";
  process.stderr.write(
    `[peers-file] ${filePath}:${lineNum} skipping "${url}"${why}\n`,
  );
}

/** Read + parse the peers file, if any. Returns `[]` when no file
 *  exists at any candidate path — never throws. Read errors (file
 *  exists but unreadable) emit one stderr line and return `[]`. */
export function loadPeersFile(): KnownHost[] {
  const filePath = resolvePeersFilePath();
  if (!filePath) {
    log("peers-file", "not present", { searched: peersFileCandidates() });
    return [];
  }
  let contents: string;
  try {
    contents = fs.readFileSync(filePath, "utf-8");
  } catch (err: any) {
    process.stderr.write(
      `[peers-file] cannot read ${filePath}: ${err?.message ?? err}\n`,
    );
    return [];
  }
  return parsePeersFile(contents, filePath);
}
