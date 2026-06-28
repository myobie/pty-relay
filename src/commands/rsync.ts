import { spawn } from "node:child_process";

/**
 * `pty-relay rsync` — thin wrapper that invokes real rsync with our
 * exec command plugged in as the transport (`-e`). The user gets
 * full rsync syntax (flags, multiple sources, --delete, etc.) without
 * the relay knowing anything about it.
 *
 * Internally:
 *
 *   pty-relay rsync [rsync-flags] <src> <dst>
 *
 * becomes
 *
 *   rsync -e "<self> exec" [rsync-flags] <src> <dst>
 *
 * where `<self>` is `node <path-to-cli.ts>` for dev, or just
 * `pty-relay` when installed. rsync will then invoke `<self> exec
 * <host> rsync --server …` for every remote endpoint it sees.
 *
 * The target side recognises the host portion of `host:/path` as the
 * target argument to our `exec` command (token URL or known-hosts
 * label). For now we require a raw token URL since label resolution
 * for `exec` hasn't shipped yet.
 *
 * Exit code is propagated from rsync verbatim.
 */

export interface RsyncOptions {
  configDir?: string;
  passphraseFile?: string;
}

export async function rsyncCommand(args: string[], _options: RsyncOptions = {}): Promise<void> {
  const self = buildSelfInvocation();
  const transport = `${self} exec`;

  // We pass --blocking-io so rsync's process layout interacts cleanly
  // with our pipes (avoid the "no buffer" hang seen with some
  // transports). rsync ignores it on local-only transfers.
  const rsyncArgs = ["-e", transport, "--blocking-io", ...args];

  const child = spawn("rsync", rsyncArgs, { stdio: "inherit" });
  const exitCode: number = await new Promise((resolve) => {
    child.on("exit", (code, signal) => {
      if (signal) resolve(128 + signalNumber(signal));
      else resolve(code ?? 1);
    });
    child.on("error", (err) => {
      process.stderr.write(`rsync spawn failed: ${err.message}\n`);
      resolve(127);
    });
  });
  process.exit(exitCode);
}

function buildSelfInvocation(): string {
  // When running the dev tree (`node src/cli.ts rsync …`), self is
  // `node <abs-path>/src/cli.ts`. When installed as a global binary,
  // process.argv[1] points at the installed bin and we can call it
  // directly. Either way, quote spaces in the path so rsync's
  // shell-style splitter of `-e` does the right thing.
  const argv0 = process.argv[0];
  const argv1 = process.argv[1];
  if (!argv1) return "pty-relay";

  // If this looks like a TS source file we still need node to run it.
  const isTsSource = argv1.endsWith(".ts");
  const parts = isTsSource ? [argv0, argv1] : [argv1];
  return parts.map(quoteForShell).join(" ");
}

function quoteForShell(s: string): string {
  if (/^[\w@./:%+\-=]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function signalNumber(signal: NodeJS.Signals): number {
  switch (signal) {
    case "SIGHUP": return 1;
    case "SIGINT": return 2;
    case "SIGTERM": return 15;
    default: return 0;
  }
}

