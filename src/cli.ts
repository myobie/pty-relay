#!/usr/bin/env node

import { extractTagFlags } from "./args.ts";

const args = process.argv.slice(2);

function getFlag(flag: string, argList: string[] = args): string | null {
  const idx = argList.indexOf(flag);
  if (idx === -1 || idx + 1 >= argList.length) return null;
  return argList[idx + 1];
}

function hasFlag(flag: string, argList: string[] = args): boolean {
  return argList.includes(flag);
}

function usage(): void {
  console.log(`pty-relay — remote access to pty sessions

Commands:
  init                      Initialize secret storage (first-time setup)
  reset                     Delete all saved credentials (start over)
  ls                        List known hosts and their sessions
  ls --filter-tag k=v       Filter sessions by tag (repeatable, all must match)
  peek <host> <session>                        Print the current screen of a remote session
  peek --plain | --full                        Plain text (no ANSI) / full scrollback
  peek --wait <text> [-t <s>] <host> <s>       Poll until text appears (repeatable; OR semantics)
  send <host> <session> "text"                 Send text literally
  send ... --seq "text" --seq key:return       Send an ordered sequence (keys resolved)
  send ... --with-delay <seconds>              Delay between --seq items
  send ... --paste                             Wrap payload in bracketed-paste markers
  tag <host> <session>                         Show tags on a remote session
  tag <host> <session> k=v [k=v…]              Set tags
  tag <host> <session> --rm k [...]            Remove tags
  tag <host> <session> --json                  Print tags as JSON
  events <host>                                Follow events from a remote daemon (Ctrl+C to stop)
  events --session <name> <host>               Filter to a single session
  events --json <host>                         Emit JSONL for scripting
  forget <host-label>       Remove a saved host
  connect [token-url]       Connect to a remote pty session (or list sessions)
  connect --spawn <n> --tag k=v  Spawn a session with tags (--tag repeatable)
  serve [port]              Run a self-hosted relay (default: 8099)
  set-name <label>          Set a custom name for this daemon
  clients                   Interactive client approval TUI
  clients list              List client tokens (use --json for JSON)
  clients approve <id>      Approve a pending client
  clients revoke <id>       Revoke a client token
  clients invite [--label]  Generate a pre-approved invite URL
  doctor                    Print environment info for troubleshooting
  version                   Print the pty-relay version

Options:
  --config-dir <dir>        Config directory (default: ~/.local/state/pty/relay)
  --passphrase-file <path>  Read passphrase from file (non-interactive)
  --backend <b>             Storage backend for init: keychain|passphrase
  --allow-new-sessions             Allow remote clients to start new pty sessions
  --skip-allow-new-sessions-confirmation  Don't prompt before enabling remote spawn
                                   (for non-interactive startup, e.g. a pty session)
  --auto-approve            Skip client approval (allow all connections)
  --tailscale               Enable Tailscale HTTPS via 'tailscale serve'
  -d, --detach              Run serve in a detached pty session
  --name <label>            Name for the wrapped pty session (default: relay-daemon)
  --json                    Output as JSON (for ls)
  --spawn <name>            Spawn a new remote session (for connect)
  --cwd <dir>               Working directory for spawned session
  --force                   Skip confirmation (for reset/init)

Environment:
  PTY_RELAY_PASSPHRASE      Passphrase (non-interactive)
  PTY_RELAY_KDF_PROFILE     KDF profile: moderate (default) | interactive
`);
}

function confirmAllowSpawn(): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write(
      "\n" +
      "WARNING: --allow-new-sessions lets remote clients start new processes on this machine.\n" +
      "Anyone with your token URL can open a shell.\n" +
      "\n" +
      "Enable remote spawn? [y/N] "
    );
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (data: string) => {
      process.stdin.pause();
      resolve(data.trim().toLowerCase() === "y");
    });
  });
}

async function main(): Promise<void> {
  const command = args[0];

  // Per-command `--help`: intercept before any dispatch so users can run
  // `pty-relay <cmd> --help` and actually get help instead of having the
  // command try to interpret `--help` as a positional arg. We only look at
  // the slot right after the command so quoted text that happens to contain
  // "--help" deeper in the argv (e.g. `pty-relay send h s "see --help"`)
  // isn't swallowed.
  if (command && (args[1] === "--help" || args[1] === "-h")) {
    usage();
    process.exit(0);
  }

  // Global --passphrase-file flag
  const passphraseFile = getFlag("--passphrase-file") ?? undefined;

  switch (command) {
    case "connect": {
      const tokenUrl = args[1];
      if (!tokenUrl) {
        console.error("Usage: pty-relay connect <token-url> [--spawn <name>]");
        process.exit(1);
      }
      const spawnName = getFlag("--spawn");
      const spawnCwd = getFlag("--cwd");
      const configDir = getFlag("--config-dir") ?? undefined;
      const spawnTags = extractTagFlags(args.slice(1));
      const { connect } = await import("./commands/connect.ts");
      await connect(tokenUrl, {
        spawn: spawnName ?? undefined,
        cwd: spawnCwd ?? undefined,
        tags: Object.keys(spawnTags).length > 0 ? spawnTags : undefined,
        configDir,
        passphraseFile,
      });
      break;
    }

    case "list":
    case "ls": {
      const configDir = getFlag("--config-dir") ?? undefined;
      const { extractFilterTags } = await import("@myobie/pty/client");
      const lsArgs = args.slice(1);
      const filterTags = extractFilterTags(lsArgs);
      const { ls } = await import("./commands/ls.ts");
      await ls(configDir, hasFlag("--json"), { passphraseFile, filterTags });
      break;
    }

    case "peek": {
      // Flags can appear anywhere; positionals are the last two non-flag
      // tokens. Collect --wait (repeatable) and -t/--timeout while scanning.
      const peekArgs = args.slice(1);
      const waitPatterns: string[] = [];
      let timeoutSec: number | undefined;
      const positional: string[] = [];
      for (let i = 0; i < peekArgs.length; i++) {
        const a = peekArgs[i];
        if (a === "--wait" && i + 1 < peekArgs.length) {
          waitPatterns.push(peekArgs[i + 1]);
          i++;
          continue;
        }
        if ((a === "-t" || a === "--timeout") && i + 1 < peekArgs.length) {
          const parsed = parseFloat(peekArgs[i + 1]);
          if (!isFinite(parsed) || parsed <= 0) {
            console.error(`peek: ${a} expects a positive number of seconds`);
            process.exit(1);
          }
          timeoutSec = parsed;
          i++;
          continue;
        }
        if (a === "--plain" || a === "--full") continue;
        if (a === "--config-dir" || a === "--passphrase-file") { i++; continue; }
        if (a.startsWith("--") || a.startsWith("-")) continue;
        positional.push(a);
      }
      const hostLabel = positional[0];
      const session = positional[1];
      if (!hostLabel || !session) {
        console.error("Usage: pty-relay peek [--plain|--full] [--wait <text>...] [-t <seconds>] <host> <session>");
        process.exit(1);
      }
      const plain = hasFlag("--plain");
      const full = hasFlag("--full");
      const configDir = getFlag("--config-dir") ?? undefined;
      const { peek } = await import("./commands/peek.ts");
      await peek(hostLabel, session, {
        plain,
        full,
        wait: waitPatterns.length > 0 ? waitPatterns : undefined,
        timeoutSec,
        configDir,
        passphraseFile,
      });
      break;
    }

    case "send": {
      // Flags can appear anywhere — scan once, collecting --seq (repeatable),
      // flag-with-value pairs, and bare positionals.
      const sendArgs = args.slice(1);
      const seqs: string[] = [];
      const positional: string[] = [];
      for (let i = 0; i < sendArgs.length; i++) {
        const a = sendArgs[i];
        if (a === "--seq" && i + 1 < sendArgs.length) {
          seqs.push(sendArgs[i + 1]);
          i++;
          continue;
        }
        if (a === "--with-delay" || a === "--config-dir" || a === "--passphrase-file") {
          i++;
          continue;
        }
        if (a.startsWith("--")) continue;
        positional.push(a);
      }
      const hostLabel = positional[0];
      const session = positional[1];
      if (!hostLabel || !session) {
        console.error("Usage:");
        console.error("  pty-relay send <host> <session> \"text\"");
        console.error("  pty-relay send <host> <session> --seq \"text\" [--seq key:return] [--with-delay <seconds>] [--paste]");
        process.exit(1);
      }
      let data: string[];
      if (seqs.length > 0) {
        // --seq values support key:name syntax — e.g. "key:return" resolves
        // to "\r". Defer to pty's `parseSeqValue` so behavior matches the
        // local `pty send` command exactly.
        const { parseSeqValue } = await import("@myobie/pty/client");
        try {
          data = seqs.map((s) => parseSeqValue(s));
        } catch (err: any) {
          console.error(err.message || "invalid --seq value");
          process.exit(1);
        }
      } else {
        const text = positional[2];
        if (!text) {
          console.error("send: provide text positionally or one/more --seq values");
          process.exit(1);
        }
        data = [text];
      }
      const delayArg = getFlag("--with-delay");
      const delayMs = delayArg ? Math.round(parseFloat(delayArg) * 1000) : undefined;
      const paste = hasFlag("--paste");
      const configDir = getFlag("--config-dir") ?? undefined;
      const { send } = await import("./commands/send.ts");
      await send(hostLabel, session, data, { delayMs, paste, configDir, passphraseFile });
      break;
    }

    case "events": {
      // Follow events from a remote host. --session filters to one session
      // (client-side); --json emits JSONL for scripting.
      const eventsArgs = args.slice(1);
      let sessionFilter: string | undefined;
      const positional: string[] = [];
      for (let i = 0; i < eventsArgs.length; i++) {
        const a = eventsArgs[i];
        if (a === "--session" && i + 1 < eventsArgs.length) {
          sessionFilter = eventsArgs[i + 1];
          i++;
          continue;
        }
        if (a === "--json") continue;
        if (a === "--config-dir" || a === "--passphrase-file") { i++; continue; }
        if (a.startsWith("--")) continue;
        positional.push(a);
      }
      const hostLabel = positional[0];
      if (!hostLabel) {
        console.error("Usage: pty-relay events [--session <name>] [--json] <host>");
        process.exit(1);
      }
      const json = hasFlag("--json");
      const configDir = getFlag("--config-dir") ?? undefined;
      const { follow } = await import("./commands/events.ts");
      await follow(hostLabel, { session: sessionFilter, json, configDir, passphraseFile });
      break;
    }

    case "tag": {
      // Flags can appear anywhere; positionals are: <host> <session> [k=v...]
      const tagArgs = args.slice(1);
      const set: Record<string, string> = {};
      const remove: string[] = [];
      const positional: string[] = [];
      for (let i = 0; i < tagArgs.length; i++) {
        const a = tagArgs[i];
        if (a === "--rm" && i + 1 < tagArgs.length) {
          remove.push(tagArgs[i + 1]);
          i++;
          continue;
        }
        if (a === "--json") continue;
        if (a === "--config-dir" || a === "--passphrase-file") {
          i++;
          continue;
        }
        if (a.startsWith("--")) continue;
        positional.push(a);
      }
      const hostLabel = positional[0];
      const session = positional[1];
      if (!hostLabel || !session) {
        console.error("Usage:");
        console.error("  pty-relay tag <host> <session>                         show tags");
        console.error("  pty-relay tag <host> <session> key=value [key=value…]  set tags");
        console.error("  pty-relay tag <host> <session> --rm key [--rm key…]    remove tags");
        process.exit(1);
      }
      // positional[2..] are the "k=v" set entries.
      for (const kv of positional.slice(2)) {
        const eq = kv.indexOf("=");
        if (eq === -1) {
          console.error(`Invalid tag arg "${kv}" — expected key=value.`);
          process.exit(1);
        }
        set[kv.slice(0, eq)] = kv.slice(eq + 1);
      }
      const json = hasFlag("--json");
      const configDir = getFlag("--config-dir") ?? undefined;
      const { tag } = await import("./commands/tag.ts");
      await tag(hostLabel, session, {
        set: Object.keys(set).length > 0 ? set : undefined,
        remove: remove.length > 0 ? remove : undefined,
        json,
        configDir,
        passphraseFile,
      });
      break;
    }

    case "forget": {
      const label = args[1];
      if (!label) {
        console.error("Usage: pty-relay forget <host-label>");
        console.error("  Run 'pty-relay ls' to see host labels.");
        process.exit(1);
      }
      const configDir = getFlag("--config-dir") ?? undefined;
      const { openSecretStore } = await import("./storage/bootstrap.ts");
      const { store } = await openSecretStore(configDir, {
        interactive: true,
        passphraseFile,
      });
      const { removeKnownHost, loadKnownHosts } = await import("./relay/known-hosts.ts");
      const before = await loadKnownHosts(store);
      const count = before.filter((h) => h.label === label).length;
      if (count === 0) {
        console.error(`No known host with label "${label}".`);
        console.error("  Run 'pty-relay ls' to see host labels.");
        process.exit(1);
      }
      await removeKnownHost(label, store);
      console.log(`Removed ${count > 1 ? `${count} entries for` : ""} "${label}".`);
      break;
    }

    case "serve": {
      // If -d/--detach is set, re-exec inside a pty session and exit.
      // pty itself handles the "already inside a pty session" case, so we
      // can blindly invoke `pty run -d --name relay-daemon -- pty-relay serve ...`
      // and rely on pty to do the right thing.
      if (hasFlag("-d") || hasFlag("--detach")) {
        const { spawnSync } = await import("node:child_process");
        // Strip -d/--detach and --name (those are for the outer pty wrapper
        // only, not the inner pty-relay serve).
        const forwardedArgs: string[] = [];
        for (let i = 0; i < args.length; i++) {
          const a = args[i];
          if (a === "-d" || a === "--detach") continue;
          if (a === "--name") {
            i++; // also skip the value
            continue;
          }
          forwardedArgs.push(a);
        }
        const name = getFlag("--name") ?? "relay-daemon";
        const ptyArgs = [
          "run",
          "-d",
          "--name",
          name,
          "--",
          process.argv[0],
          process.argv[1],
          ...forwardedArgs,
        ];
        const result = spawnSync("pty", ptyArgs, { stdio: "inherit" });
        if (result.status !== 0) {
          process.exit(result.status ?? 1);
        }

        // Wait briefly for the daemon to come up, then peek and extract
        // the token URL so the user has it even though they're detached.
        await new Promise((r) => setTimeout(r, 1500));
        const peek = spawnSync("pty", ["peek", name], {
          encoding: "utf-8",
          timeout: 5000,
        });
        const output = (peek.stdout || "") + (peek.stderr || "");
        // Strip ANSI escapes for clean matching
        const stripped = output.replace(
          /\x1b\[[0-9;?]*[a-zA-Z]/g,
          ""
        );
        const urlMatch = stripped.match(/Token URL:\s*(\S+)/);
        const tailscaleMatch = stripped.match(/Tailscale:\s*(\S+)/);

        console.log();
        console.log(`Daemon running in pty session "${name}".`);
        if (urlMatch) {
          console.log(`Token URL: ${urlMatch[1]}`);
        } else {
          console.log(
            `(Token URL not yet available; run 'pty peek ${name}' to see it.)`
          );
        }
        if (tailscaleMatch) {
          console.log(`Tailscale: ${tailscaleMatch[1]}`);
          try {
            const qr = spawnSync(
              "qrencode",
              ["-t", "ANSIUTF8", "-m", "1", tailscaleMatch[1]],
              { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"], timeout: 2000 }
            );
            if (qr.status === 0 && qr.stdout) {
              process.stdout.write(qr.stdout);
            }
          } catch {}
        }
        console.log();
        console.log(`Attach:  pty attach ${name}`);
        console.log(`Peek:    pty peek ${name}`);
        console.log(`Stop:    pty kill ${name}`);
        process.exit(0);
      }

      const portArg = args[1] && !args[1].startsWith("-") ? args[1] : getFlag("--port");
      const port = parseInt(portArg || "8099", 10);
      const configDir = getFlag("--config-dir") ?? undefined;
      let allowNewSessions = hasFlag("--allow-new-sessions");
      if (allowNewSessions && !hasFlag("--skip-allow-new-sessions-confirmation")) {
        if (!await confirmAllowSpawn()) {
          console.log("Spawn disabled.");
          allowNewSessions = false;
        }
      }
      const tailscale = hasFlag("--tailscale");
      const autoApprove = hasFlag("--auto-approve");
      const { serve } = await import("./commands/serve.ts");
      await serve(port, configDir, {
        allowNewSessions,
        tailscale,
        autoApprove,
        passphraseFile,
      });
      break;
    }

    case "clients": {
      const subcommand = args[1];
      const configDir = getFlag("--config-dir") ?? undefined;
      const opts = { configDir, passphraseFile };

      if (!subcommand || subcommand.startsWith("-")) {
        // Bare `pty-relay clients`: interactive TUI.
        // Falls back to the static list when stdin isn't a TTY (scripts, CI).
        if (process.stdin.isTTY) {
          const { clientsTui } = await import("./tui/clients-tui.ts");
          await clientsTui(configDir, { passphraseFile });
        } else {
          const { clientsList } = await import("./commands/clients.ts");
          await clientsList({ ...opts, json: hasFlag("--json") });
        }
      } else if (subcommand === "list") {
        const { clientsList } = await import("./commands/clients.ts");
        await clientsList({ ...opts, json: hasFlag("--json") });
      } else if (subcommand === "approve") {
        const id = args[2];
        if (!id) {
          console.error("Usage: pty-relay clients approve <id>");
          process.exit(1);
        }
        const { clientsApprove } = await import("./commands/clients.ts");
        await clientsApprove(id, opts);
      } else if (subcommand === "revoke") {
        const id = args[2];
        if (!id) {
          console.error("Usage: pty-relay clients revoke <id>");
          process.exit(1);
        }
        const { clientsRevoke } = await import("./commands/clients.ts");
        await clientsRevoke(id, opts);
      } else if (subcommand === "invite") {
        const label = getFlag("--label") ?? undefined;
        const { clientsInvite } = await import("./commands/clients.ts");
        await clientsInvite(label, opts);
      } else {
        console.error(`Unknown clients subcommand: ${subcommand}`);
        process.exit(1);
      }
      break;
    }

    case "set-name": {
      const label = args[1];
      if (!label) {
        console.error("Usage: pty-relay set-name <label>");
        process.exit(1);
      }
      const configDir = getFlag("--config-dir") ?? undefined;
      const { openSecretStore } = await import("./storage/bootstrap.ts");
      const { saveLabel } = await import("./relay/config.ts");
      const { store } = await openSecretStore(configDir, {
        interactive: true,
        passphraseFile,
      });
      await saveLabel(label, store);
      console.log(`Label set to: ${label}`);
      break;
    }

    case "init": {
      const configDir = getFlag("--config-dir") ?? undefined;
      const backend = getFlag("--backend") ?? undefined;
      const force = hasFlag("--force");
      const { initCommand } = await import("./commands/init.ts");
      await initCommand({ configDir, passphraseFile, backend, force });
      break;
    }

    case "reset": {
      const configDir = getFlag("--config-dir") ?? undefined;
      const force = hasFlag("--force");
      const { resetCommand } = await import("./commands/reset.ts");
      await resetCommand({ configDir, force });
      break;
    }

    case "help":
    case "--help":
    case "-h": {
      usage();
      process.exit(0);
      break;
    }

    case "version":
    case "--version":
    case "-v": {
      const { readFileSync } = await import("node:fs");
      const path = await import("node:path");
      try {
        const pkgPath = path.resolve(import.meta.dirname, "../package.json");
        const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
        console.log(`pty-relay ${pkg.version}`);
      } catch {
        console.log("pty-relay (version unknown)");
      }
      process.exit(0);
      break;
    }

    case "doctor": {
      const configDir = getFlag("--config-dir") ?? undefined;
      const { doctorCommand } = await import("./commands/doctor.ts");
      await doctorCommand({ configDir });
      break;
    }

    default:
      usage();
      process.exit(command ? 1 : 0);
  }
}

main().catch((err) => {
  console.error("Fatal:", err.message || err);
  process.exit(1);
});
