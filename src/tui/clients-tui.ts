import {
  loadClients,
  saveClients,
  findTokenById,
  generateTokenId,
  signalDaemon,
  type ClientsData,
  type ClientToken,
} from "../relay/clients.ts";
import { openSecretStore } from "../storage/bootstrap.ts";
import { createToken } from "../crypto/token.ts";
import { ready, setupConfig } from "../crypto/keys.ts";
import type { SecretStore } from "../storage/secret-store.ts";

const REFRESH_INTERVAL_MS = 2000;

interface Row {
  token: ClientToken;
}

type Mode =
  | { kind: "list" }
  | { kind: "confirm"; action: "approve" | "revoke"; tokenId: string }
  | { kind: "invite-prompt"; buffer: string };

export async function clientsTui(
  configDir?: string,
  opts?: { passphraseFile?: string }
): Promise<void> {
  if (!process.stdin.isTTY) {
    console.error(
      "Interactive clients mode requires a TTY. Use 'pty-relay clients list' for non-interactive output."
    );
    process.exit(1);
  }

  await ready();

  const { store, passphrase } = await openSecretStore(configDir, {
    interactive: true,
    passphraseFile: opts?.passphraseFile,
  });
  if (passphrase && !process.env.PTY_RELAY_PASSPHRASE) {
    process.env.PTY_RELAY_PASSPHRASE = passphrase;
  }

  // State
  let data: ClientsData = { tokens: [] };
  let rows: Row[] = [];
  let selectedIdx = 0;
  let mode: Mode = { kind: "list" };
  let statusMsg: { text: string; color: "green" | "red" | "yellow" } | null =
    null;
  let statusExpiresAt = 0;
  let scrollOffset = 0;
  let running = true;
  let refreshTimer: ReturnType<typeof setInterval> | null = null;

  async function reload(): Promise<void> {
    try {
      data = await loadClients(store);
    } catch (err: any) {
      setStatus(`Failed to load clients: ${err.message}`, "red", 5000);
      return;
    }
    // Rebuild row list (sorted: pending first, active, revoked)
    const order: Record<string, number> = {
      pending: 0,
      active: 1,
      revoked: 2,
    };
    const sorted = [...data.tokens].sort((a, b) => {
      const ord = (order[a.status] ?? 3) - (order[b.status] ?? 3);
      if (ord !== 0) return ord;
      // Within same status: newest first
      return b.created.localeCompare(a.created);
    });
    rows = sorted.map((t) => ({ token: t }));

    // Clamp selection
    if (selectedIdx >= rows.length) selectedIdx = Math.max(0, rows.length - 1);
    if (selectedIdx < 0) selectedIdx = 0;
  }

  function setStatus(
    text: string,
    color: "green" | "red" | "yellow",
    durationMs = 3000
  ): void {
    statusMsg = { text, color };
    statusExpiresAt = Date.now() + durationMs;
  }

  function getSelected(): ClientToken | null {
    return rows[selectedIdx]?.token ?? null;
  }

  function render(): void {
    const lines: string[] = [];
    lines.push("");
    lines.push("  \x1b[1mpty-relay clients\x1b[0m");
    lines.push("");

    if (rows.length === 0) {
      lines.push("  \x1b[90m(no client tokens)\x1b[0m");
      lines.push("");
    } else {
      let lastStatus: string | null = null;
      for (let i = 0; i < rows.length; i++) {
        const token = rows[i].token;
        const selected = i === selectedIdx;

        // Group header when status changes
        if (token.status !== lastStatus) {
          if (lastStatus !== null) lines.push("");
          lines.push(
            `  \x1b[90m${token.status.toUpperCase()}\x1b[0m`
          );
          lastStatus = token.status;
        }

        const cursor = selected ? "\x1b[36m▸\x1b[0m" : " ";
        const id = token.id.slice(0, 8);
        const label = formatLabel(token);
        const coloredLabel = selected
          ? `\x1b[1;36m${label}\x1b[0m`
          : token.status === "revoked"
            ? `\x1b[90m${label}\x1b[0m`
            : label;
        const created = token.created.slice(0, 16).replace("T", " ");
        const createdDim = `\x1b[90m${created}\x1b[0m`;

        lines.push(`  ${cursor} ${id}  ${padRight(coloredLabel, 32, label.length)}${createdDim}`);

        // Metadata under pending rows
        if (token.status === "pending" && token.pending_meta) {
          if (token.pending_meta.remote_addr) {
            lines.push(
              `              \x1b[90mfrom:\x1b[0m ${token.pending_meta.remote_addr}`
            );
          }
          if (token.pending_meta.user_agent) {
            const ua = summarizeUserAgent(token.pending_meta.user_agent);
            lines.push(`              \x1b[90mua:\x1b[0m   ${ua}`);
          }
        }
      }
      lines.push("");
    }

    // Status line
    if (statusMsg && Date.now() < statusExpiresAt) {
      const ansi =
        statusMsg.color === "green"
          ? "\x1b[32m"
          : statusMsg.color === "red"
            ? "\x1b[31m"
            : "\x1b[33m";
      lines.push(`  ${ansi}${statusMsg.text}\x1b[0m`);
    } else {
      statusMsg = null;
      lines.push("");
    }

    // Footer
    lines.push("");
    lines.push(
      "  \x1b[90m↑/↓: select  enter/a: approve  r: revoke  i: invite  R: refresh  q: quit\x1b[0m"
    );
    lines.push("");

    // Viewport: if the content is taller than the terminal, scroll to
    // keep the selected row visible. The header (3 lines) and footer
    // (3 lines) are always shown; the middle section scrolls.
    const termRows = process.stdout.rows || 24;
    const headerCount = 3; // title + blank line + blank/first group header
    const footerCount = 4; // status + blank + keybindings + blank

    if (lines.length <= termRows) {
      // Everything fits — no scrolling needed.
      process.stdout.write("\x1b[2J\x1b[H");
      process.stdout.write(lines.join("\n"));
    } else {
      // Find which line the selected row is on so we can ensure it's visible.
      // We tagged selected lines with the cursor character "▸".
      let selectedLine = -1;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes("▸")) { selectedLine = i; break; }
      }

      const header = lines.slice(0, headerCount);
      const footer = lines.slice(lines.length - footerCount);
      const middle = lines.slice(headerCount, lines.length - footerCount);
      const viewportHeight = termRows - headerCount - footerCount;

      // Adjust scroll offset to keep the selection visible.
      const selInMiddle = selectedLine - headerCount;
      if (selInMiddle >= 0) {
        if (selInMiddle < scrollOffset) {
          scrollOffset = selInMiddle;
        } else if (selInMiddle >= scrollOffset + viewportHeight) {
          scrollOffset = selInMiddle - viewportHeight + 1;
        }
      }
      // Clamp
      scrollOffset = Math.max(0, Math.min(scrollOffset, middle.length - viewportHeight));

      const visible = middle.slice(scrollOffset, scrollOffset + viewportHeight);
      const scrollIndicator =
        middle.length > viewportHeight
          ? `  \x1b[90m(${scrollOffset + 1}-${scrollOffset + visible.length} of ${middle.length})\x1b[0m`
          : "";

      process.stdout.write("\x1b[2J\x1b[H");
      process.stdout.write(
        [...header, ...visible, scrollIndicator, ...footer].join("\n")
      );
    }

    // Modal overlay on top
    if (mode.kind === "confirm") {
      drawConfirmModal(mode);
    } else if (mode.kind === "invite-prompt") {
      drawInvitePrompt(mode);
    }
  }

  function drawConfirmModal(m: {
    action: "approve" | "revoke";
    tokenId: string;
  }): void {
    const token = findTokenById(data, m.tokenId);
    if (!token) return;

    const verb = m.action === "approve" ? "Approve" : "Revoke";
    const label = formatLabel(token);
    const body = `${verb} token ${token.id.slice(0, 8)} (${label})?`;
    const hint =
      m.action === "revoke"
        ? "This client will be disconnected and cannot reconnect."
        : "This client will be connected immediately.";

    const bodyLen = body.length;
    const hintLen = hint.length;
    const inner = Math.max(bodyLen, hintLen, 40) + 4;

    const top = "╭" + "─".repeat(inner) + "╮";
    const bottom = "╰" + "─".repeat(inner) + "╯";
    const pad = (s: string) => {
      const remaining = inner - s.length - 2;
      return `│  ${s}${" ".repeat(Math.max(0, remaining))}│`;
    };
    const empty = `│${" ".repeat(inner)}│`;

    // Position roughly in the middle
    const verticalOffset = 8;
    const horizontalOffset = 4;
    const ansiColor =
      m.action === "revoke" ? "\x1b[31m" : "\x1b[32m";

    const boxLines = [
      top,
      empty,
      pad(`${ansiColor}${verb}?\x1b[0m`),
      empty,
      pad(body),
      pad(`\x1b[90m${hint}\x1b[0m`),
      empty,
      pad("\x1b[1m[y]\x1b[0m yes   \x1b[1m[n]\x1b[0m no"),
      empty,
      bottom,
    ];

    // Move cursor to the popup position and draw each line
    for (let i = 0; i < boxLines.length; i++) {
      process.stdout.write(
        `\x1b[${verticalOffset + i};${horizontalOffset}H${boxLines[i]}`
      );
    }
  }

  function drawInvitePrompt(m: { buffer: string }): void {
    const inner = 50;
    const top = "╭" + "─".repeat(inner) + "╮";
    const bottom = "╰" + "─".repeat(inner) + "╯";
    const empty = `│${" ".repeat(inner)}│`;
    const pad = (s: string) => {
      const visible = stripAnsi(s);
      const remaining = inner - visible.length - 2;
      return `│  ${s}${" ".repeat(Math.max(0, remaining))}│`;
    };

    const boxLines = [
      top,
      empty,
      pad("\x1b[32mNew invite token\x1b[0m"),
      empty,
      pad("Label (optional):"),
      pad(`\x1b[36m${m.buffer}\x1b[0m\x1b[7m \x1b[0m`),
      empty,
      pad("\x1b[1m[enter]\x1b[0m create  \x1b[1m[esc]\x1b[0m cancel"),
      empty,
      bottom,
    ];

    const verticalOffset = 8;
    const horizontalOffset = 4;
    for (let i = 0; i < boxLines.length; i++) {
      process.stdout.write(
        `\x1b[${verticalOffset + i};${horizontalOffset}H${boxLines[i]}`
      );
    }
  }

  async function approveSelected(): Promise<void> {
    const token = getSelected();
    if (!token) return;
    if (token.status !== "pending") {
      setStatus(
        `Can only approve pending tokens (this is ${token.status})`,
        "yellow"
      );
      render();
      return;
    }
    mode = { kind: "confirm", action: "approve", tokenId: token.id };
    render();
  }

  async function revokeSelected(): Promise<void> {
    const token = getSelected();
    if (!token) return;
    if (token.status === "revoked") {
      setStatus("Already revoked", "yellow");
      render();
      return;
    }
    mode = { kind: "confirm", action: "revoke", tokenId: token.id };
    render();
  }

  async function confirmAction(
    action: "approve" | "revoke",
    tokenId: string
  ): Promise<void> {
    const fresh = await loadClients(store);
    const token = findTokenById(fresh, tokenId);
    if (!token) {
      setStatus("Token no longer exists", "red");
      mode = { kind: "list" };
      await reload();
      render();
      return;
    }

    if (action === "approve") {
      if (token.status !== "pending") {
        setStatus(
          `Token is ${token.status}, cannot approve`,
          "yellow"
        );
        mode = { kind: "list" };
        await reload();
        render();
        return;
      }
      token.status = "active";
      token.client_id = null;
      await saveClients(fresh, store);
      const signaled = signalDaemon(configDir);
      setStatus(
        `Approved ${token.id.slice(0, 8)}${signaled ? "" : " (daemon not running)"}`,
        "green"
      );
    } else {
      if (token.status === "revoked") {
        setStatus("Already revoked", "yellow");
        mode = { kind: "list" };
        await reload();
        render();
        return;
      }
      token.status = "revoked";
      token.revoked_at = new Date().toISOString();
      token.client_id = null;
      await saveClients(fresh, store);
      const signaled = signalDaemon(configDir);
      setStatus(
        `Revoked ${token.id.slice(0, 8)}${signaled ? "" : " (daemon not running)"}`,
        "green"
      );
    }

    mode = { kind: "list" };
    await reload();
    render();
  }

  async function createInvite(label: string | null): Promise<void> {
    try {
      const fresh = await loadClients(store);
      const tokenId = generateTokenId();
      fresh.tokens.push({
        id: tokenId,
        label: label || null,
        status: "active",
        client_id: null,
        created: new Date().toISOString(),
        revoked_at: null,
      });
      await saveClients(fresh, store);

      // Build the invite URL — mirrors commands/clients.ts clientsInvite
      const { config } = await setupConfig(store);
      const url = createToken(
        "localhost:8099",
        config.publicKey,
        config.secret,
        undefined,
        tokenId
      );

      // Print on its own line ABOVE the TUI area so the user can copy it.
      // Clear screen, write the URL, then re-render.
      process.stdout.write("\x1b[2J\x1b[H");
      console.log("");
      console.log("  \x1b[32m✓ Invite created\x1b[0m");
      console.log("");
      console.log(`  ID:    ${tokenId.slice(0, 8)}`);
      if (label) console.log(`  Label: ${label}`);
      console.log(`  URL:   ${url}`);
      console.log("");
      console.log("  \x1b[90mCopy the URL now. Press any key to return to the list.\x1b[0m");

      // Wait for a single keypress before returning
      await new Promise<void>((resolve) => {
        const once = () => {
          process.stdin.off("data", once);
          resolve();
        };
        process.stdin.on("data", once);
      });

      await reload();
      setStatus(`Invite ${tokenId.slice(0, 8)} created`, "green");
    } catch (err: any) {
      setStatus(`Invite failed: ${err.message}`, "red", 5000);
    }
    render();
  }

  function moveSelection(delta: number): void {
    const next = selectedIdx + delta;
    if (next < 0) selectedIdx = 0;
    else if (next >= rows.length) selectedIdx = rows.length - 1;
    else selectedIdx = next;
    render();
  }

  function enterRawMode(): void {
    // Enter alternate screen buffer so the TUI doesn't clobber shell
    // scrollback and long lists don't bleed past the viewport.
    process.stdout.write("\x1b[?1049h");
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
  }

  function cleanup(): void {
    running = false;
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    process.stdin.pause();
    // Leave alternate screen buffer — restores the shell scrollback.
    process.stdout.write("\x1b[?1049l");
  }

  // Start
  enterRawMode();
  await reload();
  render();

  process.on("uncaughtException", (err) => {
    cleanup();
    console.error("Fatal:", err.message);
    process.exit(1);
  });

  // Auto-refresh timer — reloads clients.json every 2s so new pending
  // clients and external changes (e.g. via the CLI) show up automatically.
  refreshTimer = setInterval(async () => {
    if (!running) return;
    if (mode.kind !== "list") return; // Don't refresh during modals
    // Remember what's selected so we can try to preserve it
    const currentId = getSelected()?.id ?? null;
    await reload();
    if (currentId) {
      const newIdx = rows.findIndex((r) => r.token.id === currentId);
      if (newIdx >= 0) selectedIdx = newIdx;
    }
    render();
  }, REFRESH_INTERVAL_MS);

  process.stdin.on("data", async (key: string) => {
    if (!running) return;

    // Global quit
    if (key === "\x03") {
      // Ctrl+C — always quit
      cleanup();
      process.exit(0);
    }

    // Invite prompt mode
    if (mode.kind === "invite-prompt") {
      if (key === "\r" || key === "\n") {
        const label = mode.buffer.trim() || null;
        mode = { kind: "list" };
        await createInvite(label);
        return;
      }
      if (key === "\x1b") {
        mode = { kind: "list" };
        render();
        return;
      }
      if (key === "\x7f" || key === "\b") {
        mode = { kind: "invite-prompt", buffer: mode.buffer.slice(0, -1) };
        render();
        return;
      }
      // Printable characters only
      if (key.length === 1 && key >= " " && key < "\x7f") {
        mode = { kind: "invite-prompt", buffer: mode.buffer + key };
        render();
      }
      return;
    }

    // Confirm modal mode
    if (mode.kind === "confirm") {
      if (key === "y" || key === "Y") {
        await confirmAction(mode.action, mode.tokenId);
      } else if (key === "n" || key === "N" || key === "\x1b") {
        mode = { kind: "list" };
        render();
      }
      return;
    }

    // List mode
    if (key === "q") {
      cleanup();
      process.exit(0);
    } else if (key === "\x1b[A") {
      // Up
      moveSelection(-1);
    } else if (key === "\x1b[B") {
      // Down
      moveSelection(1);
    } else if (key === "\r" || key === "a") {
      await approveSelected();
    } else if (key === "r") {
      await revokeSelected();
    } else if (key === "i") {
      mode = { kind: "invite-prompt", buffer: "" };
      render();
    } else if (key === "R") {
      await reload();
      render();
    }
  });
}

/**
 * Label formatting — matches the pattern used in commands/clients.ts
 * but lives here too so the TUI doesn't have to import from commands/.
 */
function formatLabel(token: ClientToken): string {
  if (token.label) {
    return token.label.length > 30
      ? token.label.slice(0, 29) + "…"
      : token.label;
  }
  if (token.status === "pending" && token.pending_meta?.remote_addr) {
    return `(pending from ${token.pending_meta.remote_addr})`;
  }
  return "(unnamed)";
}

function summarizeUserAgent(ua: string): string {
  const platformMatch = ua.match(/\(([^)]+)\)/);
  const platform = platformMatch ? platformMatch[1].split(";")[0].trim() : null;

  let browser: string | null = null;
  if (/Edg\//.test(ua)) browser = "Edge";
  else if (/Chrome\//.test(ua) && !/Edg\//.test(ua)) browser = "Chrome";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/Safari\//.test(ua)) browser = "Safari";
  else if (/node/i.test(ua)) browser = "Node";

  if (browser && platform) return `${browser} on ${platform}`;
  if (browser) return browser;
  if (platform) return platform;
  return ua.length > 60 ? ua.slice(0, 57) + "..." : ua;
}

function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, "");
}

function padRight(
  str: string,
  width: number,
  visibleLen?: number
): string {
  // The input string may contain ANSI codes that don't take up visible
  // width. Caller provides the visible length for accurate padding.
  const len = visibleLen ?? stripAnsi(str).length;
  return len >= width ? str : str + " ".repeat(width - len);
}
