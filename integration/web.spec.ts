import { test, expect, type Page } from "@playwright/test";
import { Session } from "../../pty/src/testing/index.ts";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import * as net from "node:net";

const CLI_ENTRY = path.resolve(
  import.meta.dirname,
  "../src/cli.ts"
);

const PORT = 18200;

// ── Helpers ──

function waitForPort(port: number, timeout = 15000): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeout;
    function attempt() {
      const sock = net.createConnection(port, "127.0.0.1");
      sock.on("connect", () => {
        sock.destroy();
        resolve();
      });
      sock.on("error", () => {
        if (Date.now() > deadline) reject(new Error(`Port ${port} not open`));
        else setTimeout(attempt, 200);
      });
    }
    attempt();
  });
}

function extractTokenUrl(screen: { lines: string[]; text: string }): string {
  const joined = screen.lines.join(" ");
  const match = joined.match(
    /(http:\/\/localhost:\d+#[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/
  );
  if (!match) throw new Error(`No token URL in daemon output:\n${screen.text}`);
  return match[1];
}

function tokenWithSession(tokenUrl: string, session: string): string {
  const hashIdx = tokenUrl.indexOf("#");
  return `${tokenUrl.slice(0, hashIdx)}/${session}${tokenUrl.slice(hashIdx)}`;
}

async function waitForTerminalText(
  page: Page,
  text: string,
  timeout = 15000
): Promise<void> {
  await page.waitForFunction(
    (t) => {
      const el = document.querySelector("#terminal-container");
      return el?.textContent?.includes(t) ?? false;
    },
    text,
    { timeout }
  );
}

// ── Setup / Teardown ──

let serverSession: Session;
let ptySession: Session;
let stateDir: string;
let tokenUrl: string;
let baseToken: string;

const sessions: Session[] = [];
function track(s: Session): Session {
  sessions.push(s);
  return s;
}

test.beforeAll(async () => {
  // Use /tmp directly instead of os.tmpdir() because macOS resolves tmpdir
  // to /var/folders/... which is too long for Unix socket paths (104 char limit).
  stateDir = fs.mkdtempSync(path.join("/tmp", "pty-web-"));
  process.env.PTY_SESSION_DIR = stateDir;
  // Secret storage: fixed passphrase, fast KDF for tests
  process.env.PTY_RELAY_PASSPHRASE = "test-passphrase";
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";

  // Start a pty session
  ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
  track(ptySession);
  await ptySession.attach();
  await ptySession.waitForText("$", 5000);

  // Start self-hosted relay with spawn enabled
  serverSession = track(
    Session.spawn(
      "node",
      [
        CLI_ENTRY,
        "local",
        "start",
        String(PORT),
        "--config-dir",
        path.join(stateDir, "relay"),
        "--allow-new-sessions",
        "--skip-allow-new-sessions-confirmation",
        "--auto-approve",
      ],
      { rows: 24, cols: 200, env: { PTY_SESSION_DIR: stateDir } }
    )
  );

  const serverScreen = await serverSession.waitForText("Token URL", 15000);
  baseToken = extractTokenUrl(serverScreen);
  tokenUrl = tokenWithSession(baseToken, ptySession.name);
});

test.afterAll(async () => {
  for (const s of sessions) {
    try { await s.close(); } catch {}
  }
  if (stateDir) {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  }
});

// ── Tests ──

test.describe("web UI via self-hosted relay", () => {
  test("connects and shows terminal with bash prompt", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    await expect(page.locator("#terminal-view")).toBeVisible();
    await expect(page.locator("#status-overlay")).not.toBeVisible();
  });

  test("can type a command and see output", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    await page.locator("#terminal-container").click();
    await page.keyboard.type("echo web-e2e-test\n");

    await waitForTerminalText(page, "web-e2e-test");
  });

  test("shows session name in toolbar", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    const label = page.locator("#session-name-label");
    await expect(label).toHaveText(ptySession.name);
  });

  test("latency telemetry is OFF by default (no Stats button, no jsonl write)", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    // The toolbar widgets should be invisible — daemon was started
    // without --latency-stats, so the meta config says off.
    await expect(page.locator("#stats-btn")).toBeHidden();
    await expect(page.locator("#latency-stat")).toBeHidden();

    // Read the runtime config off the meta tag to confirm the daemon
    // injected the right value.
    const config = await page.evaluate(() => {
      const m = document.querySelector('meta[name="pty-relay-config"]');
      return m?.getAttribute("content");
    });
    expect(config).toContain('"latencyStats":false');
  });

  test("document.title reflects terminal OSC 2 title (and falls back to session name)", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    // Default after attach: tab title is the session name (no OSC seen yet).
    await expect.poll(() => page.title()).toBe(ptySession.name);

    // Emit OSC 2 to set the terminal window title — printf inside bash
    // is the cleanest way to send the escape sequence verbatim.
    await page.locator("#terminal-container").click();
    await page.keyboard.type(`printf '\\033]2;web-osc-title-test\\007'\n`);

    // xterm.js fires onTitleChange synchronously after parsing the
    // sequence, but the chain bash -> pty -> daemon -> ws -> xterm has
    // some latency; poll for the title change.
    await expect.poll(() => page.title(), { timeout: 5000 }).toBe(
      "web-osc-title-test"
    );

    // After detach the title should reset to the static app name so a
    // bookmarked tab doesn't keep claiming a session it isn't on.
    await page.locator("#detach-btn").click();
    await expect.poll(() => page.title(), { timeout: 5000 }).toBe("pty relay");
  });

  test("detach button returns to session list", async ({ page }) => {
    await page.goto(tokenUrl);
    await waitForTerminalText(page, "$");

    await page.locator("#detach-btn").click();

    await page.waitForFunction(() => {
      const el = document.getElementById("session-list");
      return el?.style.display === "flex";
    }, undefined, { timeout: 5000 });

    // After the TUI revamp, sessions render as `.session-row` rows
    // (the previous `.session-card` boxes are gone). Filter out the
    // "+ new session" CTA row by looking for `.col-name`, which only
    // real session rows carry.
    const rows = page.locator(".session-row:has(.col-name)");
    await expect(rows).not.toHaveCount(0);
  });
});

test.describe("session list via self-hosted relay", () => {
  test("shows session list when no session in URL path", async ({ page }) => {
    await page.goto(baseToken);

    await page.waitForFunction(() => {
      const el = document.getElementById("session-list");
      return el?.style.display === "flex";
    }, undefined, { timeout: 15000 });

    const rows = page.locator(".session-row:has(.col-name)");
    await expect(rows).not.toHaveCount(0);
  });

  test("clicking a session row opens terminal", async ({ page }) => {
    await page.goto(baseToken);

    await page.waitForFunction(() => {
      const el = document.getElementById("session-list");
      return el?.style.display === "flex";
    }, undefined, { timeout: 15000 });

    // Click a real session row (one with a name column — skips the
    // "+ new session" CTA which has only a single span).
    const row = page.locator(".session-row:has(.col-name)").first();
    await row.click();

    await expect(page.locator("#terminal-view")).toBeVisible();
    await expect(page.locator("#session-name-label")).not.toHaveText("");

    await page.locator("#terminal-container").click();
    await page.keyboard.type("echo session-list-test\n");
    await waitForTerminalText(page, "session-list-test");
  });
});

test.describe("spawn via self-hosted relay web UI", () => {
  test("New Session button spawns a session and opens terminal", async ({ page }) => {
    await page.goto(baseToken);

    await page.waitForFunction(() => {
      const el = document.getElementById("session-list");
      return el?.style.display === "flex";
    }, undefined, { timeout: 15000 });

    // The "+ new session" CTA is the only row with a .new-session-cta span.
    const newBtn = page.locator(".session-row .new-session-cta");
    await expect(newBtn).toContainText("new session");

    const spawnName = `web-spawn-${Date.now()}`;
    let dialogCount = 0;
    page.on("dialog", async (dialog) => {
      dialogCount++;
      if (dialogCount === 1) await dialog.accept(spawnName); // name
      else await dialog.accept("~"); // cwd
    });

    await newBtn.click();

    await expect(page.locator("#terminal-view")).toBeVisible({ timeout: 15000 });
    await waitForTerminalText(page, "$", 15000);

    await page.locator("#terminal-container").click();
    await page.keyboard.type("echo web-spawn-works\n");
    await waitForTerminalText(page, "web-spawn-works");
  });
});

test.describe("multi-client web via self-hosted relay", () => {
  test("two browser pages connect to same session simultaneously", async ({ browser }) => {
    const sessionToken = tokenWithSession(baseToken, ptySession.name);

    const page1 = await browser.newPage();
    const page2 = await browser.newPage();

    try {
      await page1.goto(sessionToken);
      await waitForTerminalText(page1, "$", 20000);

      await page2.goto(sessionToken);
      await waitForTerminalText(page2, "$", 20000);

      await page1.locator("#terminal-container").click();
      await page1.keyboard.type("echo multi-web-1\n");
      await waitForTerminalText(page1, "multi-web-1");

      await page2.locator("#terminal-container").click();
      await page2.keyboard.type("echo multi-web-2\n");
      await waitForTerminalText(page2, "multi-web-2");
    } finally {
      await page1.close();
      await page2.close();
    }
  });
});

test.describe("approval flow persists via localStorage (not URL)", () => {
  // Separate daemon without --auto-approve so we can exercise the approval
  // flow. We reuse the file-level `stateDir` (so pty sessions work) but
  // point the daemon at a fresh config dir inside it, since pty sessions
  // live in process.env.PTY_SESSION_DIR and we can't change that per-test.
  const APPROVAL_PORT = 18299;
  let approvalServer: Session;
  let approvalPtySession: Session;
  let approvalBaseToken: string;
  let approvalRelayDir: string;

  test.beforeAll(async () => {
    approvalRelayDir = path.join(stateDir, "approval-relay");

    approvalPtySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    await approvalPtySession.attach();
    await approvalPtySession.waitForText("$", 5000);

    approvalServer = Session.spawn(
      "node",
      [
        CLI_ENTRY,
        "local",
        "start",
        String(APPROVAL_PORT),
        "--config-dir",
        approvalRelayDir,
      ],
      { rows: 24, cols: 200, env: { PTY_SESSION_DIR: stateDir } }
    );
    const screen = await approvalServer.waitForText("Token URL", 15000);
    approvalBaseToken = extractTokenUrl(screen);
  });

  test.afterAll(async () => {
    try { await approvalServer?.close(); } catch {}
    try { await approvalPtySession?.close(); } catch {}
  });

  test("bookmark-safe: URL doesn't change after approval, localStorage holds the token, reload still works", async ({ page }) => {
    const baseSessionUrl = tokenWithSession(approvalBaseToken, approvalPtySession.name);

    // Step 1: navigate to the base URL (no client token in hash)
    await page.goto(baseSessionUrl);

    // Step 2: expect to see "waiting for approval" in the status overlay
    await page.waitForFunction(
      () => {
        const el = document.querySelector("#status-overlay");
        return el && !el.textContent?.toLowerCase().includes("connecting");
      },
      undefined,
      { timeout: 5000 }
    );

    // Capture the URL BEFORE approval — this is what we want bookmarks to use
    const urlBeforeApproval = page.url();
    expect(urlBeforeApproval).toBe(baseSessionUrl);
    // Fragment has exactly 2 parts (no client token appended)
    const hashBefore = new URL(urlBeforeApproval).hash;
    expect(hashBefore.split(".").length).toBe(2);

    // Step 3: approve via CLI
    const { spawnSync } = await import("node:child_process");
    // Find the pending token ID by listing clients
    const listResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "--config-dir", approvalRelayDir],
      {
        encoding: "utf-8",
        timeout: 10000,
        env: {
          ...process.env,
          PTY_SESSION_DIR: stateDir,
          PTY_RELAY_PASSPHRASE: "test-passphrase",
          PTY_RELAY_KDF_PROFILE: "interactive",
        },
      }
    );
    const pendingMatch = listResult.stdout.match(/^([a-f0-9]{8})\s+.*\s+pending/m);
    if (!pendingMatch) {
      throw new Error(
        `No pending token found.\nstdout: ${listResult.stdout}\nstderr: ${listResult.stderr}`
      );
    }
    const pendingId = pendingMatch[1];

    const approveResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", pendingId, "--config-dir", approvalRelayDir],
      {
        encoding: "utf-8",
        timeout: 10000,
        env: {
          ...process.env,
          PTY_SESSION_DIR: stateDir,
          PTY_RELAY_PASSPHRASE: "test-passphrase",
          PTY_RELAY_KDF_PROFILE: "interactive",
        },
      }
    );
    expect(approveResult.status).toBe(0);

    // Step 4: the terminal should come up
    await waitForTerminalText(page, "$", 20000);

    // Step 5: URL should NOT have been mutated by replaceState — the
    // client token must live in localStorage, not the address bar
    const urlAfterApproval = page.url();
    expect(urlAfterApproval).toBe(baseSessionUrl);
    const hashAfter = new URL(urlAfterApproval).hash;
    expect(hashAfter.split(".").length).toBe(2);

    // Step 6: localStorage should contain the client token
    const storedTokens = await page.evaluate(() => {
      return localStorage.getItem("pty-relay:client-tokens");
    });
    expect(storedTokens).not.toBeNull();
    const parsed = JSON.parse(storedTokens!);
    const values = Object.values(parsed) as string[];
    expect(values.length).toBeGreaterThan(0);
    expect(values[0]).toMatch(/^[a-f0-9]{24}$/); // 24-char hex token id

    // Step 7: reload the page with the SAME base URL — should auto-approve
    // using the localStorage token, no pending state, straight to terminal
    await page.reload();
    await waitForTerminalText(page, "$", 20000);
  });

  test("revoked token is cleaned from localStorage and browser re-enters approval queue", async ({ page }) => {
    const baseSessionUrl = tokenWithSession(approvalBaseToken, approvalPtySession.name);

    // First, get approved so we have a token in localStorage
    await page.goto(baseSessionUrl);

    const { spawnSync } = await import("node:child_process");
    const approveEnv = {
      ...process.env,
      PTY_SESSION_DIR: stateDir,
      PTY_RELAY_PASSPHRASE: "test-passphrase",
      PTY_RELAY_KDF_PROFILE: "interactive",
    };

    // Wait for the token to appear as pending then approve it
    let tokenId: string | null = null;
    for (let i = 0; i < 20; i++) {
      const list = spawnSync(
        "node",
        [CLI_ENTRY, "clients", "list", "--json", "--config-dir", approvalRelayDir],
        { encoding: "utf-8", timeout: 5000, env: approveEnv }
      );
      if (list.status === 0 && list.stdout) {
        try {
          const parsed = JSON.parse(list.stdout);
          const pending = parsed.tokens.find(
            (t: { status: string }) => t.status === "pending"
          );
          if (pending) {
            tokenId = pending.id;
            break;
          }
        } catch {}
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    expect(tokenId).not.toBeNull();

    const approveResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "approve",
        tokenId!.slice(0, 8),
        "--config-dir",
        approvalRelayDir,
      ],
      { encoding: "utf-8", timeout: 10000, env: approveEnv }
    );
    expect(approveResult.status).toBe(0);

    await waitForTerminalText(page, "$", 20000);

    // Sanity check: localStorage has the token
    const beforeRevoke = await page.evaluate(() =>
      localStorage.getItem("pty-relay:client-tokens")
    );
    expect(beforeRevoke).not.toBeNull();
    const beforeMap = JSON.parse(beforeRevoke!);
    expect(Object.keys(beforeMap).length).toBeGreaterThan(0);

    // Now revoke the token via CLI
    const revokeResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "revoke",
        tokenId!.slice(0, 8),
        "--config-dir",
        approvalRelayDir,
      ],
      { encoding: "utf-8", timeout: 10000, env: approveEnv }
    );
    expect(revokeResult.status).toBe(0);

    // Reload the page — with the revoked token in localStorage, the browser
    // will try it, get "token revoked", delete the localStorage entry,
    // and auto-reload. After the auto-reload it has no token and should
    // land in the pending/waiting-for-approval state.
    await page.reload();

    // Wait for either the approval-waiting state OR for localStorage to
    // have been cleared. The browser does a second reload on "token
    // revoked" so we need to wait through that.
    await page.waitForFunction(
      () => {
        const raw = localStorage.getItem("pty-relay:client-tokens");
        if (!raw) return true;
        const map = JSON.parse(raw);
        return Object.keys(map).length === 0;
      },
      undefined,
      { timeout: 10000 }
    );

    // And it should now be waiting for approval (a new pending entry
    // should exist in clients.json). Poll because the browser has to
    // finish its second reload → WebSocket connect → daemon writes
    // the pending entry before we can see it.
    let newPending: { id: string; status: string } | undefined;
    for (let i = 0; i < 30; i++) {
      const afterRevoke = spawnSync(
        "node",
        [CLI_ENTRY, "clients", "list", "--json", "--config-dir", approvalRelayDir],
        { encoding: "utf-8", timeout: 5000, env: approveEnv }
      );
      if (afterRevoke.status === 0 && afterRevoke.stdout) {
        try {
          const parsedAfter = JSON.parse(afterRevoke.stdout);
          newPending = parsedAfter.tokens.find(
            (t: { status: string; id: string }) =>
              t.status === "pending" && t.id !== tokenId
          );
          if (newPending) break;
        } catch {}
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    expect(newPending).toBeDefined();
  });
});

// ── Daemon-restart auto-reconnect ──
//
// The browser's reconnect loop should bring the page back automatically
// when the daemon process is restarted (same identity, same encrypted
// store, same listening port). The bug we're guarding against: the WS
// onclose handler used to require `handshakeComplete` to schedule a
// reconnect, but that flag is closure-local to each connectToRelay()
// call. So a reconnect attempt that itself failed (because the daemon
// was still booting) wouldn't schedule another retry.

test.describe("auto-reconnect after daemon restart", () => {
  // Use a separate daemon + pty session for this describe so we can
  // freely kill+respawn the daemon without disturbing the file-level
  // shared state used by the other test groups.
  const RECONNECT_PORT = 18298;
  let reconnectServer: Session;
  let reconnectPty: Session;
  let reconnectRelayDir: string;
  let reconnectBaseToken: string;

  function startDaemon(): Session {
    return Session.spawn(
      "node",
      [
        CLI_ENTRY,
        "local",
        "start",
        String(RECONNECT_PORT),
        "--config-dir",
        reconnectRelayDir,
        "--auto-approve",
      ],
      { rows: 24, cols: 200, env: { PTY_SESSION_DIR: stateDir } }
    );
  }

  test.beforeAll(async () => {
    reconnectRelayDir = path.join(stateDir, "reconnect-relay");

    reconnectPty = await Session.server("bash", [], { rows: 24, cols: 80 });
    await reconnectPty.attach();
    await reconnectPty.waitForText("$", 5000);

    reconnectServer = startDaemon();
    const screen = await reconnectServer.waitForText("Token URL", 15000);
    reconnectBaseToken = extractTokenUrl(screen);
  });

  test.afterAll(async () => {
    try { await reconnectServer?.close(); } catch {}
    try { await reconnectPty?.close(); } catch {}
  });

  test("browser reattaches to the session after the daemon restarts", async ({ page }) => {
    const sessionUrl = tokenWithSession(reconnectBaseToken, reconnectPty.name);

    // Phase 1: attach + verify we have a working terminal.
    await page.goto(sessionUrl);
    await waitForTerminalText(page, "$");
    await page.locator("#terminal-container").click();
    await page.keyboard.type("echo before-restart-marker\n");
    await waitForTerminalText(page, "before-restart-marker");

    // Phase 2: kill the daemon and start a fresh one against the same
    // config dir. Same encrypted store -> same Ed25519/Noise identity,
    // same secret_hash, so the browser's existing client_token + url
    // should pair against the new daemon transparently.
    await reconnectServer.close();
    // Brief gap so the kernel actually releases the port before we
    // re-bind. Also exercises the case where the browser's first
    // reconnect attempt fails because the daemon is still booting.
    await new Promise((r) => setTimeout(r, 1500));
    reconnectServer = startDaemon();
    await reconnectServer.waitForText("Primary control connection", 15000);

    // Phase 3: WITHOUT a manual page reload, the browser should auto
    // reconnect, finish the Noise handshake, re-attach to the session,
    // and respond to keystrokes again.
    //
    // We don't strictly need a long timeout — the reconnect schedule
    // starts at 1s and tops out at 10s; with a freshly-up daemon,
    // reattach typically lands within a few seconds.
    await page.locator("#terminal-container").click({ timeout: 30_000 });
    await page.keyboard.type("echo after-restart-marker\n");
    await waitForTerminalText(page, "after-restart-marker", 30_000);
  });
});
