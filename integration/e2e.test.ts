import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  CLI_ENTRY,
  Session,
  createTestContext,
  destroyTestContext,
  extractTokenUrl,
  tokenWithSession,
  track,
  getPort,
  type TestContext,
} from "./helpers/index.ts";
import { loadKnownHosts, saveKnownHost } from "../src/relay/known-hosts.ts";
import { loadClients, saveClients, findTokenById, generateTokenId, type ClientsData } from "../src/relay/clients.ts";
import { openSecretStore } from "../src/storage/bootstrap.ts";
import type { SecretStore } from "../src/storage/secret-store.ts";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

async function openStore(relayDir: string): Promise<SecretStore> {
  const { store } = await openSecretStore(relayDir, { interactive: false });
  return store;
}

async function waitForMarker(relayDir: string, timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const markerPath = path.join(relayDir, "storage.json");
  while (Date.now() < deadline) {
    if (fs.existsSync(markerPath)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`storage.json did not appear in ${relayDir}`);
}

let ctx: TestContext;
let originalSessionDir: string | undefined;

beforeEach(() => {
  ctx = createTestContext();
  originalSessionDir = process.env.PTY_SESSION_DIR;
  process.env.PTY_SESSION_DIR = ctx.stateDir;
});

afterEach(async () => {
  await destroyTestContext(ctx);
  if (originalSessionDir !== undefined) {
    process.env.PTY_SESSION_DIR = originalSessionDir;
  } else {
    delete process.env.PTY_SESSION_DIR;
  }
});

describe("basic connectivity via self-hosted relay", () => {
  it("client can connect through the relay and see terminal output", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start self-hosted relay
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect a CLI client
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("$", 15000);
    client.sendKeys("echo hello-from-relay\n");
    await client.waitForText("hello-from-relay", 5000);
  }, 60000);
});

describe("spawn via self-hosted relay", () => {
  it("client can spawn a new session with --allow-new-sessions", async () => {
    const port = getPort();

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--allow-new-sessions",
          "--skip-allow-new-sessions-confirmation",
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("--allow-new-sessions is enabled", 15000);
    const serverScreen = await server.waitForText("Token URL", 15000);
    const baseToken = extractTokenUrl(serverScreen);

    const sessionName = `spawn-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", baseToken, "--spawn", sessionName],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);
    client.sendKeys("echo spawn-works\n");
    await client.waitForText("spawn-works", 5000);
    await server.waitForText(
      `Spawned and bridging session "${sessionName}"`,
      5000
    );
  }, 60000);

  it("spawn is rejected when --allow-new-sessions is not set", async () => {
    const port = getPort();

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", baseToken, "--spawn", "should-fail"],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("not enabled", 15000);
  }, 60000);

  it("spawn with --cwd starts in the specified directory", async () => {
    const port = getPort();

    // Remote-spawn cwd is constrained to $HOME. Point the daemon's HOME at
    // a temp dir so the test can place a real subdirectory under it.
    const fakeHome = fs.mkdtempSync(path.join("/tmp", "home-cwd-"));
    const targetDir = path.join(fakeHome, "workdir");
    fs.mkdirSync(targetDir);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--allow-new-sessions",
          "--skip-allow-new-sessions-confirmation",
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir, HOME: fakeHome } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const sessionName = `cwd-test-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "connect",
          baseToken,
          "--spawn",
          sessionName,
          "--cwd",
          targetDir,
        ],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);
    client.sendKeys("pwd\n");
    await client.waitForText("workdir", 5000);

    fs.rmSync(fakeHome, { recursive: true, force: true });
  }, 60000);
});

describe("multi-client via self-hosted relay", () => {
  it("two CLI clients connect to different sessions simultaneously", async () => {
    const port = getPort();

    // Start two pty sessions
    const ptySession1 = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession1);
    await ptySession1.attach();
    await ptySession1.waitForText("$", 5000);

    const ptySession2 = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession2);
    await ptySession2.attach();
    await ptySession2.waitForText("$", 5000);

    // Start self-hosted relay
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const token1 = tokenWithSession(baseToken, ptySession1.name);
    const token2 = tokenWithSession(baseToken, ptySession2.name);

    // Connect two clients simultaneously
    const client1 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token1], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    const client2 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token2], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Both should get a shell prompt
    await client1.waitForText("$", 15000);
    await client2.waitForText("$", 15000);

    // Both can type commands independently
    client1.sendKeys("echo multi-client-1\n");
    await client1.waitForText("multi-client-1", 5000);

    client2.sendKeys("echo multi-client-2\n");
    await client2.waitForText("multi-client-2", 5000);
  }, 60000);

  it("one client disconnects, other is unaffected", async () => {
    const port = getPort();

    // Start two pty sessions
    const ptySession1 = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession1);
    await ptySession1.attach();
    await ptySession1.waitForText("$", 5000);

    const ptySession2 = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession2);
    await ptySession2.attach();
    await ptySession2.waitForText("$", 5000);

    // Start self-hosted relay
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const token1 = tokenWithSession(baseToken, ptySession1.name);
    const token2 = tokenWithSession(baseToken, ptySession2.name);

    const client1 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token1], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    const client2 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token2], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client1.waitForText("$", 15000);
    await client2.waitForText("$", 15000);

    // Verify both work
    client1.sendKeys("echo alive-1\n");
    await client1.waitForText("alive-1", 5000);

    client2.sendKeys("echo alive-2\n");
    await client2.waitForText("alive-2", 5000);

    // Disconnect client1
    await client1.close();

    // Wait a moment for cleanup
    await new Promise((r) => setTimeout(r, 1000));

    // client2 should still be fully functional
    client2.sendKeys("echo still-working\n");
    await client2.waitForText("still-working", 5000);
  }, 60000);
});

describe("session list via self-hosted relay", () => {
  it("listRemoteSessions returns sessions from the relay", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const { listRemoteSessions } = await import(
      "../src/relay/relay-client.ts"
    );
    const result = await listRemoteSessions(baseToken);

    expect(result.sessions.length).toBeGreaterThanOrEqual(1);
    const found = result.sessions.find((s) => s.name === ptySession.name);
    expect(found).toBeDefined();
    expect(found!.status).toBe("running");
  }, 60000);

  it("ls command prints sessions for known hosts", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const relayDir = path.join(ctx.stateDir, "relay");
    // Wait until the daemon has created the marker file; then we can safely
    // open the same store and seed a known host.
    await waitForMarker(relayDir);
    const hostStore = await openStore(relayDir);
    await saveKnownHost("test-host", baseToken, hostStore);

    const lsSession = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "ls", "--config-dir", relayDir],
        { rows: 24, cols: 120, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await lsSession.waitForText("test-host", 15000);
    await lsSession.waitForText(ptySession.name, 5000);
  }, 60000);
});

describe("ls --json spawn_enabled field", () => {
  it("spawn_enabled is false when relay has no --allow-new-sessions", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Seed a known host so ls can find it
    await waitForMarker(relayDir);
    const hostStore = await openStore(relayDir);
    await saveKnownHost("test-host", baseToken, hostStore);

    const lsResult = spawnSync(
      "node",
      [CLI_ENTRY, "ls", "--json", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(lsResult.status).toBe(0);

    const parsed = JSON.parse(lsResult.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].spawn_enabled).toBe(false);
    expect(parsed[0].sessions.length).toBeGreaterThanOrEqual(1);
    expect(parsed[0].error).toBeNull();
  }, 60000);

  it("spawn_enabled is true when relay has --allow-new-sessions", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--allow-new-sessions",
          "--skip-allow-new-sessions-confirmation",
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Seed a known host so ls can find it
    await waitForMarker(relayDir);
    const hostStore = await openStore(relayDir);
    await saveKnownHost("test-host", baseToken, hostStore);

    const lsResult = spawnSync(
      "node",
      [CLI_ENTRY, "ls", "--json", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(lsResult.status).toBe(0);

    const parsed = JSON.parse(lsResult.stdout);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(1);
    expect(parsed[0].spawn_enabled).toBe(true);
    expect(parsed[0].sessions.length).toBeGreaterThanOrEqual(1);
    expect(parsed[0].error).toBeNull();
  }, 60000);
});

describe("forget command", () => {
  it("removes a known host by label", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Seed two known hosts
    await waitForMarker(relayDir);
    const hostStore = await openStore(relayDir);
    await saveKnownHost("host-a", baseToken, hostStore);
    await saveKnownHost("host-b", "http://localhost:99999#fake.fake", hostStore);

    // Verify both exist
    const hostsBefore = await loadKnownHosts(hostStore);
    expect(hostsBefore.length).toBe(2);

    // Forget host-a
    const forgetResult = spawnSync(
      "node",
      [CLI_ENTRY, "forget", "host-a", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(forgetResult.status).toBe(0);
    expect(forgetResult.stdout).toContain("host-a");

    // Verify host-a is gone, host-b remains
    const hostsAfter = await loadKnownHosts(await openStore(relayDir));
    expect(hostsAfter.length).toBe(1);
    expect(hostsAfter[0].label).toBe("host-b");
  }, 60000);

  it("exits with error for unknown label", () => {
    const relayDir = path.join(ctx.stateDir, "relay-forget");
    fs.mkdirSync(relayDir, { recursive: true });

    // Initialize a store so the command can open it
    const initResult = spawnSync(
      "node",
      [CLI_ENTRY, "init", "--backend", "passphrase", "--config-dir", relayDir, "--force"],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(initResult.status).toBe(0);

    const forgetResult = spawnSync(
      "node",
      [CLI_ENTRY, "forget", "nonexistent-host", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(forgetResult.status).not.toBe(0);
    const output = (forgetResult.stdout || "") + (forgetResult.stderr || "");
    expect(output).toContain("nonexistent-host");
  }, 60000);
});

describe("doctor command", () => {
  it("prints diagnostic info without errors", () => {
    const relayDir = path.join(ctx.stateDir, "relay-doctor");

    const result = spawnSync(
      "node",
      [CLI_ENTRY, "doctor", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("pty-relay doctor");
    expect(result.stdout).toContain("Environment:");
    expect(result.stdout).toContain("node:");
    expect(result.stdout).toContain("platform:");
    expect(result.stdout).toContain("Secret storage:");
    expect(result.stdout).toContain("Config files:");
    expect(result.stdout).toContain("Environment variables:");
    expect(result.stdout).toContain("Daemon:");
  }, 60000);

  it("shows backend info for initialized config dir", () => {
    const relayDir = path.join(ctx.stateDir, "relay-doctor-init");

    // Initialize a store
    const initResult = spawnSync(
      "node",
      [CLI_ENTRY, "init", "--backend", "passphrase", "--config-dir", relayDir, "--force"],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(initResult.status).toBe(0);

    const result = spawnSync(
      "node",
      [CLI_ENTRY, "doctor", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("backend:     passphrase");
    expect(result.stdout).toContain("exists:      yes");
    expect(result.stdout).toContain("storage.json");
  }, 60000);
});

describe("version command", () => {
  it("prints version string", () => {
    const result = spawnSync(
      "node",
      [CLI_ENTRY, "--version"],
      { encoding: "utf-8", timeout: 5000 }
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^pty-relay \d+\.\d+\.\d+/);
  });

  it("'version' subcommand also works", () => {
    const result = spawnSync(
      "node",
      [CLI_ENTRY, "version"],
      { encoding: "utf-8", timeout: 5000 }
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^pty-relay \d+\.\d+\.\d+/);
  });
});

describe("clean stdin after detach", () => {
  it("Ctrl+\\ detaches cleanly with [detached] message and no garbage output", async () => {
    const port = getPort();

    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect via CLI
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("$", 15000);

    // Type a command so we know the session is working
    client.sendKeys("echo detach-test-ok\n");
    await client.waitForText("detach-test-ok", 5000);

    // Send Ctrl+\ to detach (byte 0x1c)
    client.sendKeys("\x1c");

    // Should show [detached] message
    await client.waitForText("[detached]", 5000);

    // Capture the final screen and verify no garbage characters
    const finalScreen = client.screenshot();
    // The screen should contain [detached] and NOT contain [[]] or other
    // raw escape artifacts that indicate stdin corruption
    expect(finalScreen.text).toContain("[detached]");
    expect(finalScreen.text).not.toContain("[[]]");
    expect(finalScreen.text).not.toContain("[[]");
  }, 60000);
});

describe("known hosts", () => {
  it("connect saves the host to known-hosts file", async () => {
    const port = getPort();

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--allow-new-sessions",
          "--skip-allow-new-sessions-confirmation",
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    const sessionName = `save-test-${Date.now()}`;
    const client = track(
      ctx,
      Session.spawn(
        "node",
        [CLI_ENTRY, "connect", baseToken, "--spawn", sessionName],
        { rows: 24, cols: 80, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await client.waitForText("$", 30000);

    const hostStore = await openStore(path.join(ctx.stateDir, "relay"));
    const hosts = await loadKnownHosts(hostStore);
    expect(hosts.length).toBe(1);
    expect(hosts[0].url).toContain("localhost");
  }, 60000);
});

describe("client approval", () => {
  it("--auto-approve bypasses approval", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITH --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect without any client token — should work immediately
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("$", 15000);
    client.sendKeys("echo auto-approve-works\n");
    await client.waitForText("auto-approve-works", 5000);
  }, 60000);

  it("client without token is held pending", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect without a client token
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Should show "Waiting for operator approval..."
    await client.waitForText("Waiting for operator approval", 15000);

    // Server should show pending approval message
    await server.waitForText("pending approval", 5000);

    // clients.json should have a pending entry
    const clientsStore = await openStore(relayDir);
    const data = await loadClients(clientsStore);
    const pending = data.tokens.filter((t) => t.status === "pending");
    expect(pending.length).toBe(1);

    // The pending entry should include network metadata captured at
    // connect time, so the operator can identify the client before it
    // has sent a hello message.
    const pendingEntry = pending[0];
    expect(pendingEntry.pending_meta).toBeDefined();
    // The CLI client connects to localhost, so remote_addr should look
    // like 127.0.0.1 or ::1 or ::ffff:127.0.0.1.
    expect(pendingEntry.pending_meta!.remote_addr).toBeTruthy();
    expect(pendingEntry.pending_meta!.remote_addr).toMatch(
      /^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/
    );

    // The CLI client does not set a User-Agent header via the ws
    // library by default, so user_agent may be null — don't assert
    // on it, but if present it shouldn't be empty.
    if (pendingEntry.pending_meta!.user_agent) {
      expect(pendingEntry.pending_meta!.user_agent.length).toBeGreaterThan(0);
    }

    // Running `pty-relay clients` should print metadata under the
    // pending row (from: <ip>).
    const listResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(listResult.status).toBe(0);
    expect(listResult.stdout).toContain("pending");
    expect(listResult.stdout).toMatch(/from:\s+(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)/);
  }, 60000);

  it("CLI approve connects pending client", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect without a client token — will be held pending
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("Waiting for operator approval", 15000);

    // Get the pending token ID
    const clientsStore = await openStore(relayDir);
    const data = await loadClients(clientsStore);
    const pending = data.tokens.find((t) => t.status === "pending");
    expect(pending).toBeDefined();
    const tokenIdPrefix = pending!.id.slice(0, 8);

    // Run CLI approve
    const approveResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", tokenIdPrefix, "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approveResult.status).toBe(0);

    // Client should now connect and get a shell prompt
    await client.waitForText("$", 20000);
    client.sendKeys("echo approval-works\n");
    await client.waitForText("approval-works", 5000);

    // The client sent a hello message after approval; the token's label
    // should have been backfilled from it (e.g. "Silber.local (cli)").
    // Give it a moment to persist.
    await new Promise((r) => setTimeout(r, 500));
    const afterData = await loadClients(await openStore(relayDir));
    const backfilled = afterData.tokens.find((t) => t.id === pending!.id);
    expect(backfilled).toBeDefined();
    expect(backfilled!.label).not.toBeNull();
    expect(backfilled!.label).toMatch(/\(cli\)$/);
  }, 60000);

  it("pre-auth invite provides immediate access", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const relayDir = path.join(ctx.stateDir, "relay");

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Create an invite token via CLI
    const inviteResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "invite", "--label", "test-invite", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Extract the token ID from clients.json
    const clientsStore = await openStore(relayDir);
    const data = await loadClients(clientsStore);
    const active = data.tokens.find((t) => t.status === "active" && t.label === "test-invite");
    expect(active).toBeDefined();

    // Build a URL with the client token appended
    const inviteToken = tokenWithSession(baseToken, ptySession.name);
    // Append the client token to the fragment
    const inviteUrl = inviteToken + "." + active!.id;

    // Connect with the invite URL — should auto-approve
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", inviteUrl], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("$", 15000);
    client.sendKeys("echo invite-works\n");
    await client.waitForText("invite-works", 5000);
  }, 60000);

  it("revoked token is rejected", async () => {
    const port = getPort();

    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Create an active token, then revoke it
    const inviteResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "invite", "--label", "revoke-test", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    const clientsStore = await openStore(relayDir);
    const data = await loadClients(clientsStore);
    const active = data.tokens.find((t) => t.status === "active" && t.label === "revoke-test");
    expect(active).toBeDefined();

    // Revoke it
    const revokeResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "revoke", active!.id.slice(0, 8), "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(revokeResult.status).toBe(0);

    // Connect with the revoked token
    const revokedUrl = tokenWithSession(baseToken, ptySession.name) + "." + active!.id;

    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", revokedUrl], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Should be rejected with "token revoked" error
    await client.waitForText("token revoked", 15000);
  }, 60000);

  it("'clients list' prints the static table", async () => {
    const relayDir = path.join(ctx.stateDir, "relay");

    // Seed: create an invite token via the existing CLI
    const inviteResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "list-test",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Run `clients list` (explicit subcommand — should always produce
    // the static table, even if stdout were a TTY)
    const listResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "list", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(listResult.status).toBe(0);
    expect(listResult.stdout).toContain("ID");
    expect(listResult.stdout).toContain("LABEL");
    expect(listResult.stdout).toContain("STATUS");
    expect(listResult.stdout).toContain("list-test");
    expect(listResult.stdout).toContain("active");
  }, 60000);

  it("'clients list --json' outputs valid JSON with full tokens", async () => {
    const relayDir = path.join(ctx.stateDir, "relay");

    // Seed: create an invite token
    const inviteResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "json-test",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Run `clients list --json`
    const listResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "list",
        "--json",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(listResult.status).toBe(0);

    // Must parse as valid JSON
    const parsed = JSON.parse(listResult.stdout);
    expect(parsed.tokens).toBeDefined();
    expect(Array.isArray(parsed.tokens)).toBe(true);

    // Should include our invite
    const invite = parsed.tokens.find(
      (t: { label: string | null }) => t.label === "json-test"
    );
    expect(invite).toBeDefined();
    expect(invite.status).toBe("active");
    expect(invite.id).toMatch(/^[a-f0-9]{24}$/); // full 24-char hex
    expect(invite.created).toBeTruthy();
  }, 60000);

  it("'clients' with no subcommand falls back to list in non-TTY", async () => {
    const relayDir = path.join(ctx.stateDir, "relay");

    // Create a token first
    const inviteResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "fallback-test",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Bare `pty-relay clients` under spawnSync (no TTY) should fall
    // back to the static list, not launch the TUI (which would hang).
    const bareResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(bareResult.status).toBe(0);
    expect(bareResult.stdout).toContain("fallback-test");
    expect(bareResult.stdout).toContain("active");
  }, 60000);
});

describe("credentials at rest", () => {
  it("files on disk are encrypted (no plaintext secrets visible)", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Start a pty session and connect a client so clients.json gets created
    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const token = tokenWithSession(baseToken, ptySession.name);
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );
    await client.waitForText("$", 15000);

    // Wait until clients.json has been written (server stores the client
    // session meta even under --auto-approve via any code that opens the
    // tracker). If no clients file exists, we'll only check config.json and
    // hosts.
    await new Promise((r) => setTimeout(r, 500));

    const configPath = path.join(relayDir, "config.json");
    const hostsPath = path.join(relayDir, "hosts");

    expect(fs.existsSync(configPath)).toBe(true);
    const configRaw = fs.readFileSync(configPath, "utf-8");
    // Envelope format marker
    expect(configRaw).toContain('"ct"');
    // Must not contain any of the base64 key strings the token URL embeds
    const tokenHashMatch = baseToken.match(/#([^.]+)\.([^/]+)/);
    expect(tokenHashMatch).not.toBeNull();
    const publicKeyB64Url = tokenHashMatch![1];
    expect(configRaw).not.toContain(publicKeyB64Url);
    // Must not contain common JSON fieldnames used in the plaintext config
    expect(configRaw).not.toContain('"publicKey"');
    expect(configRaw).not.toContain('"signSecretKey"');

    // The known-hosts file (from the connect call) should also be encrypted
    // and must not contain the literal baseToken
    if (fs.existsSync(hostsPath)) {
      const hostsRaw = fs.readFileSync(hostsPath, "utf-8");
      expect(hostsRaw).toContain('"ct"');
      expect(hostsRaw).not.toContain(publicKeyB64Url);
      expect(hostsRaw).not.toContain('"label"');
    }
  }, 60000);

  it("passphrase mismatch fails at startup", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // First daemon with the default passphrase creates the marker
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );
    await server.waitForText("Token URL", 15000);
    await server.close();

    // Attempt to `clients approve` with the wrong passphrase — must error
    const wrongResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", "deadbeef", "--config-dir", relayDir],
      {
        encoding: "utf-8",
        timeout: 10000,
        env: {
          ...process.env,
          PTY_SESSION_DIR: ctx.stateDir,
          PTY_RELAY_PASSPHRASE: "totally-different-passphrase",
        },
      }
    );

    expect(wrongResult.status).not.toBe(0);
    const combined = (wrongResult.stdout || "") + (wrongResult.stderr || "");
    expect(combined).toMatch(/decrypt|passphrase/i);
  }, 60000);
});

/**
 * Probe whether the OS keychain is functional here. We gate the keychain
 * e2e test on this so it doesn't fail on headless Linux CI without a
 * running Secret Service.
 */
async function probeKeychainForE2E(): Promise<boolean> {
  const { KeychainStore } = await import("../src/storage/keychain-store.ts");
  const probeDir = fs.mkdtempSync(path.join("/tmp", "e2e-kc-probe-"));
  try {
    const store = await KeychainStore.tryOpen(probeDir);
    if (!store) return false;
    try {
      await store.save("config", new TextEncoder().encode("probe"));
      const out = await store.load("config");
      const ok = !!out && new TextDecoder().decode(out) === "probe";
      await store.destroyAll();
      return ok;
    } catch {
      return false;
    }
  } catch {
    return false;
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
}

const keychainE2EAvailable = await probeKeychainForE2E();

describe.skipIf(!keychainE2EAvailable)("credentials at rest — keychain backend", () => {
  it("serve and connect work end-to-end with the keychain backend", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay-kc");

    // Important: override the integration setup env to actually use keychain.
    const kcEnv: Record<string, string> = {
      PTY_SESSION_DIR: ctx.stateDir,
      PTY_RELAY_BACKEND: "keychain",
    };
    // Explicitly remove the global passphrase so the daemon can't fall
    // back to passphrase mode if keychain fails (we want to catch regressions).
    delete kcEnv.PTY_RELAY_PASSPHRASE;

    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: kcEnv }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Start a pty session
    const ptySession = await Session.server("bash", [], { rows: 24, cols: 80 });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    const token = tokenWithSession(baseToken, ptySession.name);
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: kcEnv,
      })
    );
    await client.waitForText("$", 15000);
    client.sendKeys("echo keychain-ok\n");
    await client.waitForText("keychain-ok", 5000);

    // Verify marker file says keychain
    const markerPath = path.join(relayDir, "storage.json");
    expect(fs.existsSync(markerPath)).toBe(true);
    const marker = JSON.parse(fs.readFileSync(markerPath, "utf-8"));
    expect(marker.backend).toBe("keychain");
    expect(marker.salt).toBeUndefined();

    // Keychain-backed config dir should have marker files (.keychain suffix)
    // for each stored secret, NOT envelope JSON files.
    const configMarker = path.join(relayDir, "config.json.keychain");
    expect(fs.existsSync(configMarker)).toBe(true);
    // The marker file must not contain any plaintext secrets.
    const markerContent = fs.readFileSync(configMarker, "utf-8");
    const tokenHashMatch = baseToken.match(/#([^.]+)\.([^/]+)/);
    expect(tokenHashMatch).not.toBeNull();
    const publicKeyB64Url = tokenHashMatch![1];
    expect(markerContent).not.toContain(publicKeyB64Url);

    // Clean up keychain entries we just created so we don't leave
    // garbage in the developer's real keychain.
    const { KeychainStore } = await import("../src/storage/keychain-store.ts");
    const cleanupStore = await KeychainStore.tryOpen(relayDir);
    if (cleanupStore) {
      await cleanupStore.destroyAll();
    }
  }, 60000);
});

describe("reset command", () => {
  // All reset tests MUST use `--config-dir` pointing at a temp dir under
  // ctx.stateDir. Never let reset run against the default path — it
  // would delete the developer's real credentials.
  let ctx: TestContext;

  beforeEach(() => {
    ctx = createTestContext();
  });

  afterEach(async () => {
    await destroyTestContext(ctx);
  });

  it("is a no-op when the config dir does not exist", () => {
    const nonexistent = path.join(ctx.stateDir, "nothing-here");
    const result = spawnSync(
      "node",
      [CLI_ENTRY, "reset", "--force", "--config-dir", nonexistent],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(result.status).toBe(0);
    expect((result.stdout || "") + (result.stderr || "")).toMatch(
      /nothing to reset/i
    );
    // And the dir was not created
    expect(fs.existsSync(nonexistent)).toBe(false);
  });

  it("refuses to run without --force in non-TTY mode", () => {
    const relayDir = path.join(ctx.stateDir, "reset-no-force");
    fs.mkdirSync(relayDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(relayDir, "marker"), "something", { mode: 0o600 });

    const result = spawnSync(
      "node",
      [CLI_ENTRY, "reset", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(result.status).not.toBe(0);
    expect((result.stdout || "") + (result.stderr || "")).toMatch(/--force/i);

    // Crucially, the file was NOT deleted
    expect(fs.existsSync(path.join(relayDir, "marker"))).toBe(true);
  });

  it("wipes every file in the passphrase-backed config dir", async () => {
    const relayDir = path.join(ctx.stateDir, "reset-passphrase");

    // Use the init command to create a passphrase-backed config dir
    // (matches how a real user would set it up).
    const initResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "init",
        "--backend",
        "passphrase",
        "--config-dir",
        relayDir,
        "--force",
      ],
      {
        encoding: "utf-8",
        timeout: 15000,
      }
    );
    expect(initResult.status).toBe(0);

    // Seed some actual data by using the invite command. This exercises
    // the store end-to-end: writes config.json and clients.json files.
    const inviteResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "reset-target",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Confirm files exist before reset
    const filesBefore = fs.readdirSync(relayDir);
    expect(filesBefore).toContain("storage.json");
    expect(filesBefore.some((f) => f === "config.json")).toBe(true);
    expect(filesBefore.some((f) => f === "clients.json")).toBe(true);

    // Run reset --force
    const resetResult = spawnSync(
      "node",
      [CLI_ENTRY, "reset", "--force", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(resetResult.status).toBe(0);
    expect(resetResult.stdout).toMatch(/Reset: removed/i);

    // All files should be gone
    const filesAfter = fs.readdirSync(relayDir);
    expect(filesAfter).toEqual([]);
  });

  it("re-init after reset works (fresh state, new keys)", async () => {
    const relayDir = path.join(ctx.stateDir, "reset-reinit");

    // First init
    const firstInit = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "init",
        "--backend",
        "passphrase",
        "--config-dir",
        relayDir,
        "--force",
      ],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(firstInit.status).toBe(0);

    // Ensure a config file gets written
    const firstInvite = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "first",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(firstInvite.status).toBe(0);

    // Capture the first config's bytes so we can confirm re-init generates
    // a different one
    const firstConfigBytes = fs.readFileSync(
      path.join(relayDir, "config.json")
    );

    // Reset
    const resetResult = spawnSync(
      "node",
      [CLI_ENTRY, "reset", "--force", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(resetResult.status).toBe(0);

    // Re-init
    const secondInit = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "init",
        "--backend",
        "passphrase",
        "--config-dir",
        relayDir,
        "--force",
      ],
      { encoding: "utf-8", timeout: 15000 }
    );
    expect(secondInit.status).toBe(0);

    // Seed another config
    const secondInvite = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "second",
        "--config-dir",
        relayDir,
      ],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(secondInvite.status).toBe(0);

    // Config bytes should differ — new random keys
    const secondConfigBytes = fs.readFileSync(
      path.join(relayDir, "config.json")
    );
    expect(secondConfigBytes.equals(firstConfigBytes)).toBe(false);

    // The new `clients.json` should contain "second" and NOT "first"
    // (since reset wiped it)
    const listResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "list", "--json", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(listResult.status).toBe(0);
    const parsed = JSON.parse(listResult.stdout);
    const labels = (parsed.tokens as Array<{ label: string | null }>)
      .map((t) => t.label)
      .filter((l): l is string => l !== null);
    expect(labels).toContain("second");
    expect(labels).not.toContain("first");
  });
});

/**
 * Reset + keychain: gated on the OS keychain actually working so we
 * don't skip on headless CI. Cleans up its own keychain entries.
 */
const keychainResetAvailable = await (async () => {
  const { KeychainStore } = await import("../src/storage/keychain-store.ts");
  const probeDir = fs.mkdtempSync(path.join("/tmp", "reset-kc-probe-"));
  try {
    const store = await KeychainStore.tryOpen(probeDir);
    if (!store) return false;
    try {
      await store.save("config", new TextEncoder().encode("probe"));
      const out = await store.load("config");
      const ok = !!out && new TextDecoder().decode(out) === "probe";
      await store.destroyAll();
      return ok;
    } catch {
      return false;
    }
  } catch {
    return false;
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();

describe.skipIf(!keychainResetAvailable)("reset command — keychain backend", () => {
  let ctx: TestContext;

  beforeEach(() => {
    ctx = createTestContext();
  });

  afterEach(async () => {
    await destroyTestContext(ctx);
  });

  it("wipes keychain entries and config dir files", async () => {
    const relayDir = path.join(ctx.stateDir, "reset-keychain");

    // Init with keychain backend. Override PTY_RELAY_BACKEND for this
    // spawned process so it actually uses the keychain (the default
    // integration setup forces passphrase).
    const initResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "init",
        "--backend",
        "keychain",
        "--config-dir",
        relayDir,
        "--force",
      ],
      {
        encoding: "utf-8",
        timeout: 15000,
        env: {
          ...process.env,
          PTY_RELAY_BACKEND: "keychain",
          // Drop the shared passphrase so it doesn't accidentally
          // fall back to passphrase backend.
          PTY_RELAY_PASSPHRASE: "",
        },
      }
    );
    expect(initResult.status).toBe(0);

    // Marker should say keychain
    const marker = JSON.parse(
      fs.readFileSync(path.join(relayDir, "storage.json"), "utf-8")
    );
    expect(marker.backend).toBe("keychain");

    // Store some data through the keychain backend
    const inviteResult = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "clients",
        "invite",
        "--label",
        "kc-reset",
        "--config-dir",
        relayDir,
      ],
      {
        encoding: "utf-8",
        timeout: 10000,
        env: {
          ...process.env,
          PTY_RELAY_BACKEND: "keychain",
          PTY_RELAY_PASSPHRASE: "",
        },
      }
    );
    expect(inviteResult.status).toBe(0);

    // Confirm we can read it back through the keychain
    const { KeychainStore } = await import("../src/storage/keychain-store.ts");
    const probeBefore = await KeychainStore.tryOpen(relayDir);
    expect(probeBefore).not.toBeNull();
    const clientsBefore = await probeBefore!.load("clients");
    expect(clientsBefore).not.toBeNull();

    // Reset
    const resetResult = spawnSync(
      "node",
      [CLI_ENTRY, "reset", "--force", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(resetResult.status).toBe(0);

    // Files gone
    expect(fs.readdirSync(relayDir)).toEqual([]);

    // And critically: keychain entries gone too. A fresh KeychainStore
    // pointed at the same config dir should load `null` for "clients".
    const probeAfter = await KeychainStore.tryOpen(relayDir);
    // probeAfter may be non-null (tryOpen succeeds even with no data)
    // but loading should return null since destroyAll cleared the
    // master key AND the per-name entries.
    if (probeAfter) {
      expect(await probeAfter.load("clients")).toBeNull();
      expect(await probeAfter.load("config")).toBeNull();
      // Clean up any probe-created entries
      try { await probeAfter.destroyAll(); } catch {}
    }
  }, 60000);
});

// ---------------------------------------------------------------------------
// Real user flows (no --auto-approve)
//
// These tests exercise the full approval lifecycle WITHOUT --auto-approve.
// They catch bugs that the rest of the suite (which always uses --auto-approve)
// cannot detect:
//   - Re-exec after session picker losing the client token (double approval)
//   - Interactive TUI not sending client tokens when listing sessions
//   - Known-hosts getting duplicate entries for the same host
// ---------------------------------------------------------------------------

describe("real user flows (no auto-approve)", () => {
  // Flow 1: Connect with session in URL -> get approved -> works
  it("connect with session URL, get approved, type a command, verify known-hosts", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect without a client token (session IS in the URL)
    const clientConfigDir = path.join(ctx.stateDir, "client-config");
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Client should show "Waiting for operator approval..."
    await client.waitForText("Waiting for operator approval", 15000);

    // Get the pending token ID from the relay store
    const relayStore = await openStore(relayDir);
    const data = await loadClients(relayStore);
    const pending = data.tokens.find((t) => t.status === "pending");
    expect(pending).toBeDefined();
    const tokenIdPrefix = pending!.id.slice(0, 8);

    // Approve via CLI
    const approveResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", tokenIdPrefix, "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approveResult.status).toBe(0);

    // Client should now connect and get a shell prompt
    await client.waitForText("$", 20000);

    // Type a command and verify output
    client.sendKeys("echo flow1-approved\n");
    await client.waitForText("flow1-approved", 5000);

    // Wait for the known-hosts file to be written
    await new Promise((r) => setTimeout(r, 1000));

    // Verify known-hosts was updated with the client token
    const clientStore = await openStore(clientConfigDir);
    const hosts = await loadKnownHosts(clientStore);
    expect(hosts.length).toBe(1);
    expect(hosts[0].url).toContain("localhost");
    // The saved URL should contain the client token (third segment in the fragment)
    const savedFragment = hosts[0].url.split("#")[1];
    expect(savedFragment).toBeDefined();
    const fragmentParts = savedFragment!.split(".");
    // Fragment should be: publicKey.secret.clientToken (3 parts = has client token)
    expect(fragmentParts.length).toBe(3);
    expect(fragmentParts[2].length).toBeGreaterThan(0);
  }, 60000);

  // Flow 2: Connect without session -> get approved -> session picker -> auto-attach
  it("connect without session URL, get approved, auto-attach single session (no double approval)", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    // Connect WITHOUT session in URL (no session path)

    const clientConfigDir = path.join(ctx.stateDir, "client-config-flow2");
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", baseToken, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Client should be held pending
    await client.waitForText("Waiting for operator approval", 15000);

    // Approve via CLI
    const relayStore = await openStore(relayDir);
    const data = await loadClients(relayStore);
    const pending = data.tokens.find((t) => t.status === "pending");
    expect(pending).toBeDefined();
    const tokenIdPrefix = pending!.id.slice(0, 8);

    const approveResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", tokenIdPrefix, "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approveResult.status).toBe(0);

    // After approval, there's only one session, so auto-attach should happen.
    // The re-exec'd process should connect WITHOUT a second "Waiting for operator
    // approval" message. It should go straight to a shell prompt.
    await client.waitForText("$", 30000);

    // Verify terminal works -- the re-exec succeeded and attached to the session
    client.sendKeys("echo flow2-reexec-works\n");
    await client.waitForText("flow2-reexec-works", 5000);

    // The critical regression check: the server should NOT have logged a second
    // "pending approval" message. If the client token was lost during re-exec,
    // the re-exec'd process would enter the pending queue again (double approval).
    const serverScreenAfter = server.screenshot();
    const pendingCount = serverScreenAfter.text
      .split("pending approval").length - 1;
    expect(pendingCount).toBe(1); // Exactly one pending -- the initial connection
  }, 60000);

  // Flow 3: Interactive TUI (ls) lists sessions from an approved host
  it("ls lists sessions for a known host without timing out", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect once to get approved and save a known host
    const clientConfigDir = path.join(ctx.stateDir, "client-config-flow3");
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client.waitForText("Waiting for operator approval", 15000);

    // Approve
    const relayStore = await openStore(relayDir);
    const data = await loadClients(relayStore);
    const pending = data.tokens.find((t) => t.status === "pending");
    expect(pending).toBeDefined();

    const approveResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", pending!.id.slice(0, 8), "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approveResult.status).toBe(0);

    // Wait for shell prompt (confirms connection works)
    await client.waitForText("$", 20000);

    // Wait for known-hosts to be saved
    await new Promise((r) => setTimeout(r, 1000));

    // Disconnect
    await client.close();

    // Wait a moment for cleanup
    await new Promise((r) => setTimeout(r, 500));

    // Run `pty-relay ls --json --config-dir <clientConfigDir>` to list sessions.
    // This should send the client token from the known-hosts file and get a
    // session list back WITHOUT timing out. If the bug is present (client tokens
    // not sent during list), this would timeout or fail with "Waiting for approval".
    const lsResult = spawnSync(
      "node",
      [CLI_ENTRY, "ls", "--json", "--config-dir", clientConfigDir],
      { encoding: "utf-8", timeout: 15000 }
    );

    expect(lsResult.status).toBe(0);
    const lsOutput = JSON.parse(lsResult.stdout);
    expect(Array.isArray(lsOutput)).toBe(true);
    expect(lsOutput.length).toBeGreaterThanOrEqual(1);

    // The host should have sessions listed (not an error)
    const hostResult = lsOutput[0];
    expect(hostResult.error).toBeNull();
    expect(hostResult.sessions.length).toBeGreaterThanOrEqual(1);

    // The session we created should be in the list
    const found = hostResult.sessions.find(
      (s: { name: string }) => s.name === ptySession.name
    );
    expect(found).toBeDefined();
  }, 60000);

  // Flow 4: Known-hosts dedup (no duplicate entries for the same host)
  it("reconnecting to the same relay does not create duplicate known-host entries", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    const clientConfigDir = path.join(ctx.stateDir, "client-config-flow4");

    // First connection: get approved
    const client1 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client1.waitForText("Waiting for operator approval", 15000);

    const relayStore = await openStore(relayDir);
    const data1 = await loadClients(relayStore);
    const pending1 = data1.tokens.find((t) => t.status === "pending");
    expect(pending1).toBeDefined();

    const approve1 = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", pending1!.id.slice(0, 8), "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approve1.status).toBe(0);

    await client1.waitForText("$", 20000);
    await new Promise((r) => setTimeout(r, 1000)); // wait for known-hosts save

    // Verify exactly 1 known-host entry
    const clientStore1 = await openStore(clientConfigDir);
    const hosts1 = await loadKnownHosts(clientStore1);
    expect(hosts1.length).toBe(1);

    // Disconnect
    await client1.close();
    await new Promise((r) => setTimeout(r, 500));

    // Second connection: should auto-approve via saved token (no new approval needed)
    // Build a URL that includes the saved client token
    const savedUrl = hosts1[0].url;
    const token2 = tokenWithSession(
      savedUrl,
      ptySession.name
    );

    const client2 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token2, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Should connect immediately (auto-approved via token) -- no "Waiting for approval"
    await client2.waitForText("$", 15000);

    // Verify terminal works
    client2.sendKeys("echo dedup-test\n");
    await client2.waitForText("dedup-test", 5000);

    // Wait for known-hosts to be potentially re-saved
    await new Promise((r) => setTimeout(r, 1000));

    // Verify still exactly 1 known-host entry (not duplicated)
    const clientStore2 = await openStore(clientConfigDir);
    const hosts2 = await loadKnownHosts(clientStore2);
    expect(hosts2.length).toBe(1);
    expect(hosts2[0].url).toContain("localhost");

    await client2.close();
  }, 60000);

  // Flow 5: Pre-auth invite -> connect -> no approval needed
  it("pre-auth invite provides immediate access without approval", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);

    // Create a pre-auth invite token
    const inviteResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "invite", "--label", "flow5-invite", "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(inviteResult.status).toBe(0);

    // Extract the token ID from clients.json
    const relayStore = await openStore(relayDir);
    const clientsData = await loadClients(relayStore);
    const inviteToken = clientsData.tokens.find(
      (t) => t.status === "active" && t.label === "flow5-invite"
    );
    expect(inviteToken).toBeDefined();

    // Build the invite URL: baseToken with session + client token appended to fragment
    const sessionToken = tokenWithSession(baseToken, ptySession.name);
    const inviteUrl = sessionToken + "." + inviteToken!.id;

    // Connect with the invite URL
    const clientConfigDir = path.join(ctx.stateDir, "client-config-flow5");
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", inviteUrl, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Should connect IMMEDIATELY -- no "Waiting for operator approval"
    await client.waitForText("$", 15000);

    // Verify the screen does NOT contain "Waiting for operator approval"
    const clientScreen = client.screenshot();
    expect(clientScreen.text).not.toContain("Waiting for operator approval");

    // Type command, verify output
    client.sendKeys("echo flow5-invite-works\n");
    await client.waitForText("flow5-invite-works", 5000);
  }, 60000);

  // Flow 6: Revoked client -> reconnect -> gets rejected
  it("revoked token is rejected on reconnect", async () => {
    const port = getPort();
    const relayDir = path.join(ctx.stateDir, "relay");

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start relay WITHOUT --auto-approve
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          relayDir,
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    const clientConfigDir = path.join(ctx.stateDir, "client-config-flow6");

    // First connection: get approved
    const client1 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client1.waitForText("Waiting for operator approval", 15000);

    const relayStore = await openStore(relayDir);
    const data1 = await loadClients(relayStore);
    const pending = data1.tokens.find((t) => t.status === "pending");
    expect(pending).toBeDefined();
    const tokenId = pending!.id;

    const approveRes = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "approve", tokenId.slice(0, 8), "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(approveRes.status).toBe(0);

    await client1.waitForText("$", 20000);
    await new Promise((r) => setTimeout(r, 1000)); // wait for known-hosts save

    // Verify the known-host was saved
    const clientStore = await openStore(clientConfigDir);
    const hostsBefore = await loadKnownHosts(clientStore);
    expect(hostsBefore.length).toBe(1);

    // Disconnect
    await client1.close();
    await new Promise((r) => setTimeout(r, 500));

    // Revoke the token
    const revokeResult = spawnSync(
      "node",
      [CLI_ENTRY, "clients", "revoke", tokenId.slice(0, 8), "--config-dir", relayDir],
      { encoding: "utf-8", timeout: 10000 }
    );
    expect(revokeResult.status).toBe(0);

    // Try to reconnect with the saved known-host URL (which includes the now-revoked token)
    const savedUrl = hostsBefore[0].url;
    const revokedToken = tokenWithSession(savedUrl, ptySession.name);

    const client2 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", revokedToken, "--config-dir", clientConfigDir], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Should show "token revoked" error, NOT hang forever
    await client2.waitForText("token revoked", 15000);

    // The known-host entry should still exist (it still has the revoked token)
    const hostsAfter = await loadKnownHosts(await openStore(clientConfigDir));
    expect(hostsAfter.length).toBe(1);
  }, 60000);
});

describe("interactive TUI lifecycle", () => {
  it("connect detaches cleanly with Ctrl+\\ and process exits", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Start self-hosted relay
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // Connect a CLI client
    const client = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    // Wait for shell prompt
    await client.waitForText("$", 15000);

    // Send Ctrl+\ to detach
    client.sendKeys("\x1c");

    // Should show [detached] message
    await client.waitForText("[detached]", 5000);
  }, 60000);

  it("pty session survives client detach", async () => {
    const port = getPort();

    // Start a pty session
    const ptySession = await Session.server("bash", [], {
      rows: 24,
      cols: 80,
    });
    track(ctx, ptySession);
    await ptySession.attach();
    await ptySession.waitForText("$", 5000);

    // Write a marker before connecting
    ptySession.sendKeys("export MK=ptest\n");
    await ptySession.waitForText("MK=ptest", 5000);

    // Start self-hosted relay
    const server = track(
      ctx,
      Session.spawn(
        "node",
        [
          CLI_ENTRY,
          "local",
          "start",
          String(port),
          "--config-dir",
          path.join(ctx.stateDir, "relay"),
          "--auto-approve",
        ],
        { rows: 24, cols: 200, env: { PTY_SESSION_DIR: ctx.stateDir } }
      )
    );

    await server.waitForText("Token URL", 15000);
    const serverScreen = server.screenshot();
    const baseToken = extractTokenUrl(serverScreen);
    const token = tokenWithSession(baseToken, ptySession.name);

    // First client connects, types something, then detaches
    const client1 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client1.waitForText("$", 15000);
    client1.sendKeys("echo connected-first\n");
    await client1.waitForText("connected-first", 5000);

    // Detach
    client1.sendKeys("\x1c");
    await client1.waitForText("[detached]", 5000);

    // Wait a moment
    await new Promise(r => setTimeout(r, 500));

    // Second client connects to the same session
    const client2 = track(
      ctx,
      Session.spawn("node", [CLI_ENTRY, "connect", token], {
        rows: 24,
        cols: 80,
        env: { PTY_SESSION_DIR: ctx.stateDir },
      })
    );

    await client2.waitForText("$", 15000);

    // Verify the session persisted — the MK env var should still be there
    client2.sendKeys("echo $MK\n");
    await client2.waitForText("ptest", 5000);
  }, 60000);
});
