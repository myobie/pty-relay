import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import { spawnSync, execSync } from "node:child_process";
import {
  CLI_ENTRY,
  Session,
  createTestContext,
  destroyTestContext,
  extractTokenUrl,
  getPort,
  integEnv,
  track,
  type TestContext,
} from "./helpers/index.ts";
import { openSecretStore } from "../src/storage/bootstrap.ts";
import { saveKnownHost } from "../src/relay/known-hosts.ts";

/**
 * Phase-5 end-to-end test: drives `pty-relay rsync` against a local
 * daemon with --allow-exec, copies a small directory tree, and verifies
 * byte-identical content via SHA-256 sums.
 *
 * Skipped automatically if the `rsync` binary isn't on PATH.
 */

let ctx: TestContext;
let rsyncAvailable = false;

beforeAll(async () => {
  ctx = createTestContext();
  const check = spawnSync("rsync", ["--version"], { encoding: "utf-8" });
  rsyncAvailable = check.status === 0;
});

afterAll(async () => {
  await destroyTestContext(ctx);
});

function computeTreeShasum(root: string): string {
  // Hash file paths + contents in sorted order so the result is
  // deterministic across runs. Excludes mtime / mode / owner since
  // rsync's default invocation doesn't preserve them perfectly across
  // arbitrary transports — content equality is what we care about here.
  const hasher = crypto.createHash("sha256");
  function walk(dir: string, prefix: string): void {
    const entries = fs.readdirSync(dir).sort();
    for (const name of entries) {
      const full = path.join(dir, name);
      const stat = fs.statSync(full);
      const rel = path.join(prefix, name);
      if (stat.isDirectory()) {
        hasher.update(`D ${rel}\n`);
        walk(full, rel);
      } else {
        hasher.update(`F ${rel} ${stat.size}\n`);
        hasher.update(fs.readFileSync(full));
        hasher.update("\n");
      }
    }
  }
  walk(root, "");
  return hasher.digest("hex");
}

async function seedKnownHostLabel(
  configDir: string,
  label: string,
  tokenUrl: string,
): Promise<void> {
  const { store } = await openSecretStore(configDir, {
    interactive: false,
    passphraseFile: undefined,
  });
  await saveKnownHost(label, tokenUrl, store);
}

describe("exec mode — rsync over relay", () => {
  it("copies a directory tree byte-identical", async () => {
    if (!rsyncAvailable) {
      console.log("rsync not available; skipping");
      return;
    }

    const port = getPort();
    const relayDir = path.join(ctx.stateDir, `rsync-relay-${port}`);
    const clientDir = path.join(ctx.stateDir, `rsync-client-${port}`);
    fs.mkdirSync(relayDir, { recursive: true });
    fs.mkdirSync(clientDir, { recursive: true });

    // Daemon with both --auto-approve (skip TUI) and --allow-exec
    // (enable the exec channel mode). --skip-allow-exec-confirmation
    // bypasses the y/N prompt for non-interactive startup.
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
          "--allow-exec",
          "--skip-allow-exec-confirmation",
        ],
        {
          rows: 24,
          cols: 200,
          env: integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
        },
      ),
    );

    await server.waitForText("Token URL", 15000);
    const baseToken = extractTokenUrl(server.screenshot());

    // Seed a short known-host label on the client side so rsync's
    // host:path syntax has something parseable (a token URL has ':' and
    // '#' which rsync's host-splitter would mangle).
    const label = `r${port}`;
    await seedKnownHostLabel(clientDir, label, baseToken);

    // Build a source tree + a destination dir.
    const srcDir = path.join(ctx.stateDir, `src-${port}`);
    const dstDir = path.join(ctx.stateDir, `dst-${port}`);
    fs.mkdirSync(srcDir, { recursive: true });
    fs.mkdirSync(dstDir, { recursive: true });
    fs.writeFileSync(path.join(srcDir, "a.txt"), "hello\n");
    fs.writeFileSync(path.join(srcDir, "b.txt"), "world\n");
    fs.mkdirSync(path.join(srcDir, "sub"));
    fs.writeFileSync(path.join(srcDir, "sub", "c.txt"), "deeper content\n");
    // A binary file to exercise the substream byte-prefix path on a
    // non-printable payload.
    const bin = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    fs.writeFileSync(path.join(srcDir, "binary.bin"), bin);

    // Drive `pty-relay rsync`. The -e transport is wired automatically.
    const result = spawnSync(
      "node",
      [
        CLI_ENTRY,
        "rsync",
        "--config-dir",
        clientDir,
        "-rv",
        `${srcDir}/`,
        `${label}:${dstDir}/`,
      ],
      {
        encoding: "utf-8",
        env: { ...process.env, ...integEnv({ PTY_SESSION_DIR: ctx.stateDir }) },
        timeout: 30000,
      },
    );

    if (result.status !== 0) {
      console.log("rsync result:", result);
    }
    expect(result.error).toBeFalsy();
    expect(result.status).toBe(0);

    expect(computeTreeShasum(dstDir)).toBe(computeTreeShasum(srcDir));
  }, 60000);
});

describe("exec mode — git over relay", () => {
  it("clones a bare repo via pty-relay exec", async () => {
    // Skip on environments without git (CI containers may lack it).
    const gitCheck = spawnSync("git", ["--version"], { encoding: "utf-8" });
    if (gitCheck.status !== 0) {
      console.log("git not available; skipping");
      return;
    }

    const port = getPort();
    const relayDir = path.join(ctx.stateDir, `git-relay-${port}`);
    const clientDir = path.join(ctx.stateDir, `git-client-${port}`);
    fs.mkdirSync(relayDir, { recursive: true });
    fs.mkdirSync(clientDir, { recursive: true });

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
          "--allow-exec",
          "--skip-allow-exec-confirmation",
        ],
        {
          rows: 24,
          cols: 200,
          env: integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
        },
      ),
    );

    await server.waitForText("Token URL", 15000);
    const baseToken = extractTokenUrl(server.screenshot());

    const label = `g${port}`;
    await seedKnownHostLabel(clientDir, label, baseToken);

    // Build a bare repo on the daemon's filesystem.
    const sourceWork = path.join(ctx.stateDir, `git-src-${port}`);
    fs.mkdirSync(sourceWork, { recursive: true });
    execSync(`git init -q && git config user.email a@b && git config user.name a && echo hi > f && git add f && git commit -q -m c`, {
      cwd: sourceWork,
    });
    const bareRepo = path.join(ctx.stateDir, `git-bare-${port}.git`);
    execSync(`git clone --bare -q ${sourceWork} ${bareRepo}`);

    // git clones over `<host>:<path>` URLs use `GIT_SSH_COMMAND` to
    // override the transport. We point it at our exec wrapper so git
    // invokes `pty-relay exec <host> git-upload-pack <repo>` — the
    // exact shape ssh would have produced.
    const target = path.join(ctx.stateDir, `git-clone-target-${port}`);
    const gitSshCommand = `node ${CLI_ENTRY} exec --config-dir ${clientDir}`;
    const result = spawnSync(
      "git",
      ["clone", `${label}:${bareRepo}`, target],
      {
        encoding: "utf-8",
        env: {
          ...process.env,
          ...integEnv({ PTY_SESSION_DIR: ctx.stateDir }),
          GIT_SSH_COMMAND: gitSshCommand,
        },
        timeout: 30000,
      },
    );

    if (result.status !== 0) {
      console.log("git result:", result);
    }
    expect(result.status).toBe(0);
    expect(fs.existsSync(path.join(target, "f"))).toBe(true);
    expect(fs.readFileSync(path.join(target, "f"), "utf-8")).toBe("hi\n");
  }, 60000);
});
