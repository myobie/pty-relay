import { describe, it, expect } from "vitest";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync } from "node:child_process";

const CLI_ENTRY = path.resolve(
  import.meta.dirname,
  "../src/cli.ts"
);

function runCli(args: string[]): { stdout: string; stderr: string; exitCode: number } {
  const result = spawnSync("node", [CLI_ENTRY, ...args], {
    encoding: "utf-8",
    timeout: 10000,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      PTY_SESSION_DIR: path.join(os.tmpdir(), `pty-cli-test-${Date.now()}`),
    },
  });
  return {
    stdout: result.stdout || "",
    stderr: result.stderr || "",
    exitCode: result.status ?? 1,
  };
}

describe("CLI", () => {
  it("shows usage with unknown command", () => {
    const { stdout, exitCode } = runCli(["notacommand"]);
    expect(stdout).toContain("pty-relay");
    expect(exitCode).toBe(1);
  });

  it("usage text lists available commands", () => {
    const { stdout } = runCli(["notacommand"]);
    expect(stdout).toContain("connect");
    expect(stdout).toContain("serve");
    expect(stdout).toContain("set-name");
    expect(stdout).toContain("ls");
  });

  it("connect requires a token-url argument", () => {
    const { stderr, exitCode } = runCli(["connect"]);
    expect(stderr).toContain("Usage: pty-relay connect <token-url>");
    expect(exitCode).toBe(1);
  });

  it("set-name requires a label argument", () => {
    const { stderr, exitCode } = runCli(["set-name"]);
    expect(stderr).toContain("Usage: pty-relay set-name <label>");
    expect(exitCode).toBe(1);
  });

  it("usage includes --allow-new-sessions flag", () => {
    const { stdout } = runCli(["--help"]);
    expect(stdout).toContain("--allow-new-sessions");
  });

  it("usage includes --json flag", () => {
    const { stdout } = runCli(["--help"]);
    expect(stdout).toContain("--json");
  });

  it("usage mentions --skip-allow-new-sessions-confirmation for non-interactive startup", () => {
    const { stdout } = runCli(["--help"]);
    expect(stdout).toContain("--skip-allow-new-sessions-confirmation");
  });

  it("`<command> --help` prints help instead of running the command", () => {
    // Regression for the case where `pty-relay serve --help` would parse
    // `--help` as a port, fall back to 8099, and actually boot the server.
    const { stdout, exitCode } = runCli(["serve", "--help"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Commands:");
    expect(stdout).not.toContain("Token URL");
  });

  it("`<command> -h` also prints help", () => {
    const { stdout, exitCode } = runCli(["connect", "-h"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("Commands:");
  });

  it("--version prints the package version and exits 0", () => {
    const { stdout, exitCode } = runCli(["--version"]);
    expect(stdout).toMatch(/pty-relay \d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });

  it("-v is an alias for --version", () => {
    const { stdout, exitCode } = runCli(["-v"]);
    expect(stdout).toMatch(/pty-relay \d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });

  it("version subcommand works the same as --version", () => {
    const { stdout, exitCode } = runCli(["version"]);
    expect(stdout).toMatch(/pty-relay \d+\.\d+\.\d+/);
    expect(exitCode).toBe(0);
  });

  it("doctor prints environment info", () => {
    const tmpDir = path.join(os.tmpdir(), `pty-cli-doctor-${Date.now()}`);
    const { stdout, exitCode } = runCli([
      "doctor",
      "--config-dir",
      tmpDir,
    ]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("pty-relay doctor");
    expect(stdout).toContain("Environment:");
    expect(stdout).toContain("pty-relay:");
    expect(stdout).toContain("node:");
    expect(stdout).toContain("platform:");
    expect(stdout).toContain("External tools:");
    expect(stdout).toContain("Secret storage:");
    expect(stdout).toContain("Config files:");
    expect(stdout).toContain("Environment variables:");
    expect(stdout).toContain("Daemon:");
  });

  it("doctor does not leak secret env vars", () => {
    const tmpDir = path.join(os.tmpdir(), `pty-cli-doctor-${Date.now()}`);
    const result = spawnSync("node", [CLI_ENTRY, "doctor", "--config-dir", tmpDir], {
      encoding: "utf-8",
      timeout: 10000,
      env: {
        ...process.env,
        PTY_SESSION_DIR: tmpDir,
        PTY_RELAY_PASSPHRASE: "super-secret-value",
      },
    });
    expect(result.status).toBe(0);
    // Must NOT leak the actual passphrase value
    expect(result.stdout).not.toContain("super-secret-value");
    // But MUST show that it's set
    expect(result.stdout).toContain("PTY_RELAY_PASSPHRASE:   (set)");
  });
});
