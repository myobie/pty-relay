import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  parsePeersFile,
  loadPeersFile,
  peersFileCandidates,
  resolvePeersFilePath,
} from "../src/relay/peers-file.ts";

let tmpDir: string;
let stderrSpy: ReturnType<typeof vi.spyOn>;
let stderrBuf: string;
let env: NodeJS.ProcessEnv;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "peers-file-"));
  stderrBuf = "";
  stderrSpy = vi
    .spyOn(process.stderr, "write")
    .mockImplementation((chunk: string | Uint8Array) => {
      stderrBuf += typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
      return true;
    });
  // Save + clear env so XDG_CONFIG_HOME / PTY_RELAY_PEERS_FILE from the
  // developer's shell don't leak into the tests.
  env = { ...process.env };
  delete process.env.PTY_RELAY_PEERS_FILE;
  delete process.env.XDG_CONFIG_HOME;
});

afterEach(() => {
  stderrSpy.mockRestore();
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  process.env = env;
});

describe("parsePeersFile — line grammar", () => {
  it("accepts an ssh:// URL with no explicit label", () => {
    const hosts = parsePeersFile("ssh://web1.example.com\n", "/test/peers");
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toEqual({
      label: "web1.example.com",
      sshUrl: "ssh://web1.example.com",
    });
  });

  it("accepts an https://#pk.secret URL with no explicit label", () => {
    // 43-char URL-safe-base64 = 32 bytes; parseToken validates the
    // length so we have to use a real shape.
    const pk = "A".repeat(43);
    const sec = "B".repeat(43);
    const url = `https://relay.example.com#${pk}.${sec}`;
    const hosts = parsePeersFile(`${url}\n`, "/test/peers");
    expect(hosts).toHaveLength(1);
    expect(hosts[0]).toEqual({
      label: "relay.example.com",
      url,
    });
  });

  it("accepts an explicit label after whitespace", () => {
    const hosts = parsePeersFile(
      "ssh://me@web1.example.com:2222    prod-web-1\n",
      "/test/peers",
    );
    expect(hosts).toEqual([
      { label: "prod-web-1", sshUrl: "ssh://me@web1.example.com:2222" },
    ]);
  });

  it("auto-label strips user@ but keeps the bare hostname", () => {
    const hosts = parsePeersFile(
      "ssh://nathan@beta.host\n",
      "/test/peers",
    );
    expect(hosts[0].label).toBe("beta.host");
  });

  it("ignores comment lines and blank lines", () => {
    const contents = [
      "# this is the fleet",
      "",
      "ssh://web1",
      "  # leading-whitespace comment",
      "ssh://web2",
      "",
    ].join("\n");
    const hosts = parsePeersFile(contents, "/test/peers");
    expect(hosts.map((h) => h.label)).toEqual(["web1", "web2"]);
  });

  it("supports labels with embedded spaces (everything after the URL)", () => {
    const hosts = parsePeersFile(
      "ssh://web1    prod web 1\n",
      "/test/peers",
    );
    expect(hosts[0].label).toBe("prod web 1");
  });

  it("de-collides multiple peers with the same auto-derived label", () => {
    const hosts = parsePeersFile(
      "ssh://web\nssh://web\nssh://web\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["web", "web-2", "web-3"]);
  });

  it("de-collides multiple peers with the same explicit label", () => {
    const hosts = parsePeersFile(
      "ssh://w1  prod\nssh://w2  prod\nssh://w3  prod\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["prod", "prod-2", "prod-3"]);
  });

  it("mixed ssh + https peers in the same file", () => {
    const pk = "A".repeat(43);
    const sec = "B".repeat(43);
    const url = `https://relay.example.com#${pk}.${sec}`;
    const hosts = parsePeersFile(
      `ssh://web1\n${url}  the-relay\n`,
      "/test/peers",
    );
    expect(hosts).toEqual([
      { label: "web1", sshUrl: "ssh://web1" },
      { label: "the-relay", url },
    ]);
  });

  it("CRLF line endings are tolerated", () => {
    const hosts = parsePeersFile(
      "ssh://web1\r\nssh://web2\r\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["web1", "web2"]);
  });
});

describe("parsePeersFile — invalid lines warn + skip, never crash", () => {
  it("a malformed ssh URL skips with a warning naming the line", () => {
    const hosts = parsePeersFile(
      "ssh://\nssh://web1\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["web1"]);
    expect(stderrBuf).toContain("/test/peers:1");
    expect(stderrBuf).toContain("ssh://");
  });

  it("a non-URL token is dropped with a warning", () => {
    const hosts = parsePeersFile(
      "not-a-url\nssh://web1\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["web1"]);
    expect(stderrBuf).toContain("/test/peers:1");
    expect(stderrBuf).toContain("expected ssh:// or http(s)://");
  });

  it("an https URL missing the fragment is dropped (parseToken fail)", () => {
    const hosts = parsePeersFile(
      "https://relay.example.com\nssh://web1\n",
      "/test/peers",
    );
    expect(hosts.map((h) => h.label)).toEqual(["web1"]);
    expect(stderrBuf).toContain("/test/peers:1");
  });

  it("a totally empty file is harmless", () => {
    expect(parsePeersFile("", "/test/peers")).toEqual([]);
  });

  it("a comment-only file is harmless", () => {
    expect(parsePeersFile("# nothing\n\n# else\n", "/test/peers")).toEqual([]);
  });
});

describe("peersFileCandidates", () => {
  it("PTY_RELAY_PEERS_FILE is checked first", () => {
    process.env.PTY_RELAY_PEERS_FILE = "/explicit/path";
    process.env.XDG_CONFIG_HOME = "/xdg";
    process.env.HOME = "/home/u";
    const list = peersFileCandidates();
    expect(list[0]).toBe("/explicit/path");
  });

  it("XDG_CONFIG_HOME comes second when set", () => {
    process.env.XDG_CONFIG_HOME = "/xdg";
    process.env.HOME = "/home/u";
    const list = peersFileCandidates();
    expect(list).toContain("/xdg/pty-relay/peers");
  });

  it("falls back to ~/.config/pty-relay/peers when XDG isn't set", () => {
    process.env.HOME = "/home/u";
    const list = peersFileCandidates();
    expect(list).toContain("/home/u/.config/pty-relay/peers");
  });
});

describe("loadPeersFile + resolvePeersFilePath — I/O surface", () => {
  it("returns [] when no peers file exists at any candidate path", () => {
    process.env.HOME = tmpDir;
    expect(loadPeersFile()).toEqual([]);
    expect(resolvePeersFilePath()).toBeNull();
  });

  it("reads + parses the file when PTY_RELAY_PEERS_FILE points at one", () => {
    const filePath = path.join(tmpDir, "peers");
    fs.writeFileSync(filePath, "ssh://web1\nssh://web2 prod-web-2\n");
    process.env.PTY_RELAY_PEERS_FILE = filePath;

    expect(resolvePeersFilePath()).toBe(filePath);
    const hosts = loadPeersFile();
    expect(hosts.map((h) => h.label)).toEqual(["web1", "prod-web-2"]);
  });

  it("reads the XDG path when XDG_CONFIG_HOME is set", () => {
    const xdgDir = path.join(tmpDir, "xdg");
    const filePath = path.join(xdgDir, "pty-relay", "peers");
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, "ssh://web1\n");
    process.env.XDG_CONFIG_HOME = xdgDir;

    expect(resolvePeersFilePath()).toBe(filePath);
    expect(loadPeersFile().map((h) => h.label)).toEqual(["web1"]);
  });

  it("a stat() failure on the read returns [] + stderr line (no throw)", () => {
    // Point at a directory; readFileSync will EISDIR.
    const dirAsFile = path.join(tmpDir, "is-a-dir");
    fs.mkdirSync(dirAsFile);
    process.env.PTY_RELAY_PEERS_FILE = dirAsFile;

    expect(loadPeersFile()).toEqual([]);
    expect(stderrBuf).toContain(dirAsFile);
  });
});
