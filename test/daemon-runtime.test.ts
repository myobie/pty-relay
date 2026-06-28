import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  saveDaemonRuntime,
  loadDaemonRuntime,
  clearDaemonRuntime,
  buildExternalTokenUrl,
  runtimePath,
  type DaemonRuntime,
} from "../src/relay/daemon-runtime.ts";

/** Pure helper that mimics the signature of `createToken`. Lets the
 *  buildExternalTokenUrl tests assert what got composed without
 *  pulling in sodium just for this unit. */
function fakeCreateToken(host: string, _pk: Uint8Array, _s: Uint8Array, session?: string): string {
  return `proto://${host}${session ? "/" + session : ""}#fakepk.fakesecret`;
}

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "daemon-runtime-"));
});

afterEach(() => {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
});

describe("saveDaemonRuntime / loadDaemonRuntime", () => {
  it("round-trips a non-tailscale record", () => {
    saveDaemonRuntime(dir, { port: 9000, bind: "127.0.0.1" });
    const loaded = loadDaemonRuntime(dir);
    expect(loaded).not.toBeNull();
    expect(loaded!.port).toBe(9000);
    expect(loaded!.bind).toBe("127.0.0.1");
    expect(loaded!.tailscale).toBeUndefined();
    expect(loaded!.startedAt).toBeGreaterThan(0);
  });

  it("round-trips a tailscale record", () => {
    saveDaemonRuntime(dir, {
      port: 8099,
      bind: "127.0.0.1",
      tailscale: { hostname: "host.ts.net", port: 443, scheme: "https" },
    });
    const loaded = loadDaemonRuntime(dir);
    expect(loaded?.tailscale).toEqual({
      hostname: "host.ts.net",
      port: 443,
      scheme: "https",
    });
  });

  it("returns null when the file doesn't exist", () => {
    expect(loadDaemonRuntime(dir)).toBeNull();
  });

  it("returns null on malformed JSON", () => {
    fs.writeFileSync(runtimePath(dir), "{ not json");
    expect(loadDaemonRuntime(dir)).toBeNull();
  });

  it("returns null on missing required fields", () => {
    fs.writeFileSync(runtimePath(dir), JSON.stringify({ bind: "127.0.0.1" }));
    expect(loadDaemonRuntime(dir)).toBeNull();
  });

  it("loads the bare shape when tailscale is malformed (drops the field, keeps the rest)", () => {
    fs.writeFileSync(runtimePath(dir), JSON.stringify({
      port: 9000,
      bind: "127.0.0.1",
      startedAt: 1,
      tailscale: { hostname: "ok.ts.net" }, // missing port + scheme
    }));
    const loaded = loadDaemonRuntime(dir);
    expect(loaded?.port).toBe(9000);
    expect(loaded?.tailscale).toBeUndefined();
  });

  it("writes the file with mode 0600 (no secrets, but defense-in-depth)", () => {
    saveDaemonRuntime(dir, { port: 9000, bind: "0.0.0.0" });
    const stat = fs.statSync(runtimePath(dir));
    // On some CI environments umask can mask out the group/other bits,
    // so check that *we* set 0600 by masking down to the perms bits.
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it("saveDaemonRuntime is best-effort — failing target dir doesn't throw", () => {
    expect(() =>
      saveDaemonRuntime("/proc/will/never/be/writable/anywhere", { port: 9000, bind: "127.0.0.1" }),
    ).not.toThrow();
  });
});

describe("clearDaemonRuntime", () => {
  it("removes the runtime file", () => {
    saveDaemonRuntime(dir, { port: 9000, bind: "127.0.0.1" });
    expect(fs.existsSync(runtimePath(dir))).toBe(true);
    clearDaemonRuntime(dir);
    expect(fs.existsSync(runtimePath(dir))).toBe(false);
  });

  it("is a no-op when the file is already gone", () => {
    expect(() => clearDaemonRuntime(dir)).not.toThrow();
    expect(fs.existsSync(runtimePath(dir))).toBe(false);
  });
});

describe("buildExternalTokenUrl", () => {
  const pk = new Uint8Array([1, 2, 3]);
  const secret = new Uint8Array([4, 5, 6]);

  it("uses the tailscale hostname when present", () => {
    const runtime: DaemonRuntime = {
      port: 8099,
      bind: "127.0.0.1",
      tailscale: { hostname: "silber.ts.net", port: 443, scheme: "https" },
      startedAt: 0,
    };
    const url = buildExternalTokenUrl(runtime, pk, secret, fakeCreateToken);
    // Default https port → no port in the URL.
    expect(url).toBe("proto://silber.ts.net#fakepk.fakesecret");
  });

  it("includes the tailscale port when it's non-default", () => {
    const runtime: DaemonRuntime = {
      port: 8099,
      bind: "127.0.0.1",
      tailscale: { hostname: "silber.ts.net", port: 8443, scheme: "https" },
      startedAt: 0,
    };
    const url = buildExternalTokenUrl(runtime, pk, secret, fakeCreateToken);
    expect(url).toBe("proto://silber.ts.net:8443#fakepk.fakesecret");
  });

  it("falls back to localhost:<port> when no tailscale", () => {
    const runtime: DaemonRuntime = {
      port: 9000,
      bind: "0.0.0.0",
      startedAt: 0,
    };
    const url = buildExternalTokenUrl(runtime, pk, secret, fakeCreateToken);
    expect(url).toBe("proto://localhost:9000#fakepk.fakesecret");
  });

  it("respects the http scheme + custom port on tailscale", () => {
    const runtime: DaemonRuntime = {
      port: 9000,
      bind: "127.0.0.1",
      tailscale: { hostname: "h.ts.net", port: 80, scheme: "http" },
      startedAt: 0,
    };
    const url = buildExternalTokenUrl(runtime, pk, secret, fakeCreateToken);
    expect(url).toBe("proto://h.ts.net#fakepk.fakesecret");
  });
});
