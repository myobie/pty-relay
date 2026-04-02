import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  afterEach,
} from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import sodium from "libsodium-wrappers-sumo";
import {
  loadClients,
  saveClients,
  findTokenById,
  findPendingByClientId,
  generateTokenId,
  saveDaemonPid,
  signalDaemon,
  type ClientsData,
} from "./clients.ts";
import { PassphraseStore } from "../storage/passphrase-store.ts";
import { randomSalt } from "../crypto/aead.ts";

beforeAll(async () => {
  await sodium.ready;
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

let tmpDir: string;
let store: PassphraseStore;

beforeEach(async () => {
  tmpDir = fs.mkdtempSync(path.join("/tmp", "clients-test-"));
  store = await PassphraseStore.open(
    tmpDir,
    "test-pass",
    randomSalt(),
    "interactive"
  );
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("loadClients", () => {
  it("returns empty tokens when nothing is stored", async () => {
    const data = await loadClients(store);
    expect(data).toEqual({ tokens: [] });
  });

  it("loads valid clients data", async () => {
    const clientsData: ClientsData = {
      tokens: [
        {
          id: "abc123",
          label: "test",
          status: "active",
          client_id: null,
          created: "2026-04-01",
          revoked_at: null,
        },
      ],
    };
    await saveClients(clientsData, store);

    const data = await loadClients(store);
    expect(data.tokens).toHaveLength(1);
    expect(data.tokens[0].id).toBe("abc123");
  });

  it("returns empty tokens for unparseable stored data", async () => {
    // Write raw (non-JSON) bytes through the store to simulate corruption
    await store.save("clients", new TextEncoder().encode("not json"));
    const data = await loadClients(store);
    expect(data).toEqual({ tokens: [] });
  });
});

describe("saveClients", () => {
  it("round-trips a clients payload through the store", async () => {
    const clientsData: ClientsData = {
      tokens: [
        {
          id: "def456",
          label: null,
          status: "pending",
          client_id: "xyz",
          created: "2026-04-01",
          revoked_at: null,
        },
      ],
    };
    await saveClients(clientsData, store);

    const loaded = await loadClients(store);
    expect(loaded.tokens).toHaveLength(1);
    expect(loaded.tokens[0].id).toBe("def456");
  });

  it("creates the directory if missing", async () => {
    const subDir = path.join(tmpDir, "nested", "dir");
    const subStore = await PassphraseStore.open(
      subDir,
      "test-pass",
      randomSalt(),
      "interactive"
    );
    const clientsData: ClientsData = { tokens: [] };
    await saveClients(clientsData, subStore);
    expect(fs.existsSync(path.join(subDir, "clients.json"))).toBe(true);
  });
});

describe("findTokenById", () => {
  const data: ClientsData = {
    tokens: [
      {
        id: "abcdef123456789012345678",
        label: "first",
        status: "active",
        client_id: null,
        created: "2026-04-01",
        revoked_at: null,
      },
      {
        id: "xyz000111222333444555666",
        label: "second",
        status: "pending",
        client_id: "c1",
        created: "2026-04-02",
        revoked_at: null,
      },
    ],
  };

  it("finds by exact ID", () => {
    const result = findTokenById(data, "abcdef123456789012345678");
    expect(result?.label).toBe("first");
  });

  it("finds by unique prefix", () => {
    const result = findTokenById(data, "abcdef");
    expect(result?.label).toBe("first");
  });

  it("returns undefined for non-unique prefix", () => {
    const result = findTokenById(data, "zzz");
    expect(result).toBeUndefined();
  });

  it("returns undefined for ambiguous prefix", () => {
    const ambiguousData: ClientsData = {
      tokens: [
        { id: "aaa111", label: null, status: "active", client_id: null, created: "", revoked_at: null },
        { id: "aaa222", label: null, status: "active", client_id: null, created: "", revoked_at: null },
      ],
    };
    const result = findTokenById(ambiguousData, "aaa");
    expect(result).toBeUndefined();
  });
});

describe("findPendingByClientId", () => {
  it("finds pending token by client_id", () => {
    const data: ClientsData = {
      tokens: [
        {
          id: "tok1",
          label: null,
          status: "pending",
          client_id: "client-abc",
          created: "2026-04-01",
          revoked_at: null,
        },
        {
          id: "tok2",
          label: null,
          status: "active",
          client_id: "client-abc",
          created: "2026-04-01",
          revoked_at: null,
        },
      ],
    };

    const result = findPendingByClientId(data, "client-abc");
    expect(result?.id).toBe("tok1");
  });

  it("returns undefined when no pending match", () => {
    const data: ClientsData = {
      tokens: [
        {
          id: "tok1",
          label: null,
          status: "active",
          client_id: null,
          created: "2026-04-01",
          revoked_at: null,
        },
      ],
    };
    expect(findPendingByClientId(data, "client-abc")).toBeUndefined();
  });
});

describe("generateTokenId", () => {
  it("returns a 24-char hex string", () => {
    const id = generateTokenId();
    expect(id).toMatch(/^[0-9a-f]{24}$/);
    expect(id.length).toBe(24);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateTokenId()));
    expect(ids.size).toBe(100);
  });
});

describe("saveDaemonPid", () => {
  it("writes PID to daemon.pid and cleanup deletes it", () => {
    const cleanup = saveDaemonPid(tmpDir);
    const pidFile = path.join(tmpDir, "daemon.pid");
    expect(fs.existsSync(pidFile)).toBe(true);
    expect(fs.readFileSync(pidFile, "utf-8").trim()).toBe(String(process.pid));

    cleanup();
    expect(fs.existsSync(pidFile)).toBe(false);
  });
});

describe("signalDaemon", () => {
  it("returns false when daemon.pid does not exist", () => {
    expect(signalDaemon(tmpDir)).toBe(false);
  });

  it("returns false for invalid PID file content", () => {
    fs.writeFileSync(path.join(tmpDir, "daemon.pid"), "not-a-number");
    expect(signalDaemon(tmpDir)).toBe(false);
  });

  it("returns true when signaling own process", () => {
    // Write our own PID — we can handle SIGUSR1
    let received = false;
    const handler = () => { received = true; };
    process.on("SIGUSR1", handler);

    fs.writeFileSync(path.join(tmpDir, "daemon.pid"), String(process.pid));
    const result = signalDaemon(tmpDir);
    expect(result).toBe(true);

    // Give the signal a moment to arrive
    process.removeListener("SIGUSR1", handler);
  });
});
