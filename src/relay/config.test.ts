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
import * as os from "node:os";
import sodium from "libsodium-wrappers-sumo";
import { saveLabel, loadLabel } from "./config.ts";
import { PassphraseStore } from "../storage/passphrase-store.ts";
import { randomSalt } from "../crypto/aead.ts";

beforeAll(async () => {
  await sodium.ready;
  process.env.PTY_RELAY_KDF_PROFILE = "interactive";
});

let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pty-relay-config-test-"));
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

async function makeStore(dir: string): Promise<PassphraseStore> {
  return PassphraseStore.open(dir, "test-pass", randomSalt(), "interactive");
}

describe("saveLabel / loadLabel", () => {
  it("saves and loads a label", async () => {
    const store = await makeStore(tmp);
    await saveLabel("my-server", store);
    expect(await loadLabel(store)).toBe("my-server");
  });

  it("overwrites an existing label", async () => {
    const store = await makeStore(tmp);
    await saveLabel("old-name", store);
    await saveLabel("new-name", store);
    expect(await loadLabel(store)).toBe("new-name");
  });

  it("returns null when no label is set", async () => {
    const store = await makeStore(tmp);
    expect(await loadLabel(store)).toBeNull();
  });

  it("preserves other auth.json fields", async () => {
    const store = await makeStore(tmp);
    // Seed an auth blob with extra data
    const initial = { registered: true, relay: "test.relay" };
    await store.save(
      "auth",
      new TextEncoder().encode(JSON.stringify(initial))
    );

    await saveLabel("my-label", store);

    const raw = await store.load("auth");
    const data = JSON.parse(new TextDecoder().decode(raw!));
    expect(data.registered).toBe(true);
    expect(data.relay).toBe("test.relay");
    expect(data.label).toBe("my-label");
  });
});
