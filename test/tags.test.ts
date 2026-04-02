import { describe, it, expect } from "vitest";
import { extractTagFlags } from "../src/args.ts";
import { renderTags } from "../src/commands/ls.ts";

describe("extractTagFlags", () => {
  it("returns empty object when no --tag flags are present", () => {
    expect(extractTagFlags(["connect", "http://example/#foo"])).toEqual({});
  });

  it("parses a single --tag key=value", () => {
    expect(extractTagFlags(["--tag", "project=boom"])).toEqual({ project: "boom" });
  });

  it("parses multiple --tag flags into one record", () => {
    expect(extractTagFlags([
      "--tag", "project=boom",
      "--tag", "role=agent",
      "--tag", "env=prod",
    ])).toEqual({ project: "boom", role: "agent", env: "prod" });
  });

  it("preserves values containing = after the first =", () => {
    expect(extractTagFlags(["--tag", "filter=key=value"])).toEqual({
      filter: "key=value",
    });
  });

  it("ignores non-tag args interleaved between --tag flags", () => {
    expect(extractTagFlags([
      "--spawn", "foo",
      "--tag", "a=1",
      "--cwd", "/tmp",
      "--tag", "b=2",
    ])).toEqual({ a: "1", b: "2" });
  });

  it("last occurrence wins when the same key is given twice", () => {
    expect(extractTagFlags([
      "--tag", "role=agent",
      "--tag", "role=server",
    ])).toEqual({ role: "server" });
  });
});

describe("renderTags", () => {
  it("returns empty string when tags is undefined", () => {
    expect(renderTags(undefined)).toBe("");
  });

  it("returns empty string when tags is empty", () => {
    expect(renderTags({})).toBe("");
  });

  it("renders user tags as #key=value pairs with a leading space", () => {
    expect(renderTags({ role: "agent", env: "prod" })).toBe(" #role=agent #env=prod");
  });

  it("hides internal bookkeeping keys that pty already handles elsewhere", () => {
    expect(renderTags({
      ptyfile: "/path/pty.toml",
      "ptyfile.session": "claude",
      "ptyfile.tags": "role",
      "supervisor.status": "managed",
      strategy: "permanent",
    })).toBe("");
  });

  it("mixes user tags and internal keys, showing only user-meaningful ones", () => {
    expect(renderTags({
      role: "agent",
      ptyfile: "/path/pty.toml",
      project: "relay",
    })).toBe(" #role=agent #project=relay");
  });
});
