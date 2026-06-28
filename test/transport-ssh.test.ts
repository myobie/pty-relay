import { describe, it, expect } from "vitest";
import {
  parseSshUrl,
  looksLikeSshUrl,
} from "../src/relay/transport-ssh.ts";

describe("parseSshUrl", () => {
  it("parses bare host", () => {
    expect(parseSshUrl("ssh://host")).toEqual({ userHost: "host", port: 22 });
  });

  it("parses user@host", () => {
    expect(parseSshUrl("ssh://me@host")).toEqual({
      userHost: "me@host",
      port: 22,
    });
  });

  it("parses host:port", () => {
    expect(parseSshUrl("ssh://host:2222")).toEqual({
      userHost: "host",
      port: 2222,
    });
  });

  it("parses user@host:port", () => {
    expect(parseSshUrl("ssh://me@host:2222")).toEqual({
      userHost: "me@host",
      port: 2222,
    });
  });

  it("accepts an FQDN host", () => {
    expect(parseSshUrl("ssh://me@a.b.example.com")).toEqual({
      userHost: "me@a.b.example.com",
      port: 22,
    });
  });

  it("accepts an IPv4 host", () => {
    expect(parseSshUrl("ssh://10.0.0.1:2222")).toEqual({
      userHost: "10.0.0.1",
      port: 2222,
    });
  });

  it("accepts a trailing slash (treated as empty path)", () => {
    expect(parseSshUrl("ssh://host/")).toEqual({ userHost: "host", port: 22 });
  });

  it("rejects a non-ssh scheme", () => {
    expect(() => parseSshUrl("https://host")).toThrow(/must start with ssh:\/\//);
  });

  it("rejects an empty URL after the scheme", () => {
    expect(() => parseSshUrl("ssh://")).toThrow(/no host/);
  });

  it("rejects a path component", () => {
    expect(() => parseSshUrl("ssh://host/path")).toThrow(/must not carry a path/);
  });

  it("rejects a non-numeric port", () => {
    expect(() => parseSshUrl("ssh://host:notaport")).toThrow(/invalid port/);
  });

  it("rejects an out-of-range port", () => {
    expect(() => parseSshUrl("ssh://host:0")).toThrow(/invalid port/);
    expect(() => parseSshUrl("ssh://host:99999")).toThrow(/invalid port/);
  });

  it("rejects an empty user-info segment", () => {
    expect(() => parseSshUrl("ssh://@host")).toThrow(/empty user-info/);
  });

  it("rejects an empty host with explicit user-info", () => {
    expect(() => parseSshUrl("ssh://me@")).toThrow(/empty host/);
  });

  it("rejects non-string input", () => {
    expect(() => parseSshUrl(42 as unknown as string)).toThrow(/must be a string/);
  });

  it("is robust to a `:` in a user (theoretically possible but unusual)", () => {
    // `user:tail@host` — the lastIndexOf("@") strategy means the
    // user-info before @ stays intact and we don't try to interpret
    // its colon as a port. The user-info is whatever ssh accepts; we
    // just pass it through verbatim.
    const r = parseSshUrl("ssh://user:tail@host:2222");
    expect(r).toEqual({ userHost: "user:tail@host", port: 2222 });
  });
});

describe("looksLikeSshUrl", () => {
  it("accepts ssh://", () => {
    expect(looksLikeSshUrl("ssh://host")).toBe(true);
  });

  it("rejects http/https/labels", () => {
    expect(looksLikeSshUrl("http://host")).toBe(false);
    expect(looksLikeSshUrl("https://host")).toBe(false);
    expect(looksLikeSshUrl("my-label")).toBe(false);
    expect(looksLikeSshUrl("")).toBe(false);
  });

  it("rejects non-string input gracefully (defensive against bad CLI args)", () => {
    expect(looksLikeSshUrl(null as unknown as string)).toBe(false);
    expect(looksLikeSshUrl(undefined as unknown as string)).toBe(false);
  });
});
