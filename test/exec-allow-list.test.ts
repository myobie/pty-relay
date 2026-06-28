import { describe, it, expect } from "vitest";
import {
  EXEC_ALLOW_LIST,
  checkArgvAllowed,
} from "../src/relay/exec-allow-list.ts";

describe("EXEC_ALLOW_LIST", () => {
  it("ships rsync and git in v1", () => {
    expect(EXEC_ALLOW_LIST).toContain("rsync");
    expect(EXEC_ALLOW_LIST).toContain("git");
  });
});

describe("checkArgvAllowed", () => {
  it("accepts a bare allow-listed basename", () => {
    expect(checkArgvAllowed("rsync")).toBe("rsync");
    expect(checkArgvAllowed("git")).toBe("git");
  });

  it("accepts a /usr/bin-prefixed path and returns the basename", () => {
    expect(checkArgvAllowed("/usr/bin/rsync")).toBe("rsync");
    expect(checkArgvAllowed("/opt/homebrew/bin/git")).toBe("git");
  });

  it("rejects an unknown executable", () => {
    expect(checkArgvAllowed("curl")).toBeNull();
    expect(checkArgvAllowed("nc")).toBeNull();
    expect(checkArgvAllowed("bash")).toBeNull();
  });

  it("rejects an empty argv0", () => {
    expect(checkArgvAllowed("")).toBeNull();
  });

  it("rejects argv0 that's just a path separator", () => {
    expect(checkArgvAllowed("/")).toBeNull();
  });

  it("rejects path traversal attempts that aren't allow-listed at the basename", () => {
    // "../../rsync" basename is "rsync" — that IS allowed. The
    // allow-list is intentionally permissive about *which* rsync runs;
    // the operator implicitly trusts whatever's in their PATH.
    expect(checkArgvAllowed("../rsync")).toBe("rsync");
    // A path that ends in a non-allow-listed name is still rejected.
    expect(checkArgvAllowed("/usr/bin/curl")).toBeNull();
  });

  it("rejects non-string inputs gracefully (defensive against bad JSON)", () => {
    // checkArgvAllowed is the gate at the daemon's channel_open path;
    // garbage from the wire must not throw.
    expect(checkArgvAllowed(undefined as unknown as string)).toBeNull();
    expect(checkArgvAllowed(null as unknown as string)).toBeNull();
    expect(checkArgvAllowed(42 as unknown as string)).toBeNull();
  });

  it("backslash on windows-style paths is handled", () => {
    expect(checkArgvAllowed("C:\\Program Files\\Git\\bin\\git")).toBe("git");
  });
});
