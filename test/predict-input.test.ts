// @vitest-environment happy-dom
/**
 * Unit tests for createInputPredictor. Drives a fake Terminal whose
 * .write captures bytes (so we can assert what reached xterm) and
 * .buffer reports a configurable cursor + buffer-type. The predictor
 * doesn't depend on xterm's full surface; this fake covers what it
 * uses.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createInputPredictor } from "../browser/src/predict-input.ts";
import type { Terminal } from "@xterm/xterm";

interface FakeBuffer {
  type: "normal" | "alternate";
  cursorX: number;
  cursorY: number;
}

interface FakeTerm extends Pick<Terminal, "write"> {
  written: string[];
  buffer: { active: FakeBuffer };
}

function makeFakeTerm(initial: Partial<FakeBuffer> = {}): FakeTerm {
  const buf: FakeBuffer = {
    type: "normal",
    cursorX: 0,
    cursorY: 0,
    ...initial,
  };
  const written: string[] = [];
  return {
    written,
    buffer: { active: buf },
    // The fake's `write` simulates "char advances cursor by 1" and
    // strips ANSI sequences (CSI H + CSI K) we use for rollback so
    // tests can inspect the rollback bytes directly.
    write(data: string | Uint8Array): boolean {
      const s = typeof data === "string" ? data : new TextDecoder().decode(data);
      written.push(s);
      // Naive cursor model: any printable char advances by 1, any
      // CSI H sequence resets cursorX/cursorY.
      let i = 0;
      while (i < s.length) {
        if (s[i] === "\x1b" && s[i + 1] === "[") {
          // Find the final byte (a letter)
          let j = i + 2;
          while (j < s.length && !/[A-Za-z]/.test(s[j])) j++;
          const params = s.slice(i + 2, j);
          const finalByte = s[j];
          if (finalByte === "H") {
            const [r, c] = params.split(";").map((n) => parseInt(n, 10) || 1);
            buf.cursorY = r - 1;
            buf.cursorX = c - 1;
          }
          // Other CSI sequences ignored for cursor tracking.
          i = j + 1;
          continue;
        }
        if (s[i] >= "\x20" && s[i] <= "\x7e") {
          buf.cursorX++;
        }
        i++;
      }
      return true;
    },
  };
}

let captured: string[] = [];
const sendToServer = (data: string) => {
  captured.push(data);
};

beforeEach(() => {
  captured = [];
});

describe("createInputPredictor — disabled (default)", () => {
  it("forwards user input verbatim and writes server data straight to term", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer });
    p.onUserData("ab");
    expect(captured).toEqual(["ab"]);
    expect(t.written).toEqual([]); // no prediction, no echo to term

    p.onServerData("ab");
    expect(t.written).toEqual(["ab"]);
  });
});

describe("createInputPredictor — enabled, happy path", () => {
  it("predicts each printable char, then silently consumes matching server echo", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });

    p.onUserData("ab");
    // Both chars predicted to term, plus the data forwarded to server.
    expect(t.written).toEqual(["a", "b"]);
    expect(captured).toEqual(["ab"]);
    expect(p.pendingCount()).toBe(2);

    // Server echoes "ab" — both bytes match queue heads, no extra
    // writes to term.
    const before = t.written.length;
    p.onServerData("ab");
    expect(t.written.length).toBe(before);
    expect(p.pendingCount()).toBe(0);
  });

  it("partial server output: matching prefix consumes; remainder writes", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    p.onUserData("ab");
    expect(p.pendingCount()).toBe(2);
    // Server sends "abXY" — first two match, last two are extra.
    p.onServerData("abXY");
    expect(p.pendingCount()).toBe(0);
    // The "XY" should land in term.
    expect(t.written.slice(-1)[0]).toBe("XY");
  });
});

describe("createInputPredictor — disagreement / rollback", () => {
  it("rolls back predictions when first server byte disagrees", () => {
    const t = makeFakeTerm({ cursorX: 2, cursorY: 0 });
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });

    // User types "ab" at column 2 — predictions land at (0,2) and (0,3).
    p.onUserData("ab");
    expect(t.written).toEqual(["a", "b"]);

    // Server sends "**" instead — password mode.
    p.onServerData("**");
    // Expect rollback: CSI 1;3 H (move to row 1 col 3) + CSI K, then "**"
    const all = t.written.join("");
    expect(all).toContain("\x1b[1;3H\x1b[K");
    expect(all.endsWith("**")).toBe(true);
    expect(p.pendingCount()).toBe(0);
  });

  it("rolls back when server sends a non-matching control sequence", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    p.onUserData("a");
    // Server sends "\r$ " (CR then prompt redraw) — not the predicted 'a'.
    p.onServerData("\r$ ");
    // Rollback CSI then the server bytes verbatim.
    const all = t.written.join("");
    expect(all).toContain("\x1b[K");
    expect(all.endsWith("\r$ ")).toBe(true);
    expect(p.pendingCount()).toBe(0);
  });
});

describe("createInputPredictor — alt-screen mode", () => {
  it("does NOT predict when the terminal is on the alternate buffer", () => {
    const t = makeFakeTerm({ type: "alternate" });
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });

    p.onUserData("a");
    // No prediction written to term; data forwarded to server.
    expect(t.written).toEqual([]);
    expect(captured).toEqual(["a"]);
    expect(p.pendingCount()).toBe(0);
  });

  it("server data passes through untouched when alt-screen and no predictions", () => {
    const t = makeFakeTerm({ type: "alternate" });
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    p.onServerData("\x1b[H\x1b[2J vim startup ");
    // The \x1b[H sequence resets cursor in our fake; we just verify
    // the bytes flowed.
    expect(t.written.join("")).toContain("vim startup");
  });
});

describe("createInputPredictor — non-printable input", () => {
  it("does not predict control characters (Enter, arrows, Ctrl+C, etc.)", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });

    // Enter
    p.onUserData("\r");
    // Arrow up
    p.onUserData("\x1b[A");
    // Ctrl+C
    p.onUserData("\x03");
    expect(t.written).toEqual([]);
    expect(p.pendingCount()).toBe(0);
    // All forwarded to server though.
    expect(captured).toEqual(["\r", "\x1b[A", "\x03"]);
  });

  it("does not predict any chars in a mixed batch with control bytes", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    // term.onData fires once per keystroke; a batch containing both
    // printable + control bytes is unusual (paste with embedded \r).
    // Treat it as not-a-plain-keystroke — skip prediction entirely.
    p.onUserData("ab\rcd");
    expect(t.written).toEqual([]);
    expect(p.pendingCount()).toBe(0);
    expect(captured).toEqual(["ab\rcd"]);
  });
});

describe("createInputPredictor — runtime control", () => {
  it("setEnabled(false) rolls back outstanding predictions", () => {
    const t = makeFakeTerm({ cursorX: 5 });
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    p.onUserData("ab");
    expect(p.pendingCount()).toBe(2);

    p.setEnabled(false);
    expect(p.pendingCount()).toBe(0);
    // A rollback CSI was emitted.
    expect(t.written.join("")).toContain("\x1b[1;6H\x1b[K");
  });

  it("setEnabled(true) starts predicting from that point on", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: false });
    p.onUserData("a");
    expect(t.written).toEqual([]); // not predicted

    p.setEnabled(true);
    p.onUserData("b");
    expect(t.written).toEqual(["b"]);
    expect(p.pendingCount()).toBe(1);
  });

  it("queue is capped to prevent runaway growth on a silent server", () => {
    const t = makeFakeTerm();
    const p = createInputPredictor({ term: t as any, sendToServer, enabled: true });
    // Type 50 chars — cap is 32.
    p.onUserData("a".repeat(50));
    expect(p.pendingCount()).toBeLessThanOrEqual(32);
    // The first 32 should have been predicted; the rest forwarded
    // but not predicted.
    expect(t.written.join("").length).toBe(32);
  });
});

