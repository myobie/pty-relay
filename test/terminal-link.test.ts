import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { osc8Link } from "../src/terminal-link.ts";

/**
 * The helper has two responsibilities:
 *   1. Emit OSC 8 escape sequences when stdout is a TTY (so terminals
 *      render the URL as a clickable link).
 *   2. Stay silent — emit the bare URL — when output is piped /
 *      redirected so log files and CI consumers don't see escape
 *      noise. The honour-NO_COLOR / FORCE_COLOR convention is the
 *      well-trodden path.
 */

const ESC = "\x1b";
const BEL = "\x07";

let savedTty: boolean | undefined;
let savedNoColor: string | undefined;
let savedForceColor: string | undefined;

beforeEach(() => {
  savedTty = process.stdout.isTTY;
  savedNoColor = process.env.NO_COLOR;
  savedForceColor = process.env.FORCE_COLOR;
  delete process.env.NO_COLOR;
  delete process.env.FORCE_COLOR;
});

afterEach(() => {
  // Restore — vitest shares the process across files, so leaking
  // would make later tests TTY-dependent.
  Object.defineProperty(process.stdout, "isTTY", {
    configurable: true,
    value: savedTty,
  });
  if (savedNoColor === undefined) delete process.env.NO_COLOR;
  else process.env.NO_COLOR = savedNoColor;
  if (savedForceColor === undefined) delete process.env.FORCE_COLOR;
  else process.env.FORCE_COLOR = savedForceColor;
});

function setTty(value: boolean) {
  Object.defineProperty(process.stdout, "isTTY", {
    configurable: true,
    value,
  });
}

describe("osc8Link", () => {
  it("emits OSC 8 sequence when stdout is a TTY", () => {
    setTty(true);
    const url = "http://localhost:8099/#abc.def";
    const result = osc8Link(url);
    expect(result).toBe(`${ESC}]8;;${url}${BEL}${url}${ESC}]8;;${BEL}`);
  });

  it("uses a label when supplied (still TTY)", () => {
    setTty(true);
    const url = "https://example.com";
    const result = osc8Link(url, "click me");
    expect(result).toBe(`${ESC}]8;;${url}${BEL}click me${ESC}]8;;${BEL}`);
  });

  it("falls back to bare URL when stdout is not a TTY (pipe/redirect)", () => {
    setTty(false);
    const url = "http://localhost:8099/#abc.def";
    expect(osc8Link(url)).toBe(url);
  });

  it("when not a TTY and a label differs from URL, prints both readably", () => {
    setTty(false);
    expect(osc8Link("https://example.com", "docs")).toBe("docs (https://example.com)");
  });

  it("NO_COLOR=1 disables escapes even on a TTY", () => {
    setTty(true);
    process.env.NO_COLOR = "1";
    expect(osc8Link("https://x.test")).toBe("https://x.test");
  });

  it("FORCE_COLOR=1 enables escapes even when not a TTY", () => {
    setTty(false);
    process.env.FORCE_COLOR = "1";
    const url = "https://x.test";
    expect(osc8Link(url)).toBe(`${ESC}]8;;${url}${BEL}${url}${ESC}]8;;${BEL}`);
  });

  it("FORCE_COLOR=0 takes precedence over a TTY", () => {
    setTty(true);
    process.env.FORCE_COLOR = "0";
    expect(osc8Link("https://x.test")).toBe("https://x.test");
  });
});
