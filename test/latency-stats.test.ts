// @vitest-environment happy-dom
/**
 * Unit tests for the live latency tracker. Drives a fake xterm
 * `TermLike` so we can inject onData / onWriteParsed / onRender
 * events at controlled timestamps and verify the FIFO matching +
 * stage decomposition + report shape.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  createLatencyTracker,
  formatSummary,
  formatCompact,
  type TermLike,
  type LatencyTracker,
} from "../browser/src/latency-stats.ts";

interface FakeTerm extends TermLike {
  emitData(s: string): void;
  emitParsed(): void;
  emitRender(): void;
}

function makeFakeTerm(): FakeTerm {
  let onDataCb: ((s: string) => void) | null = null;
  let onParsedCb: (() => void) | null = null;
  let onRenderCb: ((e: { start: number; end: number }) => void) | null = null;
  return {
    onData(cb) {
      onDataCb = cb;
      return { dispose() { onDataCb = null; } };
    },
    onWriteParsed(cb) {
      onParsedCb = cb;
      return { dispose() { onParsedCb = null; } };
    },
    onRender(cb) {
      onRenderCb = cb;
      return { dispose() { onRenderCb = null; } };
    },
    emitData(s) { onDataCb?.(s); },
    emitParsed() { onParsedCb?.(); },
    emitRender() { onRenderCb?.({ start: 0, end: 0 }); },
  };
}

let now = 0;
let tracker: LatencyTracker | null = null;

beforeEach(() => {
  now = 1_000_000;
  vi.spyOn(performance, "now").mockImplementation(() => now);
});

afterEach(() => {
  tracker?.destroy();
  tracker = null;
  vi.restoreAllMocks();
});

/** Walk one keystroke through all four stages with the given per-
 *  stage durations (ms). Returns the simulated total. */
function fullStroke(term: FakeTerm, network: number, parse: number, paint: number): number {
  term.emitData("x");
  now += network;
  tracker!.recordRecv(8);
  now += parse;
  term.emitParsed();
  now += paint;
  term.emitRender();
  return network + parse + paint;
}

describe("createLatencyTracker", () => {
  it("zeros when nothing happened", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    const r = tracker.report();
    expect(r.keystrokes.count).toBe(0);
    expect(r.keystrokes.pending).toBe(0);
    expect(r.ws.count).toBe(0);
  });

  it("records a single full-stage keystroke with each stage's duration", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    fullStroke(term, 30, 5, 10); // network=30, parse=5, paint=10
    const r = tracker.report();
    expect(r.keystrokes.count).toBe(1);
    expect(r.keystrokes.pending).toBe(0);
    expect(r.keystrokes.samples[0]).toMatchObject({
      network: 30,
      parse: 5,
      paint: 10,
      total: 45,
    });
    expect(r.keystrokes.network).toMatchObject({ count: 1, median: 30 });
    expect(r.keystrokes.parse).toMatchObject({ count: 1, median: 5 });
    expect(r.keystrokes.paint).toMatchObject({ count: 1, median: 10 });
    expect(r.keystrokes.total).toMatchObject({ count: 1, median: 45 });
  });

  it("FIFO matches multiple in-flight keystrokes through stages", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    // Type two chars, then receive both echoes, then parse both, then render both.
    term.emitData("a"); // sentAt = 1_000_000
    now += 10;
    term.emitData("b"); // sentAt = 1_000_010
    now += 30;          // 30ms after b
    tracker.recordRecv(1);  // a's recvAt — 40ms after a was sent
    now += 5;
    tracker.recordRecv(1);  // b's recvAt — 35ms after b was sent
    now += 5;
    term.emitParsed();      // a's parsedAt — 5ms parse for a
    now += 2;
    term.emitParsed();      // b's parsedAt — 7ms parse for b
    now += 8;
    term.emitRender();      // a's renderedAt — 10ms paint for a
    now += 3;
    term.emitRender();      // b's renderedAt — 11ms paint for b
    const r = tracker.report();
    expect(r.keystrokes.count).toBe(2);
    // Stage-level aggregates: each stage's [a,b] sample list,
    // sorted, picking ceil(2*0.5)-1 = idx 0:
    //   network = [40, 35]  -> sorted [35, 40]  -> 35
    //   parse   = [10, 7]   -> sorted [7, 10]   -> 7
    //   paint   = [10, 11]  -> sorted [10, 11]  -> 10
    expect(r.keystrokes.network.median).toBe(35);
    expect(r.keystrokes.parse.median).toBe(7);
    expect(r.keystrokes.paint.median).toBe(10);
  });

  it("an entry without recvAt yet is counted as pending, not as a sample", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("x"); // pending: 1
    expect(tracker.report().keystrokes.pending).toBe(1);
    expect(tracker.report().keystrokes.count).toBe(0);
    // Render fires without recv → no sample, no advance.
    term.emitRender();
    expect(tracker.report().keystrokes.pending).toBe(1);
    expect(tracker.report().keystrokes.count).toBe(0);
  });

  it("each char in a multi-char onData enqueues separately", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("xyz");
    expect(tracker.report().keystrokes.pending).toBe(3);
    // Walk all three through the pipeline.
    for (let i = 0; i < 3; i++) {
      now += 10;
      tracker.recordRecv(1);
      now += 1;
      term.emitParsed();
      now += 5;
      term.emitRender();
    }
    expect(tracker.report().keystrokes.count).toBe(3);
    expect(tracker.report().keystrokes.pending).toBe(0);
  });

  it("renders without pending entries are no-ops", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitRender();
    term.emitRender();
    expect(tracker.report().keystrokes.count).toBe(0);
    expect(tracker.report().keystrokes.pending).toBe(0);
  });

  it("computes percentiles across the sample window", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    // 10 samples with totals 10..100ms (network 10-100, parse=0, paint=0)
    for (let i = 1; i <= 10; i++) {
      fullStroke(term, i * 10, 0, 0);
    }
    const r = tracker.report();
    expect(r.keystrokes.count).toBe(10);
    expect(r.keystrokes.total.min).toBe(10);
    expect(r.keystrokes.total.max).toBe(100);
    // Nearest-rank: ceil(10*0.5)-1 = 4 -> [50]; ceil(10*0.95)-1 = 9 -> [100]
    expect(r.keystrokes.total.median).toBe(50);
    expect(r.keystrokes.total.p95).toBe(100);
  });

  it("caps the rolling sample window at 200", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    for (let i = 0; i < 250; i++) fullStroke(term, 10, 1, 1);
    expect(tracker.report().keystrokes.count).toBe(200);
  });

  it("reset() clears samples + pending + ws state", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    fullStroke(term, 10, 1, 1);
    term.emitData("y"); // pending
    tracker.recordRecv(8); // ws frame
    expect(tracker.report().keystrokes.count).toBe(1);
    expect(tracker.report().keystrokes.pending).toBe(1);
    expect(tracker.report().ws.count).toBe(2); // 1 from fullStroke, 1 from above
    tracker.reset();
    expect(tracker.report().keystrokes.count).toBe(0);
    expect(tracker.report().keystrokes.pending).toBe(0);
    expect(tracker.report().ws.count).toBe(0);
  });

  it("destroy() unhooks listeners", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    tracker.destroy();
    term.emitData("a");
    tracker.recordRecv(8);
    term.emitParsed();
    term.emitRender();
    expect(tracker.report().keystrokes.count).toBe(0);
    tracker = null;
  });
});

describe("WS frame stats", () => {
  it("captures per-frame size + inter-arrival", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    tracker.recordRecv(64);
    now += 100;
    tracker.recordRecv(128);
    now += 50;
    tracker.recordRecv(32);
    const r = tracker.report();
    expect(r.ws.count).toBe(3);
    expect(r.ws.sizes).toEqual([64, 128, 32]);
    expect(r.ws.interArrivalMs).toEqual([100, 50]);
  });

  it("WS ring caps independently at 200", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    for (let i = 0; i < 250; i++) tracker.recordRecv(10);
    expect(tracker.report().ws.count).toBe(200);
  });
});

describe("summary() (compact total view)", () => {
  it("matches keystroke total stats", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    fullStroke(term, 30, 5, 10); // total 45
    fullStroke(term, 60, 5, 10); // total 75
    const s = tracker.summary();
    expect(s.count).toBe(2);
    expect(s.median).toBe(45); // n=2 nearest-rank lower
    expect(s.max).toBe(75);
  });
});

describe("formatSummary", () => {
  it("includes count, pending, latencies, supplied context", () => {
    const out = formatSummary(
      {
        count: 42, pending: 3, min: 10, median: 25, p95: 80, max: 120, windowSec: 30,
      },
      { ua: "Chrome/Mac", relay: "tailscale", viewportW: 1280, viewportH: 800 }
    );
    expect(out).toContain("samples: 42");
    expect(out).toContain("median: 25ms");
    expect(out).toContain("ua: Chrome/Mac");
    expect(out).toContain("viewport: 1280×800");
  });
});

describe("formatCompact", () => {
  it("returns n=0 with no samples", () => {
    expect(
      formatCompact({ count: 0, pending: 0, min: 0, median: 0, p95: 0, max: 0, windowSec: 0 })
    ).toBe("n=0");
  });

  it("returns a one-liner with median and p95", () => {
    expect(
      formatCompact({ count: 12, pending: 0, min: 5, median: 22.4, p95: 60, max: 90, windowSec: 5 })
    ).toBe("n=12 p50=22.4ms p95=60ms");
  });
});
