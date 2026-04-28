// @vitest-environment happy-dom
/**
 * Unit tests for the live latency tracker. Drives a fake xterm
 * `TermLike` so we can inject onData / onRender events at controlled
 * timestamps and verify the FIFO matching + summary stats.
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
  emitRender(): void;
}

function makeFakeTerm(): FakeTerm {
  let onDataCb: ((s: string) => void) | null = null;
  let onRenderCb: ((e: { start: number; end: number }) => void) | null = null;
  return {
    onData(cb) {
      onDataCb = cb;
      return { dispose() { onDataCb = null; } };
    },
    onRender(cb) {
      onRenderCb = cb;
      return { dispose() { onRenderCb = null; } };
    },
    emitData(s) { onDataCb?.(s); },
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

describe("createLatencyTracker", () => {
  it("returns zeroed summary when no events have happened yet", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    const s = tracker.summary();
    expect(s.count).toBe(0);
    expect(s.pending).toBe(0);
    expect(s.median).toBe(0);
    expect(s.samples).toEqual([]);
  });

  it("records a single roundtrip when one keystroke is followed by one render", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("a");
    now += 42;
    term.emitRender();
    const s = tracker.summary();
    expect(s.count).toBe(1);
    expect(s.pending).toBe(0);
    expect(s.median).toBe(42);
    expect(s.min).toBe(42);
    expect(s.max).toBe(42);
  });

  it("matches keystrokes to renders FIFO when multiple are in flight", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("a"); // sentAt = 1_000_000
    now += 10;
    term.emitData("b"); // sentAt = 1_000_010
    now += 30;          // now = 1_000_040
    term.emitRender(); // matches a, latency = 1_000_040 - 1_000_000 = 40ms
    now += 20;          // now = 1_000_060
    term.emitRender(); // matches b, latency = 1_000_060 - 1_000_010 = 50ms
    const s = tracker.summary();
    expect(s.count).toBe(2);
    expect(s.samples).toEqual([40, 50]);
    expect(s.pending).toBe(0);
  });

  it("each char in a multi-char onData enqueues separately (paste)", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("xyz");
    expect(tracker.summary().pending).toBe(3);
    now += 20;
    term.emitRender();
    now += 5;
    term.emitRender();
    now += 5;
    term.emitRender();
    const s = tracker.summary();
    expect(s.count).toBe(3);
    expect(s.pending).toBe(0);
  });

  it("renders without pending sends are no-ops (program output, not echo)", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitRender();
    term.emitRender();
    expect(tracker.summary().count).toBe(0);
    expect(tracker.summary().pending).toBe(0);
  });

  it("summary computes percentiles across the sample window", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    // Inject samples with latencies: 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
    for (let i = 0; i < 10; i++) {
      term.emitData("x");
      now += (i + 1) * 10;
      term.emitRender();
      // Reset 'now' so each cycle's elapsed equals (i+1)*10 from the matching sentAt.
    }
    const s = tracker.summary();
    expect(s.count).toBe(10);
    expect(s.min).toBe(10);
    expect(s.max).toBe(100);
    // p50 with 10 samples lands on the 5th -> 50; p95 lands on the 9th -> 100.
    expect(s.median).toBe(50);
    expect(s.p95).toBe(100);
  });

  it("caps the rolling window at 200 samples", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    for (let i = 0; i < 250; i++) {
      term.emitData("x");
      now += 10;
      term.emitRender();
    }
    expect(tracker.summary().count).toBe(200);
  });

  it("reset() clears samples and pending and restarts the window timer", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    term.emitData("a");
    now += 100;
    term.emitRender();
    term.emitData("b"); // pending
    now += 50;
    expect(tracker.summary().count).toBe(1);
    expect(tracker.summary().pending).toBe(1);
    tracker.reset();
    expect(tracker.summary().count).toBe(0);
    expect(tracker.summary().pending).toBe(0);
  });

  it("destroy() unhooks the listeners — subsequent events are ignored", () => {
    const term = makeFakeTerm();
    tracker = createLatencyTracker(term);
    tracker.destroy();
    term.emitData("a");
    term.emitRender();
    expect(tracker.summary().count).toBe(0);
    tracker = null; // disable afterEach destroy
  });
});

describe("formatSummary", () => {
  it("includes count, pending, latencies, and supplied context", () => {
    const out = formatSummary(
      {
        count: 42,
        pending: 3,
        min: 10,
        median: 25,
        p95: 80,
        max: 120,
        samples: [],
        windowSec: 30,
      },
      { ua: "Chrome/Mac", relay: "tailscale", viewportW: 1280, viewportH: 800 }
    );
    expect(out).toContain("samples: 42");
    expect(out).toContain("pending: 3");
    expect(out).toContain("median: 25ms");
    expect(out).toContain("p95: 80ms");
    expect(out).toContain("ua: Chrome/Mac");
    expect(out).toContain("relay: tailscale");
    expect(out).toContain("viewport: 1280×800");
  });

  it("notes when no samples yet", () => {
    const out = formatSummary({
      count: 0,
      pending: 0,
      min: 0,
      median: 0,
      p95: 0,
      max: 0,
      samples: [],
      windowSec: 0,
    });
    expect(out).toContain("no samples yet");
  });
});

describe("formatCompact", () => {
  it("returns n=0 with no samples", () => {
    expect(
      formatCompact({
        count: 0, pending: 0, min: 0, median: 0, p95: 0, max: 0, samples: [], windowSec: 0,
      })
    ).toBe("n=0");
  });

  it("returns a one-liner with median and p95", () => {
    expect(
      formatCompact({
        count: 12, pending: 0, min: 5, median: 22.4, p95: 60, max: 90, samples: [], windowSec: 5,
      })
    ).toBe("n=12 p50=22.4ms p95=60ms");
  });
});
