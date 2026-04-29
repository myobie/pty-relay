/**
 * Live latency tracking for the web terminal.
 *
 * Pipeline we measure, with one timestamp per stage:
 *
 *   user keystroke -> term.onData                    (sentAt)
 *     -> encrypt -> WS send -> daemon -> pty -> echo back
 *     -> ws.onmessage (binary)                       (recvAt)
 *     -> decrypt -> term.write -> onWriteParsed      (parsedAt)
 *     -> next RAF -> term.onRender                   (renderedAt)
 *
 * Per-stage durations:
 *   network = recvAt    - sentAt    (encrypt + WS round-trip + decrypt)
 *   parse   = parsedAt  - recvAt    (xterm parser handling the bytes)
 *   paint   = renderedAt - parsedAt (RAF wait + actual paint)
 *
 * We can't tie a SPECIFIC echo byte back to its origin keystroke
 * without protocol changes — bash echoes match what you typed in
 * order, but program output is intermixed and the daemon may batch
 * many chars into one WS frame. So this is FIFO matching at every
 * stage: each event (recv, parse, render) advances the oldest
 * pending entry to its next stage. For "type into a shell prompt"
 * this is accurate per-char; for noisy programs the per-sample
 * breakdown is biased upward (queue inflation) but the AGGREGATE
 * per-stage medians remain meaningful, since N keystrokes still
 * produce N stage transitions on average.
 *
 * Design choice: this module knows about WebSocket recv timing
 * (via recordRecv called by main.ts) but nothing about Noise or
 * the relay protocol. All measurements are end-user-felt latency
 * decomposed into the parts we can observe in the browser.
 */

/** Aggregate stats over a single dimension (total, network, parse,
 *  paint). Empty when count = 0. All ms. */
export interface StageStats {
  count: number;
  min: number;
  median: number;
  p95: number;
  max: number;
}

/** One completed keystroke's per-stage timings. */
export interface StagedSample {
  /** Wall-clock-ish performance.now() — useful as an x-axis when
   *  charting samples within a window. Origin is the page load. */
  sentAt: number;
  /** Per-stage durations in ms (rounded to 0.1). */
  network: number;
  parse: number;
  paint: number;
  total: number;
}

export interface KeystrokeReport {
  count: number;
  /** Entries in flight without all four stages filled. */
  pending: number;
  /** Window length, seconds. */
  windowSec: number;
  total: StageStats;
  network: StageStats;
  parse: StageStats;
  paint: StageStats;
  samples: StagedSample[];
}

/** Per-WebSocket-frame metrics captured outside the xterm event loop. */
export interface WsFrameStats {
  count: number;
  /** Bytes per frame across the window. */
  sizes: number[];
  /** Gaps between consecutive frame arrivals, in ms. */
  interArrivalMs: number[];
}

/** A full structured report. Snapshot-able, JSON-stringifiable;
 *  flushed to the daemon periodically as a JSONL line. */
export interface LatencyReport {
  /** ms since unix epoch — wall-clock for log correlation. */
  startedAt: number;
  endedAt: number;
  keystrokes: KeystrokeReport;
  ws: WsFrameStats;
}

/** Compact, back-compat-ish summary for the toolbar indicator. We
 *  keep it as the "total" view. */
export interface LatencySummary {
  count: number;
  pending: number;
  min: number;
  median: number;
  p95: number;
  max: number;
  windowSec: number;
}

export interface LatencyTracker {
  /** Compact "total" snapshot (used by the toolbar indicator). */
  summary(): LatencySummary;
  /** Build a full structured report covering the current window. */
  report(): LatencyReport;
  /** Note an incoming WebSocket binary frame. Caller passes byte
   *  length. The tracker timestamps internally and uses this as
   *  the recvAt for the next pending keystroke. */
  recordRecv(bytes: number): void;
  /** Drop all samples + pending. Call after a successful flush so
   *  each report covers a disjoint window. */
  reset(): void;
  destroy(): void;
}

/** Minimal subset of xterm.js Terminal that this module needs. */
export interface TermLike {
  onData(cb: (data: string) => void): { dispose(): void };
  onRender(cb: (e: { start: number; end: number }) => void): { dispose(): void };
  /** Fires after `term.write()` completes (parser done). xterm.js
   *  exposes this as `onWriteParsed`. */
  onWriteParsed(cb: () => void): { dispose(): void };
}

const SAMPLE_CAP = 200;
const PENDING_CAP = 1000;
const WS_FRAME_CAP = 200;

interface PendingEntry {
  sentAt: number;
  recvAt?: number;
  parsedAt?: number;
}

export function createLatencyTracker(term: TermLike): LatencyTracker {
  // Pending: keystrokes with sentAt set but not yet seen all stages.
  // We don't preserve renderedAt here — once we see a render, we
  // promote the entry to a completed sample and remove from pending.
  const pending: PendingEntry[] = [];
  const samples: StagedSample[] = [];
  const wsArrivals: number[] = [];
  const wsSizes: number[] = [];
  let trackerStartedAt = performance.now();
  let trackerStartedAtMs = Date.now();

  const onDataDisposer = term.onData((data: string) => {
    const now = performance.now();
    for (let i = 0; i < data.length; i++) {
      pending.push({ sentAt: now });
      if (pending.length > PENDING_CAP) pending.shift();
    }
  });

  // Each event advances the OLDEST pending entry that hasn't yet
  // filled this stage AND whose previous stage IS filled. With
  // strict FIFO ordering that's just `pending.find(predicate)`.
  function advanceRecv(): void {
    const entry = pending.find((p) => p.recvAt === undefined);
    if (entry) entry.recvAt = performance.now();
  }
  function advanceParsed(): void {
    const entry = pending.find(
      (p) => p.recvAt !== undefined && p.parsedAt === undefined
    );
    if (entry) entry.parsedAt = performance.now();
  }
  function advanceRender(): void {
    // First entry with parsedAt set — promote to a completed sample.
    const idx = pending.findIndex((p) => p.parsedAt !== undefined);
    if (idx === -1) return;
    const entry = pending[idx];
    pending.splice(idx, 1);
    const now = performance.now();
    samples.push({
      sentAt: round1(entry.sentAt - trackerStartedAt), // relative-to-window for compactness
      network: round1((entry.recvAt ?? now) - entry.sentAt),
      parse: round1((entry.parsedAt ?? now) - (entry.recvAt ?? now)),
      paint: round1(now - (entry.parsedAt ?? now)),
      total: round1(now - entry.sentAt),
    });
    if (samples.length > SAMPLE_CAP) samples.shift();
  }

  const onWriteParsedDisposer = term.onWriteParsed(() => {
    advanceParsed();
  });
  const onRenderDisposer = term.onRender(() => {
    advanceRender();
  });

  function statsFromArray(values: number[]): StageStats {
    if (values.length === 0) {
      return { count: 0, min: 0, median: 0, p95: 0, max: 0 };
    }
    const sorted = values.slice().sort((a, b) => a - b);
    const pct = (p: number) =>
      sorted[Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1))];
    return {
      count: values.length,
      min: round1(sorted[0]),
      median: round1(pct(0.5)),
      p95: round1(pct(0.95)),
      max: round1(sorted[sorted.length - 1]),
    };
  }

  function summaryNow(): LatencySummary {
    const totals = samples.map((s) => s.total);
    const stats = statsFromArray(totals);
    return {
      count: stats.count,
      pending: pending.length,
      min: stats.min,
      median: stats.median,
      p95: stats.p95,
      max: stats.max,
      windowSec: round1((performance.now() - trackerStartedAt) / 1000),
    };
  }

  function keystrokeReportNow(): KeystrokeReport {
    return {
      count: samples.length,
      pending: pending.length,
      windowSec: round1((performance.now() - trackerStartedAt) / 1000),
      total: statsFromArray(samples.map((s) => s.total)),
      network: statsFromArray(samples.map((s) => s.network)),
      parse: statsFromArray(samples.map((s) => s.parse)),
      paint: statsFromArray(samples.map((s) => s.paint)),
      samples: samples.slice(),
    };
  }

  function wsStatsNow(): WsFrameStats {
    const interArrival: number[] = [];
    for (let i = 1; i < wsArrivals.length; i++) {
      interArrival.push(round1(wsArrivals[i] - wsArrivals[i - 1]));
    }
    return {
      count: wsArrivals.length,
      sizes: wsSizes.slice(),
      interArrivalMs: interArrival,
    };
  }

  return {
    summary: summaryNow,
    report(): LatencyReport {
      return {
        startedAt: trackerStartedAtMs,
        endedAt: Date.now(),
        keystrokes: keystrokeReportNow(),
        ws: wsStatsNow(),
      };
    },
    recordRecv(bytes: number): void {
      const now = performance.now();
      wsArrivals.push(now);
      wsSizes.push(bytes);
      if (wsArrivals.length > WS_FRAME_CAP) {
        wsArrivals.shift();
        wsSizes.shift();
      }
      advanceRecv();
    },
    reset() {
      pending.length = 0;
      samples.length = 0;
      wsArrivals.length = 0;
      wsSizes.length = 0;
      trackerStartedAt = performance.now();
      trackerStartedAtMs = Date.now();
    },
    destroy() {
      onDataDisposer.dispose();
      onRenderDisposer.dispose();
      onWriteParsedDisposer.dispose();
    },
  };
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

/** Format a summary as a human-readable multi-line block suitable for
 *  pasting into chat. Includes UA + connection info passed by caller. */
export function formatSummary(
  s: LatencySummary,
  context: { ua?: string; relay?: string; viewportW?: number; viewportH?: number } = {}
): string {
  const lines = [
    "pty-relay web latency",
    "─────────────────────",
    `samples: ${s.count}   pending: ${s.pending}   window: ${s.windowSec}s`,
  ];
  if (s.count > 0) {
    lines.push(
      `min: ${s.min}ms   median: ${s.median}ms   p95: ${s.p95}ms   max: ${s.max}ms`
    );
  } else {
    lines.push("(no samples yet — type some characters into the terminal)");
  }
  if (context.ua) lines.push(`ua: ${context.ua}`);
  if (context.relay) lines.push(`relay: ${context.relay}`);
  if (context.viewportW && context.viewportH) {
    lines.push(`viewport: ${context.viewportW}×${context.viewportH}`);
  }
  return lines.join("\n");
}

/** Compact single-line form, useful for a status indicator in the
 *  toolbar so the user can eyeball latency at a glance. */
export function formatCompact(s: LatencySummary): string {
  if (s.count === 0) return `n=0`;
  return `n=${s.count} p50=${s.median}ms p95=${s.p95}ms`;
}
