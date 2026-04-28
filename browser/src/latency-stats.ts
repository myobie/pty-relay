/**
 * Live latency tracking for the web terminal.
 *
 * Pipeline we measure:
 *   user keystroke -> term.onData (sentAt)
 *     -> encrypt -> WS send -> daemon -> pty -> echo back
 *     -> WS recv -> decrypt -> term.write -> onWriteParsed
 *     -> next RAF -> onRender (renderedAt)
 *
 * We can't tie a specific echo byte back to its origin keystroke
 * without protocol changes — bash echoes match what you typed in
 * order, but program output is intermixed. So this is a FIFO
 * approximation: each user keystroke pushes a timestamp; each render
 * pops one. For "type into a shell prompt and watch it appear" this
 * is accurate; for noisy programs it's biased upward (drops are
 * silent so the count is a sanity-check, not a guarantee).
 *
 * Design choice: this module knows nothing about WebSocket or Noise.
 * It only sees xterm.js events. That's intentional — the user's
 * "letter doesn't appear fast enough" complaint is end-to-end, and
 * end-to-end is what we measure here.
 */

export interface LatencySummary {
  count: number;
  /** Pending sends with no matched render yet. Useful sanity check —
   *  if this number grows large, the FIFO approximation is breaking
   *  down (program output disambiguation issue, see module docs). */
  pending: number;
  /** All in milliseconds. */
  min: number;
  median: number;
  p95: number;
  max: number;
  /** Recent samples (last 200), for advanced analysis. */
  samples: number[];
  /** Window over which samples were collected, in seconds. */
  windowSec: number;
}

export interface LatencyTracker {
  /** Snapshot the current rolling window. */
  summary(): LatencySummary;
  /** Drop all samples + pending. Call when attaching to a new session. */
  reset(): void;
  /** Tear down event listeners. Returned by the factory's startup. */
  destroy(): void;
}

/** Minimal subset of xterm.js Terminal that this module needs. The
 *  full type from @xterm/xterm has dozens of fields; pulling them
 *  in would couple this module to the browser bundle's type space.
 *  Test code can pass a fake that exposes only these. */
export interface TermLike {
  onData(cb: (data: string) => void): { dispose(): void };
  onRender(cb: (e: { start: number; end: number }) => void): { dispose(): void };
}

const SAMPLE_CAP = 200;

export function createLatencyTracker(term: TermLike): LatencyTracker {
  const pending: number[] = []; // queue of sentAt timestamps
  const samples: number[] = []; // ring of completed roundtrip ms
  let trackerStartedAt = performance.now();

  const onDataDisposer = term.onData((data: string) => {
    const now = performance.now();
    // Push one timestamp per character. Pasting N chars at once is one
    // onData with N chars — they should each get marked since each
    // echoes back individually.
    for (let i = 0; i < data.length; i++) pending.push(now);
  });

  const onRenderDisposer = term.onRender(() => {
    if (pending.length === 0) return;
    const sentAt = pending.shift()!;
    const elapsed = performance.now() - sentAt;
    samples.push(elapsed);
    if (samples.length > SAMPLE_CAP) samples.shift();
  });

  return {
    summary(): LatencySummary {
      if (samples.length === 0) {
        return {
          count: 0,
          pending: pending.length,
          min: 0,
          median: 0,
          p95: 0,
          max: 0,
          samples: [],
          windowSec: (performance.now() - trackerStartedAt) / 1000,
        };
      }
      const sorted = samples.slice().sort((a, b) => a - b);
      // Nearest-rank percentile: ceil(n*p) - 1, clamped to [0, n-1].
      // For n=10, p=0.5 → idx 4 (the 5th value); p=0.95 → idx 9.
      const pct = (p: number) =>
        sorted[Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * p) - 1))];
      return {
        count: samples.length,
        pending: pending.length,
        min: round1(sorted[0]),
        median: round1(pct(0.5)),
        p95: round1(pct(0.95)),
        max: round1(sorted[sorted.length - 1]),
        samples: samples.slice(),
        windowSec: round1((performance.now() - trackerStartedAt) / 1000),
      };
    },
    reset() {
      pending.length = 0;
      samples.length = 0;
      trackerStartedAt = performance.now();
    },
    destroy() {
      onDataDisposer.dispose();
      onRenderDisposer.dispose();
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
