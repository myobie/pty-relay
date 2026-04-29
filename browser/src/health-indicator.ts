/**
 * Connection health classifier for the toolbar dot.
 *
 * Three states:
 *   ok     — recent samples, sane latencies, fresh WS traffic
 *   warn   — degraded: median elevated, OR queue building up, OR
 *              traffic gap building (no recv in a few seconds)
 *   bad    — disconnected, OR no traffic for many seconds while
 *              session is attached, OR sustained median misery
 *
 * Pure function: takes a snapshot, returns a state. Drive it from
 * the existing latency tick. Makes the rules trivially unit-testable
 * without faking timers or DOM.
 */

export type HealthState = "unknown" | "ok" | "warn" | "bad";

export interface HealthInputs {
  /** Is the WebSocket currently connected (WS readyState === OPEN)? */
  wsConnected: boolean;
  /** Are we attached to a session? Drives "no traffic" gating —
   *  before attach, gaps between frames don't mean anything. */
  attached: boolean;
  /** Most recent sample count from the tracker. 0 means no recent
   *  measurements (idle, or just connected). */
  sampleCount: number;
  /** Median total latency over the recent window, in ms. 0 when
   *  count is 0. */
  totalP50Ms: number;
  /** Pending queue depth — keystrokes typed without a matched
   *  render. Sustained growth here usually means echoes aren't
   *  arriving. */
  pending: number;
  /** Time since the most recent WS frame from the daemon, in ms.
   *  Infinity if no frames have been received. */
  msSinceLastWsFrame: number;
}

/** Thresholds, exported so tests can confirm we mean what we say. */
export const HEALTH_THRESHOLDS = {
  /** total p50 threshold for "warn" classification */
  warnP50Ms: 80,
  /** total p50 threshold for "bad" */
  badP50Ms: 200,
  /** pending count that signals queues backing up */
  warnPending: 5,
  badPending: 20,
  /** seconds without any WS frame from daemon (while attached)
   *  before we consider the connection unhealthy */
  warnIdleMs: 8_000,
  badIdleMs: 20_000,
} as const;

export function classify(inputs: HealthInputs): HealthState {
  if (!inputs.wsConnected) return "bad";

  // Before attach there's no point grading network — we don't have
  // samples and there's no expected echo cadence.
  if (!inputs.attached) return "unknown";

  // Idle gap. If the session is attached but nothing is coming back,
  // something is wrong — even an idle shell sends OSC/cursor frames
  // periodically, and a typing user gets continuous echo.
  if (inputs.msSinceLastWsFrame >= HEALTH_THRESHOLDS.badIdleMs) return "bad";

  let level: HealthState = "ok";

  if (inputs.msSinceLastWsFrame >= HEALTH_THRESHOLDS.warnIdleMs) {
    level = worstOf(level, "warn");
  }

  // Latency-based grading only when we have samples; an attached but
  // not-typing session shouldn't go yellow just because count=0.
  if (inputs.sampleCount > 0) {
    if (inputs.totalP50Ms >= HEALTH_THRESHOLDS.badP50Ms) {
      level = worstOf(level, "bad");
    } else if (inputs.totalP50Ms >= HEALTH_THRESHOLDS.warnP50Ms) {
      level = worstOf(level, "warn");
    }
  }

  if (inputs.pending >= HEALTH_THRESHOLDS.badPending) {
    level = worstOf(level, "bad");
  } else if (inputs.pending >= HEALTH_THRESHOLDS.warnPending) {
    level = worstOf(level, "warn");
  }

  return level;
}

function worstOf(a: HealthState, b: HealthState): HealthState {
  const order: Record<HealthState, number> = {
    unknown: 0,
    ok: 1,
    warn: 2,
    bad: 3,
  };
  return order[a] > order[b] ? a : b;
}

/** Tooltip-friendly string for the indicator. */
export function describe(state: HealthState, inputs: HealthInputs): string {
  if (state === "bad" && !inputs.wsConnected) return "Disconnected";
  if (state === "bad" && inputs.msSinceLastWsFrame >= HEALTH_THRESHOLDS.badIdleMs) {
    return `No traffic for ${Math.round(inputs.msSinceLastWsFrame / 1000)}s`;
  }
  if (state === "bad") {
    return `Slow: ${Math.round(inputs.totalP50Ms)}ms median, ${inputs.pending} pending`;
  }
  if (state === "warn") {
    return `Degraded: ${Math.round(inputs.totalP50Ms)}ms median${
      inputs.pending > 0 ? `, ${inputs.pending} pending` : ""
    }`;
  }
  if (state === "ok") {
    return `Healthy${
      inputs.sampleCount > 0 ? ` (${Math.round(inputs.totalP50Ms)}ms median)` : ""
    }`;
  }
  return "Unknown";
}
