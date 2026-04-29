// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import {
  classify,
  describe as describeState,
  HEALTH_THRESHOLDS,
  type HealthInputs,
} from "../browser/src/health-indicator.ts";

function inputs(over: Partial<HealthInputs> = {}): HealthInputs {
  return {
    wsConnected: true,
    attached: true,
    sampleCount: 50,
    totalP50Ms: 30,
    pending: 0,
    msSinceLastWsFrame: 200,
    ...over,
  };
}

describe("health classifier", () => {
  it("returns 'bad' when the WS isn't connected", () => {
    expect(classify(inputs({ wsConnected: false }))).toBe("bad");
  });

  it("returns 'unknown' before the session is attached", () => {
    // No samples to grade against, no echo expected.
    expect(classify(inputs({ attached: false, sampleCount: 0, totalP50Ms: 0 }))).toBe("unknown");
  });

  it("returns 'ok' for typical good numbers", () => {
    expect(classify(inputs({ sampleCount: 100, totalP50Ms: 35, pending: 0 }))).toBe("ok");
  });

  it("returns 'warn' when total p50 is over the warn threshold", () => {
    expect(
      classify(inputs({ sampleCount: 100, totalP50Ms: HEALTH_THRESHOLDS.warnP50Ms + 5 }))
    ).toBe("warn");
  });

  it("returns 'bad' when total p50 exceeds the bad threshold", () => {
    expect(
      classify(inputs({ sampleCount: 100, totalP50Ms: HEALTH_THRESHOLDS.badP50Ms + 50 }))
    ).toBe("bad");
  });

  it("ignores latency thresholds when there are no samples (idle attached session)", () => {
    // A session that's connected, attached, but the user isn't typing.
    // Latency p50=0 because there are 0 samples — that shouldn't
    // make us report bad.
    expect(
      classify(inputs({ sampleCount: 0, totalP50Ms: 0, msSinceLastWsFrame: 100 }))
    ).toBe("ok");
  });

  it("returns 'warn' when pending crosses the warn threshold", () => {
    expect(classify(inputs({ pending: HEALTH_THRESHOLDS.warnPending }))).toBe("warn");
  });

  it("returns 'bad' when pending crosses the bad threshold", () => {
    expect(classify(inputs({ pending: HEALTH_THRESHOLDS.badPending }))).toBe("bad");
  });

  it("returns 'warn' when there's been no WS traffic for the warn-idle window", () => {
    expect(
      classify(inputs({ msSinceLastWsFrame: HEALTH_THRESHOLDS.warnIdleMs + 1 }))
    ).toBe("warn");
  });

  it("returns 'bad' when there's been no traffic for the bad-idle window", () => {
    expect(
      classify(inputs({ msSinceLastWsFrame: HEALTH_THRESHOLDS.badIdleMs + 1 }))
    ).toBe("bad");
  });

  it("idle traffic does not flag a non-attached session", () => {
    // Long since last frame doesn't matter when we're not attached
    // (e.g. on the overview waiting for sessions list).
    expect(
      classify(
        inputs({ attached: false, msSinceLastWsFrame: 60_000, sampleCount: 0, totalP50Ms: 0 })
      )
    ).toBe("unknown");
  });

  it("worst signal wins (warn latency + bad pending = bad)", () => {
    expect(
      classify(
        inputs({
          totalP50Ms: HEALTH_THRESHOLDS.warnP50Ms + 5,
          pending: HEALTH_THRESHOLDS.badPending,
        })
      )
    ).toBe("bad");
  });
});

describe("describe()", () => {
  it("special-cases disconnected", () => {
    expect(describeState("bad", inputs({ wsConnected: false }))).toBe("Disconnected");
  });

  it("reports idle-time when bad due to traffic gap", () => {
    expect(
      describeState("bad", inputs({ msSinceLastWsFrame: 25_000 }))
    ).toMatch(/No traffic for 25s/);
  });

  it("includes median when ok with samples", () => {
    expect(describeState("ok", inputs({ sampleCount: 50, totalP50Ms: 42 }))).toBe(
      "Healthy (42ms median)"
    );
  });

  it("just says Healthy when ok with no samples", () => {
    expect(describeState("ok", inputs({ sampleCount: 0, totalP50Ms: 0 }))).toBe("Healthy");
  });
});
