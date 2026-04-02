import { describe, it, expect } from "vitest";
import { reconnectDelay } from "../src/commands/connect.ts";

describe("reconnectDelay", () => {
  it("returns 1s for the first attempt", () => {
    expect(reconnectDelay(0)).toBe(1000);
  });

  it("returns 2s for the second attempt", () => {
    expect(reconnectDelay(1)).toBe(2000);
  });

  it("returns 4s for the third attempt", () => {
    expect(reconnectDelay(2)).toBe(4000);
  });

  it("returns 8s for the fourth attempt", () => {
    expect(reconnectDelay(3)).toBe(8000);
  });

  it("caps at 15s", () => {
    expect(reconnectDelay(4)).toBe(15000); // would be 16000, capped
    expect(reconnectDelay(5)).toBe(15000); // would be 32000, capped
    expect(reconnectDelay(10)).toBe(15000);
  });

  it("follows exponential backoff pattern", () => {
    const delays = [0, 1, 2, 3, 4, 5].map(reconnectDelay);
    expect(delays).toEqual([1000, 2000, 4000, 8000, 15000, 15000]);
  });
});
