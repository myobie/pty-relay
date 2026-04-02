import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

// Mock WebSocket before importing the module under test
const mockWsInstances: MockWebSocket[] = [];

class MockWebSocket extends EventEmitter {
  static OPEN = 1;
  static CLOSED = 3;

  binaryType = "nodebuffer";
  readyState = MockWebSocket.OPEN;
  pingFn = vi.fn();
  terminateFn = vi.fn();
  closeFn = vi.fn();
  sendFn = vi.fn();

  constructor(_url: string) {
    super();
    mockWsInstances.push(this);
  }

  ping() { this.pingFn(); }
  terminate() {
    this.terminateFn();
    this.readyState = MockWebSocket.CLOSED;
    // terminate fires close
    this.emit("close");
  }
  close() {
    this.closeFn();
    this.readyState = MockWebSocket.CLOSED;
  }
  send(data: unknown) { this.sendFn(data); }
}

vi.mock("ws", () => ({
  default: MockWebSocket,
}));

// Now import after mock is set up
const { ClientRelayConnection } = await import("../src/terminal/client-connection.ts");

beforeEach(() => {
  mockWsInstances.length = 0;
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

function createEvents() {
  return {
    onReady: vi.fn(),
    onEncryptedMessage: vi.fn(),
    onPeerDisconnected: vi.fn(),
    onError: vi.fn(),
    onClose: vi.fn(),
    onWaitingForApproval: vi.fn(),
  };
}

describe("ClientRelayConnection pong timeout", () => {
  it("sends a ping every 15 seconds", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    expect(ws.pingFn).not.toHaveBeenCalled();

    vi.advanceTimersByTime(15000);
    expect(ws.pingFn).toHaveBeenCalledTimes(1);

    // Send pong so the connection stays alive for the next ping cycle
    ws.emit("pong");

    vi.advanceTimersByTime(15000);
    expect(ws.pingFn).toHaveBeenCalledTimes(2);

    conn.close();
  });

  it("terminates if no pong received within 5s of a ping", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    // Advance to trigger the first ping
    vi.advanceTimersByTime(15000);
    expect(ws.pingFn).toHaveBeenCalledTimes(1);

    // No pong received — advance past the pong timeout
    vi.advanceTimersByTime(5000);
    expect(ws.terminateFn).toHaveBeenCalledTimes(1);
  });

  it("does NOT terminate if pong is received in time", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    // Advance to trigger the first ping
    vi.advanceTimersByTime(15000);
    expect(ws.pingFn).toHaveBeenCalledTimes(1);

    // Simulate pong received after 2s
    vi.advanceTimersByTime(2000);
    ws.emit("pong");

    // Advance past the original 5s pong timeout — should NOT terminate
    vi.advanceTimersByTime(3000);
    expect(ws.terminateFn).not.toHaveBeenCalled();

    conn.close();
  });

  it("fires onClose when terminated due to pong timeout", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    // Trigger ping + pong timeout
    vi.advanceTimersByTime(15000 + 5000);

    expect(events.onClose).toHaveBeenCalledTimes(1);
  });

  it("clears pong timer on close", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    // Trigger ping (starts pong timer)
    vi.advanceTimersByTime(15000);

    // Close before pong timeout fires
    conn.close();

    // Advance past pong timeout — should NOT terminate since we closed
    vi.advanceTimersByTime(5000);
    expect(ws.terminateFn).not.toHaveBeenCalled();
  });
});

describe("ClientRelayConnection peer_disconnected", () => {
  it("fires onPeerDisconnected when relay sends peer_disconnected", () => {
    const events = createEvents();
    const conn = new ClientRelayConnection("ws://test", new Uint8Array(32), events);
    conn.connect();

    const ws = mockWsInstances[0];
    ws.emit("open");

    // Simulate receiving a peer_disconnected text message
    ws.emit("message", JSON.stringify({ type: "peer_disconnected" }), false);

    expect(events.onPeerDisconnected).toHaveBeenCalledTimes(1);

    conn.close();
  });
});
