import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Buffer } from "node:buffer";
import { Terminal, type TerminalConnection } from "../src/terminal/terminal.ts";
import {
  MessageType,
  encodePacket,
} from "../../pty/src/protocol.ts";

function createMockConnection(): TerminalConnection {
  return {
    sendApp: vi.fn(),
    sendBridgeData: vi.fn(),
  };
}

function makeExitPacket(exitCode: number): Uint8Array {
  const payload = Buffer.alloc(4);
  payload.writeInt32BE(exitCode, 0);
  return new Uint8Array(encodePacket(MessageType.EXIT, payload));
}

function feedAttached(t: Terminal): void {
  t.handleAppMessage("attached", { type: "attached" });
}

function feedError(t: Terminal, message: string): void {
  t.handleAppMessage("error", { type: "error", message });
}

// Suppress terminal escape sequences written to stdout during tests
let stdoutWriteSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  stdoutWriteSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
});

afterEach(() => {
  stdoutWriteSpy.mockRestore();
});

describe("Terminal callbacks", () => {
  it("calls onDetach and does NOT call process.exit when onDetach is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    const onDetach = vi.fn();
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
      onDetach,
    });

    // First, put terminal in "attached" state so detach makes sense
    feedAttached(terminal);

    // Simulate Ctrl+\ by feeding the detach byte via handleMessage
    // Actually, detach is triggered by stdin, so we call it indirectly.
    // The simplest approach: call the private detach method.
    (terminal as any).detach();

    expect(onDetach).toHaveBeenCalledOnce();
    expect(exitSpy).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("calls onExit with exit code and does NOT call process.exit when onExit is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    const onExit = vi.fn();
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
      onExit,
    });

    // Put terminal in attached state
    feedAttached(terminal);

    // Feed an EXIT packet
    terminal.handlePtyBytes(makeExitPacket(0));

    expect(onExit).toHaveBeenCalledOnce();
    expect(onExit).toHaveBeenCalledWith(0);
    expect(exitSpy).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("calls onExit with non-zero exit code", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    const onExit = vi.fn();
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
      onExit,
    });

    feedAttached(terminal);
    terminal.handlePtyBytes(makeExitPacket(42));

    expect(onExit).toHaveBeenCalledOnce();
    expect(onExit).toHaveBeenCalledWith(42);
    expect(exitSpy).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("calls onError with the error message and does NOT call process.exit when onError is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    const onError = vi.fn();
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
      onError,
    });

    // Feed an error message (before attached state)
    feedError(terminal, "session not found");

    expect(onError).toHaveBeenCalledOnce();
    expect(onError).toHaveBeenCalledWith("session not found");
    expect(exitSpy).not.toHaveBeenCalled();

    exitSpy.mockRestore();
  });

  it("calls process.exit when NO onExit callback is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as any);
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
    });

    feedAttached(terminal);
    terminal.handlePtyBytes(makeExitPacket(0));

    expect(exitSpy).toHaveBeenCalledWith(0);

    exitSpy.mockRestore();
  });

  it("calls process.exit(1) on error when NO onError callback is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as any);
    const conn = createMockConnection();
    // Suppress console.error
    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
    });

    feedError(terminal, "something broke");

    expect(exitSpy).toHaveBeenCalledWith(1);

    exitSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it("calls process.exit(0) on detach when NO onDetach callback is provided", () => {
    const exitSpy = vi.spyOn(process, "exit").mockImplementation((() => {}) as any);
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
    });

    (terminal as any).detach();

    expect(exitSpy).toHaveBeenCalledWith(0);

    exitSpy.mockRestore();
  });
});

describe("Terminal removeListeners", () => {
  it("clears stdinHandler and resizeHandler", () => {
    const conn = createMockConnection();

    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
    });

    // Initially no handlers
    expect((terminal as any).stdinHandler).toBeNull();
    expect((terminal as any).resizeHandler).toBeNull();

    // Set handlers manually to simulate enterRawMode having run
    const stdinFn = () => {};
    const resizeFn = () => {};
    (terminal as any).stdinHandler = stdinFn;
    (terminal as any).resizeHandler = resizeFn;

    // Spy on removeListener
    const stdinRemoveSpy = vi.spyOn(process.stdin, "removeListener");
    const stdoutRemoveSpy = vi.spyOn(process.stdout, "removeListener");

    terminal.removeListeners();

    expect((terminal as any).stdinHandler).toBeNull();
    expect((terminal as any).resizeHandler).toBeNull();
    expect(stdinRemoveSpy).toHaveBeenCalledWith("data", stdinFn);
    expect(stdoutRemoveSpy).toHaveBeenCalledWith("resize", resizeFn);

    stdinRemoveSpy.mockRestore();
    stdoutRemoveSpy.mockRestore();
  });

  it("is safe to call multiple times", () => {
    const conn = createMockConnection();
    const terminal = new Terminal({
      connection: conn,
      session: "test",
      cols: 80,
      rows: 24,
    });

    // Should not throw when called with no handlers set
    expect(() => terminal.removeListeners()).not.toThrow();
    expect(() => terminal.removeListeners()).not.toThrow();
  });
});
