import { describe, it, expect } from "vitest";

/**
 * The relay broadcasts a `{"type":"revoked"}` JSON frame (followed by
 * close code 4001) on every socket authenticated by a revoked key or
 * a deleted account. Previously only the primary socket handled this —
 * now per-client daemon sockets and client_pair sockets do too.
 *
 * Unit-test scope: verify the frame routing logic inside
 * `PrimaryRelayConnection.handleTextMessage`. The full relay-close
 * pathway is exercised in the end-to-end smoke test against the
 * deployed relay.
 */

// @ts-expect-error — private method under test; tests need access
import { PrimaryRelayConnection, REVOKED_CLOSE_CODE } from "../src/relay/primary-connection.ts";

function makeConn(onRevoked: () => void): PrimaryRelayConnection {
  return new PrimaryRelayConnection("ws://localhost:0/nope", {
    onConnected: () => {},
    onClientWaiting: () => {},
    onClientDisconnected: () => {},
    onError: () => {},
    onClose: () => {},
    onRevoked,
  });
}

describe("PrimaryRelayConnection revoked frame", () => {
  it("fires onRevoked when the relay sends {type:'revoked'}", () => {
    let called = 0;
    const conn = makeConn(() => { called++; });
    // Reach into the private method to drive it without a real WS.
    (conn as any).handleTextMessage(JSON.stringify({ type: "revoked" }));
    expect(called).toBe(1);
  });

  it("ignores revoked frames with extra fields (future-compat)", () => {
    let called = 0;
    const conn = makeConn(() => { called++; });
    (conn as any).handleTextMessage(
      JSON.stringify({ type: "revoked", reason: "key_deleted", key_id: "abc" })
    );
    expect(called).toBe(1);
  });

  it("doesn't fire onRevoked for unrelated frames", () => {
    let called = 0;
    const conn = makeConn(() => { called++; });
    (conn as any).handleTextMessage(JSON.stringify({ type: "draining" }));
    (conn as any).handleTextMessage(JSON.stringify({ type: "client_waiting", client_id: "x" }));
    (conn as any).handleTextMessage("not json");
    expect(called).toBe(0);
  });

  it("exports the standard 4001 close code", () => {
    expect(REVOKED_CLOSE_CODE).toBe(4001);
  });
});
